import {
  buildBundle,
  IBundleFields,
  loadVectors,
  parseBundleFields,
  parseEntryFields,
  rangeFields,
  signEntry,
} from './TrustBaseTestUtils.js';
import { RootTrustBaseV2 } from '../../../../../src/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseUpdateError } from '../../../../../src/api/bft/trustbase/TrustBaseError.js';
import { TrustBaseHistory } from '../../../../../src/api/bft/trustbase/TrustBaseHistory.js';
import { TrustBaseStatus } from '../../../../../src/api/bft/trustbase/TrustBaseRange.js';
import { TrustBaseUpdater } from '../../../../../src/api/bft/trustbase/TrustBaseUpdater.js';
import { ITrustBaseRequest, ITrustBaseSource } from '../../../../../src/api/ITrustBaseSource.js';
import { NetworkId } from '../../../../../src/api/NetworkId.js';
import { HexConverter } from '../../../../../src/util/HexConverter.js';

type Handler = (request: ITrustBaseRequest, call: number) => Promise<Uint8Array>;

class FakeSource implements ITrustBaseSource {
  public readonly requests: ITrustBaseRequest[] = [];

  public constructor(private readonly handler: Handler) {}

  public getTrustBasePage(request: ITrustBaseRequest): Promise<Uint8Array> {
    this.requests.push(request);
    return this.handler(request, this.requests.length);
  }
}

const FAST = { backoffMs: 0 };
const serve = (bytes: Uint8Array): FakeSource => new FakeSource(() => Promise.resolve(bytes));
const fail = (): FakeSource => new FakeSource(() => Promise.reject(new Error('unreachable')));

const refusal = (status: TrustBaseStatus, effectiveEnd = 1n): Uint8Array =>
  buildBundle({
    ...rangeFields(),
    effectiveEnd,
    endEntryId: null,
    entries: [],
    status: BigInt(status),
  });

/** A history holding the genesis of the three-entry vector. */
async function atGenesis(): Promise<TrustBaseHistory> {
  const fields = threeEntries();
  const history = TrustBaseHistory.create(await RootTrustBaseV2.decode(fields.entries[0]).entryId());
  await history.append(RootTrustBaseV2.decode(fields.entries[0]));
  return history;
}

function threeEntries(): IBundleFields {
  const vector = loadVectors().bundles.find((candidate) => candidate.name.startsWith('three'));
  return parseBundleFields(HexConverter.decode(vector?.hex ?? ''));
}

const failure = async (promise: Promise<unknown>): Promise<TrustBaseUpdateError> => {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(TrustBaseUpdateError);
  return error as TrustBaseUpdateError;
};

describe('TrustBaseUpdater', () => {
  it('appends the entries after the tip from one page, asking from the tip epoch + 1', async () => {
    const history = await atGenesis();
    const source = serve(buildBundle(rangeFields()));

    await expect(TrustBaseUpdater.update(history, [source], FAST)).resolves.toBe(2);

    expect(history.tip?.epoch).toBe(3n);
    expect(source.requests).toHaveLength(1);
    expect(source.requests[0].fromEpoch).toBe(2n);
    expect(source.requests[0].snapshot).toBeNull();
    expect(source.requests[0].network.id).toBe(5);
  });

  it('follows the cursor and echoes the end epoch and entry id of the first page on the next', async () => {
    const history = await atGenesis();
    const f = rangeFields();
    const endId = await RootTrustBaseV2.decode(f.entries[1]).entryId();
    const source = new FakeSource((request) =>
      Promise.resolve(
        request.snapshot === null
          ? buildBundle({ ...f, entries: [f.entries[0]], nextEpoch: 3n })
          : buildBundle({ ...f, entries: [f.entries[1]], fromEpoch: 3n }),
      ),
    );

    await expect(TrustBaseUpdater.update(history, [source], FAST)).resolves.toBe(2);

    expect(source.requests.map((request) => request.fromEpoch)).toEqual([2n, 3n]);
    expect(source.requests[1].snapshot?.end).toBe(3n);
    expect(HexConverter.encode(source.requests[1].snapshot?.entryId ?? new Uint8Array())).toBe(
      HexConverter.encode(endId),
    );
  });

  it('a source that has nothing newer is a result, not an error: 0 appended', async () => {
    const history = await atGenesis();
    await expect(
      TrustBaseUpdater.update(history, [serve(refusal(TrustBaseStatus.NOT_YET_AVAILABLE))], FAST),
    ).resolves.toBe(0);
    expect(history.tip?.epoch).toBe(1n);
  });

  it('is current only when every source says nothing newer', async () => {
    const history = await atGenesis();
    const nothing = refusal(TrustBaseStatus.NOT_YET_AVAILABLE);
    await expect(TrustBaseUpdater.update(history, [serve(nothing), serve(nothing)], FAST)).resolves.toBe(0);

    const error = await failure(TrustBaseUpdater.update(history, [serve(nothing), fail()], { ...FAST, rounds: 1 }));
    expect(error.causes).toHaveLength(1);
  });

  it('does not take a source that claims an end at or after the wanted epoch as "nothing newer"', async () => {
    const history = await atGenesis();
    const lagging = serve(refusal(TrustBaseStatus.NOT_YET_AVAILABLE, 2n));
    await failure(TrustBaseUpdater.update(history, [lagging], { ...FAST, rounds: 1 }));
    expect(history.tip?.epoch).toBe(1n);
  });

  it('a source that lags behind the snapshot is a failure and keeps the authenticated prefix', async () => {
    const history = await atGenesis();
    const f = rangeFields();
    const lagging = refusal(TrustBaseStatus.NOT_YET_AVAILABLE, 2n);
    const source = new FakeSource((request) =>
      Promise.resolve(
        request.snapshot === null ? buildBundle({ ...f, entries: [f.entries[0]], nextEpoch: 3n }) : lagging,
      ),
    );
    await failure(TrustBaseUpdater.update(history, [source], { ...FAST, rounds: 1 }));
    expect(history.tip?.epoch).toBe(2n);
  });

  it('falls through to the next source when one is unreachable', async () => {
    const history = await atGenesis();
    await expect(TrustBaseUpdater.update(history, [fail(), serve(buildBundle(rangeFields()))], FAST)).resolves.toBe(2);
  });

  it('does not ask a source again after a final refusal, but does after busy and unavailable', async () => {
    const history = await atGenesis();
    const final = serve(refusal(TrustBaseStatus.HISTORY_MISMATCH));
    const busy = serve(refusal(TrustBaseStatus.BUSY));
    const error = await failure(TrustBaseUpdater.update(history, [final, busy], FAST));
    expect(final.requests).toHaveLength(1);
    expect(busy.requests).toHaveLength(2);
    expect(error.causes).toHaveLength(3);
  });

  it('a busy source that recovers on the second pass serves the range', async () => {
    const history = await atGenesis();
    const busy = refusal(TrustBaseStatus.BUSY);
    const good = buildBundle(rangeFields());
    const source = new FakeSource((_request, call) => Promise.resolve(call === 1 ? busy : good));
    await expect(TrustBaseUpdater.update(history, [source], FAST)).resolves.toBe(2);
  });

  it('a source that serves an entry the history refuses is skipped and the next source serves the range', async () => {
    const history = await atGenesis();
    const f = rangeFields();
    const thin = signEntry(parseEntryFields(f.entries[0]), ['a']);
    const bad = serve(
      buildBundle({
        ...f,
        effectiveEnd: 2n,
        endEntryId: await RootTrustBaseV2.decode(thin).entryId(),
        entries: [thin],
      }),
    );
    const good = serve(buildBundle(f));

    await expect(TrustBaseUpdater.update(history, [bad, good], FAST)).resolves.toBe(2);
    expect(bad.requests).toHaveLength(1);
    expect(history.tip?.epoch).toBe(3n);
  });

  it('a response for another network or garbage bytes is a failure of that source', async () => {
    const history = await atGenesis();
    const f = rangeFields();
    const error = await failure(
      TrustBaseUpdater.update(history, [serve(buildBundle({ ...f, network: 6n })), serve(new Uint8Array([1, 2, 3]))], {
        ...FAST,
        rounds: 1,
      }),
    );
    expect(error.causes).toHaveLength(2);
  });

  it('a page that does not continue the requested range is a failure', async () => {
    const history = await atGenesis();
    const f = rangeFields();
    // epoch 3 only, though epoch 2 was asked for
    const skipping = buildBundle({ ...f, entries: [f.entries[1]], fromEpoch: 3n });
    await failure(TrustBaseUpdater.update(history, [serve(skipping)], { ...FAST, rounds: 1 }));
    expect(history.tip?.epoch).toBe(1n);
  });

  it('catches an empty history up from the genesis when it is given the network', async () => {
    const f = threeEntries();
    const history = TrustBaseHistory.create(await RootTrustBaseV2.decode(f.entries[0]).entryId());
    const source = serve(buildBundle(f));

    await expect(TrustBaseUpdater.update(history, [source], { ...FAST, network: NetworkId.fromId(5) })).resolves.toBe(
      3,
    );
    expect(source.requests[0].fromEpoch).toBe(1n);
    expect(history.tip?.epoch).toBe(3n);
  });

  it('refuses an empty history without a network, and no sources', async () => {
    const history = TrustBaseHistory.create(new Uint8Array(32));
    await failure(TrustBaseUpdater.update(history, [fail()], FAST));
    await failure(TrustBaseUpdater.update(await atGenesis(), [], FAST));
  });

  it('shares one update between concurrent callers of the same history', async () => {
    const history = await atGenesis();
    const source = serve(buildBundle(rangeFields()));
    const [a, b] = await Promise.all([
      TrustBaseUpdater.update(history, [source], FAST),
      TrustBaseUpdater.update(history, [source], FAST),
    ]);
    expect([a, b]).toEqual([2, 2]);
    expect(source.requests).toHaveLength(1);
    // and a later update is a new one
    await expect(TrustBaseUpdater.update(history, [serve(refusal(3))], FAST)).resolves.toBe(0);
  });

  it('stops at an aborted signal without asking', async () => {
    const history = await atGenesis();
    const source = serve(buildBundle(rangeFields()));
    const controller = new AbortController();
    controller.abort(new Error('deadline'));
    await expect(TrustBaseUpdater.update(history, [source], { ...FAST, signal: controller.signal })).rejects.toThrow(
      'deadline',
    );
    expect(source.requests).toHaveLength(0);
  });
});
