import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { TrustBaseHistory } from '../../../src/api/bft/trustbase/TrustBaseHistory.js';
import { TrustBaseResponseStatus } from '../../../src/api/bft/trustbase/TrustBaseResponse.js';
import { TrustBaseUpdateError } from '../../../src/api/bft/trustbase/TrustBaseUpdateError.js';
import { CertificateVerificationResult } from '../../../src/api/bft/verification/CertificateVerdict.js';
import { SleepError } from '../../../src/internal/abortable.js';
import { HexConverter } from '../../../src/util/HexConverter.js';
import { fetchTrustBaseEntries, verifyWithTrustBaseUpdate } from '../../../src/util/TrustBaseUtils.js';
import { encodeTrustBasePage, StaticTrustBaseSource } from '../../utils/TrustBaseSourceFixture.js';

/** The signed chain of the shared UTB vectors: epochs 1..4, network 3. */
const vectors = JSON.parse(readFileSync(join(process.cwd(), 'tests/fixtures/utb/v1/utb-vectors-v1.json'), 'utf8')) as {
  chain: { epoch: number; hex: string }[];
  entryCases: { id: string; input: string }[];
  network: number;
  pin: string;
};
const chain = new Map(vectors.chain.map((c) => [BigInt(c.epoch), HexConverter.decode(c.hex)]));
const NETWORK = vectors.network;

function genesisHistory(): Promise<TrustBaseHistory> {
  return TrustBaseHistory.fromGenesis(chain.get(1n)!, HexConverter.decode(vectors.pin));
}

/** A verification that needs epoch `epoch`: "no entry" until the history holds it. */
function needs(epoch: bigint): (h: TrustBaseHistory) => Promise<CertificateVerificationResult> {
  return (h) =>
    Promise.resolve(
      h.tipEpoch >= epoch
        ? new CertificateVerificationResult('Fake', 'ok')
        : new CertificateVerificationResult('Fake', 'no_entry_for_epoch', '', [], { epoch, latest: h.tipEpoch }),
    );
}

describe('verifyWithTrustBaseUpdate', () => {
  it('fetches from the latest held epoch + 1, appends, and verifies again', async () => {
    const history = await genesisHistory();
    const source = new StaticTrustBaseSource(NETWORK, chain);
    const result = await verifyWithTrustBaseUpdate(needs(3n), history, source);
    expect(result.verdict).toBe('ok');
    expect(history.tipEpoch).toBe(4n); // one fetch brings everything the source has
    expect(source.calls).toEqual([{ fromEpoch: 2n, maxEntries: 64 }]);
  });

  it('follows the per-fetch cap at once, without pausing', async () => {
    const history = await genesisHistory();
    const source = new StaticTrustBaseSource(NETWORK, chain);
    const started = Date.now();
    const result = await verifyWithTrustBaseUpdate(needs(4n), history, source, { intervalMs: 5000, maxEntries: 1 });
    expect(result.verdict).toBe('ok');
    expect(source.calls.map((c) => c.fromEpoch)).toEqual([2n, 3n, 4n]);
    expect(Date.now() - started).toBeLessThan(4000);
  });

  it('waits the interval while the source does not have the epoch yet', async () => {
    const history = await genesisHistory();
    const source = new StaticTrustBaseSource(NETWORK, chain, 1n);
    const promise = verifyWithTrustBaseUpdate(needs(2n), history, source, { intervalMs: 20 });
    setTimeout(() => (source.available = 2n), 50);
    expect((await promise).verdict).toBe('ok');
    expect(source.calls.length).toBeGreaterThan(1);
    expect(source.calls.every((c) => c.fromEpoch === 2n)).toBe(true);
  });

  it('gives up after the attempts and returns the retryable result', async () => {
    const history = await genesisHistory();
    const source = new StaticTrustBaseSource(NETWORK, chain, 1n);
    const result = await verifyWithTrustBaseUpdate(needs(2n), history, source, { attempts: 3, intervalMs: 1 });
    expect(result.verdict).toBe('no_entry_for_epoch');
    expect(result.missing).toEqual({ epoch: 2n, latest: 1n });
    expect(source.calls).toHaveLength(3);
  });

  it('returns the retryable result when the budget runs out, and throws on caller cancellation', async () => {
    const history = await genesisHistory();
    const source = new StaticTrustBaseSource(NETWORK, chain, 1n);
    const result = await verifyWithTrustBaseUpdate(needs(2n), history, source, { intervalMs: 10_000, timeoutMs: 50 });
    expect(result.verdict).toBe('no_entry_for_epoch');

    const controller = new AbortController();
    const cancelled = verifyWithTrustBaseUpdate(needs(2n), history, source, {
      intervalMs: 10_000,
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 20);
    await expect(cancelled).rejects.toBeInstanceOf(SleepError);
  });

  it('returns the retryable result when the budget runs out during a fetch', async () => {
    const history = await genesisHistory();
    const hanging = {
      getTrustBaseEntries: (_from: bigint, _max: number, options?: { signal?: AbortSignal }): Promise<Uint8Array> =>
        new Promise((_resolve, reject) => {
          options?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
        }),
    };
    const result = await verifyWithTrustBaseUpdate(needs(2n), history, hanging, { timeoutMs: 50 });
    expect(result.verdict).toBe('no_entry_for_epoch');
  });

  it('never fetches for a final result', async () => {
    const history = await genesisHistory();
    const source = new StaticTrustBaseSource(NETWORK, chain);
    for (const verdict of ['ok', 'invalid', 'malformed'] as const) {
      const result = await verifyWithTrustBaseUpdate(
        () => Promise.resolve(new CertificateVerificationResult('Fake', verdict)),
        history,
        source,
      );
      expect(result.verdict).toBe(verdict);
    }
    expect(source.calls).toHaveLength(0);
  });

  it('refuses an entry that does not authenticate, keeping what was appended before', async () => {
    const history = await genesisHistory();
    const source = new StaticTrustBaseSource(NETWORK, chain);
    const bad = HexConverter.decode(vectors.entryCases.find((c) => c.id === 'refused.below-threshold')!.input);
    source.overrides.push(await encodeTrustBasePage(NETWORK, TrustBaseResponseStatus.OK, 2n, [bad], 2n));
    const error = await verifyWithTrustBaseUpdate(needs(2n), history, source).catch((e: unknown) => e);
    expect(TrustBaseUpdateError.is(error) && error.reason).toBe('rejected');
    expect(history.tipEpoch).toBe(1n);

    // a conflicting record for a held epoch is refused too; held entries are never replaced
    await history.append(chain.get(2n)!);
    const conflict = HexConverter.decode(vectors.entryCases.find((c) => c.id === 'conflict.e2')!.input);
    source.overrides.push(await encodeTrustBasePage(NETWORK, TrustBaseResponseStatus.OK, 3n, [chain.get(3n)!], 3n));
    expect(await fetchTrustBaseEntries(history, source)).toBe(1);
    await expect(history.append(conflict)).rejects.toMatchObject({ reason: 'conflict' });
    expect(HexConverter.encode(history.bytes(2n)!)).toBe(HexConverter.encode(chain.get(2n)!));
  });

  it('refuses a response of another network, a refusal status, a wrong start or undecodable bytes', async () => {
    const cases: [Uint8Array, string][] = [
      [await encodeTrustBasePage(NETWORK + 1, TrustBaseResponseStatus.OK, 2n, [chain.get(2n)!], 2n), 'malformed'],
      [await encodeTrustBasePage(NETWORK, TrustBaseResponseStatus.BUSY, 2n, [], 1n), 'refused'],
      [await encodeTrustBasePage(NETWORK, TrustBaseResponseStatus.OK, 3n, [chain.get(3n)!], 3n), 'malformed'],
      [new Uint8Array([0xa0]), 'malformed'],
    ];
    for (const [bytes, reason] of cases) {
      const history = await genesisHistory();
      const source = new StaticTrustBaseSource(NETWORK, chain);
      source.overrides.push(bytes);
      await expect(fetchTrustBaseEntries(history, source)).rejects.toMatchObject({
        name: 'TrustBaseUpdateError',
        reason,
      });
    }
    // a well-formed page for another network
    const history = await genesisHistory();
    const source = new StaticTrustBaseSource(NETWORK, chain);
    source.overrides.push(
      await encodeTrustBasePage(NETWORK + 1, TrustBaseResponseStatus.NOT_YET_AVAILABLE, 2n, [], 1n),
    );
    await expect(fetchTrustBaseEntries(history, source)).rejects.toMatchObject({ reason: 'wrong_network' });
  });

  it('shares one fetch between concurrent updates of one history', async () => {
    const history = await genesisHistory();
    const source = new StaticTrustBaseSource(NETWORK, chain);
    const [a, b] = await Promise.all([fetchTrustBaseEntries(history, source), fetchTrustBaseEntries(history, source)]);
    expect([a, b]).toEqual([3, 3]);
    expect(source.calls).toHaveLength(1);
  });

  it('refuses a cap outside the page limit', async () => {
    const history = await genesisHistory();
    const source = new StaticTrustBaseSource(NETWORK, chain);
    await expect(fetchTrustBaseEntries(history, source, { maxEntries: 65 })).rejects.toBeInstanceOf(RangeError);
    await expect(fetchTrustBaseEntries(history, source, { maxEntries: 0 })).rejects.toBeInstanceOf(RangeError);
  });
});
