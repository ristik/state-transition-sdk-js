import { UnicityCertificate } from '../../../src/api/bft/UnicityCertificate.js';
import { IAggregatorClient } from '../../../src/api/IAggregatorClient.js';
import { InclusionProofResponse } from '../../../src/api/InclusionProofResponse.js';
import { IInclusionProofRequestOptions } from '../../../src/api/IRequestOptions.js';
import { JsonRpcDataError } from '../../../src/api/json-rpc/JsonRpcDataError.js';
import { JsonRpcNetworkError } from '../../../src/api/json-rpc/JsonRpcNetworkError.js';
import { NetworkId } from '../../../src/api/NetworkId.js';
import { StateId } from '../../../src/api/StateId.js';
import { DataHash } from '../../../src/crypto/hash/DataHash.js';
import { HashAlgorithm } from '../../../src/crypto/hash/HashAlgorithm.js';
import { SigningService } from '../../../src/crypto/secp256k1/SigningService.js';
import { SignaturePredicate } from '../../../src/predicate/builtin/SignaturePredicate.js';
import { PredicateVerifierService } from '../../../src/predicate/verification/PredicateVerifierService.js';
import { StateTransitionClient } from '../../../src/StateTransitionClient.js';
import { MintTransaction } from '../../../src/transaction/MintTransaction.js';
import { TokenSalt } from '../../../src/transaction/TokenSalt.js';
import { TokenType } from '../../../src/transaction/TokenType.js';
import { IWaitInclusionProofOptions, SleepError, waitInclusionProof } from '../../../src/util/InclusionProofUtils.js';
import { expiresAt } from '../../utils/ExpiresAt.js';
import { createRootTrustBase } from '../../utils/RootTrustBaseFixture.js';
import { createUnicityCertificate } from '../../utils/UnicityCertificateFixture.js';
import { createUnicityCertificateVerifier } from '../../utils/UnicityCertificateVerifierFixture.js';

jest.setTimeout(60_000);

type Answer = () => Promise<InclusionProofResponse>;

/** One recorded request: what was asked, and when (monotonic). */
interface ICall {
  readonly at: number;
  readonly options: IInclusionProofRequestOptions | undefined;
}

/** An aggregator whose answers the test scripts; the last script entry repeats. */
type Entry = (call: number, options?: IInclusionProofRequestOptions) => Answer;

class Scripted implements IAggregatorClient {
  public readonly calls: ICall[] = [];

  public constructor(private readonly script: Entry[]) {}

  public getInclusionProof(
    _stateId: StateId,
    options?: IInclusionProofRequestOptions,
  ): Promise<InclusionProofResponse> {
    this.calls.push({ at: performance.now(), options });
    return this.script[Math.min(this.calls.length - 1, this.script.length - 1)](this.calls.length, options)();
  }

  public submitCertificationRequest(): ReturnType<IAggregatorClient['submitCertificationRequest']> {
    throw new Error('not used');
  }
}

describe('waitInclusionProof overload answers', () => {
  const owner = SigningService.generate();
  const trustBase = createRootTrustBase(owner.publicKey);
  const predicateVerifier = PredicateVerifierService.create();
  const verifier = createUnicityCertificateVerifier();
  let transaction: MintTransaction;
  let certificate: UnicityCertificate;

  beforeAll(async () => {
    transaction = await MintTransaction.create(NetworkId.LOCAL, SignaturePredicate.create(owner.publicKey), {
      expiresAt: expiresAt(),
      salt: TokenSalt.generate(),
      tokenType: TokenType.generate(),
    });
    certificate = await createUnicityCertificate(new DataHash(HashAlgorithm.SHA256, new Uint8Array(32)), owner);
  });
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  const pending: Answer = () => Promise.resolve(InclusionProofResponse.notCertified(1n, certificate).withWaitedMs(0));
  const failing =
    (error: Error): Answer =>
    () =>
      Promise.reject(error);
  const http = (status: number, retryAfterMs?: number, rpcError?: JsonRpcDataError): JsonRpcNetworkError =>
    new JsonRpcNetworkError(status, 'overloaded', rpcError, retryAfterMs);

  /** Starts a wait and lets the fake clock run; `proof` (the last answer) is a pending read followed by a failure. */
  const start = (client: IAggregatorClient, options: IWaitInclusionProofOptions): Promise<unknown> => {
    const result = waitInclusionProof(
      new StateTransitionClient(client),
      trustBase,
      predicateVerifier,
      verifier,
      transaction,
      options,
    );
    const settled = result.then(
      () => 'proof',
      (e: unknown) => e,
    );
    return settled;
  };
  const times = (client: Scripted): number[] => client.calls.map((c) => Math.round(c.at));
  const ends =
    (n: number, answer: Answer): ((call: number) => Answer) =>
    (call) =>
      call >= n ? failing(new Error('end')) : answer;
  const pendingFirst = (after: Answer): Array<(call: number) => Answer> => [
    step(after),
    step(pending),
    ends(4, pending),
  ];
  const step = (answer: Answer) => (): Answer => answer;

  it('503 then pending then more reads: one pause, then plain reads at the interval, no waitMs', async () => {
    const client = new Scripted(pendingFirst(failing(http(503))));
    const done = start(client, { intervalMs: 1000, timeoutMs: 15_000 });
    await jest.advanceTimersByTimeAsync(10_000);
    expect(await done).toEqual(new Error('end'));
    expect(client.calls).toHaveLength(4);
    expect(client.calls[0].options?.waitMs).toBeGreaterThan(0);
    for (const call of client.calls.slice(1)) {
      expect(call.options).not.toHaveProperty('waitMs');
    }
    const t = times(client);
    expect(t[1] - t[0]).toBe(1000);
    expect(t[2] - t[1]).toBe(1000);
  });

  it('-32006 busy is the same inconclusive answer', async () => {
    const client = new Scripted(pendingFirst(failing(new JsonRpcDataError({ code: -32006, message: 'busy' }))));
    const done = start(client, { intervalMs: 500, timeoutMs: 15_000 });
    await jest.advanceTimersByTimeAsync(10_000);
    expect(await done).toEqual(new Error('end'));
    expect(client.calls).toHaveLength(4);
    expect(client.calls.slice(1).every((c) => c.options?.waitMs === undefined)).toBe(true);
    expect(times(client)[1] - times(client)[0]).toBe(500);
  });

  it('data.retryable:true on any error code is an overload answer', async () => {
    const error = new JsonRpcDataError({ code: -32099, data: { retryable: true }, message: 'later' });
    const client = new Scripted(pendingFirst(failing(error)));
    const done = start(client, { intervalMs: 500, timeoutMs: 15_000 });
    await jest.advanceTimersByTimeAsync(10_000);
    expect(await done).toEqual(new Error('end'));
    expect(client.calls).toHaveLength(4);
  });

  it('429 with Retry-After pauses max(interval, Retry-After)', async () => {
    const client = new Scripted(pendingFirst(failing(http(429, 3000))));
    const done = start(client, { intervalMs: 1000, timeoutMs: 15_000 });
    await jest.advanceTimersByTimeAsync(20_000);
    expect(await done).toEqual(new Error('end'));
    expect(times(client)[1] - times(client)[0]).toBe(3000);
    expect(times(client)[2] - times(client)[1]).toBe(1000);
  });

  it('a Retry-After shorter than the interval does not shorten the pause', async () => {
    const client = new Scripted(pendingFirst(failing(http(503, 200))));
    const done = start(client, { intervalMs: 1000, timeoutMs: 15_000 });
    await jest.advanceTimersByTimeAsync(10_000);
    await done;
    expect(times(client)[1] - times(client)[0]).toBe(1000);
  });

  it('a Retry-After larger than the remaining budget fails at once with the timeout type and the overload as cause', async () => {
    const overload = http(503, 30_000);
    const client = new Scripted([step(failing(overload))]);
    const done = start(client, { intervalMs: 1000, timeoutMs: 15_000 });
    await jest.advanceTimersByTimeAsync(1);
    const error = await done;
    expect(error).toBeInstanceOf(SleepError);
    expect((error as SleepError).message).toMatch(/overloaded/);
    expect((error as SleepError).message).toMatch(/30000 ms/);
    expect((error as SleepError).cause).toBe(overload);
    expect(client.calls).toHaveLength(1);
    expect(jest.getTimerCount()).toBe(0);
  });

  it('a Retry-After above 60 s is capped at 60 s', async () => {
    const client = new Scripted([step(failing(http(503, 600_000)))]);
    const done = start(client, { intervalMs: 1000, timeoutMs: 15_000 });
    await jest.advanceTimersByTimeAsync(1);
    expect(((await done) as SleepError).message).toMatch(/60000 ms/);
  });

  it('a non-retryable error still ends the wait at once', async () => {
    for (const error of [http(500), http(404 + 100), new JsonRpcDataError({ code: -32000, message: 'bad' })]) {
      const client = new Scripted([step(failing(error))]);
      const done = start(client, { intervalMs: 1000, timeoutMs: 15_000 });
      await jest.advanceTimersByTimeAsync(1);
      expect(await done).toBe(error);
      expect(client.calls).toHaveLength(1);
    }
  });
});
