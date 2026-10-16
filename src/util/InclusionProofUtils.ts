import { RootTrustBase } from '../api/bft/RootTrustBase.js';
import { UnicityCertificateVerifier } from '../api/bft/verification/UnicityCertificateVerifier.js';
import { InclusionProof } from '../api/InclusionProof.js';
import {
  InclusionProofConflictError,
  InclusionProofExpiredError,
  InclusionProofUnknownError,
} from '../api/InclusionProofStatusError.js';
import { JsonRpcNetworkError } from '../api/json-rpc/JsonRpcNetworkError.js';
import { StateId } from '../api/StateId.js';
import { PredicateVerifierService } from '../predicate/verification/PredicateVerifierService.js';
import { StateTransitionClient } from '../StateTransitionClient.js';
import { ITransaction } from '../transaction/ITransaction.js';
import {
  InclusionProofVerificationRule,
  InclusionProofVerificationStatus,
} from '../transaction/verification/rule/InclusionProofVerificationRule.js';

/**
 * Thrown by {@link waitInclusionProof} when the wait is aborted, whether the
 * caller's abort signal fires while a poll request is in flight, while its
 * response is being verified, or while sleeping between polls.
 */
export class SleepError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'SleepError';
  }
}

/**
 * Build the error reported when the caller's abort signal has fired. Nothing
 * here may throw: it runs inside the `abort` listeners, and an exception there
 * would skip the `reject` that ends the wait — the very hang this module
 * guards against.
 *
 * @param {AbortSignal} signal Aborted signal.
 * @returns {SleepError} Error carrying the signal's abort reason.
 */
function createAbortError(signal: AbortSignal): SleepError {
  let reason: Error | undefined;
  let message = 'Wait was aborted';
  try {
    reason = signal.reason as Error | undefined;
    if (reason != null) {
      message = reason.toString();
    }
  } catch {
    // A signal whose reason cannot be read or described still has to end the wait.
  }

  return new SleepError(message, { cause: reason });
}

/**
 * Detach an abort listener without letting a hostile or exotic signal break
 * the wait. The listeners are one-shot, so a refused removal is harmless.
 *
 * @param {AbortSignal} signal Signal the listener was attached to.
 * @param {Function} listener Listener to detach.
 */
function removeAbortListener(signal: AbortSignal, listener: () => void): void {
  try {
    signal.removeEventListener('abort', listener);
  } catch {
    // Cleanup is best effort; failing it must not leave a promise unsettled.
  }
}

/**
 * Stop the wait immediately if the signal has already fired.
 *
 * @param {AbortSignal} signal Signal to inspect.
 * @throws {SleepError} If the signal is aborted.
 */
function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) {
    throw createAbortError(signal);
  }
}

/**
 * Run one poll bounded by the caller's signal. The poll is handed a fresh
 * signal of its own so that the abort reaches the transport as a plain
 * `AbortSignal` — callers may pass any signal-like wrapper — and cancels only
 * this request. The wait settles as soon as either the poll settles or the
 * signal fires, so a poll that ignores its signal, or never responds at all,
 * still cannot outlive the caller's deadline.
 *
 * @param {Function} poll Runs one poll with the request's own abort signal.
 * @param {AbortSignal} signal Signal that ends the wait.
 * @returns {Promise} Promise settling with the poll, or rejecting on abort.
 * @throws {SleepError} If the signal fires before the poll settles.
 */
function abortable<T>(poll: (signal: AbortSignal) => Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const request = new AbortController();

    function onAbort(): void {
      // Reject first: the wait must end even if cancelling the request does not.
      const error = createAbortError(signal);
      reject(error);
      request.abort(error.cause);
    }

    // An already-aborted signal never dispatches `abort` again, so a listener
    // attached now would never fire: check first, subscribe second.
    if (signal.aborted) {
      onAbort();
      return;
    }

    signal.addEventListener('abort', onAbort, { once: true });
    // Both outcomes stay handled, so a poll that rejects after the wait has
    // already been abandoned is not reported as an unhandled rejection.
    void poll(request.signal)
      .then(resolve, reject)
      .finally(() => removeAbortListener(signal, onAbort));
  });
}

/**
 * Wait for the given delay, unless the signal fires first.
 *
 * @param {number} ms Delay in milliseconds.
 * @param {AbortSignal} signal Signal that ends the wait.
 * @returns {Promise<void>} Promise resolving once the delay has elapsed.
 * @throws {SleepError} If the signal is or becomes aborted.
 */
function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    // Same lost-abort hazard as above: an `abort` listener registered after the
    // signal has fired is never called, which would leave the poll loop running
    // for the lifetime of the process.
    if (signal.aborted) {
      reject(createAbortError(signal));
      return;
    }

    const timeout = setTimeout(() => {
      removeAbortListener(signal, onAbort);
      resolve();
    }, ms);

    function onAbort(): void {
      clearTimeout(timeout);
      reject(createAbortError(signal));
    }

    signal.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Options of {@link waitInclusionProof}.
 */
export interface IWaitInclusionProofOptions {
  /** Delay between polls in milliseconds. Defaults to 1000. */
  readonly intervalMs?: number;
  /** Abort signal that terminates polling. Defaults to a 10s timeout. */
  readonly signal?: AbortSignal;
  /**
   * Ask the aggregator for its (unauthenticated) status hint and stop early on `expired` and `unknown`. Defaults to
   * `true`. `false` restores the behavior of SDK 3.0: nothing but the proof decides, the wait ends with a proof, an
   * error, or the signal.
   */
  readonly statusHints?: boolean;
  /**
   * How long an `unknown` hint is tolerated, counted from the start of the wait, before the wait fails with
   * {@link InclusionProofUnknownError}. Defaults to two poll intervals; `0` fails at the first `unknown`. Ignored
   * without `statusHints`.
   */
  readonly unknownGraceMs?: number;
}

function isSignalLike(value: unknown): value is AbortSignal {
  return (
    typeof value === 'object' &&
    value !== null &&
    'aborted' in value &&
    typeof (value as { addEventListener?: unknown }).addEventListener === 'function'
  );
}

/**
 * Poll the aggregator until a valid inclusion proof for the given transaction
 * is available, or the abort signal fires.
 *
 * The returned promise always settles: once the signal has fired the wait
 * rejects, regardless of whether the deadline was reached while requesting,
 * while verifying, or while sleeping between polls.
 *
 * Unless `statusHints` is `false`, the wait asks the aggregator for its status hint. `pending` keeps waiting. The hint is
 * **unauthenticated**: it only decides when to stop waiting, it never makes a proof valid or invalid (a proof that is
 * present is verified exactly as before whatever the hint says), and `unknown`/`expired` is not a proof of absence. A
 * server that does not send a hint, or an unrecognized one, behaves as before. `unknown` is rechecked for a grace
 * period, because the wait normally starts right after submission and an HA instance that has not seen the request yet
 * answers `unknown`.
 *
 * @param {StateTransitionClient} client Client used to fetch inclusion proofs.
 * @param {RootTrustBase} trustBase Root trust base used to verify the inclusion certificate.
 * @param {PredicateVerifierService} predicateVerifier Verifier used to check the transaction predicate.
 * @param {UnicityCertificateVerifier} unicityCertificateVerifier Unicity certificate verifier.
 * @param {ITransaction} transaction Transaction whose inclusion is being awaited.
 * @param {IWaitInclusionProofOptions} [options] Signal, interval and hint handling.
 * @returns {Promise<InclusionProof>} Verified inclusion proof.
 * @throws {SleepError} If the abort signal fires before a proof is available.
 * @throws {InclusionProofExpiredError} If the aggregator hints the request as expired (and has no proof): it was dropped
 *   before inclusion. Resubmittable.
 * @throws {InclusionProofUnknownError} If the aggregator keeps hinting the request as unknown (and has no proof) for
 *   longer than `unknownGraceMs` since the wait began. Resubmittable.
 * @throws {InclusionProofConflictError} If the proof served for the state id certifies another request than the
 *   transaction (a conflicting submission was queued first); the proof is not yet authenticated. Not resubmittable.
 */
export function waitInclusionProof(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  predicateVerifier: PredicateVerifierService,
  unicityCertificateVerifier: UnicityCertificateVerifier,
  transaction: ITransaction,
  options?: IWaitInclusionProofOptions,
): Promise<InclusionProof>;
/**
 * @deprecated Positional form of SDK 3.0, kept as it was (no status hints, they need the options form): pass
 *   `{ signal, intervalMs }` instead.
 * @param {StateTransitionClient} client Client used to fetch inclusion proofs.
 * @param {RootTrustBase} trustBase Root trust base used to verify the inclusion certificate.
 * @param {PredicateVerifierService} predicateVerifier Verifier used to check the transaction predicate.
 * @param {UnicityCertificateVerifier} unicityCertificateVerifier Unicity certificate verifier.
 * @param {ITransaction} transaction Transaction whose inclusion is being awaited.
 * @param {AbortSignal} signal Abort signal that terminates polling. Defaults to a 10s timeout.
 * @param {number} interval Delay between polls in milliseconds. Defaults to 1000.
 * @returns {Promise<InclusionProof>} Verified inclusion proof.
 */
export function waitInclusionProof(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  predicateVerifier: PredicateVerifierService,
  unicityCertificateVerifier: UnicityCertificateVerifier,
  transaction: ITransaction,
  signal?: AbortSignal,
  interval?: number,
): Promise<InclusionProof>;
export async function waitInclusionProof(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  predicateVerifier: PredicateVerifierService,
  unicityCertificateVerifier: UnicityCertificateVerifier,
  transaction: ITransaction,
  signalOrOptions?: AbortSignal | IWaitInclusionProofOptions,
  positionalInterval?: number,
): Promise<InclusionProof> {
  // the options form, or the positional form of SDK 3.0 (a signal, possibly a wrapper exposing only the AbortSignal
  // surface, and an interval)
  const positional = positionalInterval !== undefined || isSignalLike(signalOrOptions);
  const options: IWaitInclusionProofOptions = positional ? {} : (signalOrOptions ?? {});
  const signal: AbortSignal =
    (positional ? (signalOrOptions as AbortSignal | undefined) : options.signal) ?? AbortSignal.timeout(10000);
  const interval = positional ? (positionalInterval ?? 1000) : (options.intervalMs ?? 1000);
  const statusHints = positional ? false : options.statusHints !== false;
  const stateId = await StateId.fromTransaction(transaction);
  const transactionHash = await transaction.calculateTransactionHash();
  const unknownGraceMs = options.unknownGraceMs ?? 2 * interval;
  const started = Date.now();

  const poll = async (requestSignal: AbortSignal): Promise<InclusionProof | null> => {
    const response = await client.getInclusionProof(
      stateId,
      statusHints ? { includeStatusHint: true, signal: requestSignal } : { signal: requestSignal },
    );
    const { inclusionProof } = response;
    // without statusHints nothing but the proof counts, also what a server volunteers
    const statusHint = statusHints ? response.statusHint : null;
    // The aggregator has not certified this state yet. The response type is what says so; by the
    // time a proof exists it is complete, so there is nothing else here to poll through.
    if (inclusionProof == null) {
      // Unauthenticated hints decide only when to stop waiting. No status, `pending`, `included` without a proof, and
      // a status this SDK does not know keep the legacy behavior: poll on.
      if (statusHint === 'expired') {
        throw new InclusionProofExpiredError(stateId);
      }
      if (statusHint === 'unknown' && Date.now() - started >= unknownGraceMs) {
        throw new InclusionProofUnknownError(stateId, Date.now() - started);
      }
      return null;
    }

    const verificationStatus = await InclusionProofVerificationRule.verify(
      trustBase,
      predicateVerifier,
      unicityCertificateVerifier,
      inclusionProof,
      transactionHash,
      transaction.expiresAt,
      transaction.lockScript,
      transaction.sourceStateHash,
    );

    if (verificationStatus.status !== InclusionProofVerificationStatus.OK) {
      // another request was certified for this state id: typed, so that a conflicting submission is not reported as a
      // generic verification failure
      if (
        verificationStatus.status === InclusionProofVerificationStatus.TRANSACTION_HASH_MISMATCH ||
        verificationStatus.status === InclusionProofVerificationStatus.CERTIFICATION_DATA_MISMATCH
      ) {
        throw new InclusionProofConflictError(verificationStatus.status, stateId, inclusionProof);
      }
      throw new Error(`Invalid inclusion proof status: ${verificationStatus.status}`);
    }

    return inclusionProof;
  };

  while (true) {
    throwIfAborted(signal);

    try {
      const inclusionProof = await abortable(poll, signal);
      if (inclusionProof !== null) {
        return inclusionProof;
      }
    } catch (err) {
      // A missing proof is the expected "not certified yet" answer; anything
      // else — including the {@link SleepError} raised on abort — ends the wait.
      if (!(err instanceof JsonRpcNetworkError && err.status === 404)) {
        throw err;
      }
    }

    await sleep(interval, signal);
  }
}
