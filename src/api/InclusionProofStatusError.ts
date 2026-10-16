import { InclusionProof } from './InclusionProof.js';
import { ProofStatus } from './ProofStatus.js';
import { StateId } from './StateId.js';

/**
 * The aggregator reports that the state id will not be certified by waiting on it. Carries the status hint.
 *
 * Remember that the status is an **unauthenticated hint**: this error means "stop waiting and decide", not "the state
 * is unspent" and not "the transaction failed". The signed request can be submitted again (the aggregator
 * deduplicates), and a proof, if one exists, is still verified like any other.
 */
export abstract class InclusionProofStatusError extends Error {
  public override readonly name: string = 'InclusionProofStatusError';

  /**
   * @param {ProofStatus} status Status the aggregator reported.
   * @param {StateId} stateId State id that was waited for.
   * @param {string} message Message.
   */
  protected constructor(
    public readonly status: ProofStatus,
    public readonly stateId: StateId,
    message: string,
  ) {
    super(message);
  }
}

/**
 * The aggregator dropped the request because its deadline passed before it was included.
 */
export class InclusionProofExpiredError extends InclusionProofStatusError {
  public override readonly name: string = 'InclusionProofExpiredError';

  /**
   * @param {StateId} stateId State id that was waited for.
   */
  public constructor(stateId: StateId) {
    super(
      'expired',
      stateId,
      `The aggregator reports ${stateId.toString()} as expired: the request was dropped before it was included. ` +
        'This is an unauthenticated hint; the same signed request may be submitted again.',
    );
  }
}

/**
 * The aggregator does not know the request: never seen, misrouted, lost, or wiped by a restart.
 */
export class InclusionProofUnknownError extends InclusionProofStatusError {
  public override readonly name: string = 'InclusionProofUnknownError';

  /**
   * @param {StateId} stateId State id that was waited for.
   * @param {number} [waitedMs] How long the status stayed unknown before the wait gave up.
   */
  public constructor(stateId: StateId, waitedMs: number = 0) {
    super(
      'unknown',
      stateId,
      `The aggregator does not know ${stateId.toString()} (unknown for ${waitedMs} ms): not submitted to this ` +
        'aggregator, misrouted, lost or dropped. This is an unauthenticated hint, not a proof of absence or of the ' +
        'state being unspent; the same signed request may be submitted again.',
    );
  }
}

/**
 * The aggregator returned a proof for this state id that certifies a different request than the awaited transaction: a
 * conflicting submission (another device, a re-created transaction, an application bug) was queued first and will be
 * the one certified, so the awaited transaction was not and cannot be certified for this state. Not a status hint: it
 * is detected by comparing the proof's certification data with the transaction.
 *
 * The comparison happens before the proof's certificate is verified, so the proof carried here is **not yet
 * authenticated**: verify it against the trust base before relying on it (or on what it says about the other request).
 * The message starts with the legacy `Invalid inclusion proof status: <status>` text.
 */
export class InclusionProofConflictError extends Error {
  public override readonly name: string = 'InclusionProofConflictError';

  /**
   * @param {string} reason Verification status that revealed the conflict (`TRANSACTION_HASH_MISMATCH` or
   *   `CERTIFICATION_DATA_MISMATCH`).
   * @param {StateId} stateId State id that was waited for.
   * @param {InclusionProof} inclusionProof The proof served for the state id, not authenticated.
   */
  public constructor(
    public readonly reason: string,
    public readonly stateId: StateId,
    public readonly inclusionProof: InclusionProof,
  ) {
    super(
      `Invalid inclusion proof status: ${reason}: the aggregator certified another request for ${stateId.toString()}; ` +
        'this transaction was not (and cannot be) certified for that state.',
    );
  }
}
