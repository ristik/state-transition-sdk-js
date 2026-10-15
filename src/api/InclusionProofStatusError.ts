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
