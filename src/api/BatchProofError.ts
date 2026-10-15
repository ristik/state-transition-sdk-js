/**
 * Classification of a failed `get_inclusion_proofs.v1` call. Applications switch on `kind` (and `detail`), they never
 * parse JSON-RPC reason strings.
 *
 * - `unavailable`: the service reports it cannot serve the material now (state not in the snapshot, view not retained
 *   or evicted, no finalized or partition view) or is under pressure (`busy`). Inputs are intact, a new attempt may
 *   succeed, waiting cannot make an excluded leaf appear in a fixed root.
 * - `unsupported`: the endpoint does not support the method or the configuration (e.g. a parent/child aggregator).
 * - `rejected`: the service refused the request itself (invalid params), retrying the same input cannot succeed.
 * - `limit_exceeded`: a method limit (state count, request or response size) was hit.
 * - `server`: operational failure of the service (database, internal or unknown error code), code preserved.
 * - `transport`: the HTTP exchange failed (connection error, non-success status).
 * - `invalid_response`: the response is malformed or inconsistent with the request.
 */
export type BatchProofErrorKind =
  'invalid_response' | 'limit_exceeded' | 'rejected' | 'server' | 'transport' | 'unavailable' | 'unsupported';

/**
 * Failure of a batch inclusion proof call. Caller cancellation is never wrapped: an aborted request rejects with the
 * platform's `AbortError`/`TimeoutError`.
 */
export class BatchProofError extends Error {
  public override readonly name: string = 'BatchProofError';

  /**
   * @param {BatchProofErrorKind} kind Classification.
   * @param {string} message Message.
   * @param {object} [info] Details echoed from the response.
   * @param {number} [info.code] JSON-RPC error code, if the failure was a JSON-RPC error.
   * @param {string} [info.detail] Service detail, e.g. `view_not_retained`, `busy:pinned_views`, `state_count`.
   * @param {boolean} [info.retryable] Whether a new attempt may succeed.
   * @param {unknown} [info.cause] Underlying error.
   */
  public constructor(
    public readonly kind: BatchProofErrorKind,
    message: string,
    public readonly info: {
      readonly cause?: unknown;
      readonly code?: number;
      readonly detail?: string;
      readonly retryable?: boolean;
    } = {},
  ) {
    super(message, { cause: info.cause });
  }

  /**
   * @returns {number|undefined} JSON-RPC error code, if any.
   */
  public get code(): number | undefined {
    return this.info.code;
  }

  /**
   * @returns {string|undefined} Service detail, if any.
   */
  public get detail(): string | undefined {
    return this.info.detail;
  }

  /**
   * @returns {boolean} Whether a new attempt may succeed. Never a promise that the same root will be served again.
   */
  public get retryable(): boolean {
    return this.info.retryable ?? false;
  }
}
