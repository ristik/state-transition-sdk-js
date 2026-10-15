/**
 * Per-request options accepted by aggregator client methods.
 */
export interface IRequestOptions {
  /**
   * Signal that cancels the request. Implementations performing network I/O
   * should forward it to the underlying transport so that an abandoned request
   * is released instead of running to completion.
   */
  readonly signal?: AbortSignal;
}

/**
 * Options of a single inclusion proof request.
 */
export interface IInclusionProofRequestOptions extends IRequestOptions {
  /**
   * Ask the aggregator for its status hint (`included` / `pending` / `expired` / `unknown`) next to the proof. Opt-in:
   * without it the request and the result are exactly what they always were. A server without the feature ignores
   * the flag and answers as before, which is the legacy behavior (no status). The status is an **unauthenticated
   * hint**, see {@link ProofStatus}.
   */
  readonly includeStatus?: boolean;
}
