/**
 * Why a consolidation attempt did not produce a token. These are failures, not "unavailable" outcomes: an unavailable
 * outcome is the service explicitly reporting that it cannot serve the proof material now, see
 * {@link ConsolidationResult}.
 *
 * - `cancelled`: the caller's signal aborted the attempt. Never retryable by the SDK.
 * - `timeout`: the attempt's total deadline expired.
 * - `transport`: an HTTP exchange failed.
 * - `server`: a service reported an operational failure (database, internal or unknown error code).
 * - `rejected`: a service refused the request itself (invalid parameters); retrying the same input cannot succeed.
 * - `invalid_response`: a response is malformed or inconsistent with the request.
 * - `integrity`: the material is cryptographically or structurally refused, see {@link ConsolidationOutcome}. Never
 *   disguised as unavailability: signature, authority, path and binding failures always end here.
 * - `input`: the token or the configuration cannot be consolidated as given.
 */
export type ConsolidationErrorKind =
  'cancelled' | 'input' | 'integrity' | 'invalid_response' | 'rejected' | 'server' | 'timeout' | 'transport';

/**
 * Stable reason of an `integrity` or `input` failure. Mirrors the reference implementation's outcome names so that
 * shared fixtures bind to them rather than to message text.
 */
export type ConsolidationOutcome =
  | 'binding_mismatch'
  | 'expired'
  | 'incompatible_lineage'
  | 'invalid_input'
  | 'reference_time_after_target'
  | 'unauthenticated'
  | 'unsupported';

/**
 * Typed failure of a consolidation attempt. The original token is never modified by any outcome.
 */
export class ConsolidationError extends Error {
  public override readonly name: string = 'ConsolidationError';

  /**
   * @param {ConsolidationErrorKind} kind Classification.
   * @param {string} message Message.
   * @param {object} [info] Details.
   * @param {unknown} [info.cause] Underlying error.
   * @param {string} [info.detail] Service detail echoed from a failed call.
   * @param {ConsolidationOutcome} [info.outcome] Outcome of an integrity failure.
   * @param {string} [info.shard] Bit string of the shard concerned.
   * @param {boolean} [info.retryable] Whether a new attempt may succeed.
   */
  public constructor(
    public readonly kind: ConsolidationErrorKind,
    message: string,
    public readonly info: {
      readonly cause?: unknown;
      readonly detail?: string;
      readonly outcome?: ConsolidationOutcome;
      readonly retryable?: boolean;
      readonly shard?: string;
    } = {},
  ) {
    super(message, { cause: info.cause });
  }

  /**
   * @returns {string|undefined} Service detail, if any.
   */
  public get detail(): string | undefined {
    return this.info.detail;
  }

  /**
   * @returns {ConsolidationOutcome|undefined} Outcome of an integrity or input failure.
   */
  public get outcome(): ConsolidationOutcome | undefined {
    return this.info.outcome;
  }

  /**
   * @returns {boolean} Whether a new attempt may succeed (transport failures and deadlines only; never a cancellation).
   */
  public get retryable(): boolean {
    return this.info.retryable ?? false;
  }

  /**
   * @returns {string|undefined} Shard concerned, as a bit string.
   */
  public get shard(): string | undefined {
    return this.info.shard;
  }
}
