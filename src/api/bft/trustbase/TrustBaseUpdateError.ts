import { SdkError } from '../../SdkError.js';

/**
 * Stable reasons of {@link TrustBaseUpdateError}:
 *
 * - `rejected`: an entry the source sent does not authenticate from the held history (bad signature, link, epoch, or a conflict with a held
 *   epoch); `cause` is the `TrustBaseError`. The source is faulty; nothing after the refused entry was appended.
 * - `malformed`: the source's response does not decode under the page limits.
 * - `wrong_network`: the response is for another network.
 * - `refused`: the source answered with a status other than OK or NotYetAvailable (`status` names it).
 */
export type TrustBaseUpdateErrorReason = 'malformed' | 'refused' | 'rejected' | 'wrong_network';

/**
 * Thrown when fetching newer trust-base entries fails for a reason that waiting does not fix. Entries appended before the failure stay held.
 */
export class TrustBaseUpdateError extends SdkError<'TrustBaseUpdateError'> {
  public override readonly name = 'TrustBaseUpdateError' as const;

  /**
   * @param {TrustBaseUpdateErrorReason} reason Stable reason.
   * @param {string} message Message.
   * @param {object} [options] Options.
   * @param {unknown} [options.cause] Underlying error.
   */
  public constructor(
    public readonly reason: TrustBaseUpdateErrorReason,
    message: string,
    options?: { readonly cause?: unknown },
  ) {
    super(message, options);
  }

  /**
   * @param {unknown} error Anything that was thrown.
   * @returns {boolean} True for a trust-base update error of this or another copy of the SDK.
   */
  public static override is(error: unknown): error is TrustBaseUpdateError {
    return SdkError.is(error) && error.name === 'TrustBaseUpdateError';
  }
}
