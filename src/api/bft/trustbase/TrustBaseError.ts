import { SdkError } from '../../SdkError.js';

/**
 * Stable machine-readable reasons of {@link TrustBaseError}. Tests and callers must bind to these rather than to message text.
 *
 * - `malformed`: the bytes are not the canonical encoding of a well-formed object (wrong tag or version, non-canonical form, out of bounds).
 * - `invalid`: a well-formed entry that does not verify (structure rules, chain link, signatures, quorum).
 * - `gap`: the entry does not directly follow the latest held entry; fetch the missing epochs first.
 * - `conflict`: a different entry (other unsigned bytes) for an epoch already held. Held entries are never replaced.
 * - `genesis`: the genesis entry is not the pinned one, or is not a genesis entry.
 * - `bundle`: not a complete trust-base bundle.
 */
export type TrustBaseErrorReason = 'bundle' | 'conflict' | 'gap' | 'genesis' | 'invalid' | 'malformed';

/**
 * Thrown by the Unicity Trust Base codec, the entry verifier and {@link TrustBaseHistory}. `reason` is its discriminant.
 */
export class TrustBaseError extends SdkError<'TrustBaseError'> {
  public override readonly name = 'TrustBaseError' as const;

  /**
   * @param {TrustBaseErrorReason} reason Stable reason.
   * @param {string} message Message.
   * @param {object} [options] Options.
   * @param {unknown} [options.cause] Underlying error.
   */
  public constructor(
    public readonly reason: TrustBaseErrorReason,
    message: string,
    options?: { readonly cause?: unknown },
  ) {
    super(message, options);
  }

  /**
   * @param {unknown} error Anything that was thrown.
   * @returns {boolean} True for a trust-base error of this or another copy of the SDK.
   */
  public static override is(error: unknown): error is TrustBaseError {
    return SdkError.is(error) && error.name === 'TrustBaseError';
  }
}
