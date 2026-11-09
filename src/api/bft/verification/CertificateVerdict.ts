import { findNoTrustBaseEntry } from './TrustBaseEntryResult.js';
import { VerificationResult } from '../../../verification/VerificationResult.js';
import { VerificationStatus } from '../../../verification/VerificationStatus.js';

/**
 * The class of a unicity certificate check, the same classes as the native (B1) verifier:
 *
 * - `ok`;
 * - `no_entry_for_epoch`: the seal's epoch is newer than the latest held trust-base entry. Retryable: fetch the missing entries (from the latest held
 *   epoch + 1), append them, verify again;
 * - `invalid`: a well-formed certificate that does not verify (B1 `valid = false`);
 * - `malformed`: bytes outside the accepted encoding or bounds (B1 `status = error`). Final.
 */
export type CertificateVerdict = 'invalid' | 'malformed' | 'no_entry_for_epoch' | 'ok';

/**
 * A verification result that carries its {@link CertificateVerdict}, and for `no_entry_for_epoch` the missing epoch and the latest held epoch (null
 * for an empty history).
 */
export class CertificateVerificationResult extends VerificationResult<VerificationStatus> {
  /**
   * @param {string} rule Rule name.
   * @param {CertificateVerdict} verdict Class.
   * @param {string} [message] Message.
   * @param {VerificationResult<unknown>[]} [results] Child results.
   * @param {object} [missing] For `no_entry_for_epoch`.
   * @param {bigint} missing.epoch The seal's epoch.
   * @param {bigint|null} missing.latest The latest held epoch.
   */
  public constructor(
    rule: string,
    public readonly verdict: CertificateVerdict,
    message: string = '',
    results: VerificationResult<unknown>[] = [],
    public readonly missing: { readonly epoch: bigint; readonly latest: bigint | null } | null = null,
  ) {
    super(rule, verdict === 'ok' ? VerificationStatus.OK : VerificationStatus.FAIL, message, results);
  }

  /**
   * Find the first missing-entry failure in a verification trace (for example a token's): the typed {@link NoTrustBaseEntryResult}.
   *
   * @param {VerificationResult<unknown>} result Root of the trace.
   * @returns {object|null} The missing epoch and the latest held epoch, or null.
   */
  public static findMissingEpoch(
    result: VerificationResult<unknown>,
  ): { readonly epoch: bigint; readonly latest: bigint | null } | null {
    const found = findNoTrustBaseEntry(result);
    return found === null ? null : { epoch: found.epoch, latest: found.tipEpoch };
  }

  /**
   * @param {VerificationResult<unknown>} result Any result.
   * @returns {CertificateVerdict} Its class: the own verdict of a classified result, `no_entry_for_epoch` for the typed missing-entry failure,
   *   otherwise `ok`/`invalid` by status.
   */
  public static verdictOf(result: VerificationResult<unknown>): CertificateVerdict {
    if (result instanceof CertificateVerificationResult) {
      return result.verdict;
    }
    if (findNoTrustBaseEntry(result) !== null) {
      return 'no_entry_for_epoch';
    }
    return result.status === VerificationStatus.OK ? 'ok' : 'invalid';
  }
}
