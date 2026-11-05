import { findNoTrustBaseEntry } from './TrustBaseEntryResult.js';
import { VerificationResult } from '../../../verification/VerificationResult.js';
import { VerificationStatus } from '../../../verification/VerificationStatus.js';
import { ITrustBaseSource } from '../../ITrustBaseSource.js';
import { TrustBaseHistory } from '../trustbase/TrustBaseHistory.js';
import { ITrustBaseUpdateOptions, TrustBaseUpdater } from '../trustbase/TrustBaseUpdater.js';

/**
 * Verify, and when the only thing missing is a trust-base entry, update the history from the sources and verify once more.
 *
 * `verify` is run first. A result that is OK, or that fails for any reason other than the typed no-entry failure, is returned as it is: no fetch
 * can help it. On the typed no-entry failure the history is updated (see {@link TrustBaseUpdater.update}); if that appended nothing, the first
 * result stands, and otherwise `verify` runs once more and its result is returned, whatever it is. There is no loop: one update, one retry.
 *
 * @param {TrustBaseHistory} history The history `verify` reads. It is extended in place.
 * @param {ITrustBaseSource[]} sources Where newer entries come from.
 * @param {() => Promise<VerificationResult<VerificationStatus>>} verify The verification, run against `history`.
 * @param {ITrustBaseUpdateOptions} [options] Update options.
 * @returns {Promise<VerificationResult<VerificationStatus>>} The result of the last verification.
 * @throws {TrustBaseUpdateError} If the update failed (as opposed to finding nothing newer).
 */
export async function verifyWithUpdate(
  history: TrustBaseHistory,
  sources: readonly ITrustBaseSource[],
  verify: () => Promise<VerificationResult<VerificationStatus>>,
  options?: ITrustBaseUpdateOptions,
): Promise<VerificationResult<VerificationStatus>> {
  const first = await verify();
  if (first.status === VerificationStatus.OK || findNoTrustBaseEntry(first) === null) {
    return first;
  }
  if ((await TrustBaseUpdater.update(history, sources, options)) === 0) {
    return first;
  }
  return verify();
}
