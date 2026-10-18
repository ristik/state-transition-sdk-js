import { VerificationResult } from '../../../../verification/VerificationResult.js';
import { VerificationStatus } from '../../../../verification/VerificationStatus.js';
import { AGGREGATION_PARTITION_ID } from '../../AggregationPartition.js';
import { UnicityCertificate } from '../../UnicityCertificate.js';
import { SealVerificationSession } from '../SealVerificationSession.js';

/**
 * Rule for the application-level shape of a unicity certificate, checked before any hashing or signature work: it is of
 * the aggregation partition ({@link AGGREGATION_PARTITION_ID}), and it satisfies the structural rules of the native
 * `UnicityCertificate.IsValid` (bft-go-base): input record, 32 byte technical record hash, and seal.
 *
 * It never throws: a certificate that violates a rule yields a failed result.
 */
export class UnicityCertificateStructureRule {
  /**
   * @param {UnicityCertificate} unicityCertificate Certificate to check.
   * @returns {string|null} Failure description, or `null` if the certificate is acceptable.
   */
  public static failure(unicityCertificate: UnicityCertificate): string | null {
    try {
      if (unicityCertificate.unicityTreeCertificate.partitionIdentifier !== AGGREGATION_PARTITION_ID) {
        return `The certificate is of partition ${unicityCertificate.unicityTreeCertificate.partitionIdentifier}, expected ${AGGREGATION_PARTITION_ID}.`;
      }
      const inputRecordFailure = unicityCertificate.inputRecord.structureFailure();
      if (inputRecordFailure !== null) {
        return `Invalid input record: ${inputRecordFailure}`;
      }
      if (unicityCertificate.technicalRecordHash?.length !== 32) {
        return 'The technical record hash must be 32 bytes.';
      }
      const sealFailure = SealVerificationSession.checkSealStructure(unicityCertificate.unicitySeal);
      if (sealFailure !== null) {
        return sealFailure;
      }
      return null;
    } catch {
      // malformed material never throws out of verification
      return 'The certificate is malformed.';
    }
  }

  /**
   * @param {UnicityCertificate} unicityCertificate Certificate to check.
   * @returns {VerificationResult<VerificationStatus>} Verification outcome.
   */
  public static verify(unicityCertificate: UnicityCertificate): VerificationResult<VerificationStatus> {
    const failure = UnicityCertificateStructureRule.failure(unicityCertificate);
    return failure === null
      ? new VerificationResult('UnicityCertificateStructureRule', VerificationStatus.OK)
      : new VerificationResult('UnicityCertificateStructureRule', VerificationStatus.FAIL, failure);
  }
}
