import { ShardTreeCertificate } from '../../../api/bft/ShardTreeCertificate.js';
import { StateId } from '../../../api/StateId.js';
import { VerificationResult } from '../../../verification/VerificationResult.js';
import { VerificationStatus } from '../../../verification/VerificationStatus.js';

/**
 * Verifies that a state id falls under the shard identified by a shard tree
 * certificate.
 */
export class ShardIdMatchesStateIdRule {
  /**
   * Verify that the certificate has one sibling per shard id bit and that `stateId` is prefixed by its shard id.
   *
   * @param {StateId} stateId State id under verification.
   * @param {ShardTreeCertificate} shardTreeCertificate Shard tree certificate carrying the expected shard.
   * @returns {VerificationResult<VerificationStatus>} OK if the sibling count equals the shard length and the shard is empty or a prefix, FAIL otherwise.
   */
  public static verify(
    stateId: StateId,
    shardTreeCertificate: ShardTreeCertificate,
  ): VerificationResult<VerificationStatus> {
    const shardId = shardTreeCertificate.shard;
    // The fold hashes one sibling per label bit; a different count leaves label bits unbound (relabelling).
    if (shardTreeCertificate.siblingHashList.length !== shardId.length) {
      return new VerificationResult('ShardIdMatchesStateIdRule', VerificationStatus.FAIL);
    }

    if (shardId.length === 0) {
      return new VerificationResult('ShardIdMatchesStateIdRule', VerificationStatus.OK);
    }

    if (!shardId.isPrefixOf(stateId.data)) {
      return new VerificationResult('ShardIdMatchesStateIdRule', VerificationStatus.FAIL);
    }

    return new VerificationResult('ShardIdMatchesStateIdRule', VerificationStatus.OK);
  }
}
