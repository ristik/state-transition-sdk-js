import { RootTrustBase } from '../api/bft/RootTrustBase.js';
import { UnicitySeal } from '../api/bft/UnicitySeal.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { SealVerificationSession } from '../api/bft/verification/SealVerificationSession.js';
import { ISignatureVerifier } from '../crypto/ISignatureVerifier.js';
import { Signature } from '../crypto/secp256k1/Signature.js';
import { VerificationResult } from '../verification/VerificationResult.js';
import { VerificationStatus } from '../verification/VerificationStatus.js';

/**
 * Quorum rule of the ordinary certificate verifier, backed by an operation scoped {@link SealVerificationSession}.
 *
 * Every proof of a consolidated token carries the same seal, so the leaf checks of one verification would otherwise
 * repeat the same signature work, and parallel checks would all miss a completed-results memo. Through the session a
 * distinct complete seal under a trust base is checked once, concurrent requests share the running check, failures
 * are never remembered. A different trust base than the session's is never served from its memo.
 */
export class SessionQuorumRule extends UnicitySealQuorumSignaturesVerificationRule {
  /**
   * @param {ISignatureVerifier<Signature>} signatureVerifier Verifier used when the rule is asked about another trust base.
   * @param {SealVerificationSession} session Operation scoped session.
   * @param {RootTrustBase} trustBase The session's trust base.
   */
  public constructor(
    signatureVerifier: ISignatureVerifier<Signature>,
    private readonly session: SealVerificationSession,
    private readonly sessionTrustBase: RootTrustBase,
  ) {
    super(signatureVerifier);
  }

  /**
   * @inheritDoc
   */
  public override verify(
    trustBase: RootTrustBase,
    unicitySeal: UnicitySeal,
  ): Promise<VerificationResult<VerificationStatus>> {
    return trustBase === this.sessionTrustBase
      ? this.session.verifyQuorum(unicitySeal)
      : super.verify(trustBase, unicitySeal);
  }
}
