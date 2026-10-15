import { RootTrustBase } from '../api/bft/RootTrustBase.js';
import { UnicitySeal } from '../api/bft/UnicitySeal.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { SealVerificationSession } from '../api/bft/verification/SealVerificationSession.js';
import { ISignatureVerifier } from '../crypto/ISignatureVerifier.js';
import { Signature } from '../crypto/secp256k1/Signature.js';
import { VerificationResult } from '../verification/VerificationResult.js';
import { VerificationStatus } from '../verification/VerificationStatus.js';

/** Never asked: this rule answers through the session or the rule it wraps. */
const NEVER: ISignatureVerifier<Signature> = {
  algorithm: 'secp256k1',
  verify: () => Promise.resolve(false),
};

/**
 * Quorum rule of the ordinary certificate verifier, backed by an operation scoped {@link SealVerificationSession}.
 *
 * Every proof of a consolidated token carries the same seal, so the leaf checks of one verification would otherwise
 * repeat the same signature work, and parallel checks would all miss a completed-results memo. Through the session a
 * distinct complete seal under a trust base is checked once, concurrent requests share the running check, failures
 * are never remembered. The session's misses are decided by `inner`, the caller's own rule (its signature verifier and
 * cache), so the injected verification is what is shared, never replaced. A different trust base than the session's is
 * answered by `inner` directly.
 */
export class SessionQuorumRule extends UnicitySealQuorumSignaturesVerificationRule {
  /**
   * @param {UnicitySealQuorumSignaturesVerificationRule} inner The caller's rule.
   * @param {SealVerificationSession} session Operation scoped session whose misses `inner` decides.
   * @param {RootTrustBase} sessionTrustBase The session's trust base.
   */
  public constructor(
    private readonly inner: UnicitySealQuorumSignaturesVerificationRule,
    private readonly session: SealVerificationSession,
    private readonly sessionTrustBase: RootTrustBase,
  ) {
    super(NEVER);
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
      : this.inner.verify(trustBase, unicitySeal);
  }
}
