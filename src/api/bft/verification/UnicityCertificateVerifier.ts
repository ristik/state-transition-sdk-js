import { CertificateVerdict, CertificateVerificationResult } from './CertificateVerdict.js';
import { UnicityCertificateFormatRule } from './rule/UnicityCertificateFormatRule.js';
import { UnicityCertificateStructureRule } from './rule/UnicityCertificateStructureRule.js';
import { UnicitySealHashMatchesWithRootHashRule } from './rule/UnicitySealHashMatchesWithRootHashRule.js';
import { UnicitySealQuorumSignaturesVerificationRule } from './rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { SealVerificationSession } from './SealVerificationSession.js';
import { DataHasher } from '../../../crypto/hash/DataHasher.js';
import { HashAlgorithm } from '../../../crypto/hash/HashAlgorithm.js';
import { CborSerializer } from '../../../serialization/cbor/CborSerializer.js';
import { HexConverter } from '../../../util/HexConverter.js';
import { VerificationResult } from '../../../verification/VerificationResult.js';
import { VerificationStatus } from '../../../verification/VerificationStatus.js';
import { InclusionProof } from '../../InclusionProof.js';
import { AGGREGATION_PARTITION_ID } from '../AggregationPartition.js';
import { ITrustBaseAuthority } from '../trustbase/TrustBaseAuthority.js';
import { UnicityCertificate } from '../UnicityCertificate.js';

const OPERATION_CAPABILITY = Symbol('beginOperation');

/** Options of a certificate verification. */
export interface IUnicityCertificateVerificationOptions {
  /** Expected partition, the aggregation partition by default. */
  readonly partitionId?: bigint;
}

/**
 * Result of a {@link UnicityCertificateVerifier} run, with its {@link CertificateVerdict} (`no_entry_for_epoch` is retryable after appending newer
 * trust-base entries).
 */
export class UnicityCertificateVerificationResult extends CertificateVerificationResult {
  private constructor(
    verdict: CertificateVerdict,
    results: VerificationResult<unknown>[],
    missing: { readonly epoch: bigint; readonly latest: bigint } | null = null,
  ) {
    super('UnicityCertificateVerification', verdict, '', results, missing);
  }

  /**
   * Build a failed verification result, classified by its failing (last) child.
   *
   * @param {VerificationResult<unknown>[]} results Child rule results, the failing one last.
   * @returns {UnicityCertificateVerificationResult} Failed result.
   */
  public static fail(results: VerificationResult<unknown>[]): UnicityCertificateVerificationResult {
    const last = results[results.length - 1];
    const verdict = last ? CertificateVerificationResult.verdictOf(last) : 'invalid';
    const missing = last instanceof CertificateVerificationResult ? last.missing : null;
    return new UnicityCertificateVerificationResult(verdict === 'ok' ? 'invalid' : verdict, results, missing);
  }

  /**
   * Build a successful verification result.
   *
   * @param {VerificationResult<unknown>[]} results Child rule results.
   * @returns {UnicityCertificateVerificationResult} Successful result.
   */
  public static ok(results: VerificationResult<unknown>[]): UnicityCertificateVerificationResult {
    return new UnicityCertificateVerificationResult('ok', results);
  }
}

/**
 * Unicity certificate verification.
 *
 * Composed from the quorum-signature rule, which carries the signature verifier
 * and any seal memo, so callers pass this domain-level verifier around rather
 * than a bare signature verifier that says nothing about what it verifies:
 *
 * ```ts
 * new UnicityCertificateVerifier(
 *   new UnicitySealQuorumSignaturesVerificationRule(
 *     new Secp256k1SignatureVerifier(),
 *     new VerifiedSealCache(256), // omit to verify every seal afresh
 *   ),
 * );
 * ```
 */
export class UnicityCertificateVerifier {
  /**
   * @param {UnicitySealQuorumSignaturesVerificationRule} quorumSignaturesRule Seal quorum-signature rule.
   */
  public constructor(protected readonly quorumSignaturesRule: UnicitySealQuorumSignaturesVerificationRule) {}

  /**
   * @returns {UnicitySealQuorumSignaturesVerificationRule} The quorum rule this verifier applies, with its signature
   *   verifier and cache: whoever shares seal work with this verifier must do it through this rule.
   */
  public get quorumRule(): UnicitySealQuorumSignaturesVerificationRule {
    return this.quorumSignaturesRule;
  }

  /**
   * Begin one verification operation (e.g. one token with every nested token).
   *
   * Returns a verifier with the same rules whose repeated work is shared for the operation only: a distinct complete
   * unicity certificate has its shard and partition path to the seal hash evaluated once, a distinct complete seal has
   * its quorum signatures checked once (concurrent checks share the running one), and the authority identity is built
   * once. Per-input rules (leaf data, reference time, predicates, paths to the state root) are not shared. Memo keys
   * commit to the complete certificate or seal bytes and the operation's authority snapshot, only successes are kept,
   * and the state is bounded and discarded with the returned object.
   *
   * A subclass that customizes verification, or a verifier built with a customized quorum rule, returns itself: injected
   * verifiers and rules keep full control.
   *
   * @param {SealVerificationSession} [session] Session to adopt for its trust base, so that a caller that already
   *   authenticated a seal strictly in the same operation does not pay the quorum check twice.
   * @returns {UnicityCertificateVerifier} Operation scoped verifier.
   */
  public beginOperation(session?: SealVerificationSession): UnicityCertificateVerifier {
    // neither a customized verifier nor a customized quorum rule is wrapped: the operation memoizes and hands the rule a
    // snapshot of the trust base, which only a rule that is pure in (authority content, seal bytes) can rely on
    if (
      Object.getPrototypeOf(this) !== UnicityCertificateVerifier.prototype ||
      Object.getPrototypeOf(this.quorumSignaturesRule) !== UnicitySealQuorumSignaturesVerificationRule.prototype
    ) {
      return this;
    }
    return new OperationUnicityCertificateVerifier(OPERATION_CAPABILITY, this.quorumSignaturesRule, session);
  }

  /**
   * Verify the unicity certificate in an inclusion proof against the held trust-base history.
   *
   * @param {ITrustBaseAuthority} trustBase Held trust-base history.
   * @param {InclusionProof} inclusionProof Inclusion proof carrying the unicity certificate.
   * @param {IUnicityCertificateVerificationOptions} [options] Options.
   * @returns {Promise<UnicityCertificateVerificationResult>} Verification outcome with its class.
   */
  public verify(
    trustBase: ITrustBaseAuthority,
    inclusionProof: InclusionProof,
    options?: IUnicityCertificateVerificationOptions,
  ): Promise<UnicityCertificateVerificationResult> {
    return this.verifyCertificate(trustBase, inclusionProof.unicityCertificate, options);
  }

  /**
   * Verify a unicity certificate against the held trust-base history, in the order and with the classes of the native B1 verifier: format and
   * bounds (`malformed`), structure and partition (`invalid`), the tree path to the seal hash (`invalid`), then the seal against the committee of
   * its own epoch (`no_entry_for_epoch` for an epoch newer than the latest held one, otherwise `invalid` or `ok`).
   *
   * @param {ITrustBaseAuthority} trustBase Held trust-base history.
   * @param {UnicityCertificate} certificate Certificate.
   * @param {IUnicityCertificateVerificationOptions} [options] Options.
   * @returns {Promise<UnicityCertificateVerificationResult>} Verification outcome with its class.
   */
  public async verifyCertificate(
    trustBase: ITrustBaseAuthority,
    certificate: UnicityCertificate,
    options?: IUnicityCertificateVerificationOptions,
  ): Promise<UnicityCertificateVerificationResult> {
    const results: VerificationResult<VerificationStatus>[] = [];

    let result: VerificationResult<VerificationStatus> = UnicityCertificateFormatRule.verify(certificate);
    results.push(result);
    if (result.status !== VerificationStatus.OK) {
      return UnicityCertificateVerificationResult.fail(results);
    }

    result = UnicityCertificateStructureRule.verify(certificate, options?.partitionId ?? AGGREGATION_PARTITION_ID);
    results.push(result);
    if (result.status !== VerificationStatus.OK) {
      return UnicityCertificateVerificationResult.fail(results);
    }

    result = await this.verifyBody(certificate);
    results.push(result);
    if (result.status !== VerificationStatus.OK) {
      return UnicityCertificateVerificationResult.fail(results);
    }

    result = await this.verifySeal(trustBase, certificate);
    results.push(result);
    if (result.status !== VerificationStatus.OK) {
      return UnicityCertificateVerificationResult.fail(results);
    }

    return UnicityCertificateVerificationResult.ok(results);
  }

  /**
   * @param {UnicityCertificate} certificate Certificate.
   * @returns {Promise<VerificationResult<VerificationStatus>>} The shard and unicity tree path to the seal hash.
   */
  protected verifyBody(certificate: UnicityCertificate): Promise<VerificationResult<VerificationStatus>> {
    return UnicitySealHashMatchesWithRootHashRule.verify(certificate);
  }

  /**
   * @param {ITrustBaseAuthority} trustBase Held trust-base history.
   * @param {UnicityCertificate} certificate Certificate.
   * @returns {Promise<VerificationResult<VerificationStatus>>} The seal against its epoch committee.
   */
  protected verifySeal(
    trustBase: ITrustBaseAuthority,
    certificate: UnicityCertificate,
  ): Promise<VerificationResult<VerificationStatus>> {
    return this.quorumSignaturesRule.verify(trustBase, certificate.unicitySeal);
  }
}

/**
 * Hardware-independent work counters of an operation scoped verifier.
 */
export interface IOperationVerificationStats {
  /** Authority identities built (once per trust base of the operation, never per proof). */
  readonly authorityBuilds: number;
  /** Shard and partition path evaluations to the seal hash actually executed (distinct complete certificates). */
  readonly bodyChecks: number;
  /** Body results served from the memo or a running check. */
  readonly bodyHits: number;
  /** Certificate encodings made to key the memo (one per verified proof). */
  readonly encodes: number;
  /** Quorum signature verifications actually executed (distinct complete seals per trust base). */
  readonly quorumChecks: number;
}

/**
 * {@link UnicityCertificateVerifier} for one operation, see {@link UnicityCertificateVerifier.beginOperation}.
 */
export class OperationUnicityCertificateVerifier extends UnicityCertificateVerifier {
  private static readonly MAX_BODIES = 256;

  private readonly bodies = new Map<string, VerificationResult<VerificationStatus>>();

  private readonly counters = { bodyChecks: 0, bodyHits: 0, encodes: 0 };

  private readonly inFlight = new Map<string, Promise<VerificationResult<VerificationStatus>>>();

  private readonly sessions = new Map<ITrustBaseAuthority, SealVerificationSession>();

  /**
   * Not constructible by applications: obtain it with {@link UnicityCertificateVerifier.beginOperation}, so that an
   * operation always starts from the caller's own verifier and rule.
   *
   * @param {symbol} capability Module private capability.
   * @param {UnicitySealQuorumSignaturesVerificationRule} rule Quorum rule of the verifier this operation began from.
   * @param {SealVerificationSession} [session] Session to adopt for its trust base.
   */
  public constructor(
    capability: symbol,
    rule: UnicitySealQuorumSignaturesVerificationRule,
    session?: SealVerificationSession,
  ) {
    super(rule);
    if (capability !== OPERATION_CAPABILITY) {
      throw new TypeError('An operation verifier is obtained with UnicityCertificateVerifier.beginOperation().');
    }
    if (session) {
      this.sessions.set(session.sourceTrustBase, session);
    }
  }

  /**
   * @returns {IOperationVerificationStats} Snapshot of the work counters.
   */
  public get stats(): IOperationVerificationStats {
    let authorityBuilds = 0;
    let quorumChecks = 0;
    for (const session of this.sessions.values()) {
      authorityBuilds++;
      quorumChecks += session.stats.quorumChecks;
    }
    return { ...this.counters, authorityBuilds, quorumChecks };
  }

  /**
   * @inheritDoc
   */
  public override beginOperation(): OperationUnicityCertificateVerifier {
    return this;
  }

  /**
   * The operation's seal session for a trust base (created on first use): whoever authenticates seals strictly in this
   * operation, e.g. `verifyNonInclusion`, shares the quorum checks of the proofs verified through this verifier.
   *
   * @param {ITrustBaseAuthority} trustBase Held trust-base history.
   * @returns {SealVerificationSession} The session.
   */
  public sessionFor(trustBase: ITrustBaseAuthority): SealVerificationSession {
    return this.session(trustBase);
  }

  /**
   * @inheritDoc
   */
  protected override verifyBody(certificate: UnicityCertificate): Promise<VerificationResult<VerificationStatus>> {
    return this.body(certificate);
  }

  /**
   * @inheritDoc
   */
  protected override verifySeal(
    trustBase: ITrustBaseAuthority,
    certificate: UnicityCertificate,
  ): Promise<VerificationResult<VerificationStatus>> {
    return this.session(trustBase).verifyQuorumSignaturesOnly(certificate.unicitySeal);
  }

  private async body(certificate: UnicityCertificate): Promise<VerificationResult<VerificationStatus>> {
    this.counters.encodes++;
    const key = HexConverter.encode(
      (
        await new DataHasher(HashAlgorithm.SHA256)
          .update(CborSerializer.encodeByteString(certificate.toCBOR()))
          .digest()
      ).imprint,
    );
    const done = this.bodies.get(key);
    if (done) {
      this.counters.bodyHits++;
      return done;
    }
    const running = this.inFlight.get(key);
    if (running) {
      this.counters.bodyHits++;
      return running;
    }

    this.counters.bodyChecks++;
    const check = UnicitySealHashMatchesWithRootHashRule.verify(certificate).then(
      (result) => {
        this.inFlight.delete(key);
        if (result.status === VerificationStatus.OK) {
          if (this.bodies.size >= OperationUnicityCertificateVerifier.MAX_BODIES) {
            const oldest = this.bodies.keys().next();
            if (!oldest.done) {
              this.bodies.delete(oldest.value);
            }
          }
          this.bodies.set(key, result);
        }
        return result;
      },
      (error: unknown) => {
        this.inFlight.delete(key);
        throw error;
      },
    );
    this.inFlight.set(key, check);
    return check;
  }

  private session(trustBase: ITrustBaseAuthority): SealVerificationSession {
    let session = this.sessions.get(trustBase);
    if (!session) {
      session = new SealVerificationSession(trustBase, this.quorumSignaturesRule);
      this.sessions.set(trustBase, session);
    }
    return session;
  }
}
