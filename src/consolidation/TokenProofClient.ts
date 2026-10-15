import { ConsolidationError } from './ConsolidationError.js';
import { ConsolidationResult, IProofSummary } from './ConsolidationResult.js';
import { IConsolidationItem, IConsolidationOptions, ProofConsolidator } from './ProofConsolidator.js';
import { ShardRouting } from './ShardRouting.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { SealVerificationSession } from '../api/bft/verification/SealVerificationSession.js';
import { UnicityCertificateVerifier } from '../api/bft/verification/UnicityCertificateVerifier.js';
import { InclusionProof } from '../api/InclusionProof.js';
import { ISignatureVerifier } from '../crypto/ISignatureVerifier.js';
import { Secp256k1SignatureVerifier } from '../crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { Signature } from '../crypto/secp256k1/Signature.js';
import { CborDeserializer } from '../serialization/cbor/CborDeserializer.js';
import { CborSerializer } from '../serialization/cbor/CborSerializer.js';
import { Token } from '../transaction/Token.js';
import { IVerificationContext } from '../transaction/verification/IVerificationContext.js';
import { VerificationContext } from '../transaction/verification/VerificationContext.js';
import { areUint8ArraysEqual } from '../util/TypedArrayUtils.js';
import { VerificationStatus } from '../verification/VerificationStatus.js';

/**
 * Configuration of a {@link TokenProofClient}.
 */
export interface ITokenProofClientOptions {
  /** Maximum number of completed seal checks one operation remembers. Default 64. */
  readonly maxSealCacheEntries?: number;
  /** Trusted shard routing, configured once. Endpoints and credentials come from here only. */
  readonly routing: ShardRouting;
  /** Verifier of the root nodes' signatures. Default secp256k1. */
  readonly signatureVerifier?: ISignatureVerifier<Signature>;
  /**
   * The existing verification context. Its trust base is the anchored authority, its predicate and issuance services
   * are used as they are. Its certificate verifier is replaced for the operation by one backed by the operation's seal
   * session (inject a custom signature verifier through `signatureVerifier`).
   */
  readonly verificationContext: IVerificationContext;
}

/**
 * Options of one {@link TokenProofClient.consolidate} call.
 */
export type ITokenConsolidationOptions = IConsolidationOptions;

/**
 * Explicit preparation of a token for verification by an EVM contract (including internal bridge back) or a zkVM:
 * returns an ordinary token whose replaceable outer-history proofs all share one unicity seal, so that the target
 * verifier authenticates that seal once.
 *
 * Consolidation is optional and never automatic: nothing in the SDK calls this class. It needs no signing key, never
 * submits anything and never modifies its input. Proofs inside signed mint justifications, split/burn dependencies
 * and opaque predicate data are not replaceable and stay byte-for-byte unchanged, so a token with nested proofs can
 * still need other seals; the one-seal claim is about the outer history only. The token's size does not shrink.
 */
export class TokenProofClient {
  /**
   * @param {ITokenProofClientOptions} options Configuration.
   * @throws {ConsolidationError} `input` if the routing and the verification context are for different networks.
   */
  public constructor(private readonly options: ITokenProofClientOptions) {
    const network = options.routing.networkId;
    if (network && !network.equals(options.verificationContext.trustBase.networkId)) {
      throw new ConsolidationError('input', 'The routing is configured for another network than the trust base.', {
        outcome: 'incompatible_lineage',
      });
    }
  }

  private static distinctSeals(proofs: readonly InclusionProof[]): number {
    const seals: Uint8Array[] = [];
    for (const proof of proofs) {
      const seal = proof.unicityCertificate.unicitySeal.toCBOR();
      if (!seals.some((known) => areUint8ArraysEqual(known, seal))) {
        seals.push(seal);
      }
    }
    return seals.length;
  }

  /**
   * Token bytes with the proofs of the outer history swapped. Every other byte (signed transactions, mint
   * justifications and their nested proofs, predicates) is copied verbatim; the result is only ever used by decoding
   * it into a token that is then fully verified.
   */
  private static replaceOuterProofs(tokenBytes: Uint8Array, proofs: readonly InclusionProof[]): Uint8Array {
    const tag = CborDeserializer.decodeTag(tokenBytes);
    const [version, genesis, transfers] = CborDeserializer.decodeArray(tag.data, 3);
    const transferItems = CborDeserializer.decodeArray(transfers);
    if (proofs.length !== transferItems.length + 1) {
      throw new ConsolidationError('integrity', 'Proof count does not match the token history.', {
        outcome: 'invalid_input',
      });
    }
    const swap = (certified: Uint8Array, proof: InclusionProof): Uint8Array => {
      const [transaction] = CborDeserializer.decodeArray(certified, 2);
      return CborSerializer.encodeArray(transaction, proof.toCBOR());
    };
    return CborSerializer.encodeTag(
      tag.tag,
      CborSerializer.encodeArray(
        version,
        swap(genesis, proofs[0]),
        CborSerializer.encodeArray(...transferItems.map((item, i) => swap(item, proofs[i + 1]))),
      ),
    );
  }

  /**
   * Rebuild the token's outer-history proofs under one master seal.
   *
   * One attempt makes one `latest` request to the master shard and one exact-root request to every other
   * participating shard (in parallel, bounded), under one total deadline. If the proofs already share a seal the
   * verified token is returned without any request.
   *
   * @param {Token} token Token to prepare, unchanged on every outcome.
   * @param {ITokenConsolidationOptions} [options] Deadline, cancellation and bounds.
   * @returns {Promise<ConsolidationResult>} `consolidated` with a fully verified immutable token, or `unavailable`
   *   with a stable reason when the service cannot provide the material.
   * @throws {ConsolidationError} Typed cancellation, deadline, transport, server, response or integrity failure.
   */
  public async consolidate(token: Token, options: ITokenConsolidationOptions = {}): Promise<ConsolidationResult> {
    const signatureVerifier = this.options.signatureVerifier ?? new Secp256k1SignatureVerifier();
    const { trustBase } = this.options.verificationContext;
    const session = new SealVerificationSession(
      trustBase,
      new UnicitySealQuorumSignaturesVerificationRule(signatureVerifier),
      { maxEntries: this.options.maxSealCacheEntries },
    );
    const context = this.operationContext(signatureVerifier, session);

    const original = await token.verify(context);
    if (original.status !== VerificationStatus.OK) {
      throw new ConsolidationError('integrity', 'The token does not verify.', {
        cause: original,
        outcome: 'invalid_input',
      });
    }

    const outer = [token.genesis, ...token.transactions];
    const items: IConsolidationItem[] = outer.map((transaction) => ({
      certificationData: transaction.inclusionProof.certificationData,
      proof: transaction.inclusionProof,
    }));
    const originalSeals = TokenProofClient.distinctSeals(items.map((item) => item.proof));
    const evidenceQuorumChecks = session.stats.quorumChecks;

    if (originalSeals === 1) {
      return {
        status: 'consolidated',
        summary: {
          alreadyConsolidated: true,
          consolidatedSeals: 1,
          evidenceQuorumChecks,
          masterRound: items[0].proof.unicityCertificate.unicitySeal.rootChainRoundNumber,
          masterShard: items[0].proof.unicityCertificate.shardTreeCertificate.shard.toString(),
          originalSeals,
          outerProofs: items.length,
          quorumChecks: 0,
          requests: 0,
          requiredRound: items[0].proof.unicityCertificate.unicitySeal.rootChainRoundNumber,
          shards: new Set(items.map((i) => i.proof.unicityCertificate.shardTreeCertificate.shard.toString())).size,
        },
        token,
      };
    }

    const attempt = await new ProofConsolidator(this.options.routing, session).consolidate(items, options);
    if (attempt.status === 'unavailable') {
      return { detail: attempt.detail, reason: attempt.reason, retryable: attempt.retryable, status: 'unavailable' };
    }

    // rebuild from the original signed bytes with only the replaceable proofs swapped, then verify everything again
    const proofs = attempt.responses.map((response) => response.inclusionProof as InclusionProof);
    const rebuilt = await Token.fromCBOR(TokenProofClient.replaceOuterProofs(token.toCBOR(), proofs));
    const result = await rebuilt.verify(context);
    if (result.status !== VerificationStatus.OK) {
      throw new ConsolidationError('integrity', 'The consolidated token does not verify.', {
        cause: result,
        outcome: 'invalid_input',
      });
    }

    const rebuiltOuter = [rebuilt.genesis, ...rebuilt.transactions].map((t) => t.inclusionProof);
    const consolidatedSeals = TokenProofClient.distinctSeals(rebuiltOuter);
    if (consolidatedSeals !== 1) {
      throw new ConsolidationError('integrity', 'The consolidated outer history does not share one seal.', {
        outcome: 'invalid_input',
      });
    }

    const summary: IProofSummary = {
      alreadyConsolidated: false,
      consolidatedSeals,
      evidenceQuorumChecks,
      masterRound: attempt.masterRound,
      masterShard: attempt.masterShard.toString(),
      originalSeals,
      outerProofs: items.length,
      quorumChecks: session.stats.quorumChecks - evidenceQuorumChecks,
      requests: attempt.requests,
      requiredRound: attempt.requiredRound,
      shards: attempt.shards,
    };
    return { status: 'consolidated', summary, token: rebuilt };
  }

  /** Verification context of one operation: the caller's, with the certificate verifier backed by the session. */
  private operationContext(
    signatureVerifier: ISignatureVerifier<Signature>,
    session: SealVerificationSession,
  ): IVerificationContext {
    const context = this.options.verificationContext;
    return new VerificationContext(
      context.trustBase,
      context.predicateVerifier,
      new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(signatureVerifier)).beginOperation(
        session,
      ),
      context.mintJustificationVerifier,
      context.tokenIssuanceVerifier,
    );
  }
}
