import { NetworkId } from '../NetworkId.js';
import { InputRecord } from './InputRecord.js';
import { IPartitionViewPolicy, PartitionView, PartitionViewLeaf } from './PartitionView.js';
import { PartitionViewError } from './PartitionViewError.js';
import { ShardId } from './ShardId.js';
import { ShardTree } from './ShardTree.js';
import { UnicityCertificate } from './UnicityCertificate.js';
import { UnicitySeal } from './UnicitySeal.js';
import { UnicityTreeCertificate } from './UnicityTreeCertificate.js';
import { ISealAuthenticator } from './verification/ISealAuthenticator.js';
import { DataHasher } from '../../crypto/hash/DataHasher.js';
import { HashAlgorithm } from '../../crypto/hash/HashAlgorithm.js';
import { CborSerializer } from '../../serialization/cbor/CborSerializer.js';
import { HexConverter } from '../../util/HexConverter.js';
import { VerificationStatus } from '../../verification/VerificationStatus.js';

/** Capability to construct, held by this module only (the symbol is not exported). */
const AUTHENTICATED = Symbol('authenticated');

/**
 * Partition view whose complete content is committed by an authenticated seal.
 *
 * Instances come only from {@link PartitionViewAuthenticator.authenticate}, after the view hashed into the enclosing
 * certificate's partition path and seal hash, matched the enclosing certificate's own leaf exactly, and the complete
 * seal was authenticated under the verifier's anchored authority (network, exact epoch, round at least the epoch
 * start, quorum). There is no flag or map a caller can supply to obtain one. Immutable: every accessor returns copies.
 *
 * The committed scheme and configuration hashes are authenticated by the commitment itself, they are not taken from
 * the response on trust and no independent hash list is required.
 */
export class AuthenticatedPartitionView {
  /** Identity of the anchored authority and verifier policy the seal was authenticated under. */
  public readonly authority: string;
  /** Partition id. */
  public readonly partitionId: bigint;
  /** Identity of the optional pins applied during authentication. */
  public readonly policy: string;
  /** The complete authenticated seal. */
  public readonly seal: UnicitySeal;

  private readonly _certificates: readonly UnicityCertificate[];
  private readonly _leaves: readonly PartitionViewLeaf[];
  private readonly _scheme: readonly ShardId[];

  /**
   * Not callable outside this module, use {@link PartitionViewAuthenticator.authenticate}.
   *
   * @param {symbol} capability Module private capability.
   * @param {object} parts Verified parts.
   * @param {string} parts.authority Authority identity the seal was authenticated under.
   * @param {UnicityCertificate[]} parts.certificates Derived ordinary certificates in canonical order.
   * @param {PartitionViewLeaf[]} parts.leaves Committed leaves.
   * @param {bigint} parts.partitionId Partition id.
   * @param {string} parts.policy Identity of the policy applied.
   * @param {ShardId[]} parts.scheme Committed scheme.
   * @param {UnicitySeal} parts.seal Authenticated seal.
   */
  public constructor(
    capability: typeof AUTHENTICATED,
    parts: {
      readonly authority: string;
      readonly certificates: readonly UnicityCertificate[];
      readonly leaves: readonly PartitionViewLeaf[];
      readonly partitionId: bigint;
      readonly policy: string;
      readonly scheme: readonly ShardId[];
      readonly seal: UnicitySeal;
    },
  ) {
    if ((capability as symbol) !== AUTHENTICATED) {
      throw new Error('AuthenticatedPartitionView can only be created by PartitionViewAuthenticator.');
    }
    this.authority = parts.authority;
    this.partitionId = parts.partitionId;
    this.policy = parts.policy;
    this.seal = parts.seal;
    this._certificates = parts.certificates.slice();
    this._leaves = parts.leaves.slice();
    this._scheme = parts.scheme.slice();
    Object.freeze(this);
  }

  /**
   * @returns {PartitionViewLeaf[]} Committed leaves in canonical order.
   */
  public get leaves(): PartitionViewLeaf[] {
    return this._leaves.slice();
  }

  /**
   * @returns {NetworkId} Network of the authenticated seal.
   */
  public get networkId(): NetworkId {
    return this.seal.networkId;
  }

  /**
   * @returns {ShardId[]} Committed sharding scheme, empty for a single shard partition.
   */
  public get scheme(): ShardId[] {
    return this._scheme.slice();
  }

  /**
   * Ordinary version 1 unicity certificates of every shard in canonical order, each carrying the shared partition
   * certificate and the identical complete master seal. Shards in their initial state keep their native null input
   * record fields.
   *
   * @returns {UnicityCertificate[]} Certificates.
   */
  public assembleCertificates(): UnicityCertificate[] {
    return this._certificates.slice();
  }

  /**
   * @param {ShardId} shard Shard of the partition.
   * @returns {UnicityCertificate} Certificate of the shard.
   * @throws {Error} If the shard is not committed by the view.
   */
  public certificateOf(shard: ShardId): UnicityCertificate {
    const index = this._leaves.findIndex((leaf) => leaf.shardId.equals(shard));
    if (index < 0) {
      throw new Error(`Shard "${shard.toString()}" is not in the authenticated view.`);
    }
    return this._certificates[index];
  }
}

/**
 * Turns an untrusted candidate {@link PartitionView} into an {@link AuthenticatedPartitionView}.
 *
 * Steps: structural validation of the candidate (distinct valid prefixes, complete coverage, canonical order, optional
 * pins), shard tree rebuild and partition path evaluation to the seal hash (nil path steps rejected), exact match of
 * the enclosing certificate's own leaf, then authentication of the complete seal by the anchored authority. The
 * authority is the caller's, never derived from the response.
 *
 * Optional pins (scheme, per-shard configuration hashes) are a stricter policy and are part of
 * {@link PartitionViewAuthenticator.identity}, which keys the bounded memo of authenticated views and should key any
 * cache derived from them.
 */
export class PartitionViewAuthenticator {
  private static readonly MAX_ENTRIES = 16;

  private readonly completed = new Map<string, AuthenticatedPartitionView>();
  private readonly inFlight = new Map<string, Promise<AuthenticatedPartitionView>>();
  private readonly policyId: string;

  /**
   * @param {bigint} partition Partition the caller expects.
   * @param {ISealAuthenticator} sealAuthenticator Authenticates the master seal under the anchored authority.
   * @param {IPartitionViewPolicy} [policy] Optional stricter pins.
   */
  public constructor(
    private readonly partition: bigint,
    private readonly sealAuthenticator: ISealAuthenticator,
    private readonly policy: IPartitionViewPolicy = {},
  ) {
    this.policyId = JSON.stringify([
      policy.scheme ? PartitionView.canonicalShardOrder(policy.scheme).map((id) => id.toString()) : null,
      policy.shardConfigurationHashes
        ? Array.from(policy.shardConfigurationHashes.entries())
            .map(([shard, hash]) => [shard, HexConverter.encode(hash)])
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        : null,
    ]);
  }

  /**
   * @returns {string} Identity of partition, authority and pins; part of any cache or session key.
   */
  public get identity(): string {
    return JSON.stringify([this.partition.toString(), this.sealAuthenticator.identity, this.policyId]);
  }

  private static create(
    view: PartitionView,
    tree: ShardTree,
    uc: UnicityCertificate,
    authority: string,
    policy: string,
  ): AuthenticatedPartitionView {
    const utc: UnicityTreeCertificate = uc.unicityTreeCertificate;
    const leaves = view.leaves;
    return new AuthenticatedPartitionView(AUTHENTICATED, {
      authority,
      certificates: leaves.map(
        (leaf) =>
          new UnicityCertificate(
            InputRecord.fromCBOR(leaf.inputRecord.toCBOR()),
            leaf.technicalRecordHash,
            leaf.shardConfigurationHash,
            tree.certificate(leaf.shardId),
            utc,
            uc.unicitySeal,
          ),
      ),
      leaves,
      partitionId: view.partitionId,
      policy,
      scheme: view.scheme,
      seal: uc.unicitySeal,
    });
  }

  /**
   * Authenticate a candidate view against its enclosing certificate.
   *
   * @param {PartitionView | Uint8Array} candidate Candidate view or its bytes.
   * @param {UnicityCertificate | Uint8Array} enclosing Certificate (or its bytes) carrying the seal.
   * @returns {Promise<AuthenticatedPartitionView>} Authenticated view.
   * @throws {PartitionViewError} If any check fails.
   */
  public async authenticate(
    candidate: PartitionView | Uint8Array,
    enclosing: UnicityCertificate | Uint8Array,
  ): Promise<AuthenticatedPartitionView> {
    const view = candidate instanceof Uint8Array ? PartitionView.fromCBOR(candidate) : candidate;
    const uc = enclosing instanceof Uint8Array ? PartitionView.decodeEnclosingCertificate(enclosing) : enclosing;

    // nested shape first: native path evaluation and encoding must never see a nil element
    uc.unicityTreeCertificate.steps.forEach((step, i) => {
      if (step == null) {
        throw new PartitionViewError('tree_mismatch', `Unicity tree certificate hash step ${i} is nil.`);
      }
    });

    const key = HexConverter.encode(
      (
        await new DataHasher(HashAlgorithm.SHA256)
          .update(
            CborSerializer.encodeArray(
              CborSerializer.encodeTextString(this.identity),
              CborSerializer.encodeByteString(view.toCBOR()),
              CborSerializer.encodeByteString(uc.toCBOR()),
            ),
          )
          .digest()
      ).imprint,
    );
    const done = this.completed.get(key);
    if (done) {
      return done;
    }
    const running = this.inFlight.get(key);
    if (running) {
      return running;
    }

    const run = this.run(view, uc).then(
      (authenticated) => {
        this.inFlight.delete(key);
        if (this.completed.size >= PartitionViewAuthenticator.MAX_ENTRIES) {
          const oldest = this.completed.keys().next();
          if (!oldest.done) {
            this.completed.delete(oldest.value);
          }
        }
        this.completed.set(key, authenticated);
        return authenticated;
      },
      (error: unknown) => {
        this.inFlight.delete(key);
        throw error;
      },
    );
    this.inFlight.set(key, run);
    return run;
  }

  private async run(view: PartitionView, uc: UnicityCertificate): Promise<AuthenticatedPartitionView> {
    // 1-3: candidate structure, tree and partition path to the seal hash, exact enclosing leaf
    const tree = await view.verifyTree(uc, this.partition, this.policy);

    // 4: only then the seal, under the caller's anchored authority
    const result = await this.sealAuthenticator.authenticate(uc.unicitySeal);
    if (result.status !== VerificationStatus.OK) {
      throw new PartitionViewError('seal_invalid', `Authenticating unicity seal: ${result.message || 'failed'}.`);
    }

    return PartitionViewAuthenticator.create(view, tree, uc, this.sealAuthenticator.identity, this.policyId);
  }
}
