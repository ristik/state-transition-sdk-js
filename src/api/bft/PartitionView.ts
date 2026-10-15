import { InputRecord } from './InputRecord.js';
import { PartitionViewError } from './PartitionViewError.js';
import { ShardId } from './ShardId.js';
import { ShardTree } from './ShardTree.js';
import { UnicityCertificate } from './UnicityCertificate.js';
import { ISealAuthenticator } from './verification/ISealAuthenticator.js';
import { UnicitySealHashMatchesWithRootHashRule } from './verification/rule/UnicitySealHashMatchesWithRootHashRule.js';
import { CborDeserializer } from '../../serialization/cbor/CborDeserializer.js';
import { CborError } from '../../serialization/cbor/CborError.js';
import { CborSerializer } from '../../serialization/cbor/CborSerializer.js';
import { areUint8ArraysEqual } from '../../util/TypedArrayUtils.js';
import { VerificationStatus } from '../../verification/VerificationStatus.js';

/**
 * Trusted description of the partition a view is validated against. It must come from the verifier's own
 * configuration, never from the response carrying the view.
 */
export interface IPartitionViewTopology {
  /**
   * Sharding scheme of the partition: empty for a single shard partition, otherwise at least two shards forming a
   * complete prefix-free set.
   */
  readonly scheme: readonly ShardId[];
  /**
   * Admitted shard configuration hashes by shard id bit string ({@link ShardId.toString}). Present entries must match
   * the view, certificate assembly requires an entry for every shard.
   */
  readonly shardConfigurationHashes: ReadonlyMap<string, Uint8Array>;
}

const HASH_LENGTH = 32;
const SINGLE_SHARD = ShardId.decode(new Uint8Array([0x80]));

/**
 * Committed content of one shard in a {@link PartitionView}.
 */
export class PartitionViewLeaf {
  private readonly _shardConfigurationHash: Uint8Array;
  private readonly _technicalRecordHash: Uint8Array;

  public constructor(
    public readonly shardId: ShardId,
    public readonly inputRecord: InputRecord,
    technicalRecordHash: Uint8Array,
    shardConfigurationHash: Uint8Array,
  ) {
    this._technicalRecordHash = new Uint8Array(technicalRecordHash);
    this._shardConfigurationHash = new Uint8Array(shardConfigurationHash);
  }

  /**
   * @returns {Uint8Array} Copy of the shard configuration hash.
   */
  public get shardConfigurationHash(): Uint8Array {
    return new Uint8Array(this._shardConfigurationHash);
  }

  /**
   * @returns {Uint8Array} Copy of the technical record hash.
   */
  public get technicalRecordHash(): Uint8Array {
    return new Uint8Array(this._technicalRecordHash);
  }

  /**
   * @returns {Uint8Array} CBOR encoding `[shardId, inputRecord, trHash, shardConfHash]`.
   */
  public toCBOR(): Uint8Array {
    return CborSerializer.encodeArray(
      CborSerializer.encodeByteString(this.shardId.encode()),
      this.inputRecord.toCBOR(),
      CborSerializer.encodeByteString(this._technicalRecordHash),
      CborSerializer.encodeByteString(this._shardConfigurationHash),
    );
  }

  /**
   * Check the per leaf limits. Does not know the expected topology.
   *
   * @returns {void}
   * @throws {PartitionViewError} If the leaf is out of bounds.
   */
  public validateBounds(): void {
    if (this.shardId.length > PartitionView.MAX_SHARD_ID_BITS) {
      throw new PartitionViewError(
        'bounds',
        `Shard ID is ${this.shardId.length} bits, limit is ${PartitionView.MAX_SHARD_ID_BITS}.`,
      );
    }

    const ir = this.inputRecord;
    const hash = ir.hash;
    const previousHash = ir.previousHash ?? new Uint8Array(0);
    const blockHash = ir.blockHash ?? new Uint8Array(0);

    // same rules as the native input record validation
    if (ir.roundNumber !== 0n && ir.timestamp === 0n) {
      throw new PartitionViewError('bounds', 'Input record timestamp is unassigned.');
    }
    const unchanged = areUint8ArraysEqual(previousHash, hash);
    if (unchanged && blockHash.length !== 0) {
      throw new PartitionViewError('bounds', "Input record state hash didn't change but block hash is not nil.");
    }
    if (!unchanged && blockHash.length === 0) {
      throw new PartitionViewError('bounds', 'Input record block hash is nil but state hash changed.');
    }

    if (ir.summaryValue.length > PartitionView.MAX_SUMMARY_VALUE_BYTES) {
      throw new PartitionViewError(
        'bounds',
        `Summary value is ${ir.summaryValue.length} bytes, limit is ${PartitionView.MAX_SUMMARY_VALUE_BYTES}.`,
      );
    }
    for (const [name, value] of [
      ['state hash', hash],
      ['previous hash', previousHash],
      ['block hash', blockHash],
      ['executed transactions hash', ir.executedTransactionsHash ?? new Uint8Array(0)],
    ] as const) {
      // absent/empty (initial state, unchanged state) or a full hash
      if (value.length !== 0 && value.length !== HASH_LENGTH) {
        throw new PartitionViewError('bounds', `${name} must be empty or ${HASH_LENGTH} bytes, got ${value.length}.`);
      }
    }
    const irLength = ir.toCBOR().length;
    if (irLength > PartitionView.MAX_INPUT_RECORD_BYTES) {
      throw new PartitionViewError(
        'bounds',
        `Input record is ${irLength} bytes, limit is ${PartitionView.MAX_INPUT_RECORD_BYTES}.`,
      );
    }
    if (this._technicalRecordHash.length !== HASH_LENGTH) {
      throw new PartitionViewError('bounds', `TRHash must be ${HASH_LENGTH} bytes.`);
    }
    if (this._shardConfigurationHash.length !== HASH_LENGTH) {
      throw new PartitionViewError('bounds', `ShardConfHash must be ${HASH_LENGTH} bytes.`);
    }
  }
}

/**
 * Partition view: the complete vector of shard tree leaves of one partition, as committed by a single unicity seal.
 *
 * Untagged, explicitly versioned CBOR array `[1, partitionId, [[shardId, inputRecord, trHash, shardConfHash], ...]]`
 * from which the ordinary unicity certificates of every shard can be derived. A decoded view is NOT trusted:
 * {@link PartitionView.assembleCertificates} authenticates it against the enclosing certificate and the seal.
 */
export class PartitionView {
  /** Maximum size of an encoded view. */
  public static readonly MAX_BYTES = 16 * 1024;
  /** Maximum size of an encoded input record. */
  public static readonly MAX_INPUT_RECORD_BYTES = 1024;
  /** Maximum number of shards in a view. */
  public static readonly MAX_LEAVES = 8;
  /** Maximum shard id length in bits. */
  public static readonly MAX_SHARD_ID_BITS = 256;
  /** Maximum size of the input record summary value. */
  public static readonly MAX_SUMMARY_VALUE_BYTES = 256;

  private static readonly MAX_PARTITION_ID = 0xffffffffn;
  private static readonly VERSION = 1n;

  private readonly _leaves: PartitionViewLeaf[];

  /**
   * @param {bigint} partitionId Partition id, nonzero 32-bit unsigned.
   * @param {PartitionViewLeaf[]} leaves Leaves in canonical order.
   * @throws {PartitionViewError} If the view is out of bounds.
   */
  public constructor(
    public readonly partitionId: bigint,
    leaves: readonly PartitionViewLeaf[],
  ) {
    this._leaves = leaves.slice();
    if (partitionId <= 0n || partitionId > PartitionView.MAX_PARTITION_ID) {
      throw new PartitionViewError('bounds', 'Partition ID must be a nonzero 32-bit unsigned integer.');
    }
    if (this._leaves.length < 1 || this._leaves.length > PartitionView.MAX_LEAVES) {
      throw new PartitionViewError(
        'bounds',
        `Leaf count must be 1..${PartitionView.MAX_LEAVES}, got ${this._leaves.length}.`,
      );
    }
    this._leaves.forEach((leaf, i) => {
      try {
        leaf.validateBounds();
      } catch (e) {
        throw e instanceof PartitionViewError ? new PartitionViewError(e.reason, `Leaf ${i}: ${e.message}`) : e;
      }
    });
  }

  /**
   * @returns {PartitionViewLeaf[]} Copy of the leaf list.
   */
  public get leaves(): PartitionViewLeaf[] {
    return this._leaves.slice();
  }

  /**
   * @returns {bigint} Wire-format version of the view.
   */
  public get version(): bigint {
    return PartitionView.VERSION;
  }

  /**
   * Shard ids of the scheme in binary tree left-to-right order (lexicographic bit string, `0` before `1`). Empty
   * scheme yields the single empty shard id.
   *
   * @param {readonly ShardId[]} scheme Sharding scheme.
   * @returns {ShardId[]} Shard ids in canonical order.
   * @throws {PartitionViewError} If the scheme is not a complete prefix-free set within limits.
   */
  public static canonicalShardOrder(scheme: readonly ShardId[]): ShardId[] {
    if (scheme.length === 0) {
      return [SINGLE_SHARD];
    }
    if (scheme.length > PartitionView.MAX_LEAVES) {
      throw new PartitionViewError(
        'topology',
        `Scheme has ${scheme.length} shards, limit is ${PartitionView.MAX_LEAVES}.`,
      );
    }
    // a single shard partition is the empty scheme, never a one element scheme
    if (scheme.length === 1) {
      throw new PartitionViewError('topology', 'Scheme can not contain a single shard.');
    }

    const ids = scheme.map((id) => ({ bits: id.toString(), id }));
    let maxLength = 0;
    for (const { bits } of ids) {
      if (bits.length === 0) {
        throw new PartitionViewError('topology', 'Scheme may not contain the empty shard id.');
      }
      if (bits.length > PartitionView.MAX_SHARD_ID_BITS) {
        throw new PartitionViewError(
          'topology',
          `Shard ID ${bits} is longer than ${PartitionView.MAX_SHARD_ID_BITS} bits.`,
        );
      }
      maxLength = Math.max(maxLength, bits.length);
    }
    for (const [i, a] of ids.entries()) {
      for (const [j, b] of ids.entries()) {
        if (i !== j && b.bits.startsWith(a.bits)) {
          throw new PartitionViewError('topology', `Scheme is not prefix-free: ${a.bits} is prefix of ${b.bits}.`);
        }
      }
    }
    // prefix-free scheme covers the whole tree iff the Kraft sum equals one
    const sum = ids.reduce((acc, { bits }) => acc + (1n << BigInt(maxLength - bits.length)), 0n);
    if (sum !== 1n << BigInt(maxLength)) {
      throw new PartitionViewError('topology', 'Scheme does not cover the whole shard tree.');
    }

    return ids.sort((a, b) => (a.bits < b.bits ? -1 : a.bits > b.bits ? 1 : 0)).map(({ id }) => id);
  }

  /**
   * Decode the enclosing certificate of a view, rejecting any encoding that does not re-encode byte-identically, so
   * derived certificates carry exactly the master seal bytes that were authenticated.
   *
   * @param {Uint8Array} bytes CBOR bytes of a unicity certificate.
   * @returns {UnicityCertificate} Decoded certificate.
   * @throws {PartitionViewError} If decoding fails or the encoding is not canonical.
   */
  public static decodeEnclosingCertificate(bytes: Uint8Array): UnicityCertificate {
    let uc: UnicityCertificate;
    try {
      uc = UnicityCertificate.fromCBOR(bytes);
    } catch (e) {
      throw new PartitionViewError(
        'malformed',
        `Decoding enclosing unicity certificate: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    if (!areUint8ArraysEqual(uc.toCBOR(), bytes)) {
      throw new PartitionViewError('malformed', 'Enclosing unicity certificate is not canonically encoded.');
    }
    return uc;
  }
  /**
   * Strictly decode a view: bounded input size, exact array lengths, no trailing bytes, no indefinite length items,
   * explicit version 1, untagged, and the encoding must be the canonical one.
   *
   * @param {Uint8Array} bytes CBOR bytes.
   * @returns {PartitionView} Decoded view, not authenticated.
   * @throws {PartitionViewError} If the bytes are not a valid view.
   */
  public static fromCBOR(bytes: Uint8Array): PartitionView {
    if (bytes.length > PartitionView.MAX_BYTES) {
      throw new PartitionViewError(
        'bounds',
        `Partition view is ${bytes.length} bytes, limit is ${PartitionView.MAX_BYTES}.`,
      );
    }

    let view: PartitionView;
    try {
      const data = CborDeserializer.decodeArray(bytes, 3);
      const version = CborDeserializer.decodeUnsignedInteger(data[0]);
      if (version !== PartitionView.VERSION) {
        throw new PartitionViewError('unsupported_version', `Unsupported partition view version ${version}.`);
      }
      const partitionId = CborDeserializer.decodeUnsignedInteger(data[1]);
      const leafItems = CborDeserializer.decodeArray(data[2]);
      if (leafItems.length < 1 || leafItems.length > PartitionView.MAX_LEAVES) {
        throw new PartitionViewError(
          'bounds',
          `Leaf count must be 1..${PartitionView.MAX_LEAVES}, got ${leafItems.length}.`,
        );
      }

      view = new PartitionView(
        partitionId,
        leafItems.map((item) => {
          const leaf = CborDeserializer.decodeArray(item, 4);
          return new PartitionViewLeaf(
            ShardId.decode(CborDeserializer.decodeByteString(leaf[0])),
            InputRecord.fromCBOR(leaf[1]),
            CborDeserializer.decodeByteString(leaf[2]),
            CborDeserializer.decodeByteString(leaf[3]),
          );
        }),
      );
    } catch (e) {
      if (e instanceof PartitionViewError) {
        throw e;
      }
      if (e instanceof CborError || e instanceof RangeError) {
        throw new PartitionViewError('malformed', `Decoding partition view: ${e.message}`);
      }
      throw e;
    }

    // decoded fields have no other representation, but a mismatch would mean the decoder accepted a non-canonical form
    if (!areUint8ArraysEqual(view.toCBOR(), bytes)) {
      throw new PartitionViewError('malformed', 'Partition view is not canonically encoded.');
    }
    return view;
  }

  /**
   * Derive the ordinary version 1 unicity certificate of every shard in the view, in canonical order.
   *
   * Requires every step of {@link PartitionView.verifyTree}, the topology to carry the admitted configuration hash of
   * every shard and the seal of the enclosing certificate to be authenticated by `sealAuthenticator` (signatures,
   * network and epoch against the verifier's own trusted authority). Tree root equality alone is not authentication.
   * Derived certificates share the partition certificate and the identical, complete master seal.
   *
   * @param {UnicityCertificate} enclosingUc Certificate carrying the seal the view is committed under.
   * @param {bigint} partition Expected partition id.
   * @param {IPartitionViewTopology} topology Trusted topology.
   * @param {ISealAuthenticator} sealAuthenticator Authenticates the master seal against the trusted authority.
   * @returns {Promise<UnicityCertificate[]>} Certificates of all shards.
   * @throws {PartitionViewError} If any check fails.
   */
  public async assembleCertificates(
    enclosingUc: UnicityCertificate,
    partition: bigint,
    topology: IPartitionViewTopology,
    sealAuthenticator: ISealAuthenticator,
  ): Promise<UnicityCertificate[]> {
    for (const id of PartitionView.canonicalShardOrder(topology.scheme)) {
      const admitted = topology.shardConfigurationHashes.get(id.toString());
      if (!admitted || admitted.length !== HASH_LENGTH) {
        throw new PartitionViewError(
          'config_not_admitted',
          `Shard "${id.toString()}": admitted configuration hash is required.`,
        );
      }
    }

    const tree = await this.verifyTree(enclosingUc, partition, topology);

    const result = await sealAuthenticator.authenticate(enclosingUc.unicitySeal);
    if (result.status !== VerificationStatus.OK) {
      throw new PartitionViewError('seal_invalid', `Authenticating unicity seal: ${result.message || 'failed'}.`);
    }

    return this._leaves.map((leaf) => this.deriveCertificate(leaf, tree, enclosingUc));
  }

  /**
   * Validate the structure and rebuild the native shard tree from the leaves.
   *
   * @param {bigint} partition Expected partition id.
   * @param {IPartitionViewTopology} topology Trusted topology.
   * @returns {Promise<ShardTree>} Shard tree.
   * @throws {PartitionViewError} If the view does not match the topology.
   */
  public buildShardTree(partition: bigint, topology: IPartitionViewTopology): Promise<ShardTree> {
    this.validateStructure(partition, topology);
    return ShardTree.create(
      this._leaves.map((leaf) => ({
        inputRecord: leaf.inputRecord,
        shard: leaf.shardId,
        shardConfigurationHash: leaf.shardConfigurationHash,
        technicalRecordHash: leaf.technicalRecordHash,
      })),
    );
  }

  /**
   * Convert to CBOR bytes.
   *
   * @returns {Uint8Array} CBOR bytes.
   */
  public toCBOR(): Uint8Array {
    const bytes = CborSerializer.encodeArray(
      CborSerializer.encodeUnsignedInteger(this.version),
      CborSerializer.encodeUnsignedInteger(this.partitionId),
      CborSerializer.encodeArray(...this._leaves.map((leaf) => leaf.toCBOR())),
    );
    if (bytes.length > PartitionView.MAX_BYTES) {
      throw new PartitionViewError(
        'bounds',
        `Encoded partition view is ${bytes.length} bytes, limit is ${PartitionView.MAX_BYTES}.`,
      );
    }
    return bytes;
  }

  /**
   * Check that the view is a well formed view of the given partition and exactly the shards of the topology in
   * canonical order. Does not touch any hash tree.
   *
   * @param {bigint} partition Expected partition id.
   * @param {IPartitionViewTopology} topology Trusted topology.
   * @returns {void}
   * @throws {PartitionViewError} If the view does not match.
   */
  public validateStructure(partition: bigint, topology: IPartitionViewTopology): void {
    if (this.partitionId !== partition) {
      throw new PartitionViewError(
        'topology',
        `Partition view is for partition ${this.partitionId}, expected ${partition}.`,
      );
    }
    const order = PartitionView.canonicalShardOrder(topology.scheme);
    if (this._leaves.length !== order.length) {
      throw new PartitionViewError(
        'topology',
        `View has ${this._leaves.length} leaves, topology has ${order.length} shards.`,
      );
    }
    order.forEach((id, i) => {
      const leaf = this._leaves[i];
      if (!leaf.shardId.equals(id)) {
        throw new PartitionViewError(
          'topology',
          `Leaf ${i} is shard "${leaf.shardId.toString()}", expected "${id.toString()}".`,
        );
      }
      const admitted = topology.shardConfigurationHashes.get(id.toString());
      if (admitted && !areUint8ArraysEqual(admitted, leaf.shardConfigurationHash)) {
        throw new PartitionViewError(
          'config_not_admitted',
          `Shard "${id.toString()}": configuration hash does not match the admitted configuration.`,
        );
      }
    });
  }

  /**
   * Check that the view hashes into the unicity seal of the enclosing certificate: structure and topology are
   * validated, the partition certificate must be for the view's partition and the rebuilt shard tree root must evaluate
   * through it to the seal hash. The enclosing certificate's own shard leaf must match the view completely.
   *
   * The seal signatures are NOT checked here, see {@link PartitionView.assembleCertificates}.
   *
   * @param {UnicityCertificate} enclosingUc Certificate carrying the seal the view is committed under.
   * @param {bigint} partition Expected partition id.
   * @param {IPartitionViewTopology} topology Trusted topology.
   * @returns {Promise<ShardTree>} The rebuilt shard tree.
   * @throws {PartitionViewError} If the view is not committed by the certificate.
   */
  public async verifyTree(
    enclosingUc: UnicityCertificate,
    partition: bigint,
    topology: IPartitionViewTopology,
  ): Promise<ShardTree> {
    const tree = await this.buildShardTree(partition, topology);

    const utc = enclosingUc.unicityTreeCertificate;
    if (utc.partitionIdentifier !== this.partitionId) {
      throw new PartitionViewError(
        'tree_mismatch',
        `Enclosing certificate is for partition ${utc.partitionIdentifier}, view is for ${this.partitionId}.`,
      );
    }
    utc.steps.forEach((step, i) => {
      // not reachable through the wire decoder, but certificates may be constructed
      if (step == null) {
        throw new PartitionViewError('tree_mismatch', `Unicity tree certificate hash step ${i} is nil.`);
      }
    });

    // enclosing certificate's own leaf and native shard path
    const own = enclosingUc.shardTreeCertificate.shard;
    const leaf = this._leaves.find((l) => l.shardId.equals(own));
    if (!leaf) {
      throw new PartitionViewError(
        'enclosing_certificate_mismatch',
        `Enclosing certificate shard "${own.toString()}" is not in the view.`,
      );
    }
    const ownCertificate = tree.certificate(own);
    const ownSiblings = enclosingUc.shardTreeCertificate.siblingHashList;
    if (
      ownSiblings.length !== own.length ||
      ownSiblings.length !== ownCertificate.siblingHashList.length ||
      !ownSiblings.every((hash, i) => areUint8ArraysEqual(hash, ownCertificate.siblingHashList[i]))
    ) {
      throw new PartitionViewError(
        'enclosing_certificate_mismatch',
        'Enclosing certificate shard tree certificate does not match the view.',
      );
    }
    if (!areUint8ArraysEqual(enclosingUc.inputRecord.toCBOR(), leaf.inputRecord.toCBOR())) {
      throw new PartitionViewError(
        'enclosing_certificate_mismatch',
        'Enclosing certificate input record does not match the view leaf.',
      );
    }
    if (!areUint8ArraysEqual(enclosingUc.technicalRecordHash, leaf.technicalRecordHash)) {
      throw new PartitionViewError(
        'enclosing_certificate_mismatch',
        'Enclosing certificate TRHash does not match the view leaf.',
      );
    }
    if (!areUint8ArraysEqual(enclosingUc.shardConfigurationHash, leaf.shardConfigurationHash)) {
      throw new PartitionViewError(
        'enclosing_certificate_mismatch',
        'Enclosing certificate shard configuration hash does not match the view leaf.',
      );
    }

    // the view's own tree through the partition path of the enclosing certificate must be the sealed hash
    const derived = this.deriveCertificate(leaf, tree, enclosingUc);
    const result = await UnicitySealHashMatchesWithRootHashRule.verify(derived);
    if (result.status !== VerificationStatus.OK) {
      throw new PartitionViewError('tree_mismatch', 'Partition view does not match the seal hash.');
    }

    return tree;
  }

  private deriveCertificate(
    leaf: PartitionViewLeaf,
    tree: ShardTree,
    enclosingUc: UnicityCertificate,
  ): UnicityCertificate {
    return new UnicityCertificate(
      leaf.inputRecord,
      leaf.technicalRecordHash,
      leaf.shardConfigurationHash,
      tree.certificate(leaf.shardId),
      enclosingUc.unicityTreeCertificate,
      enclosingUc.unicitySeal,
    );
  }
}
