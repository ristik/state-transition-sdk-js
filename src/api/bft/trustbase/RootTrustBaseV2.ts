import { secp256k1 } from '@noble/curves/secp256k1.js';

import { TrustBaseError } from './TrustBaseError.js';
import { DataHash } from '../../../crypto/hash/DataHash.js';
import { DataHasher } from '../../../crypto/hash/DataHasher.js';
import { HashAlgorithm } from '../../../crypto/hash/HashAlgorithm.js';
import { Secp256k1SignatureVerifier } from '../../../crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { Signature } from '../../../crypto/secp256k1/Signature.js';
import { CborDeserializer } from '../../../serialization/cbor/CborDeserializer.js';
import { CborMap } from '../../../serialization/cbor/CborMap.js';
import { CborMapEntry } from '../../../serialization/cbor/CborMapEntry.js';
import { CborReader } from '../../../serialization/cbor/CborReader.js';
import { CborSerializer } from '../../../serialization/cbor/CborSerializer.js';
import { MajorType } from '../../../serialization/cbor/MajorType.js';
import { areUint8ArraysEqual, compareUint8Arrays } from '../../../util/TypedArrayUtils.js';
import { RootTrustBase } from '../RootTrustBase.js';

/** One member of an epoch's root committee. */
export interface IRootTrustBaseV2Member {
  /** libp2p peer identifier of the member. */
  readonly nodeId: string;
  /** Compressed (33-byte) secp256k1 signing key. */
  readonly signingKey: Uint8Array;
  /** Voting weight, 1..2^40. */
  readonly weight: bigint;
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: true });
const VERIFIER = new Secp256k1SignatureVerifier();

/**
 * A Unicity Trust Base entry, record version 2: the root committee of one epoch, signed by the previous epoch's committee.
 *
 * Wire form (tag 39000, deterministic CBOR): `[2, networkId, epoch, epochStartRound, [[nodeId, signingKey, weight]…], quorumThreshold, stateHash,
 * changeRecordHash, previousEntryId, {nodeId → signature} | null]`. The entry's identity is {@link entryId} = SHA-256 of {@link sigBytes} (the entry
 * with the signature field encoded as null), so two valid signature subsets of one entry have the same identity. The genesis entry has a 32-byte
 * zero `previousEntryId` and null signatures; it is authenticated by a pin on its EntryID, never by signatures.
 *
 * Mirrors bft-go-base `types.RootTrustBaseV2` (ristik fork, bft-go-base#2): decoding is strict (exact tag, version and arity, canonical encoding
 * only, bounded sizes) and witness signatures follow the strict 65-byte recoverable rule.
 */
export class RootTrustBaseV2 {
  public static readonly ID_LENGTH = 32;
  /** The admitted committee size: entries with more members are never stored (bft-core utb.MaxMembers). */
  public static readonly MAX_ADMITTED_MEMBERS = 16;
  /** Largest encoded entry accepted anywhere (bft-core utbstore / GetTrustBase). */
  public static readonly MAX_ENCODED_LENGTH = 64 * 1024;
  /** Member-list bound while decoding; deployments admit far fewer (see {@link MAX_ADMITTED_MEMBERS}). */
  public static readonly MAX_MEMBERS = 256;
  public static readonly MAX_NODE_ID_LENGTH = 128;
  public static readonly MAX_WEIGHT = 1n << 40n;
  public static readonly TAG = 39000n;
  public static readonly VERSION = 2n;

  private constructor(
    public readonly networkId: number,
    public readonly epoch: bigint,
    public readonly epochStartRound: bigint,
    private readonly _rootNodes: readonly IRootTrustBaseV2Member[],
    public readonly quorumThreshold: bigint,
    private readonly _stateHash: Uint8Array | null,
    private readonly _changeRecordHash: Uint8Array | null,
    private readonly _previousEntryId: Uint8Array | null,
    private readonly _signatures: ReadonlyMap<string, Uint8Array> | null,
  ) {}

  /** @returns {Uint8Array|null} Copy of the change-record hash (null or 32 bytes). */
  public get changeRecordHash(): Uint8Array | null {
    return this._changeRecordHash ? new Uint8Array(this._changeRecordHash) : null;
  }

  /** @returns {boolean} True when the predecessor id is 32 zero bytes. */
  public get isGenesis(): boolean {
    return (
      this._previousEntryId !== null &&
      this._previousEntryId.length === RootTrustBaseV2.ID_LENGTH &&
      this._previousEntryId.every((b) => b === 0)
    );
  }

  /** @returns {Uint8Array} Copy of the predecessor's EntryID (32 zero bytes for the genesis entry). */
  public get previousEntryId(): Uint8Array {
    return new Uint8Array(this._previousEntryId ?? []);
  }

  /** @returns {IRootTrustBaseV2Member[]} Copy of the members, sorted by node identifier. */
  public get rootNodes(): IRootTrustBaseV2Member[] {
    return this._rootNodes.map((m) => ({
      nodeId: m.nodeId,
      signingKey: new Uint8Array(m.signingKey),
      weight: m.weight,
    }));
  }

  /** @returns {Map<string, Uint8Array>|null} Copy of the witness signatures (null for the genesis entry). */
  public get signatures(): Map<string, Uint8Array> | null {
    if (this._signatures === null) {
      return null;
    }
    return new Map([...this._signatures].map(([id, sig]) => [id, new Uint8Array(sig)]));
  }

  /** @returns {Uint8Array|null} Copy of the state hash (null or 32 bytes). */
  public get stateHash(): Uint8Array | null {
    return this._stateHash ? new Uint8Array(this._stateHash) : null;
  }

  /** @returns {bigint} Total weight of the committee. */
  public get totalWeight(): bigint {
    return this._rootNodes.reduce((sum, m) => sum + m.weight, 0n);
  }

  /**
   * Build an unsigned entry. Members are sorted by node identifier; the threshold is the caller's and is checked by {@link validate}.
   *
   * @param {object} fields Entry fields.
   * @param {number} fields.networkId Network identifier.
   * @param {bigint} fields.epoch Epoch number.
   * @param {bigint} fields.epochStartRound First root round of the epoch.
   * @param {IRootTrustBaseV2Member[]} fields.rootNodes Members.
   * @param {bigint} fields.quorumThreshold Threshold, floor(2W/3)+1.
   * @param {Uint8Array|null} fields.stateHash State hash (null or 32 bytes).
   * @param {Uint8Array|null} fields.changeRecordHash Change-record hash (null or 32 bytes).
   * @param {Uint8Array} fields.previousEntryId Predecessor EntryID (32 zero bytes for a genesis entry).
   * @returns {RootTrustBaseV2} The unsigned entry, shape-checked (sign it with {@link withSignatures} unless it is a genesis entry).
   * @throws {TrustBaseError} `invalid` for a structure rule.
   */
  public static create(fields: {
    readonly changeRecordHash: Uint8Array | null;
    readonly epoch: bigint;
    readonly epochStartRound: bigint;
    readonly networkId: number;
    readonly previousEntryId: Uint8Array;
    readonly quorumThreshold: bigint;
    readonly rootNodes: readonly IRootTrustBaseV2Member[];
    readonly stateHash: Uint8Array | null;
  }): RootTrustBaseV2 {
    const nodes = fields.rootNodes
      .map((m) => ({ nodeId: m.nodeId, signingKey: new Uint8Array(m.signingKey), weight: m.weight }))
      .sort((a, b) => compareUint8Arrays(TEXT_ENCODER.encode(a.nodeId), TEXT_ENCODER.encode(b.nodeId)));
    const entry = new RootTrustBaseV2(
      fields.networkId,
      fields.epoch,
      fields.epochStartRound,
      nodes,
      fields.quorumThreshold,
      absentAsNull(fields.stateHash),
      absentAsNull(fields.changeRecordHash),
      new Uint8Array(fields.previousEntryId),
      null,
    );
    entry.validateShape();
    return entry;
  }

  /**
   * Strictly decode a tagged version-2 entry and check its structure ({@link validate}); signatures are not verified.
   *
   * @param {Uint8Array} bytes Tagged CBOR.
   * @returns {RootTrustBaseV2} The entry.
   * @throws {TrustBaseError} `malformed` for anything but the canonical encoding of a well-formed entry, `invalid` for a structure rule.
   */
  public static fromCBOR(bytes: Uint8Array): RootTrustBaseV2 {
    let entry: RootTrustBaseV2;
    try {
      if (bytes.length > RootTrustBaseV2.MAX_ENCODED_LENGTH) {
        throw new Error(`${bytes.length} bytes exceed ${RootTrustBaseV2.MAX_ENCODED_LENGTH}`);
      }
      const tagged = CborDeserializer.decodeTag(bytes);
      if (tagged.tag !== RootTrustBaseV2.TAG) {
        throw new Error(`tag ${tagged.tag}, expected ${RootTrustBaseV2.TAG}`);
      }
      const data = CborDeserializer.decodeArray(tagged.data, 10);
      const version = CborDeserializer.decodeUnsignedInteger(data[0]);
      if (version !== RootTrustBaseV2.VERSION) {
        throw new Error(`version ${version}, expected ${RootTrustBaseV2.VERSION}`);
      }
      const networkId = CborDeserializer.decodeUnsignedInteger(data[1]);
      if (networkId > 0xffffn) {
        throw new Error(`network ${networkId}`);
      }
      const nodes = CborDeserializer.decodeArray(data[4]);
      if (nodes.length > RootTrustBaseV2.MAX_MEMBERS) {
        throw new Error(`${nodes.length} members exceed ${RootTrustBaseV2.MAX_MEMBERS}`);
      }
      const signatures = CborDeserializer.decodeNullable(data[9], (map) => {
        const entries = CborDeserializer.decodeMap(map);
        if (entries.length > RootTrustBaseV2.MAX_MEMBERS) {
          throw new Error(`${entries.length} signatures exceed ${RootTrustBaseV2.MAX_MEMBERS}`);
        }
        return new Map(entries.map((e) => [decodeText(e.key), CborDeserializer.decodeByteString(e.value)]));
      });
      entry = new RootTrustBaseV2(
        Number(networkId),
        CborDeserializer.decodeUnsignedInteger(data[2]),
        CborDeserializer.decodeUnsignedInteger(data[3]),
        nodes.map((node) => {
          const [nodeId, key, weight] = CborDeserializer.decodeArray(node, 3);
          return {
            nodeId: decodeText(nodeId),
            signingKey: CborDeserializer.decodeByteString(key),
            weight: CborDeserializer.decodeUnsignedInteger(weight),
          };
        }),
        CborDeserializer.decodeUnsignedInteger(data[5]),
        CborDeserializer.decodeNullable(data[6], decodePresentHash),
        CborDeserializer.decodeNullable(data[7], decodePresentHash),
        CborDeserializer.decodeNullable(data[8], CborDeserializer.decodeByteString),
        signatures,
      );
    } catch (error) {
      throw new TrustBaseError('malformed', `Not a trust base v2 entry: ${message(error)}.`, { cause: error });
    }
    if (!areUint8ArraysEqual(entry.toCBOR(), bytes)) {
      throw new TrustBaseError('malformed', 'Not the deterministic encoding of a trust base v2 entry.');
    }
    entry.validate();
    return entry;
  }

  /**
   * The version-2 genesis entry of an on-disk (JSON, version 1) genesis trust base, as bft-core derives it (`utb.BuildUnsigned(nil,
   * utb.FromProjection(v1))`): the same network, epoch, start, members, weights and threshold, a zero predecessor and no signatures. The V1 signatures
   * are ignored: the genesis is authenticated by the pin on the returned entry's EntryID. Empty state and change-record hashes become CBOR null, the
   * one byte form of an absent hash.
   *
   * @param {RootTrustBase} legacy The JSON genesis trust base.
   * @returns {RootTrustBaseV2} The unsigned genesis entry.
   * @throws {TrustBaseError} `invalid` when the result breaks a version-2 rule (for example a threshold other than floor(2W/3)+1).
   */
  public static genesisFromLegacy(legacy: RootTrustBase): RootTrustBaseV2 {
    return RootTrustBaseV2.create({
      changeRecordHash: legacy.changeRecordHash,
      epoch: legacy.epoch,
      epochStartRound: legacy.epochStartRound,
      networkId: legacy.networkId.id,
      previousEntryId: new Uint8Array(RootTrustBaseV2.ID_LENGTH),
      quorumThreshold: legacy.quorumThreshold,
      rootNodes: [...legacy.rootNodes.values()].map((n) => ({
        nodeId: n.nodeId,
        signingKey: n.signingKey,
        weight: n.stakedAmount,
      })),
      stateHash: legacy.stateHash,
    });
  }

  /**
   * @returns {Promise<Uint8Array>} The EntryID, SHA-256 of {@link sigBytes}: independent of the signatures.
   */
  public async entryId(): Promise<Uint8Array> {
    return (await this.sigBytesHash()).data;
  }

  /**
   * @returns {Uint8Array} The signed preimage: the encoding with the signature field as CBOR null (not removed from the array).
   */
  public sigBytes(): Uint8Array {
    return this.encode(null);
  }

  /**
   * @returns {Uint8Array} The tagged deterministic CBOR encoding.
   */
  public toCBOR(): Uint8Array {
    return this.encode(this._signatures);
  }

  /**
   * {@link validateShape} plus the witness rule: the genesis carries null signatures, every other entry a non-empty signature map.
   *
   * @throws {TrustBaseError} `invalid` for the first violated rule.
   */
  public validate(): void {
    this.validateShape();
    if (this.isGenesis) {
      if (this._signatures !== null) {
        throw new TrustBaseError('invalid', 'Invalid trust base v2 entry: the genesis entry carries signatures.');
      }
    } else if (this._signatures === null || this._signatures.size === 0) {
      throw new TrustBaseError('invalid', 'Invalid trust base v2 entry: a non-genesis entry has no signatures.');
    }
  }

  /**
   * Check the entry's shape, without the witness rule (an unsigned entry passes, as bft-core `utbentry.ValidateShape`): epoch ≥ 1, members (sorted by
   * raw node-identifier bytes, unique, valid compressed keys, unique keys, positive bounded weights, bounded count), the exact threshold
   * floor(2W/3)+1, hash lengths and a 32-byte predecessor id.
   *
   * @throws {TrustBaseError} `invalid` for the first violated rule.
   */
  public validateShape(): void {
    const bad = (text: string): TrustBaseError =>
      new TrustBaseError('invalid', `Invalid trust base v2 entry: ${text}.`);
    if (this.epoch === 0n) {
      throw bad('epoch is zero');
    }
    const n = this._rootNodes.length;
    if (n === 0 || n > RootTrustBaseV2.MAX_MEMBERS) {
      throw bad(`${n} members (1..${RootTrustBaseV2.MAX_MEMBERS})`);
    }
    let total = 0n;
    const keys = new Set<string>();
    let previous: Uint8Array | null = null;
    for (const m of this._rootNodes) {
      const id = TEXT_ENCODER.encode(m.nodeId);
      if (id.length === 0 || id.length > RootTrustBaseV2.MAX_NODE_ID_LENGTH) {
        throw bad('a node identifier is empty or too long');
      }
      if (previous !== null && compareUint8Arrays(previous, id) >= 0) {
        throw bad(`members are not strictly sorted by node identifier at "${m.nodeId}"`);
      }
      previous = id;
      if (m.weight === 0n || m.weight > RootTrustBaseV2.MAX_WEIGHT) {
        throw bad(`member "${m.nodeId}" weight ${m.weight} outside 1..${RootTrustBaseV2.MAX_WEIGHT}`);
      }
      if (!isCompressedKey(m.signingKey)) {
        throw bad(`member "${m.nodeId}" signing key is not a compressed secp256k1 point`);
      }
      const key = Array.from(m.signingKey).join(',');
      if (keys.has(key)) {
        throw bad(`member "${m.nodeId}" shares a signing key`);
      }
      keys.add(key);
      total += m.weight;
    }
    if (this.quorumThreshold !== (total * 2n) / 3n + 1n) {
      throw bad(
        `quorum threshold ${this.quorumThreshold}, expected ${(total * 2n) / 3n + 1n} for total weight ${total}`,
      );
    }
    for (const [name, hash] of [
      ['state hash', this._stateHash],
      ['change record hash', this._changeRecordHash],
    ] as const) {
      if (hash !== null && hash.length !== 0 && hash.length !== RootTrustBaseV2.ID_LENGTH) {
        throw bad(`${name} is ${hash.length} bytes (null or ${RootTrustBaseV2.ID_LENGTH})`);
      }
    }
    if (this._previousEntryId === null || this._previousEntryId.length !== RootTrustBaseV2.ID_LENGTH) {
      throw bad('previous entry id is not 32 bytes');
    }
  }

  /**
   * Check the entry as the genesis: its structure and a zero predecessor. Its authority is a pin on its EntryID, which the caller compares.
   *
   * @throws {TrustBaseError} `invalid` or `genesis`.
   */
  public verifyGenesis(): void {
    this.validate();
    if (!this.isGenesis) {
      throw new TrustBaseError('genesis', 'Not a genesis entry.');
    }
  }

  /**
   * Check signatures by this entry's members, strictly: every supplied signature must be from a member and valid (an unknown or invalid extra fails
   * even when the rest reach quorum), and the signers' weight must reach the threshold. A signature is exactly 65 bytes `r‖s‖v`, `1 ≤ r,s < n`,
   * low-S, `v` in 0..3, and the key it recovers must be the member's key.
   *
   * @param {DataHash} hash SHA-256 of the signed bytes.
   * @param {ReadonlyMap<string, Uint8Array>} signatures Node identifier → signature.
   * @throws {TrustBaseError} `invalid`.
   */
  public async verifyQuorumSignatures(hash: DataHash, signatures: ReadonlyMap<string, Uint8Array>): Promise<void> {
    let weight = 0n;
    for (const [nodeId, bytes] of signatures) {
      const member = this._rootNodes.find((m) => m.nodeId === nodeId);
      if (!member) {
        throw new TrustBaseError(
          'invalid',
          `Trust base v2 signature check failed: signer "${nodeId}" is not a member.`,
        );
      }
      let signature: Signature;
      try {
        signature = Signature.decode(bytes);
      } catch (error) {
        throw new TrustBaseError(
          'invalid',
          `Trust base v2 signature check failed: signer "${nodeId}": ${message(error)}`,
          {
            cause: error,
          },
        );
      }
      if (!(await VERIFIER.verify(hash, signature, member.signingKey))) {
        throw new TrustBaseError(
          'invalid',
          `Trust base v2 signature check failed: signer "${nodeId}": verification failed.`,
        );
      }
      weight += member.weight;
    }
    if (weight < this.quorumThreshold) {
      throw new TrustBaseError(
        'invalid',
        `Trust base v2 signature check failed: quorum not reached, signed weight ${weight}, threshold ${this.quorumThreshold}.`,
      );
    }
  }

  /**
   * Check that this entry extends `previous`: valid structure, not a genesis, the same network, epoch previous+1, a later start round, the
   * predecessor's EntryID, and a strict quorum of the predecessor's members signing {@link sigBytes}.
   *
   * @param {RootTrustBaseV2} previous The authenticated predecessor.
   * @throws {TrustBaseError} `invalid`.
   */
  public async verifySuccessor(previous: RootTrustBaseV2): Promise<void> {
    this.validate();
    const chain = (text: string): TrustBaseError =>
      new TrustBaseError('invalid', `Trust base v2 entry does not extend the predecessor: ${text}.`);
    if (this.isGenesis) {
      throw chain('a genesis entry has no predecessor');
    }
    if (this.networkId !== previous.networkId) {
      throw chain(`network ${this.networkId}, predecessor ${previous.networkId}`);
    }
    if (this.epoch !== previous.epoch + 1n) {
      throw chain(`epoch ${this.epoch}, predecessor ${previous.epoch}`);
    }
    if (this.epochStartRound <= previous.epochStartRound) {
      throw chain(`epoch start ${this.epochStartRound}, predecessor ${previous.epochStartRound}`);
    }
    if (!areUint8ArraysEqual(this._previousEntryId, await previous.entryId())) {
      throw chain('previous entry id does not match');
    }
    await previous.verifyQuorumSignatures(await this.sigBytesHash(), this._signatures ?? new Map());
  }

  /**
   * @param {ReadonlyMap<string, Uint8Array>|null} signatures Witness signatures.
   * @returns {RootTrustBaseV2} This entry with the given signature field.
   */
  public withSignatures(signatures: ReadonlyMap<string, Uint8Array> | null): RootTrustBaseV2 {
    return new RootTrustBaseV2(
      this.networkId,
      this.epoch,
      this.epochStartRound,
      this._rootNodes,
      this.quorumThreshold,
      this._stateHash,
      this._changeRecordHash,
      this._previousEntryId,
      signatures ? new Map([...signatures].map(([id, sig]) => [id, new Uint8Array(sig)])) : null,
    );
  }

  private encode(signatures: ReadonlyMap<string, Uint8Array> | null): Uint8Array {
    return CborSerializer.encodeTag(
      RootTrustBaseV2.TAG,
      CborSerializer.encodeArray(
        CborSerializer.encodeUnsignedInteger(RootTrustBaseV2.VERSION),
        CborSerializer.encodeUnsignedInteger(this.networkId),
        CborSerializer.encodeUnsignedInteger(this.epoch),
        CborSerializer.encodeUnsignedInteger(this.epochStartRound),
        CborSerializer.encodeArray(
          ...this._rootNodes.map((m) =>
            CborSerializer.encodeArray(
              CborSerializer.encodeTextString(m.nodeId),
              CborSerializer.encodeByteString(m.signingKey),
              CborSerializer.encodeUnsignedInteger(m.weight),
            ),
          ),
        ),
        CborSerializer.encodeUnsignedInteger(this.quorumThreshold),
        CborSerializer.encodeNullable(absentAsNull(this._stateHash), CborSerializer.encodeByteString),
        CborSerializer.encodeNullable(absentAsNull(this._changeRecordHash), CborSerializer.encodeByteString),
        CborSerializer.encodeNullable(this._previousEntryId, CborSerializer.encodeByteString),
        CborSerializer.encodeNullable(signatures, (map) =>
          CborSerializer.encodeMap(
            new CborMap(
              [...map].map(
                ([id, sig]) =>
                  new CborMapEntry(CborSerializer.encodeTextString(id), CborSerializer.encodeByteString(sig)),
              ),
            ),
          ),
        ),
      ),
    );
  }

  private sigBytesHash(): Promise<DataHash> {
    return new DataHasher(HashAlgorithm.SHA256).update(this.sigBytes()).digest();
  }
}

function decodeText(data: Uint8Array): string {
  const reader = new CborReader(data);
  const length = reader.readLength(MajorType.TEXT_STRING);
  if (length > BigInt(RootTrustBaseV2.MAX_NODE_ID_LENGTH)) {
    throw new Error(`text of ${length} bytes`);
  }
  const text = TEXT_DECODER.decode(reader.read(Number(length)));
  reader.assertExhausted();
  return text;
}

/** An absent hash has one byte form, CBOR null: a present hash must not be an empty byte string (bft-go-base#3). */
function decodePresentHash(data: Uint8Array): Uint8Array {
  const hash = CborDeserializer.decodeByteString(data);
  if (hash.length === 0) {
    throw new Error('an absent hash is null, not an empty byte string');
  }
  return hash;
}

/** The canonical absent hash is null: an empty value is held (and encoded) as null, so both give the same bytes and EntryID. */
function absentAsNull(hash: Uint8Array | null): Uint8Array | null {
  return hash && hash.length > 0 ? new Uint8Array(hash) : null;
}

function isCompressedKey(key: Uint8Array): boolean {
  if (key.length !== 33 || (key[0] !== 0x02 && key[0] !== 0x03)) {
    return false;
  }
  try {
    secp256k1.Point.fromBytes(key);
    return true;
  } catch {
    return false;
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
