import { ShardId } from './ShardId.js';
import { CborDeserializer } from '../../serialization/cbor/CborDeserializer.js';
import { CborError } from '../../serialization/cbor/CborError.js';
import { CborSerializer } from '../../serialization/cbor/CborSerializer.js';
import { HexConverter } from '../../util/HexConverter.js';
import { dedent } from '../../util/StringUtils.js';

/**
 * Shard tree certificate.
 */
export class ShardTreeCertificate {
  public static readonly CBOR_TAG = 39003n;
  private static readonly VERSION = 1n;

  /**
   * @param {ShardId} _shard Shard.
   * @param {Uint8Array[]} _siblingHashList Sibling hashes, one per shard bit.
   * @param {boolean} [nullList] The (empty) list was encoded as CBOR null, as Go encodes a nil slice; kept so the bytes round-trip.
   */
  public constructor(
    private readonly _shard: ShardId,
    private readonly _siblingHashList: Uint8Array[],
    private readonly nullList: boolean = false,
  ) {
    this.nullList = nullList && _siblingHashList.length === 0;
    this._siblingHashList = _siblingHashList.map((hash) => new Uint8Array(hash));
  }

  /**
   * Get the shard.
   */
  public get shard(): ShardId {
    return this._shard;
  }

  /**
   * Get the sibling hash list.
   */
  public get siblingHashList(): Uint8Array[] {
    return this._siblingHashList.map((hash) => new Uint8Array(hash));
  }

  /**
   * @returns {bigint} Wire-format version of this certificate.
   */
  public get version(): bigint {
    return ShardTreeCertificate.VERSION;
  }

  /**
   * Create shard tree certificate from CBOR bytes.
   *
   * @param bytes CBOR bytes
   * @return shard tree certificate
   */
  public static fromCBOR(bytes: Uint8Array): ShardTreeCertificate {
    const tag = CborDeserializer.decodeTag(bytes);
    if (tag.tag !== ShardTreeCertificate.CBOR_TAG) {
      throw new CborError(`Invalid CBOR tag for ShardTreeCertificate: ${tag.tag}`);
    }

    const data = CborDeserializer.decodeArray(tag.data, 3);
    const version = CborDeserializer.decodeUnsignedInteger(data[0]);
    if (version !== ShardTreeCertificate.VERSION) {
      throw new CborError(`Unsupported ShardTreeCertificate version: ${version}`);
    }

    return new ShardTreeCertificate(
      ShardId.decode(CborDeserializer.decodeByteString(data[1])),
      (CborDeserializer.decodeNullable(data[2], (list) => CborDeserializer.decodeArray(list)) ?? []).map((hash) =>
        CborDeserializer.decodeByteString(hash),
      ),
      CborDeserializer.decodeNullable(data[2], () => false) === null,
    );
  }

  /**
   * Convert shard tree certificate to CBOR bytes.
   *
   * @return CBOR bytes
   */
  public toCBOR(): Uint8Array {
    return CborSerializer.encodeTag(
      ShardTreeCertificate.CBOR_TAG,
      CborSerializer.encodeArray(
        CborSerializer.encodeUnsignedInteger(this.version),
        CborSerializer.encodeByteString(this._shard.encode()),
        this.nullList
          ? CborSerializer.encodeNull()
          : CborSerializer.encodeArray(...this._siblingHashList.map((hash) => CborSerializer.encodeByteString(hash))),
      ),
    );
  }

  /**
   * Returns a string representation of the ShardTreeCertificate.
   * @returns The string representation.
   */
  public toString(): string {
    return dedent`
      Shard Tree Certificate
        Shard: ${this._shard.toString()}
        Sibling Hash List: [
          ${this._siblingHashList.map((hash) => HexConverter.encode(hash)).join('\n')}
        ]`;
  }
}
