import { RootTrustBaseV2 } from './RootTrustBaseV2.js';
import { TrustBaseBundleError, TrustBaseEncodingError } from './TrustBaseError.js';
import { CborDeserializer } from '../../../serialization/cbor/CborDeserializer.js';
import { areUint8ArraysEqual } from '../../../util/TypedArrayUtils.js';
import { NetworkId } from '../../NetworkId.js';

/**
 * Budget of a bundle decode; a release supplies it, there is no fixed history length. `maxBytes` is checked before anything is read. `maxEntries`
 * is checked after the entry list has been split (the CBOR reader walks the array before the count is known), so what bounds that allocation is
 * the input size, `maxBytes`, not `maxEntries`.
 */
export interface ITrustBaseBundleLimits {
  readonly maxBytes: number;
  readonly maxEntries: number;
}

/**
 * A complete Unicity Trust Base release bundle: the GetTrustBase response (CBOR tag 39015) with status OK, starting at the genesis entry, ending
 * at the release tip, with no continuation cursor. The reference is bft-core `gettrustbase.DecodeBundle`.
 *
 * Wire form: tag 39015 over `[1, networkId, 0, fromEpoch, effectiveEnd, endEntryId, [entry...], null]`, each entry a complete tag-39000
 * {@link RootTrustBaseV2}, consecutive and ascending from the genesis, each linked to its predecessor by entry id. A one-entry bundle holds a
 * genesis entry only.
 *
 * Decoding checks the structure and the links, not the signatures: the history that installs the bundle authenticates every entry after the
 * genesis, and the genesis against a pinned entry id.
 */
export class TrustBaseBundle {
  public static readonly CBOR_TAG = 39015n;
  /** Bound of one embedded entry in bytes. */
  public static readonly MAX_ENTRY_BYTES = 64 * 1024;
  public static readonly VERSION = 1n;
  /** Number of defined response statuses; the response carries the status of a refused request, a bundle never does. */
  private static readonly STATUS_COUNT = 8n;
  private static readonly STATUS_OK = 0n;

  private constructor(
    public readonly networkId: NetworkId,
    private readonly _entries: RootTrustBaseV2[],
    private readonly _raw: Uint8Array[],
  ) {}

  /** @returns {RootTrustBaseV2[]} The entries, ascending from the genesis. */
  public get entries(): RootTrustBaseV2[] {
    return [...this._entries];
  }

  /** @returns {Uint8Array[]} Copies of the canonical bytes of each entry, ascending from the genesis. */
  public get raw(): Uint8Array[] {
    return this._raw.map((bytes) => new Uint8Array(bytes));
  }

  /** @returns {RootTrustBaseV2} The release tip, the last entry. */
  public get tip(): RootTrustBaseV2 {
    return this._entries[this._entries.length - 1];
  }

  /**
   * Strictly decode a complete bundle.
   *
   * @param {Uint8Array} bytes Tagged bundle.
   * @param {ITrustBaseBundleLimits} limits Size budget, checked before allocation.
   * @returns {Promise<TrustBaseBundle>} Decoded bundle.
   * @throws {TrustBaseEncodingError} If the bytes (or an entry) are not the deterministic encoding, or exceed the budget.
   * @throws {TrustBaseInvalidError} If an embedded entry fails a structure rule.
   * @throws {TrustBaseBundleError} If the response is not a complete, linked history from a genesis entry.
   */
  public static async decode(bytes: Uint8Array, limits: ITrustBaseBundleLimits): Promise<TrustBaseBundle> {
    if (bytes.length > limits.maxBytes) {
      throw new TrustBaseEncodingError(`${bytes.length} bytes exceed the budget of ${limits.maxBytes}.`);
    }

    const header = TrustBaseBundle.parse(bytes, limits.maxEntries);

    if (header.status !== TrustBaseBundle.STATUS_OK) {
      throw new TrustBaseBundleError(`Status ${header.status}: not a complete bundle.`);
    }
    if (header.nextEpoch !== null) {
      throw new TrustBaseBundleError('A continuation cursor: not a complete bundle.');
    }
    if (header.entries.length === 0) {
      throw new TrustBaseBundleError('An OK response without entries.');
    }
    if (header.endEntryId === null) {
      throw new TrustBaseBundleError('No end entry id.');
    }

    const entries: RootTrustBaseV2[] = [];
    let previousId: Uint8Array | null = null;
    for (const [index, raw] of header.entries.entries()) {
      if (raw.length > TrustBaseBundle.MAX_ENTRY_BYTES) {
        throw new TrustBaseEncodingError(`Entry ${index} of ${raw.length} bytes.`);
      }

      const entry = RootTrustBaseV2.decode(raw);
      if (entry.networkId.id !== header.network) {
        throw new TrustBaseBundleError(
          `Entry ${index} of network ${entry.networkId.id} in a bundle for ${header.network}.`,
        );
      }

      const previous: RootTrustBaseV2 | undefined = entries[index - 1];
      if (previous === undefined) {
        if (!entry.isGenesis()) {
          throw new TrustBaseBundleError(`Epoch ${entry.epoch} is not a genesis entry (a partial range).`);
        }
        if (entry.epoch !== header.fromEpoch) {
          throw new TrustBaseBundleError(
            `First entry is epoch ${entry.epoch}, the bundle starts at ${header.fromEpoch}.`,
          );
        }
      } else {
        if (entry.epoch !== previous.epoch + 1n) {
          throw new TrustBaseBundleError(`Epoch ${entry.epoch} does not follow ${previous.epoch}.`);
        }
        if (previousId === null || !areUint8ArraysEqual(entry.previousEntryId, previousId)) {
          throw new TrustBaseBundleError(`Epoch ${entry.epoch} does not link to its predecessor.`);
        }
      }

      previousId = await entry.entryId();
      entries.push(entry);
    }

    const tip = entries[entries.length - 1];
    if (tip.epoch !== header.effectiveEnd) {
      throw new TrustBaseBundleError(`The bundle ends at epoch ${tip.epoch}, its header says ${header.effectiveEnd}.`);
    }
    if (previousId === null || !areUint8ArraysEqual(header.endEntryId, previousId)) {
      throw new TrustBaseBundleError('The end entry id differs from the last entry.');
    }

    return new TrustBaseBundle(entries[0].networkId, entries, header.entries);
  }

  private static parse(
    bytes: Uint8Array,
    maxEntries: number,
  ): {
    effectiveEnd: bigint;
    endEntryId: Uint8Array | null;
    entries: Uint8Array[];
    fromEpoch: bigint;
    network: number;
    nextEpoch: bigint | null;
    status: bigint;
  } {
    try {
      const tagged = CborDeserializer.decodeTag(bytes);
      if (tagged.tag !== TrustBaseBundle.CBOR_TAG) {
        throw new TrustBaseEncodingError(`Tag ${tagged.tag}, expected ${TrustBaseBundle.CBOR_TAG}.`);
      }

      const fields = CborDeserializer.decodeArray(tagged.data);
      if (fields.length !== 8) {
        throw new TrustBaseEncodingError(`Expected 8 fields, got ${fields.length}.`);
      }

      const uint64 = (data: Uint8Array): bigint => {
        return CborDeserializer.decodeUnsignedInteger(data);
      };

      const version = uint64(fields[0]);
      if (version !== TrustBaseBundle.VERSION) {
        throw new TrustBaseEncodingError(`Version ${version}, expected ${TrustBaseBundle.VERSION}.`);
      }
      const network = uint64(fields[1]);
      // A header network of 0 is not refused here: no entry has network 0 (validate), so the entries cannot match it and the bundle is refused as such.
      if (network > 0xffffn) {
        throw new TrustBaseEncodingError(`Network identifier ${network} above 65535.`);
      }
      const status = uint64(fields[2]);
      if (status >= TrustBaseBundle.STATUS_COUNT) {
        throw new TrustBaseEncodingError(`Status ${status} is not defined.`);
      }
      const endEntryId = CborDeserializer.decodeNullable(fields[5], (item) => CborDeserializer.decodeByteString(item));
      if (endEntryId !== null && endEntryId.length !== RootTrustBaseV2.ID_LENGTH) {
        throw new TrustBaseEncodingError(`End id of ${endEntryId.length} bytes.`);
      }
      const entries = CborDeserializer.decodeArray(fields[6]);
      if (entries.length > maxEntries) {
        throw new TrustBaseEncodingError(`${entries.length} entries exceed ${maxEntries}.`);
      }
      const nextEpoch = CborDeserializer.decodeNullable(fields[7], uint64);

      return {
        effectiveEnd: uint64(fields[4]),
        endEntryId,
        entries,
        fromEpoch: uint64(fields[3]),
        network: Number(network),
        nextEpoch,
        status,
      };
    } catch (error) {
      if (error instanceof TrustBaseEncodingError) {
        throw error;
      }
      throw new TrustBaseEncodingError(error instanceof Error ? error.message : String(error));
    }
  }
}
