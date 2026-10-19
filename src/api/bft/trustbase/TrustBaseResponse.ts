import { RootTrustBaseV2 } from './RootTrustBaseV2.js';
import { TrustBaseError } from './TrustBaseError.js';
import { CborDeserializer } from '../../../serialization/cbor/CborDeserializer.js';
import { CborSerializer } from '../../../serialization/cbor/CborSerializer.js';
import { areUint8ArraysEqual } from '../../../util/TypedArrayUtils.js';

/** Status of a GetTrustBase response. */
export enum TrustBaseResponseStatus {
  OK = 0,
  INVALID_REQUEST = 1,
  WRONG_NETWORK = 2,
  NOT_YET_AVAILABLE = 3,
  HISTORY_MISMATCH = 4,
  LIMIT_TOO_SMALL = 5,
  BUSY = 6,
  UNAVAILABLE = 7,
}

/** Bounds of one response decode; `maxBytes` is checked before anything is decoded. */
export interface ITrustBaseResponseLimits {
  readonly maxBytes: number;
  readonly maxEntries: number;
}

/**
 * The GetTrustBase response, which is also the release bundle format: tag 39015 (provisional; bft-core `gettrustbase.ResponseTag`),
 * `[version=1, network, status, fromEpoch, effectiveEnd, endEntryId | null, [entry…], nextEpoch | null]`, entries embedded verbatim as their canonical
 * tagged bytes.
 *
 * Mirrors bft-core `gettrustbase.Response`, `DecodeResponse` and `DecodeBundle`.
 */
export class TrustBaseResponse {
  /** Peer page caps (bft-core `gettrustbase.PageLimits`). */
  public static readonly PAGE_LIMITS: ITrustBaseResponseLimits = { maxBytes: 1 << 20, maxEntries: 64 };
  /** Provisional tag, as bft-core `gettrustbase.ResponseTag`. */
  public static readonly TAG = 39015n;
  public static readonly VERSION = 1n;

  private constructor(
    public readonly networkId: number,
    public readonly status: TrustBaseResponseStatus,
    public readonly fromEpoch: bigint,
    public readonly effectiveEnd: bigint,
    private readonly _endEntryId: Uint8Array | null,
    private readonly _rawEntries: readonly Uint8Array[],
    public readonly nextEpoch: bigint | null,
    public readonly entries: readonly RootTrustBaseV2[],
  ) {}

  /** @returns {Uint8Array|null} Copy of the EntryID of `effectiveEnd`. */
  public get endEntryId(): Uint8Array | null {
    return this._endEntryId ? new Uint8Array(this._endEntryId) : null;
  }

  /** @returns {Uint8Array[]} Copies of the entries' canonical bytes. */
  public get rawEntries(): Uint8Array[] {
    return this._rawEntries.map((e) => new Uint8Array(e));
  }

  /**
   * Strictly decode a complete bundle: status OK, starting at a genesis entry, no cursor, consecutive entries linked by predecessor EntryID up to
   * `effectiveEnd` with the matching end id, nothing after. Structure and links only; see {@link verifyBundle} for the signatures.
   *
   * @param {Uint8Array} bytes Tagged CBOR.
   * @param {ITrustBaseResponseLimits} limits File budget (not the page caps).
   * @returns {Promise<TrustBaseResponse>} The bundle.
   * @throws {TrustBaseError} `malformed` or `bundle`.
   */
  public static async decodeBundle(bytes: Uint8Array, limits: ITrustBaseResponseLimits): Promise<TrustBaseResponse> {
    const response = await TrustBaseResponse.fromCBOR(bytes, limits);
    if (response.status !== TrustBaseResponseStatus.OK) {
      throw new TrustBaseError(
        'bundle',
        `Not a complete trust-base bundle: status ${TrustBaseResponseStatus[response.status]}.`,
      );
    }
    if (response.nextEpoch !== null) {
      throw new TrustBaseError('bundle', 'Not a complete trust-base bundle: a continuation cursor.');
    }
    if (!response.entries[0].isGenesis) {
      throw new TrustBaseError(
        'bundle',
        `Not a complete trust-base bundle: epoch ${response.entries[0].epoch} is not a genesis entry (a partial range).`,
      );
    }
    return response;
  }

  /**
   * Encode the complete history (ascending from the genesis) as a release bundle, after checking it with the same decoder that loads it.
   *
   * @param {Uint8Array[]} rawEntries Canonical entry bytes, the genesis first.
   * @returns {Promise<Uint8Array>} The bundle.
   * @throws {TrustBaseError} `bundle` or `malformed` for a gap, duplicate or broken link.
   */
  public static async encodeBundle(rawEntries: readonly Uint8Array[]): Promise<Uint8Array> {
    if (rawEntries.length === 0) {
      throw new TrustBaseError('bundle', 'Not a complete trust-base bundle: no entries.');
    }
    const first = RootTrustBaseV2.fromCBOR(rawEntries[0]);
    const last = RootTrustBaseV2.fromCBOR(rawEntries[rawEntries.length - 1]);
    const bytes = new TrustBaseResponse(
      first.networkId,
      TrustBaseResponseStatus.OK,
      first.epoch,
      last.epoch,
      await last.entryId(),
      rawEntries,
      null,
      [],
    ).toCBOR();
    await TrustBaseResponse.decodeBundle(bytes, { maxBytes: bytes.length, maxEntries: rawEntries.length });
    return bytes;
  }

  /**
   * Strictly decode a response and check its internal consistency: status and cursor rules, and for an OK page a contiguous ascending run of
   * structurally valid entries of the response's network, linked by predecessor EntryID, ending at `effectiveEnd` when no cursor remains.
   * Signatures are not verified here; the history verifies each entry when it is appended.
   *
   * @param {Uint8Array} bytes Tagged CBOR.
   * @param {ITrustBaseResponseLimits} limits Bounds.
   * @returns {Promise<TrustBaseResponse>} The response.
   * @throws {TrustBaseError} `malformed`.
   */
  public static async fromCBOR(
    bytes: Uint8Array,
    limits: ITrustBaseResponseLimits = TrustBaseResponse.PAGE_LIMITS,
  ): Promise<TrustBaseResponse> {
    const malformed = (text: string, cause?: unknown): TrustBaseError =>
      new TrustBaseError('malformed', `Invalid trust-base response: ${text}.`, { cause });
    if (limits.maxBytes <= 0 || bytes.length > limits.maxBytes) {
      throw malformed(`${bytes.length} bytes exceed ${limits.maxBytes}`);
    }
    let response: TrustBaseResponse;
    try {
      const tagged = CborDeserializer.decodeTag(bytes);
      if (tagged.tag !== TrustBaseResponse.TAG) {
        throw new Error(`tag ${tagged.tag}, expected ${TrustBaseResponse.TAG}`);
      }
      const data = CborDeserializer.decodeArray(tagged.data, 8);
      const version = CborDeserializer.decodeUnsignedInteger(data[0]);
      if (version !== TrustBaseResponse.VERSION) {
        throw new Error(`version ${version}`);
      }
      const network = CborDeserializer.decodeUnsignedInteger(data[1]);
      if (network > 0xffffn) {
        throw new Error(`network ${network}`);
      }
      const status = CborDeserializer.decodeUnsignedInteger(data[2]);
      if (status > BigInt(TrustBaseResponseStatus.UNAVAILABLE)) {
        throw new Error(`status ${status}`);
      }
      const entries = CborDeserializer.decodeArray(data[6]);
      if (entries.length > limits.maxEntries) {
        throw new Error(`${entries.length} entries exceed ${limits.maxEntries}`);
      }
      const endEntryId = CborDeserializer.decodeNullable(data[5], CborDeserializer.decodeByteString);
      if (endEntryId !== null && endEntryId.length !== RootTrustBaseV2.ID_LENGTH) {
        throw new Error(`end id of ${endEntryId.length} bytes`);
      }
      response = new TrustBaseResponse(
        Number(network),
        Number(status),
        CborDeserializer.decodeUnsignedInteger(data[3]),
        CborDeserializer.decodeUnsignedInteger(data[4]),
        endEntryId,
        entries,
        CborDeserializer.decodeNullable(data[7], CborDeserializer.decodeUnsignedInteger),
        [],
      );
    } catch (error) {
      throw malformed(error instanceof Error ? error.message : String(error), error);
    }
    if (!areUint8ArraysEqual(response.toCBOR(), bytes)) {
      throw malformed('not the deterministic encoding');
    }
    if (response.status !== TrustBaseResponseStatus.OK) {
      if (response._rawEntries.length !== 0 || response.nextEpoch !== null) {
        throw malformed(`status ${TrustBaseResponseStatus[response.status]} carries entries or a cursor`);
      }
      return response;
    }
    return response.withEntries(await TrustBaseResponse.checkPage(response));
  }

  /**
   * The offline bundle check: the genesis must be the pinned identity and every later entry must carry a strict quorum of its predecessor's members.
   *
   * @param {TrustBaseResponse} bundle A decoded bundle.
   * @param {Uint8Array} pin The genesis EntryID.
   * @throws {TrustBaseError} `genesis` or `invalid`.
   */
  public static async verifyBundle(bundle: TrustBaseResponse, pin: Uint8Array): Promise<void> {
    const genesis = bundle.entries[0];
    genesis.verifyGenesis();
    if (!areUint8ArraysEqual(await genesis.entryId(), pin)) {
      throw new TrustBaseError('genesis', 'The bundle genesis is not the pinned identity.');
    }
    for (let i = 1; i < bundle.entries.length; i++) {
      const entry = bundle.entries[i];
      if (entry.rootNodes.length > RootTrustBaseV2.MAX_ADMITTED_MEMBERS) {
        throw new TrustBaseError('invalid', `Epoch ${entry.epoch} has ${entry.rootNodes.length} members.`);
      }
      await entry.verifySuccessor(bundle.entries[i - 1]);
    }
  }

  private static async checkPage(response: TrustBaseResponse): Promise<RootTrustBaseV2[]> {
    const malformed = (text: string, cause?: unknown): TrustBaseError =>
      new TrustBaseError('malformed', `Invalid trust-base response: ${text}.`, { cause });
    if (response._rawEntries.length === 0) {
      throw malformed('an OK response without entries');
    }
    if (response._endEntryId === null) {
      throw malformed('no end entry id');
    }
    const out: RootTrustBaseV2[] = [];
    let previousId: Uint8Array = new Uint8Array(RootTrustBaseV2.ID_LENGTH);
    for (const [i, raw] of response._rawEntries.entries()) {
      let entry: RootTrustBaseV2;
      try {
        entry = RootTrustBaseV2.fromCBOR(raw);
      } catch (error) {
        throw malformed(`entry ${i}: ${error instanceof Error ? error.message : String(error)}`, error);
      }
      if (entry.networkId !== response.networkId) {
        throw malformed(`entry ${i} of network ${entry.networkId} in a response for ${response.networkId}`);
      }
      if (i === 0 && entry.epoch !== response.fromEpoch) {
        throw malformed(`first entry is epoch ${entry.epoch}, page starts at ${response.fromEpoch}`);
      }
      if (i > 0) {
        if (entry.epoch !== out[i - 1].epoch + 1n) {
          throw malformed(`epoch ${entry.epoch} does not follow ${out[i - 1].epoch}`);
        }
        if (!areUint8ArraysEqual(entry.previousEntryId, previousId)) {
          throw malformed(`epoch ${entry.epoch} does not link to its predecessor`);
        }
      }
      previousId = await entry.entryId();
      out.push(entry);
    }
    const last = out[out.length - 1].epoch;
    if (response.nextEpoch === null && last !== response.effectiveEnd) {
      throw malformed(`page ends at ${last} without a cursor before the effective end ${response.effectiveEnd}`);
    }
    if (
      response.nextEpoch !== null &&
      (response.nextEpoch !== last + 1n || response.nextEpoch > response.effectiveEnd)
    ) {
      throw malformed(`cursor ${response.nextEpoch} after epoch ${last} (end ${response.effectiveEnd})`);
    }
    if (last === response.effectiveEnd && !areUint8ArraysEqual(response._endEntryId, previousId)) {
      throw malformed('end entry id differs from the last entry');
    }
    return out;
  }

  /**
   * @returns {Uint8Array} The tagged deterministic CBOR encoding.
   */
  public toCBOR(): Uint8Array {
    return CborSerializer.encodeTag(
      TrustBaseResponse.TAG,
      CborSerializer.encodeArray(
        CborSerializer.encodeUnsignedInteger(TrustBaseResponse.VERSION),
        CborSerializer.encodeUnsignedInteger(this.networkId),
        CborSerializer.encodeUnsignedInteger(this.status),
        CborSerializer.encodeUnsignedInteger(this.fromEpoch),
        CborSerializer.encodeUnsignedInteger(this.effectiveEnd),
        CborSerializer.encodeNullable(this._endEntryId, CborSerializer.encodeByteString),
        CborSerializer.encodeArray(...this._rawEntries),
        CborSerializer.encodeNullable(this.nextEpoch, CborSerializer.encodeUnsignedInteger),
      ),
    );
  }

  private withEntries(entries: RootTrustBaseV2[]): TrustBaseResponse {
    return new TrustBaseResponse(
      this.networkId,
      this.status,
      this.fromEpoch,
      this.effectiveEnd,
      this._endEntryId,
      this._rawEntries,
      this.nextEpoch,
      entries,
    );
  }
}
