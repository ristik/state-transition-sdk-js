import { RootTrustBaseV2 } from '../../src/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseResponse, TrustBaseResponseStatus } from '../../src/api/bft/trustbase/TrustBaseResponse.js';
import { IRequestOptions } from '../../src/api/IRequestOptions.js';
import { ITrustBaseSource } from '../../src/api/ITrustBaseSource.js';
import { CborSerializer } from '../../src/serialization/cbor/CborSerializer.js';

/** Encode a GetTrustBase response page (tag 39015) as the aggregator does. */
export async function encodeTrustBasePage(
  network: number,
  status: TrustBaseResponseStatus,
  fromEpoch: bigint,
  entries: readonly Uint8Array[],
  effectiveEnd: bigint,
  nextEpoch: bigint | null = null,
  endEntry: Uint8Array | null = entries.length ? entries[entries.length - 1] : null,
): Promise<Uint8Array> {
  // the EntryID of `effectiveEnd`, as the server freezes it (also on a partial page)
  const endId = endEntry ? await RootTrustBaseV2.fromCBOR(endEntry).entryId() : null;
  return CborSerializer.encodeTag(
    TrustBaseResponse.TAG,
    CborSerializer.encodeArray(
      CborSerializer.encodeUnsignedInteger(1n),
      CborSerializer.encodeUnsignedInteger(network),
      CborSerializer.encodeUnsignedInteger(status),
      CborSerializer.encodeUnsignedInteger(fromEpoch),
      CborSerializer.encodeUnsignedInteger(effectiveEnd),
      CborSerializer.encodeNullable(endId, CborSerializer.encodeByteString),
      CborSerializer.encodeArray(...entries),
      CborSerializer.encodeNullable(nextEpoch, CborSerializer.encodeUnsignedInteger),
    ),
  );
}

/**
 * An in-memory trust-base source over a list of signed entries (epoch → canonical bytes): it serves the entries from `from` up to `available`, at
 * most `maxEntries`, with a cursor when more remain, and `NotYetAvailable` when it has nothing at or after `from`. Records every request.
 */
export class StaticTrustBaseSource implements ITrustBaseSource {
  public available: bigint;
  public readonly calls: { fromEpoch: bigint; maxEntries: number }[] = [];
  /** Replace the next responses (in order) with these bytes. */
  public readonly overrides: Uint8Array[] = [];

  public constructor(
    private readonly network: number,
    private readonly entries: ReadonlyMap<bigint, Uint8Array>,
    available?: bigint,
  ) {
    this.available = available ?? [...entries.keys()].reduce((a, b) => (b > a ? b : a), 0n);
  }

  public async getTrustBaseEntries(
    fromEpoch: bigint,
    maxEntries: number,
    options?: IRequestOptions,
  ): Promise<Uint8Array> {
    options?.signal?.throwIfAborted();
    this.calls.push({ fromEpoch, maxEntries });
    const override = this.overrides.shift();
    if (override) {
      return override;
    }
    if (fromEpoch > this.available) {
      return await encodeTrustBasePage(
        this.network,
        TrustBaseResponseStatus.NOT_YET_AVAILABLE,
        fromEpoch,
        [],
        this.available,
        null,
        this.entries.get(this.available) ?? null,
      );
    }
    const page: Uint8Array[] = [];
    let epoch = fromEpoch;
    for (; epoch <= this.available && page.length < maxEntries; epoch++) {
      page.push(this.entries.get(epoch)!);
    }
    return await encodeTrustBasePage(
      this.network,
      TrustBaseResponseStatus.OK,
      fromEpoch,
      page,
      this.available,
      epoch <= this.available ? epoch : null,
      this.entries.get(this.available),
    );
  }
}
