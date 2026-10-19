import { IRequestOptions } from './IRequestOptions.js';

/**
 * Where newer Unicity Trust Base entries are fetched from (the aggregator's `GET /api/v1/trustbases`, a mirror, a test double). The source is
 * untrusted transport: it returns the encoded GetTrustBase response (tag 39015) and the caller decodes it with the page limits and appends every
 * entry through `TrustBaseHistory.append`, which authenticates it from the latest held entry.
 */
export interface ITrustBaseSource {
  /**
   * @param {bigint} fromEpoch First epoch wanted: always the latest held epoch + 1.
   * @param {number} maxEntries Most entries wanted in this response.
   * @param {IRequestOptions} [options] Request options.
   * @returns {Promise<Uint8Array>} The encoded response (tag 39015).
   */
  getTrustBaseEntries(fromEpoch: bigint, maxEntries: number, options?: IRequestOptions): Promise<Uint8Array>;
}
