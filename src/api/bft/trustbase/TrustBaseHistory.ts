import { RootTrustBaseV2 } from './RootTrustBaseV2.js';
import { TrustBaseError } from './TrustBaseError.js';
import { ITrustBaseResponseLimits, TrustBaseResponse } from './TrustBaseResponse.js';
import { areUint8ArraysEqual } from '../../../util/TypedArrayUtils.js';

/** The latest held entry. */
export interface ITrustBaseTip {
  readonly entryId: Uint8Array;
  readonly epoch: bigint;
}

/** Budget for loading a shipped bundle (a release artifact, not a network page). */
export const DEFAULT_BUNDLE_LIMITS: ITrustBaseResponseLimits = { maxBytes: 64 << 20, maxEntries: 1 << 16 };

/**
 * The held Unicity Trust Base history: every entry from the pinned genesis forward, append-only.
 *
 * The latest held entry is effectively the pin (owner §29): a release ships the complete history known at release time, and every later entry is
 * verified from the latest held one and then anchors the next. {@link append} is the single way in, with exactly the rules of bft-core `utbstore`:
 *
 * - the next epoch is verified strictly from the held predecessor ({@link RootTrustBaseV2.verifySuccessor}) and the admitted member limit;
 * - an entry of a held epoch with the same unsigned bytes (same EntryID) and a valid witness is a no-op that keeps the held bytes; a different valid
 *   signature subset is not a fork;
 * - an entry of a held epoch with different unsigned bytes is a `conflict`; held entries are never replaced;
 * - an entry that does not directly follow the tip is a `gap`; nothing is skipped.
 */
export class TrustBaseHistory {
  private readonly entries: RootTrustBaseV2[];
  private readonly ids: Uint8Array[];
  private readonly raw: Uint8Array[];
  /** Serialises every mutation: each append runs its check, verification and push without another one interleaving at an `await`. */
  private writes: Promise<unknown> = Promise.resolve();

  private constructor(genesis: RootTrustBaseV2, genesisRaw: Uint8Array, genesisId: Uint8Array) {
    this.entries = [genesis];
    this.raw = [genesisRaw];
    this.ids = [genesisId];
  }

  /** @returns {bigint} The genesis epoch. */
  public get genesisEpoch(): bigint {
    return this.entries[0].epoch;
  }

  /** @returns {number} The network identifier. */
  public get networkId(): number {
    return this.entries[0].networkId;
  }

  /** @returns {ITrustBaseTip} The latest held entry. */
  public get tip(): ITrustBaseTip {
    const last = this.entries.length - 1;
    return { entryId: new Uint8Array(this.ids[last]), epoch: this.entries[last].epoch };
  }

  /**
   * A history loaded from a shipped bundle (tag 39015): the bundle's genesis must be the pinned one and every entry is appended through
   * {@link append}.
   *
   * @param {Uint8Array} bundle The bundle bytes.
   * @param {Uint8Array} pin The genesis EntryID.
   * @param {ITrustBaseResponseLimits} limits File budget.
   * @returns {Promise<TrustBaseHistory>} The history.
   * @throws {TrustBaseError} The first refusal.
   */
  public static async fromBundle(
    bundle: Uint8Array,
    pin: Uint8Array,
    limits: ITrustBaseResponseLimits = DEFAULT_BUNDLE_LIMITS,
  ): Promise<TrustBaseHistory> {
    const decoded = await TrustBaseResponse.decodeBundle(bundle, limits);
    const raw = decoded.rawEntries;
    const history = await TrustBaseHistory.fromGenesis(raw[0], pin);
    await history.installBundle(decoded);
    return history;
  }

  /**
   * A history holding the pinned genesis alone.
   *
   * @param {Uint8Array} genesis Canonical bytes of the genesis entry.
   * @param {Uint8Array} pin Its EntryID, the deployment's authenticated genesis identity.
   * @returns {Promise<TrustBaseHistory>} The history.
   * @throws {TrustBaseError} `malformed`, `invalid` or `genesis`.
   */
  public static async fromGenesis(genesis: Uint8Array, pin: Uint8Array): Promise<TrustBaseHistory> {
    const entry = RootTrustBaseV2.fromCBOR(genesis);
    entry.verifyGenesis();
    if (entry.rootNodes.length > RootTrustBaseV2.MAX_ADMITTED_MEMBERS) {
      throw new TrustBaseError('genesis', `The genesis has ${entry.rootNodes.length} members.`);
    }
    const id = await entry.entryId();
    if (!areUint8ArraysEqual(id, pin)) {
      throw new TrustBaseError('genesis', 'The genesis entry does not match the pin.');
    }
    return new TrustBaseHistory(entry, new Uint8Array(genesis), id);
  }

  /**
   * Append one entry given as its canonical bytes. Appends are serialised: concurrent calls (a piggybacked entry and a fetch, or two
   * verifications that both miss an epoch) take effect one after another, so an epoch is never stored twice.
   *
   * @param {Uint8Array} bytes Tagged entry.
   * @returns {Promise<boolean>} True when the entry was new; false for a no-op replay of a held entry.
   * @throws {TrustBaseError} `malformed` or `invalid` (refused), `gap`, or `conflict`.
   */
  public append(bytes: Uint8Array): Promise<boolean> {
    return this.exclusive(() => this.appendExclusive(bytes));
  }

  /**
   * @param {bigint} epoch Epoch.
   * @returns {Uint8Array|null} The held canonical bytes of the epoch (a replay with another witness never replaces them), or null.
   */
  public bytes(epoch: bigint): Uint8Array | null {
    const index = epoch - this.genesisEpoch;
    return index >= 0n && index < BigInt(this.raw.length) ? new Uint8Array(this.raw[Number(index)]) : null;
  }

  /**
   * @param {bigint} epoch Epoch.
   * @returns {RootTrustBaseV2|null} The held entry of the epoch, or null when it is not held.
   */
  public entry(epoch: bigint): RootTrustBaseV2 | null {
    const index = epoch - this.genesisEpoch;
    return index >= 0n && index < BigInt(this.entries.length) ? this.entries[Number(index)] : null;
  }

  /**
   * @returns {Promise<Uint8Array>} The whole held history as one bundle (tag 39015), to persist or ship.
   */
  public exportBundle(): Promise<Uint8Array> {
    return TrustBaseResponse.encodeBundle(this.raw);
  }

  /**
   * Append the entries of a decoded bundle (or page) in order, as one serialised mutation (no other append interleaves); a refusal leaves the
   * history at the last good entry. An older bundle neither truncates nor rolls back the history.
   *
   * @param {TrustBaseResponse} bundle Decoded bundle or OK page.
   * @returns {Promise<number>} The number of new entries.
   * @throws {TrustBaseError} The first refusal.
   */
  public installBundle(bundle: TrustBaseResponse): Promise<number> {
    return this.exclusive(async () => {
      let added = 0;
      for (const raw of bundle.rawEntries) {
        if (await this.appendExclusive(raw)) {
          added++;
        }
      }
      return added;
    });
  }

  /** {@link append} while holding the write chain. */
  private async appendExclusive(bytes: Uint8Array): Promise<boolean> {
    const entry = RootTrustBaseV2.fromCBOR(bytes);
    const first = this.genesisEpoch;
    const tip = this.entries[this.entries.length - 1];
    if (entry.epoch < first) {
      throw new TrustBaseError('gap', `Epoch ${entry.epoch} precedes the genesis ${first}.`);
    }
    if (entry.epoch <= tip.epoch) {
      const index = Number(entry.epoch - first);
      if (!areUint8ArraysEqual(await entry.entryId(), this.ids[index])) {
        throw new TrustBaseError(
          'conflict',
          `An entry of epoch ${entry.epoch} with different unsigned bytes is already held.`,
        );
      }
      if (index === 0) {
        // the genesis is authenticated by the pin; it has no witness
        if (entry.signatures !== null) {
          throw new TrustBaseError('invalid', 'A genesis entry carrying signatures.');
        }
        return false;
      }
      // the supplied witness must itself be valid; the first held witness is kept
      await entry.verifySuccessor(this.entries[index - 1]);
      return false;
    }
    if (entry.epoch !== tip.epoch + 1n) {
      throw new TrustBaseError('gap', `Epoch ${entry.epoch} does not directly follow the held tip ${tip.epoch}.`);
    }
    if (entry.rootNodes.length > RootTrustBaseV2.MAX_ADMITTED_MEMBERS) {
      throw new TrustBaseError('invalid', `Epoch ${entry.epoch} has ${entry.rootNodes.length} members.`);
    }
    await entry.verifySuccessor(tip);
    // everything awaited before the first mutation: the three lists change together or not at all
    const id = await entry.entryId();
    this.entries.push(entry);
    this.raw.push(new Uint8Array(bytes));
    this.ids.push(id);
    return true;
  }

  /**
   * Run a mutation after every earlier one has settled, whatever its outcome.
   *
   * @param {Function} task The mutation.
   * @returns {Promise<T>} Its result.
   */
  private exclusive<T>(task: () => Promise<T>): Promise<T> {
    const run = this.writes.then(task, task);
    this.writes = run.catch(() => undefined);
    return run;
  }
}
