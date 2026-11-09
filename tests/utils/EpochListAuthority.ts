import { ITrustBaseHistory } from '../../src/api/bft/trustbase/ITrustBaseHistory.js';
import { RootTrustBaseV2 } from '../../src/api/bft/trustbase/RootTrustBaseV2.js';
import { NetworkId } from '../../src/api/NetworkId.js';
import { HexConverter } from '../../src/util/HexConverter.js';

/** One epoch of a test authority: the committee and its round interval, as the B1 seal corpus lists them. */
export interface ITestEpoch {
  readonly end: bigint | number | null;
  readonly epoch: bigint | number;
  readonly members: readonly { readonly key: string; readonly nodeId: string; readonly weight: bigint | number }[];
  readonly start: bigint | number;
  readonly threshold: bigint | number;
}

/**
 * A trust-base history built directly from committees, for verifier tests whose vectors list committees rather than signed entries (the B1 corpus
 * states the registry, not a signed history): the entries are plain records with the fields verification reads, not chain-checked. Production code
 * uses `TrustBaseHistory` / `TrustBaseSession`.
 */
export class EpochListAuthority implements ITrustBaseHistory {
  public readonly entries: RootTrustBaseV2[];

  public constructor(
    public readonly networkId: NetworkId,
    private readonly epochs: readonly ITestEpoch[],
  ) {
    this.entries = [...epochs]
      .sort((a, b) => (BigInt(a.epoch) < BigInt(b.epoch) ? -1 : 1))
      .map((e) => {
        const members = e.members.map((m) => ({
          nodeId: m.nodeId,
          sigKey: HexConverter.decode(m.key),
          weight: BigInt(m.weight),
        }));
        return {
          // content-addressed like an entry encoding: memo keys must change when the committee does
          encode: (): Uint8Array =>
            new TextEncoder().encode(
              JSON.stringify([
                String(e.epoch),
                String(e.start),
                String(e.threshold),
                e.members.map((m) => [m.nodeId, m.key, String(m.weight)]),
              ]),
            ),
          epoch: BigInt(e.epoch),
          epochStartRound: BigInt(e.start),
          members,
          networkId,
          quorumThreshold: BigInt(e.threshold),
        } as unknown as RootTrustBaseV2;
      });
  }

  public get genesisPin(): Uint8Array {
    return new Uint8Array(32);
  }

  public get isEmpty(): boolean {
    return this.entries.length === 0;
  }

  public get tip(): RootTrustBaseV2 | null {
    return this.entries[this.entries.length - 1] ?? null;
  }

  public entryForEpoch(epoch: bigint): RootTrustBaseV2 | null {
    return this.entries.find((e) => e.epoch === epoch) ?? null;
  }

  public epochEndRound(epoch: bigint): bigint | null {
    const listed = this.epochs.find((e) => BigInt(e.epoch) === epoch);
    return listed === undefined || listed.end === null ? null : BigInt(listed.end);
  }
}
