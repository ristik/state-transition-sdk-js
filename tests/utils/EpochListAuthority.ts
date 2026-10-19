import { RootTrustBase } from '../../src/api/bft/RootTrustBase.js';
import { IEpochCommittee, ITrustBaseAuthority } from '../../src/api/bft/trustbase/TrustBaseAuthority.js';
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
 * A trust-base authority built directly from committees, for verifier tests whose vectors list committees rather than signed entries (the B1
 * corpus states the registry, not a signed history). Production code uses `TrustBaseHistory`.
 */
export class EpochListAuthority implements ITrustBaseAuthority {
  private readonly committees: Map<bigint, IEpochCommittee>;

  public constructor(
    public readonly networkId: NetworkId,
    epochs: readonly ITestEpoch[],
  ) {
    this.committees = new Map(
      epochs.map((e) => [
        BigInt(e.epoch),
        {
          end: e.end === null ? null : BigInt(e.end),
          epoch: BigInt(e.epoch),
          // content-addressed like an EntryID: memo keys must change when the committee does
          id: JSON.stringify([
            String(e.epoch),
            String(e.start),
            String(e.threshold),
            e.members.map((m) => [m.nodeId, m.key, String(m.weight)]),
          ]),
          members: new Map(
            e.members.map((m) => [m.nodeId, { signingKey: HexConverter.decode(m.key), weight: BigInt(m.weight) }]),
          ),
          networkId,
          start: BigInt(e.start),
          threshold: BigInt(e.threshold),
        },
      ]),
    );
  }

  public get genesisEpoch(): bigint {
    return [...this.committees.keys()].reduce((a, b) => (b < a ? b : a));
  }

  public get identity(): string {
    return JSON.stringify([
      this.networkId.id,
      [...this.committees.values()].map((c) => [c.id, c.end?.toString() ?? null]),
    ]);
  }

  public get tipEpoch(): bigint {
    return [...this.committees.keys()].reduce((a, b) => (b > a ? b : a));
  }

  public committee(epoch: bigint): IEpochCommittee | null {
    return this.committees.get(epoch) ?? null;
  }

  public snapshot(): ITrustBaseAuthority {
    return this;
  }
}

/**
 * The single committee of a legacy (JSON, version 1) trust base as a test authority: its epoch from its start round, open-ended. For unit tests
 * whose vectors carry a version-1 trust base; applications load a JSON genesis through `RootTrustBaseV2.genesisFromLegacy` into a
 * `TrustBaseHistory`.
 *
 * @param {RootTrustBase} legacy Version-1 trust base.
 * @returns {ITrustBaseAuthority} The authority.
 */
export function legacyAuthority(legacy: RootTrustBase): ITrustBaseAuthority {
  return new EpochListAuthority(legacy.networkId, [
    {
      end: null,
      epoch: legacy.epoch,
      members: [...legacy.rootNodes.entries()].map(([nodeId, node]) => ({
        key: HexConverter.encode(node.signingKey),
        nodeId,
        weight: node.stakedAmount,
      })),
      start: legacy.epochStartRound,
      threshold: legacy.quorumThreshold,
    },
  ]);
}
