import { NetworkId } from '../../NetworkId.js';

/** One member of an epoch committee. */
export interface IEpochCommitteeMember {
  /** Compressed secp256k1 signing key. */
  readonly signingKey: Uint8Array;
  /** Voting weight. */
  readonly weight: bigint;
}

/**
 * The root committee of one epoch as a verifier uses it: who may sign the epoch's seals, with which weight and threshold, and for which root rounds.
 */
export interface IEpochCommittee {
  /** First root round after the epoch: the next held epoch's start, or null while this is the newest held epoch (it accepts every later round). */
  readonly end: bigint | null;
  readonly epoch: bigint;
  /** Identity of the committee record (the EntryID, hex): part of every memo key derived from its verdicts. */
  readonly id: string;
  /** Node identifier → member. */
  readonly members: ReadonlyMap<string, IEpochCommitteeMember>;
  readonly networkId: NetworkId;
  /** First root round of the epoch. */
  readonly start: bigint;
  /** Weight the signers must reach, floor(2W/3)+1. */
  readonly threshold: bigint;
}

/**
 * The trusted authority a unicity certificate is verified against: the held Unicity Trust Base history (see `TrustBaseHistory`). A seal is checked
 * against the committee of its own epoch, within that epoch's round interval; an epoch newer than the latest held one is reported as missing (fetch
 * the newer entries and retry), never as invalid.
 */
export interface ITrustBaseAuthority {
  /** The first held epoch; seals of earlier epochs are invalid. */
  readonly genesisEpoch: bigint;
  /** Identity of the held history (network, genesis and latest EntryID): part of every cache and session key. */
  readonly identity: string;
  readonly networkId: NetworkId;
  /** The latest held epoch. */
  readonly tipEpoch: bigint;

  /**
   * @param {bigint} epoch Epoch.
   * @returns {IEpochCommittee|null} The committee of a held epoch, or null.
   */
  committee(epoch: bigint): IEpochCommittee | null;

  /**
   * @returns {ITrustBaseAuthority} An immutable view of the current state: later appends do not change it.
   */
  snapshot(): ITrustBaseAuthority;
}
