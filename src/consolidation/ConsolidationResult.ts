import type { Token } from '../transaction/Token.js';

/**
 * Stable reason why the service cannot provide the proof material. The original token is intact and no claim is made
 * about its validity.
 *
 * - `unsupported_capability`: the endpoint (or client) has no batch proof method.
 * - `unsupported_configuration`: the endpoint serves it but not for this configuration (e.g. parent/child mode).
 * - `pending_publication`: the master view does not cover the history yet (it is older than the original proofs, or
 *   no finalized view exists). A later attempt may succeed.
 * - `target_not_retained`: a required view or state is not (or no longer) retained by a shard; a later attempt
 *   against a fresh latest view may succeed, the same root cannot be repaired by waiting.
 * - `partition_view_unavailable`: the master served no partition view.
 * - `busy`: the service is under pressure.
 * - `limit_exceeded`: the token needs more states per shard than one batch carries (no chunking is attempted).
 */
export type ProofUnavailableReason =
  | 'busy'
  | 'limit_exceeded'
  | 'partition_view_unavailable'
  | 'pending_publication'
  | 'target_not_retained'
  | 'unsupported_capability'
  | 'unsupported_configuration';

/**
 * Diagnostics of a successful consolidation (optional reading for advanced users and tests).
 */
export interface IProofSummary {
  /** True when the outer proofs already shared one seal and the token was returned without any network request. */
  readonly alreadyConsolidated: boolean;
  /** Distinct complete seals among the returned token's outer proofs (1 when consolidated). */
  readonly consolidatedSeals: number;
  /** Quorum checks spent authenticating the original outer proofs. */
  readonly evidenceQuorumChecks: number;
  /** Root chain round of the master seal. */
  readonly masterRound: bigint;
  /** Bit string of the master shard. */
  readonly masterShard: string;
  /** Distinct complete seals among the original outer proofs. */
  readonly originalSeals: number;
  /** Number of replaceable proofs in the outer history (genesis and every transfer). */
  readonly outerProofs: number;
  /** Quorum signature checks of the master seal and the consolidated outer history. */
  readonly quorumChecks: number;
  /** HTTP requests made (m, in two waves; one when m is 1). */
  readonly requests: number;
  /** Highest root chain round among the original proofs (R_min). */
  readonly requiredRound: bigint;
  /** Shards that took part. */
  readonly shards: number;
}

/**
 * Outcome of {@link TokenProofClient.consolidate}. Cancellation, deadline, transport, server, response and integrity
 * failures are thrown as {@link ConsolidationError}, never reported as `unavailable`.
 */
export type ConsolidationResult =
  | { readonly status: 'consolidated'; readonly summary: IProofSummary; readonly token: Token }
  | {
      readonly detail?: string;
      readonly reason: ProofUnavailableReason;
      readonly retryable: boolean;
      readonly status: 'unavailable';
    };
