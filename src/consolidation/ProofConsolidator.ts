import { ConsolidationError, ConsolidationOutcome } from './ConsolidationError.js';
import { ProofUnavailableReason } from './ConsolidationResult.js';
import { IShardEndpoint, ShardRouting } from './ShardRouting.js';
import { BatchProofError } from '../api/BatchProofError.js';
import { PartitionViewAuthenticator } from '../api/bft/AuthenticatedPartitionView.js';
import { PartitionView } from '../api/bft/PartitionView.js';
import { PartitionViewError } from '../api/bft/PartitionViewError.js';
import { ShardId } from '../api/bft/ShardId.js';
import { UnicityCertificate } from '../api/bft/UnicityCertificate.js';
import { UnicitySealHashMatchesWithRootHashRule } from '../api/bft/verification/rule/UnicitySealHashMatchesWithRootHashRule.js';
import { SealVerificationSession } from '../api/bft/verification/SealVerificationSession.js';
import { CertificationData } from '../api/CertificationData.js';
import { IBatchRequestOptions, InclusionProofBatch, isBatchAggregatorClient } from '../api/IBatchAggregatorClient.js';
import { InclusionProof } from '../api/InclusionProof.js';
import { InclusionProofResponse } from '../api/InclusionProofResponse.js';
import { calculateLeafValue } from '../api/LeafValue.js';
import { NetworkId } from '../api/NetworkId.js';
import { StateId } from '../api/StateId.js';
import { DataHash } from '../crypto/hash/DataHash.js';
import { HashAlgorithm } from '../crypto/hash/HashAlgorithm.js';
import { areUint8ArraysEqual } from '../util/TypedArrayUtils.js';
import { VerificationStatus } from '../verification/VerificationStatus.js';

/**
 * One original outer-history proof: the signed certification data and the proof that certified it.
 */
export interface IConsolidationItem {
  readonly certificationData: CertificationData;
  readonly proof: InclusionProof;
}

/**
 * Options of one consolidation attempt.
 */
export interface IConsolidationOptions {
  /** Master shard to use instead of the shard of the newest original proof; it must take part. */
  readonly master?: ShardId;
  /** Upper bound on concurrent exact-root requests of the second wave. Default 4. */
  readonly maxParallel?: number;
  /** Aborts the attempt and every outstanding request. */
  readonly signal?: AbortSignal;
  /** Total deadline of the attempt in milliseconds. Default 10 000. */
  readonly timeoutMs?: number;
}

/**
 * Work counters of an attempt. `quorumChecks` is the master seal's quorum check (the seal checks of the original
 * proofs are reported separately).
 */
export interface IConsolidationCounters {
  readonly bodyChecks: number;
  readonly evidenceQuorumChecks: number;
  readonly leafChecks: number;
  readonly quorumChecks: number;
}

/**
 * Proofs rebuilt under one master seal.
 */
export interface IConsolidatedProofs {
  readonly counters: IConsolidationCounters;
  /** Root chain round of the master seal. */
  readonly masterRound: bigint;
  readonly masterShard: ShardId;
  /** Requests made and request waves (one wave when a single shard takes part, otherwise two). */
  readonly requests: number;
  /** Highest root chain round among the original proofs (R_min). */
  readonly requiredRound: bigint;
  /** Replacement proofs in input order: original certification data and reference time, new unicity certificate. */
  readonly responses: readonly InclusionProofResponse[];
  readonly shards: number;
  readonly waves: number;
}

/**
 * Result of one attempt: rebuilt proofs, or an explicit unavailable outcome of the service.
 */
export type ConsolidationAttempt =
  | ({ readonly status: 'consolidated' } & IConsolidatedProofs)
  | {
      readonly detail?: string;
      readonly reason: ProofUnavailableReason;
      readonly retryable: boolean;
      readonly status: 'unavailable';
    };

/** Service outcome that ends the attempt as `unavailable`, internal control flow. */
class Unavailable extends Error {
  public constructor(
    public readonly reason: ProofUnavailableReason,
    public readonly retryable: boolean,
    public readonly detail?: string,
  ) {
    super(reason);
  }
}

interface IGroup {
  readonly endpoint: IShardEndpoint;
  readonly indexes: number[];
}

interface IShardBatch {
  readonly batch: InclusionProofBatch;
  readonly group: IGroup;
}

/** One attempt's deadline and cancellation. */
class AttemptClock {
  public readonly controller = new AbortController();
  private expired = false;
  private readonly onAbort: () => void;
  private readonly timer: ReturnType<typeof setTimeout>;

  public constructor(
    timeoutMs: number,
    private readonly external?: AbortSignal,
  ) {
    this.timer = setTimeout(() => {
      this.expired = true;
      this.controller.abort();
    }, timeoutMs);
    this.onAbort = (): void => this.controller.abort();
    if (external?.aborted) {
      this.controller.abort();
    }
    external?.addEventListener('abort', this.onAbort, { once: true });
  }

  public get signal(): AbortSignal {
    return this.controller.signal;
  }

  public dispose(): void {
    clearTimeout(this.timer);
    this.external?.removeEventListener('abort', this.onAbort);
  }

  /**
   * @returns {ConsolidationError|null} The typed deadline or cancellation error once the attempt is done.
   */
  public done(): ConsolidationError | null {
    if (this.expired) {
      return new ConsolidationError('timeout', 'The attempt deadline expired.', { retryable: true });
    }
    if (this.controller.signal.aborted || this.external?.aborted) {
      return new ConsolidationError('cancelled', 'The attempt was cancelled.');
    }
    return null;
  }

  public throwIfDone(): void {
    const error = this.done();
    if (error) {
      throw error;
    }
  }
}

function isAbort(e: unknown): boolean {
  // by name, not by class: abort reasons come from the platform's realm
  return typeof e === 'object' && e !== null && 'name' in e && (e.name === 'AbortError' || e.name === 'TimeoutError');
}

function integrity(
  outcome: ConsolidationOutcome,
  message: string,
  shard?: ShardId,
  cause?: unknown,
): ConsolidationError {
  return new ConsolidationError('integrity', message, { cause, outcome, shard: shard?.toString() });
}

function viewFailure(e: unknown, shard: ShardId): unknown {
  if (e instanceof PartitionViewError) {
    return integrity(e.reason === 'seal_invalid' ? 'unauthenticated' : 'invalid_input', e.message, shard, e);
  }
  return e;
}

/**
 * Master-first consolidation of original outer-history proofs into proofs under one master seal.
 *
 * One attempt: authenticate the original proofs and derive R_min (the highest root round among them); one `latest`
 * batch from the master shard, whose partition view is authenticated under the anchored authority (network, exact
 * epoch, round at least the epoch start, quorum) and must be at least R_min; then one exact-root batch per other
 * participating shard, bounded parallel, at the roots the authenticated view commits to. Every output certificate is
 * derived from the authenticated view and carries the identical master seal; every proof is checked against its
 * original input. One total deadline governs the attempt and the abort signal reaches every request. There is no
 * retry, no chunking, no chase of newer seals, and nothing is ever submitted.
 */
export class ProofConsolidator {
  public static readonly DEFAULT_MAX_PARALLEL = 4;
  public static readonly DEFAULT_TIMEOUT_MS = 10_000;

  /**
   * @param {ShardRouting} routing Trusted routing of the partition.
   * @param {SealVerificationSession} session Operation scoped seal authentication, anchored to the trusted authority.
   */
  public constructor(
    private readonly routing: ShardRouting,
    private readonly session: SealVerificationSession,
  ) {}

  private static requestFailure(e: unknown, shard: ShardId, role: 'master' | 'peer', clock: AttemptClock): unknown {
    const done = clock.done();
    if (done && (isAbort(e) || !(e instanceof ConsolidationError))) {
      return done;
    }
    if (e instanceof ConsolidationError || e instanceof Unavailable) {
      return e;
    }
    const bits = shard.toString();
    if (!(e instanceof BatchProofError)) {
      return isAbort(e)
        ? new ConsolidationError('cancelled', 'The request was aborted.', { cause: e, shard: bits })
        : new ConsolidationError('transport', e instanceof Error ? e.message : String(e), {
            cause: e,
            retryable: true,
            shard: bits,
          });
    }
    const info = { cause: e, detail: e.detail, shard: bits };
    switch (e.kind) {
      case 'unavailable': {
        const detail = e.detail ?? '';
        if (detail.startsWith('busy')) {
          return new Unavailable('busy', true, detail);
        }
        if (detail === 'partition_view_unavailable') {
          return new Unavailable('partition_view_unavailable', e.retryable, detail);
        }
        if (detail === 'view_not_retained' || (detail === 'state_not_included' && role === 'peer')) {
          return new Unavailable('target_not_retained', e.retryable, detail);
        }
        return new Unavailable('pending_publication', e.retryable, detail);
      }
      case 'unsupported':
        return new Unavailable(
          e.detail === 'method_not_found' ? 'unsupported_capability' : 'unsupported_configuration',
          false,
          e.detail,
        );
      case 'limit_exceeded':
        return new Unavailable('limit_exceeded', false, e.detail);
      case 'rejected':
        return new ConsolidationError('rejected', e.message, info);
      case 'server':
        return new ConsolidationError('server', e.message, { ...info, retryable: e.retryable });
      case 'invalid_response':
        return new ConsolidationError('invalid_response', e.message, { ...info, outcome: 'invalid_input' });
      default:
        return new ConsolidationError('transport', e.message, { ...info, retryable: true });
    }
  }

  /**
   * Run one attempt. Inputs are never modified.
   *
   * @param {IConsolidationItem[]} items Original outer-history proofs.
   * @param {IConsolidationOptions} [options] Attempt options.
   * @returns {Promise<ConsolidationAttempt>} Rebuilt proofs or an unavailable outcome.
   * @throws {ConsolidationError} Typed failure: cancellation, deadline, transport, server, response or integrity.
   */
  public async consolidate(
    items: readonly IConsolidationItem[],
    options: IConsolidationOptions = {},
  ): Promise<ConsolidationAttempt> {
    const clock = new AttemptClock(options.timeoutMs ?? ProofConsolidator.DEFAULT_TIMEOUT_MS, options.signal);
    try {
      return await this.run(items, options, clock);
    } catch (e) {
      if (e instanceof Unavailable) {
        const done = clock.done();
        if (done) {
          throw done;
        }
        return { detail: e.detail, reason: e.reason, retryable: e.retryable, status: 'unavailable' };
      }
      const done = clock.done();
      if (done && (isAbort(e) || !(e instanceof ConsolidationError))) {
        throw done;
      }
      throw e;
    } finally {
      clock.dispose();
    }
  }

  /**
   * Authenticate every original proof (shard and partition path to its seal hash, leaf rules, seal quorum under the
   * trusted authority) and derive R_min: the highest root round among them. All seals must be of one network.
   */
  private async authenticateEvidence(
    items: readonly IConsolidationItem[],
    stateIds: readonly StateId[],
  ): Promise<{ network: NetworkId; round: bigint; shard: ShardId }> {
    const order = PartitionView.canonicalShardOrder(this.routing.scheme);
    let best: { network: NetworkId; round: bigint; shard: ShardId } | null = null;
    for (const [i, item] of items.entries()) {
      const uc = item.proof.unicityCertificate;
      const shard = uc.shardTreeCertificate.shard;
      if (!order.some((id) => id.equals(shard))) {
        throw integrity('incompatible_lineage', `Evidence ${i}: shard "${shard.toString()}" is not in the topology.`);
      }
      this.checkUcShape(i, uc, shard);
      if ((await UnicitySealHashMatchesWithRootHashRule.verify(uc)).status !== VerificationStatus.OK) {
        throw integrity('binding_mismatch', `Evidence ${i}: the shard path does not reach the seal hash.`, shard);
      }
      await this.leafRules(item, stateIds[i], item.proof, uc, shard);

      const seal = uc.unicitySeal;
      if (best !== null && !seal.networkId.equals(best.network)) {
        throw integrity('incompatible_lineage', `Evidence ${i}: seal of another network than earlier evidence.`);
      }
      if (!seal.networkId.equals(this.session.trustBaseNetwork)) {
        throw integrity('unauthenticated', `Evidence ${i}: seal of another network than the trusted authority.`);
      }
      const quorum = await this.session.verifyQuorum(seal);
      if (quorum.status !== VerificationStatus.OK) {
        throw integrity('unauthenticated', `Evidence ${i}: the seal is not authenticated.`, shard);
      }
      if (best === null || seal.rootChainRoundNumber > best.round) {
        best = { network: seal.networkId, round: seal.rootChainRoundNumber, shard };
      }
    }
    return best as { network: NetworkId; round: bigint; shard: ShardId };
  }

  /** The source proofs are rooted at the state the master view commits to, for this very shard and partition. */
  private checkExactRoot(shardBatch: IShardBatch, target: UnicityCertificate, shard: ShardId): void {
    const local = this.commonUc(shardBatch, shard);
    if (!areUint8ArraysEqual(local.inputRecord.hash, target.inputRecord.hash)) {
      throw integrity('binding_mismatch', 'The source root differs from the master view root.', shard);
    }
    if (
      !local.shardTreeCertificate.shard.equals(shard) ||
      local.unicityTreeCertificate.partitionIdentifier !== this.routing.partitionId
    ) {
      throw integrity('binding_mismatch', 'The source certificate identity differs from the shard.', shard);
    }
  }

  /** Structure of a certificate for the configured partition and shard (the native `IsValid` checks). */
  private checkUcShape(index: number, uc: UnicityCertificate, shard: ShardId): void {
    const fail = (message: string): ConsolidationError =>
      integrity('incompatible_lineage', `Certificate ${index}: ${message}`, shard);
    if (uc.unicityTreeCertificate.partitionIdentifier !== this.routing.partitionId) {
      throw fail('partition differs from the configured partition.');
    }
    if (uc.shardTreeCertificate.siblingHashList.length !== shard.length) {
      throw fail('shard path length does not match the shard id.');
    }
    if (uc.technicalRecordHash?.length !== 32) {
      throw fail('technical record hash must be 32 bytes.');
    }
    const pinned = this.routing.shardConfigurationHashes?.get(shard.toString());
    if (pinned && !areUint8ArraysEqual(pinned, uc.shardConfigurationHash)) {
      throw fail('shard configuration hash differs from the pinned configuration.');
    }
    const sealFailure = SealVerificationSession.checkSealStructure(uc.unicitySeal);
    if (sealFailure !== null) {
      throw fail(sealFailure);
    }
  }

  /** The batch's elements as certified proofs carrying byte-identical local certificates. */
  private commonUc(shardBatch: IShardBatch, shard: ShardId): UnicityCertificate {
    const proofs = shardBatch.batch.proofs;
    let first: Uint8Array | null = null;
    for (const [i, response] of proofs.entries()) {
      if (!response.inclusionProof) {
        throw new ConsolidationError('invalid_response', `Proof ${i} of shard "${shard.toString()}" is empty.`, {
          outcome: 'invalid_input',
          shard: shard.toString(),
        });
      }
      const bytes = response.inclusionProof.unicityCertificate.toCBOR();
      if (first !== null && !areUint8ArraysEqual(first, bytes)) {
        throw integrity('invalid_input', `Proof ${i} carries a different unicity certificate.`, shard);
      }
      first = bytes;
    }
    return (proofs[0].inclusionProof as InclusionProof).unicityCertificate;
  }

  private async fetch(
    group: IGroup,
    stateIds: readonly StateId[],
    root: DataHash | undefined,
    clock: AttemptClock,
    role: 'master' | 'peer',
    signal: AbortSignal = clock.signal,
  ): Promise<IShardBatch> {
    clock.throwIfDone();
    const ids = group.indexes.map((i) => stateIds[i]);
    const requestOptions: IBatchRequestOptions = { signal, stateRoot: root };
    try {
      const batch = await (
        group.endpoint.client as unknown as {
          getInclusionProofs(ids: readonly StateId[], options: IBatchRequestOptions): Promise<InclusionProofBatch>;
        }
      ).getInclusionProofs(ids, requestOptions);
      clock.throwIfDone();
      if (batch.proofs.length !== ids.length) {
        throw new ConsolidationError(
          'invalid_response',
          `Got ${batch.proofs.length} proofs for ${ids.length} states.`,
          { outcome: 'invalid_input', shard: group.endpoint.shard.toString() },
        );
      }
      return { batch, group };
    } catch (e) {
      throw ProofConsolidator.requestFailure(e, group.endpoint.shard, role, clock);
    }
  }

  /** Exact-root requests with bounded parallelism; the first failure aborts the rest, reported deterministically. */
  private async fetchAll(
    groups: readonly IGroup[],
    roots: readonly DataHash[],
    stateIds: readonly StateId[],
    maxParallel: number | undefined,
    clock: AttemptClock,
  ): Promise<IShardBatch[]> {
    const limit = Math.max(1, Math.floor(maxParallel ?? ProofConsolidator.DEFAULT_MAX_PARALLEL));
    const results = new Array<IShardBatch | undefined>(groups.length);
    const errors = new Array<unknown>(groups.length);
    const inner = new AbortController();
    const onAbort = (): void => inner.abort();
    clock.signal.addEventListener('abort', onAbort, { once: true });

    let next = 0;
    const worker = async (): Promise<void> => {
      for (;;) {
        const i = next++;
        if (i >= groups.length || inner.signal.aborted) {
          return;
        }
        try {
          results[i] = await this.fetch(groups[i], stateIds, roots[i], clock, 'peer', inner.signal);
        } catch (e) {
          errors[i] = e;
          inner.abort();
          return;
        }
      }
    };
    try {
      await Promise.all(Array.from({ length: Math.min(limit, groups.length) }, () => worker()));
    } finally {
      clock.signal.removeEventListener('abort', onAbort);
    }

    const failures = errors.filter((e) => e !== undefined);
    if (failures.length > 0) {
      // the originating failure, not the cancellations it caused in siblings
      const origin = failures.find(
        (e) => !(e instanceof ConsolidationError && (e.kind === 'cancelled' || e.kind === 'timeout')),
      );
      throw (origin ?? failures[0]) as Error;
    }
    clock.throwIfDone();
    return results as IShardBatch[];
  }

  /** Route every state to its endpoint, groups in canonical shard order, indexes in input order. */
  private group(stateIds: readonly StateId[]): IGroup[] {
    const byShard = new Map<string, IGroup>();
    stateIds.forEach((stateId, index) => {
      const endpoint = this.routing.route(stateId);
      const key = endpoint.shard.toString();
      const group = byShard.get(key) ?? { endpoint, indexes: [] };
      group.indexes.push(index);
      byShard.set(key, group);
    });
    const order = PartitionView.canonicalShardOrder(this.routing.scheme);
    return order.flatMap((id) => {
      const group = byShard.get(id.toString());
      return group ? [group] : [];
    });
  }

  /**
   * The per input rules, shared by the original proofs and the replacements: expiry, reference time not after the
   * certificate's timestamp, shard membership and the path to the target state root.
   */
  private async leafRules(
    item: IConsolidationItem,
    stateId: StateId,
    proof: InclusionProof,
    target: UnicityCertificate,
    shard: ShardId,
  ): Promise<void> {
    const { expiresAt } = item.certificationData;
    if (expiresAt != null && proof.referenceTime >= expiresAt) {
      throw integrity(
        'expired',
        `${stateId.toString()}: reference time ${proof.referenceTime} reaches expiry ${expiresAt}.`,
        shard,
      );
    }
    if (proof.referenceTime > target.inputRecord.timestamp) {
      throw integrity(
        'reference_time_after_target',
        `${stateId.toString()}: reference time ${proof.referenceTime} is after the target timestamp.`,
        shard,
      );
    }
    if (target.shardTreeCertificate.shard.length > 0 && !target.shardTreeCertificate.shard.isPrefixOf(stateId.data)) {
      throw integrity(
        'binding_mismatch',
        `${stateId.toString()} does not belong to shard "${shard.toString()}".`,
        shard,
      );
    }
    const root = target.inputRecord.hash;
    if (root.length !== 32) {
      throw integrity('unsupported', `The target state root has ${root.length} bytes.`, shard);
    }
    const leafValue = await calculateLeafValue(item.certificationData.transactionHash, proof.referenceTime);
    if (!(await proof.inclusionCertificate.verify(stateId, leafValue, new DataHash(HashAlgorithm.SHA256, root)))) {
      throw integrity(
        'binding_mismatch',
        `${stateId.toString()}: the proof path does not reach the target root.`,
        shard,
      );
    }
  }

  private pickMaster(groups: readonly IGroup[], preferred: ShardId | undefined, newest: ShardId): IGroup {
    const want = preferred ?? newest;
    const master = groups.find((g) => g.endpoint.shard.equals(want));
    if (!master) {
      throw new ConsolidationError('input', `Master shard "${want.toString()}" does not take part.`, {
        outcome: 'invalid_input',
      });
    }
    return master;
  }

  /** One replacement proof: original certification data and reference time, proof path of the response, target UC. */
  private async replace(
    item: IConsolidationItem,
    stateId: StateId,
    response: InclusionProofResponse,
    target: UnicityCertificate,
    shard: ShardId,
  ): Promise<InclusionProofResponse> {
    const source = response.inclusionProof as InclusionProof;
    if (!areUint8ArraysEqual(source.certificationData.toCBOR(), item.certificationData.toCBOR())) {
      throw integrity(
        'binding_mismatch',
        `${stateId.toString()}: the proof is not bound to the original input.`,
        shard,
      );
    }
    const replacement = new InclusionProof(
      item.certificationData,
      source.referenceTime,
      source.inclusionCertificate,
      target,
    );
    await this.leafRules(item, stateId, replacement, target, shard);
    // the reference time is part of the committed leaf: a proof of another leaf value is not the original's
    if (source.referenceTime !== item.proof.referenceTime) {
      throw integrity(
        'binding_mismatch',
        `${stateId.toString()}: the reference time differs from the original.`,
        shard,
      );
    }
    return InclusionProofResponse.certified(response.blockNumber, replacement);
  }

  private async run(
    items: readonly IConsolidationItem[],
    options: IConsolidationOptions,
    clock: AttemptClock,
  ): Promise<ConsolidationAttempt> {
    if (items.length === 0) {
      throw new ConsolidationError('input', 'No proofs to consolidate.', { outcome: 'invalid_input' });
    }
    const stateIds = await Promise.all(items.map((item) => StateId.fromCertificationData(item.certificationData)));
    const keys = stateIds.map((id) => id.toString());
    if (new Set(keys).size !== keys.length) {
      throw new ConsolidationError('input', 'Duplicate state in the proofs to consolidate.', {
        outcome: 'invalid_input',
      });
    }
    const groups = this.group(stateIds);

    // the capability is a precondition of the whole attempt: a missing or limited batch service is not emulated
    for (const group of groups) {
      if (!isBatchAggregatorClient(group.endpoint.client)) {
        throw new Unavailable('unsupported_capability', false, group.endpoint.shard.toString());
      }
      if (group.indexes.length > 256) {
        throw new Unavailable('limit_exceeded', false, 'state_count');
      }
    }

    const evidenceBefore = this.session.stats.quorumChecks;
    const bound = await this.authenticateEvidence(items, stateIds);
    const evidenceQuorumChecks = this.session.stats.quorumChecks - evidenceBefore;
    clock.throwIfDone();

    const master = this.pickMaster(groups, options.master, bound.shard);
    let requests = 0;

    // wave 1: the master's latest batch and partition view
    const masterBatch = await this.fetch(master, stateIds, undefined, clock, 'master');
    requests++;
    const viewBytes = masterBatch.batch.partitionViewBytes;
    if (!viewBytes) {
      throw new Unavailable('partition_view_unavailable', true, master.endpoint.shard.toString());
    }
    clock.throwIfDone();
    const masterShard = master.endpoint.shard;
    const enclosing = this.commonUc(masterBatch, masterShard);
    if (!enclosing.shardTreeCertificate.shard.equals(masterShard)) {
      throw integrity('binding_mismatch', 'The master certificate is of another shard.', masterShard);
    }

    const authenticator = new PartitionViewAuthenticator(this.routing.partitionId, this.session, {
      scheme: this.routing.scheme,
      shardConfigurationHashes: this.routing.shardConfigurationHashes,
    });
    const quorumBefore = this.session.stats.quorumChecks;
    let authenticated;
    try {
      authenticated = await authenticator.authenticate(viewBytes, enclosing);
    } catch (e) {
      throw viewFailure(e, masterShard);
    }
    const quorumChecks = this.session.stats.quorumChecks - quorumBefore;
    if (!authenticated.networkId.equals(bound.network)) {
      throw integrity('incompatible_lineage', 'The master seal is of another network than the original proofs.');
    }
    const masterRound = authenticated.seal.rootChainRoundNumber;
    if (masterRound < bound.round) {
      // a valid seal that does not cover the history yet: the service has not published far enough
      throw new Unavailable('pending_publication', true, 'master_round_below_required');
    }
    clock.throwIfDone();

    // wave 2: exact roots of the other participating shards, bounded parallel
    const peers = groups.filter((g) => g !== master);
    const roots = peers.map((g) => {
      const leaf = authenticated.leaves.find((l) => l.shardId.equals(g.endpoint.shard));
      if (!leaf) {
        throw integrity('binding_mismatch', 'A participating shard is not in the master view.', g.endpoint.shard);
      }
      return new DataHash(HashAlgorithm.SHA256, leaf.inputRecord.hash);
    });
    const peerBatches = await this.fetchAll(peers, roots, stateIds, options.maxParallel, clock);
    requests += peers.length;
    clock.throwIfDone();

    // every shard under the identical master seal
    const batches: IShardBatch[] = [masterBatch, ...peerBatches];
    const responses: (InclusionProofResponse | undefined)[] = new Array<InclusionProofResponse | undefined>(
      items.length,
    );
    let bodyChecks = 0;
    let leafChecks = 0;
    for (const shardBatch of batches) {
      const shard = shardBatch.group.endpoint.shard;
      const target = authenticated.certificateOf(shard);
      this.checkExactRoot(shardBatch, target, shard);
      bodyChecks++;
      if ((await UnicitySealHashMatchesWithRootHashRule.verify(target)).status !== VerificationStatus.OK) {
        throw integrity('binding_mismatch', 'The shard path does not reach the seal hash.', shard);
      }
      const proofs = shardBatch.batch.proofs;
      for (const [position, index] of shardBatch.group.indexes.entries()) {
        leafChecks++;
        responses[index] = await this.replace(items[index], stateIds[index], proofs[position], target, shard);
      }
    }
    clock.throwIfDone();

    return {
      counters: { bodyChecks, evidenceQuorumChecks, leafChecks, quorumChecks },
      masterRound,
      masterShard,
      requests,
      requiredRound: bound.round,
      responses: responses as InclusionProofResponse[],
      shards: batches.length,
      status: 'consolidated',
      waves: peers.length > 0 ? 2 : 1,
    };
  }
}
