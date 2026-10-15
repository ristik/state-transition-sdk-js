import { ISealAuthenticator } from './ISealAuthenticator.js';
import { UnicitySealQuorumSignaturesVerificationRule } from './rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { DataHasher } from '../../../crypto/hash/DataHasher.js';
import { HashAlgorithm } from '../../../crypto/hash/HashAlgorithm.js';
import { CborSerializer } from '../../../serialization/cbor/CborSerializer.js';
import { HexConverter } from '../../../util/HexConverter.js';
import { VerificationResult } from '../../../verification/VerificationResult.js';
import { VerificationStatus } from '../../../verification/VerificationStatus.js';
import { RootTrustBase } from '../RootTrustBase.js';
import { UnicitySeal } from '../UnicitySeal.js';

/**
 * Counters of a {@link SealVerificationSession}.
 */
export interface ISealVerificationSessionStats {
  /** Requests that joined a check already in flight. */
  readonly inFlightJoins: number;
  /** Requests served from a completed successful check. */
  readonly memoHits: number;
  /** Distinct quorum signature verifications executed (cache and in-flight misses). */
  readonly quorumChecks: number;
}

/**
 * Seal authentication scoped to one operation (e.g. verification of one token or one consolidation attempt).
 *
 * Every shard certificate and transaction proof of a consolidated token carries the same master seal, so each leaf
 * check would repeat the same quorum signature work. The session authenticates a complete seal once per
 * (policy, authority, seal) and serves repeats from a bounded memo of *successes*; checks that are still running are
 * shared too, so concurrent leaf checks do not all miss and each repeat the signatures. Failures are never memoized
 * and a failed or throwing check is dropped from the in-flight set.
 *
 * The memo key commits to the length-delimited complete seal encoding (signatures included, so altered signature
 * witnesses cannot hit an entry), the trust base content (network, epoch, nodes, quorum) and the verifier policy id.
 * Network, epoch and epoch start of the seal are always checked against the trust base, independently of the memo.
 *
 * The session owns exactly one quorum rule (and so one signature verifier); it is not shared between workers or
 * operations and no verified flag can be supplied from outside.
 */
export class SealVerificationSession implements ISealAuthenticator {
  private readonly completed = new Map<string, VerificationResult<VerificationStatus>>();
  private readonly counters = { inFlightJoins: 0, memoHits: 0, quorumChecks: 0 };
  private readonly inFlight = new Map<string, Promise<VerificationResult<VerificationStatus>>>();

  /**
   * @param {RootTrustBase} trustBase Trusted authority the seals are authenticated against.
   * @param {UnicitySealQuorumSignaturesVerificationRule} quorumRule Quorum rule, runs on every distinct miss.
   * @param {object} [options] Options.
   * @param {number} [options.maxEntries] Upper bound on retained successful checks, the oldest is evicted first.
   * @param {string} [options.policy] Identifier of the verifier policy, part of the memo key.
   * @throws {Error} If `maxEntries` is not a positive integer.
   */
  public constructor(
    private readonly trustBase: RootTrustBase,
    private readonly quorumRule: UnicitySealQuorumSignaturesVerificationRule,
    private readonly options: { readonly maxEntries?: number; readonly policy?: string } = {},
  ) {
    const maxEntries = options.maxEntries ?? 64;
    if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
      throw new Error('SealVerificationSession maxEntries must be a positive integer');
    }
  }

  /**
   * @returns {ISealVerificationSessionStats} Snapshot of the counters.
   */
  public get stats(): ISealVerificationSessionStats {
    return { ...this.counters };
  }

  /**
   * Check the seal belongs to the authority the trust base represents: structure, network, epoch and epoch start.
   * Quorum signatures are NOT checked.
   *
   * @param {RootTrustBase} trustBase Trusted authority.
   * @param {UnicitySeal} seal Seal.
   * @returns {string|null} Failure description or null if the seal is within the authority.
   */
  public static checkAuthority(trustBase: RootTrustBase, seal: UnicitySeal): string | null {
    if (!seal.hash.length) {
      return 'Seal hash is missing.';
    }
    if (seal.rootChainRoundNumber < 1n) {
      return 'Seal root chain round is invalid.';
    }
    if (!seal.signatures?.size) {
      return 'Seal has no signatures.';
    }
    if (!seal.networkId.equals(trustBase.networkId)) {
      return `Seal is of network ${seal.networkId.id}, trust base is of network ${trustBase.networkId.id}.`;
    }
    if (seal.epoch !== trustBase.epoch) {
      return `Seal is of epoch ${seal.epoch}, trust base is of epoch ${trustBase.epoch}.`;
    }
    if (seal.rootChainRoundNumber < trustBase.epochStartRound) {
      return `Seal round ${seal.rootChainRoundNumber} is before the start of epoch ${trustBase.epoch} (round ${trustBase.epochStartRound}).`;
    }
    return null;
  }

  /**
   * Authenticate the seal: authority context first, then the quorum signatures, once per distinct seal.
   *
   * @param {UnicitySeal} seal Seal.
   * @returns {Promise<VerificationResult<VerificationStatus>>} Outcome.
   */
  public async authenticate(seal: UnicitySeal): Promise<VerificationResult<VerificationStatus>> {
    const failure = SealVerificationSession.checkAuthority(this.trustBase, seal);
    if (failure !== null) {
      return new VerificationResult('SealAuthority', VerificationStatus.FAIL, failure);
    }

    const key = await this.keyFor(seal);
    const done = this.completed.get(key);
    if (done) {
      this.counters.memoHits++;
      return done;
    }
    const running = this.inFlight.get(key);
    if (running) {
      this.counters.inFlightJoins++;
      return running;
    }

    this.counters.quorumChecks++;
    const check = this.quorumRule.verify(this.trustBase, seal).then(
      (result) => {
        this.inFlight.delete(key);
        if (result.status === VerificationStatus.OK) {
          this.remember(key, result);
        }
        return result;
      },
      (error: unknown) => {
        this.inFlight.delete(key);
        throw error;
      },
    );
    this.inFlight.set(key, check);
    return check;
  }

  private async keyFor(seal: UnicitySeal): Promise<string> {
    const hash = await new DataHasher(HashAlgorithm.SHA256)
      .update(
        CborSerializer.encodeArray(
          CborSerializer.encodeTextString(this.options.policy ?? ''),
          CborSerializer.encodeTextString(JSON.stringify(this.trustBase.toJSON())),
          CborSerializer.encodeByteString(seal.toCBOR()),
        ),
      )
      .digest();
    return HexConverter.encode(hash.imprint);
  }

  private remember(key: string, result: VerificationResult<VerificationStatus>): void {
    if (this.completed.size >= (this.options.maxEntries ?? 64)) {
      const oldest = this.completed.keys().next();
      if (!oldest.done) {
        this.completed.delete(oldest.value);
      }
    }
    this.completed.set(key, result);
  }
}
