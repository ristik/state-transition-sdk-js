import { DataHash } from '../../../../crypto/hash/DataHash.js';
import { DataHasher } from '../../../../crypto/hash/DataHasher.js';
import { HashAlgorithm } from '../../../../crypto/hash/HashAlgorithm.js';
import { ISignatureVerifier } from '../../../../crypto/ISignatureVerifier.js';
import { Signature } from '../../../../crypto/secp256k1/Signature.js';
import { CborSerializer } from '../../../../serialization/cbor/CborSerializer.js';
import { HexConverter } from '../../../../util/HexConverter.js';
import { VerificationResult } from '../../../../verification/VerificationResult.js';
import { VerificationStatus } from '../../../../verification/VerificationStatus.js';
import { IEpochCommittee, ITrustBaseAuthority } from '../../trustbase/TrustBaseAuthority.js';
import { UnicitySeal } from '../../UnicitySeal.js';
import { CertificateVerificationResult } from '../CertificateVerdict.js';
import { VerifiedSealCache } from '../VerifiedSealCache.js';

const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = CURVE_N >> 1n;
const TEXT_ENCODER = new TextEncoder();

/**
 * Rule to verify that a unicity seal is authenticated by the trust-base committee of its own epoch, with exactly the native B1 rule (bft-core
 * `b1ref`, the any-age bridge verifier), so that a wallet accepts exactly the seals the chain accepts:
 *
 * 1. **Format** (B1 refuses the input, `malformed`): at most {@link MAX_SIGNATURES} signatures; signer identifiers of at most
 *    {@link MAX_NODE_ID_BYTES} bytes; every signature 64 bytes `r‖s`, or 65 bytes `r‖s‖v` with `v` 0 or 1.
 * 2. **Authority**: signatures present; the seal's network; the committee of `seal.epoch` (an epoch after the latest held one is
 *    `no_entry_for_epoch`, retryable; one before the first held epoch is invalid); the root round inside the epoch's interval, `start ≤ r` and `r < end`
 *    once the next epoch is held.
 * 3. **Signatures**: every supplied signature is checked, with no early exit; an unknown signer, `r` or `s` out of range (`1 ≤ r < n`,
 *    `1 ≤ s ≤ n/2`) or a signature that does not verify against the member's listed key fails the seal even when the others reach the threshold;
 *    the verified members' weights must reach the committee threshold. The recovery byte is not trusted: a signature is valid when one of the four
 *    recovery bytes recovers the member's key, which is exactly ECDSA validity under that key (the carried byte is tried first).
 *
 * This is stricter than upstream O3 (which let an unknown or malformed extra signature count zero) and than the native shard path (which lets a known
 * member's invalid signature count zero): for honest seals all agree. Signature work dominates proof verification and every proof of an aggregator
 * round carries the same seal, so successes can be memoised in a caller-supplied {@link VerifiedSealCache}.
 */
export class UnicitySealQuorumSignaturesVerificationRule {
  public static readonly MAX_NODE_ID_BYTES = 128;
  public static readonly MAX_SIGNATURES = 16;

  /**
   * @param {ISignatureVerifier<Signature>} signatureVerifier Recovering secp256k1 verifier for the root-node signatures.
   * @param {VerifiedSealCache} [cache] Memo for verified seals; omit to verify every seal afresh.
   */
  public constructor(
    private readonly signatureVerifier: ISignatureVerifier<Signature>,
    private readonly cache?: VerifiedSealCache,
  ) {}

  /**
   * The B1 format checks of a seal's signature map, independent of any authority.
   *
   * @param {UnicitySeal} seal Seal.
   * @returns {string|null} Why the seal is malformed, or null.
   */
  public static checkSignatureFormat(seal: UnicitySeal): string | null {
    const witnesses = seal.witnesses;
    if (witnesses === null) {
      return null;
    }
    if (witnesses.size > UnicitySealQuorumSignaturesVerificationRule.MAX_SIGNATURES) {
      return `${witnesses.size} signatures exceed ${UnicitySealQuorumSignaturesVerificationRule.MAX_SIGNATURES}.`;
    }
    for (const [signer, witness] of witnesses) {
      if (TEXT_ENCODER.encode(signer).length > UnicitySealQuorumSignaturesVerificationRule.MAX_NODE_ID_BYTES) {
        return `Signer identifier of more than ${UnicitySealQuorumSignaturesVerificationRule.MAX_NODE_ID_BYTES} bytes.`;
      }
      if (witness.length !== 64 && witness.length !== 65) {
        return `Signature of "${signer}" is ${witness.length} bytes (64 or 65).`;
      }
      if (witness.length === 65 && witness[64] > 1) {
        return `Signature of "${signer}" has recovery byte ${witness[64]} (0 or 1).`;
      }
    }
    return null;
  }

  /**
   * Select the committee of the seal's epoch and check the seal's network and root round against it.
   *
   * @param {ITrustBaseAuthority} authority Held trust-base history.
   * @param {UnicitySeal} seal Seal.
   * @returns {IEpochCommittee|CertificateVerificationResult} The committee, or the failed check.
   */
  public static selectCommittee(
    authority: ITrustBaseAuthority,
    seal: UnicitySeal,
  ): IEpochCommittee | CertificateVerificationResult {
    const rule = 'UnicitySealAuthorityRule';
    if (!seal.networkId.equals(authority.networkId)) {
      return new CertificateVerificationResult(
        rule,
        'invalid',
        `Seal is of network ${seal.networkId.id}, the trust base of network ${authority.networkId.id}.`,
      );
    }
    const committee = authority.committee(seal.epoch);
    if (committee === null) {
      if (seal.epoch > authority.tipEpoch) {
        return new CertificateVerificationResult(
          rule,
          'no_entry_for_epoch',
          `No trust-base entry for epoch ${seal.epoch}; the latest held epoch is ${authority.tipEpoch}.`,
          [],
          { epoch: seal.epoch, latest: authority.tipEpoch },
        );
      }
      return new CertificateVerificationResult(
        rule,
        'invalid',
        `Seal epoch ${seal.epoch} precedes the first held epoch ${authority.genesisEpoch}.`,
      );
    }
    if (seal.rootChainRoundNumber < committee.start) {
      return new CertificateVerificationResult(
        rule,
        'invalid',
        `Seal round ${seal.rootChainRoundNumber} is before the start ${committee.start} of epoch ${committee.epoch}.`,
      );
    }
    if (committee.end !== null && seal.rootChainRoundNumber >= committee.end) {
      return new CertificateVerificationResult(
        rule,
        'invalid',
        `Seal round ${seal.rootChainRoundNumber} is at or after the end ${committee.end} of epoch ${committee.epoch}.`,
      );
    }
    return committee;
  }

  /**
   * The memo key commits to the committee record and its interval (a later held epoch closes an interval) and to the complete seal encoding,
   * signatures included (`calculateHash` excludes them, so it cannot be the key).
   *
   * @param {IEpochCommittee} committee Committee of the seal's epoch.
   * @param {UnicitySeal} unicitySeal Seal.
   * @returns {Promise<string>} Cache key.
   */
  private static async cacheKeyFor(committee: IEpochCommittee, unicitySeal: UnicitySeal): Promise<string> {
    const hash = await new DataHasher(HashAlgorithm.SHA256)
      .update(
        CborSerializer.encodeArray(
          CborSerializer.encodeTextString(JSON.stringify([committee.id, committee.end?.toString() ?? null])),
          CborSerializer.encodeByteString(unicitySeal.toCBOR()),
        ),
      )
      .digest();
    return HexConverter.encode(hash.imprint);
  }

  /**
   * Verify the seal against the committee of its epoch in the held history.
   *
   * @param {ITrustBaseAuthority} authority Held trust-base history.
   * @param {UnicitySeal} unicitySeal Seal to verify.
   * @returns {Promise<CertificateVerificationResult>} Verification outcome with its class.
   */
  public async verify(
    authority: ITrustBaseAuthority,
    unicitySeal: UnicitySeal,
  ): Promise<CertificateVerificationResult> {
    const rule = 'UnicitySealQuorumSignaturesVerificationRule';
    const malformed = UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat(unicitySeal);
    if (malformed !== null) {
      return new CertificateVerificationResult(rule, 'malformed', malformed);
    }
    if (!unicitySeal.witnesses?.size) {
      return new CertificateVerificationResult(rule, 'invalid', 'Seal has no signatures.');
    }
    const committee = UnicitySealQuorumSignaturesVerificationRule.selectCommittee(authority, unicitySeal);
    if (committee instanceof CertificateVerificationResult) {
      return committee;
    }

    const cacheKey = this.cache
      ? await UnicitySealQuorumSignaturesVerificationRule.cacheKeyFor(committee, unicitySeal)
      : null;
    if (cacheKey !== null) {
      const cached = this.cache?.get(cacheKey) ?? null;
      if (cached !== null) {
        return cached as CertificateVerificationResult;
      }
    }

    const hash = await unicitySeal.calculateHash();
    const results = await Promise.all(
      Array.from(unicitySeal.witnesses.entries()).map(([nodeId, witness]) =>
        this.verifySignature(committee, nodeId, witness, hash),
      ),
    );

    if (results.some((r) => r.status !== VerificationStatus.OK)) {
      return new CertificateVerificationResult(rule, 'invalid', 'A supplied signature does not verify.', results);
    }
    const weight = Array.from(unicitySeal.witnesses.keys()).reduce(
      (sum, nodeId) => sum + (committee.members.get(nodeId)?.weight ?? 0n),
      0n,
    );
    if (weight < committee.threshold) {
      return new CertificateVerificationResult(
        rule,
        'invalid',
        `Signed weight ${weight} is below the threshold ${committee.threshold} of epoch ${committee.epoch}.`,
        results,
      );
    }
    const result = new CertificateVerificationResult(
      rule,
      'ok',
      'Unicity quorum signatures verification threshold reached',
      results,
    );
    // only successes are memoised: a flood of bad seals cannot evict good entries
    if (cacheKey !== null) {
      this.cache?.set(cacheKey, result);
    }
    return result;
  }

  private async verifySignature(
    committee: IEpochCommittee,
    nodeId: string,
    witness: Uint8Array,
    hash: DataHash,
  ): Promise<VerificationResult<VerificationStatus>> {
    const rule = `SignatureVerificationRule[${nodeId}]`;
    const member = committee.members.get(nodeId) ?? null;
    if (member === null) {
      return new VerificationResult(rule, VerificationStatus.FAIL, 'Signer is not a member of the epoch committee');
    }
    const r = BigInt(`0x${HexConverter.encode(witness.subarray(0, 32))}`);
    const s = BigInt(`0x${HexConverter.encode(witness.subarray(32, 64))}`);
    if (r === 0n || r >= CURVE_N || s === 0n || s > HALF_N) {
      return new VerificationResult(rule, VerificationStatus.FAIL, 'Signature r or s out of range');
    }
    const carried = witness.length === 65 ? witness[64] : 0;
    for (const recovery of [carried, ...[0, 1, 2, 3].filter((v) => v !== carried)]) {
      if (
        await this.signatureVerifier.verify(hash, new Signature(witness.subarray(0, 64), recovery), member.signingKey)
      ) {
        return new VerificationResult(rule, VerificationStatus.OK);
      }
    }
    return new VerificationResult(rule, VerificationStatus.FAIL, 'Signature verification failed');
  }
}
