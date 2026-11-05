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
 * Rule to verify that a unicity seal is authenticated by the trust-base committee of its own epoch, with upstream's seal rule (also the rule of
 * bft-core `b1ref`, the any-age bridge verifier and the native shard path), so that a wallet accepts exactly the seals the chain accepts:
 *
 * 1. **Format** (the input is refused, `malformed`): at most {@link MAX_SIGNATURES} signatures and signer identifiers of at most
 *    {@link MAX_NODE_ID_BYTES} bytes. A signature value of any other width is a well-formed witness, not a format failure.
 * 2. **Authority**: signatures present; the seal's network; the committee of `seal.epoch` (an epoch after the latest held one is
 *    `no_entry_for_epoch`, retryable; one before the first held epoch is invalid); the root round inside the epoch's interval, `start ≤ r` and `r < end`
 *    once the next epoch is held. An empty signature value is `invalid`: upstream's seal validation refuses it.
 * 3. **Signatures**: each supplied signature is judged alone. An unknown signer, and a signature that is not exactly 65 bytes `r‖s‖v` with
 *    `1 ≤ r < n`, `1 ≤ s ≤ n/2`, `v` in 0..3 and recovering (over the seal hash) to the member's listed key, contribute zero and never fail the
 *    seal. The supplied recovery byte is binding: it is never discarded, normalized or replaced by the other parity. The weights of the valid
 *    signatures must reach the committee threshold.
 *
 * A trust-base ENTRY's witnesses are a different object and stay strict (a bad extra refuses a successor entry). Signature work dominates proof
 * verification and every proof of an aggregator round carries the same seal, so successes can be memoised in a caller-supplied
 * {@link VerifiedSealCache}; its key covers the complete seal encoding, witnesses included.
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
   * The format checks of a seal's signature map (count and identifier length), independent of any authority.
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
    for (const signer of witnesses.keys()) {
      if (TEXT_ENCODER.encode(signer).length > UnicitySealQuorumSignaturesVerificationRule.MAX_NODE_ID_BYTES) {
        return `Signer identifier of more than ${UnicitySealQuorumSignaturesVerificationRule.MAX_NODE_ID_BYTES} bytes.`;
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
    for (const [signer, witness] of unicitySeal.witnesses) {
      if (witness.length === 0) {
        return new CertificateVerificationResult(rule, 'invalid', `Signature of "${signer}" is empty.`);
      }
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

    // a signature that does not count contributes zero; only the weight of the valid ones is summed
    const names = Array.from(unicitySeal.witnesses.keys());
    const weight = names.reduce(
      (sum, nodeId, i) =>
        results[i].status === VerificationStatus.OK ? sum + (committee.members.get(nodeId)?.weight ?? 0n) : sum,
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
    if (witness.length !== 65 || witness[64] > 3) {
      return new VerificationResult(
        rule,
        VerificationStatus.FAIL,
        'Signature is not 65 bytes with a recovery ID of 0 to 3',
      );
    }
    const r = BigInt(`0x${HexConverter.encode(witness.subarray(0, 32))}`);
    const s = BigInt(`0x${HexConverter.encode(witness.subarray(32, 64))}`);
    if (r === 0n || r >= CURVE_N || s === 0n || s > HALF_N) {
      return new VerificationResult(rule, VerificationStatus.FAIL, 'Signature r or s out of range');
    }
    if (
      await this.signatureVerifier.verify(hash, new Signature(witness.subarray(0, 64), witness[64]), member.signingKey)
    ) {
      return new VerificationResult(rule, VerificationStatus.OK);
    }
    return new VerificationResult(rule, VerificationStatus.FAIL, 'Signature verification failed');
  }
}
