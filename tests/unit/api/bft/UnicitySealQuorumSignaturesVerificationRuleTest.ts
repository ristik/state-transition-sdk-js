import { UnicitySeal } from '../../../../src/api/bft/UnicitySeal.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../../../../src/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { VerifiedSealCache } from '../../../../src/api/bft/verification/VerifiedSealCache.js';
import { NetworkId } from '../../../../src/api/NetworkId.js';
import { Secp256k1SignatureVerifier } from '../../../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { SigningService } from '../../../../src/crypto/secp256k1/SigningService.js';
import { VerificationStatus } from '../../../../src/verification/VerificationStatus.js';
import { createTrustBase, TEST_EPOCH } from '../../../utils/RootTrustBaseFixture.js';

/** Seal body shared by every seal built here, so their content hashes match. */
const SEAL_CONTENT_HASH = new Uint8Array(32).fill(0x11);

function signingServiceFrom(fill: number): SigningService {
  return new SigningService(new Uint8Array(32).fill(fill));
}

function sealSignedBy(signingService: SigningService): Promise<UnicitySeal> {
  return UnicitySeal.create(
    NetworkId.LOCAL,
    0n,
    BigInt(TEST_EPOCH),
    0n,
    null,
    SEAL_CONTENT_HASH,
    new Map([['NODE', signingService]]),
  );
}

describe('UnicitySealQuorumSignaturesVerificationRule', () => {
  const rootNode = signingServiceFrom(0x01);
  const impostor = signingServiceFrom(0x02);

  let signatureVerifier: Secp256k1SignatureVerifier;
  let verifySpy: jest.SpyInstance;
  let rule: UnicitySealQuorumSignaturesVerificationRule;

  beforeEach(() => {
    signatureVerifier = new Secp256k1SignatureVerifier();
    verifySpy = jest.spyOn(signatureVerifier, 'verify');
    rule = new UnicitySealQuorumSignaturesVerificationRule(signatureVerifier, new VerifiedSealCache(256));
  });

  it('verifies a quorum seal, then serves the repeat from the memo', async () => {
    const trustBase = createTrustBase(rootNode.publicKey);
    const seal = await sealSignedBy(rootNode);

    const first = await rule.verify(trustBase, seal);
    expect(first.status).toEqual(VerificationStatus.OK);
    expect(verifySpy).toHaveBeenCalledTimes(1);

    const second = await rule.verify(trustBase, seal);
    expect(second.status).toEqual(VerificationStatus.OK);
    expect(verifySpy).toHaveBeenCalledTimes(1);
  });

  it('verifies every seal afresh when constructed without a cache', async () => {
    const uncached = new UnicitySealQuorumSignaturesVerificationRule(signatureVerifier);
    const trustBase = createTrustBase(rootNode.publicKey);
    const seal = await sealSignedBy(rootNode);

    expect((await uncached.verify(trustBase, seal)).status).toEqual(VerificationStatus.OK);
    expect((await uncached.verify(trustBase, seal)).status).toEqual(VerificationStatus.OK);
    expect(verifySpy).toHaveBeenCalledTimes(2);
  });

  // The memo must key on the seal's COMPLETE encoding, not on calculateHash():
  // that hash deliberately excludes the signatures (it is what the root nodes
  // sign), so two seals with the same body but different signatures share it.
  // Keyed on it, this forged seal would be served a cached OK and its bogus
  // signatures would never be checked.
  it('rejects a seal whose signatures were replaced, even after the genuine one was memoised', async () => {
    const trustBase = createTrustBase(rootNode.publicKey);
    const genuine = await sealSignedBy(rootNode);
    const forged = await sealSignedBy(impostor);

    // The trap: identical bodies, hence identical signature-excluding hashes.
    expect((await forged.calculateHash()).toString()).toEqual((await genuine.calculateHash()).toString());

    expect((await rule.verify(trustBase, genuine)).status).toEqual(VerificationStatus.OK);
    expect((await rule.verify(trustBase, forged)).status).toEqual(VerificationStatus.FAIL);
  });

  // The memo is keyed by the committee content (its EntryID in a held history), never by object identity: another key for the same epoch is
  // another committee and never hits a verdict computed under the first one.
  it('re-verifies under an authority with other keys', async () => {
    const seal = await sealSignedBy(rootNode);

    expect((await rule.verify(createTrustBase(rootNode.publicKey), seal)).status).toEqual(VerificationStatus.OK);
    expect(verifySpy).toHaveBeenCalledTimes(1);

    expect((await rule.verify(createTrustBase(impostor.publicKey), seal)).status).toEqual(VerificationStatus.FAIL);
    expect(verifySpy).toHaveBeenCalledTimes(2); // one recovery per signature: the supplied recovery byte is binding, no other parity is tried
  });

  // upstream's seal validation refuses an empty signature value, even beside a quorum; every other width is a zero-weight witness
  it('refuses an empty signature value and counts any other width as zero', async () => {
    const trustBase = createTrustBase(rootNode.publicKey);
    const genuine = await sealSignedBy(rootNode);
    const bytes = genuine.toCBOR();
    // the witness map is the last item: { "NODE": h'<65 bytes>' }; replace the byte string (0x58 0x41 + 65 bytes)
    const withWitness = (witness: Uint8Array): UnicitySeal => {
      const head = bytes.subarray(0, bytes.length - 67);
      const header = witness.length < 24 ? [0x40 + witness.length] : [0x58, witness.length];
      return UnicitySeal.fromCBOR(new Uint8Array([...head, ...header, ...witness]));
    };
    expect((await rule.verify(trustBase, withWitness(bytes.subarray(bytes.length - 65)))).status).toEqual(
      VerificationStatus.OK,
    );
    expect((await rule.verify(trustBase, withWitness(new Uint8Array(0)))).status).toEqual(VerificationStatus.FAIL);
    // an empty value of an unknown signer beside the genuine quorum is refused too (not a zero-weight extra); a 3-byte one is a zero-weight extra
    const withExtra = (extra: number[]): UnicitySeal => {
      const mapStart = bytes.length - 73; // 0xa1, "NODE" (5 bytes), the 67-byte witness
      const tail = bytes.subarray(mapStart + 1);
      return UnicitySeal.fromCBOR(
        new Uint8Array([...bytes.subarray(0, mapStart), 0xa2, ...tail, 0x64, 0x5a, 0x5a, 0x5a, 0x5a, ...extra]),
      );
    };
    expect((await rule.verify(trustBase, withExtra([0x43, 1, 2, 3]))).status).toEqual(VerificationStatus.OK);
    expect((await rule.verify(trustBase, withExtra([0x40]))).status).toEqual(VerificationStatus.FAIL);
    // a real signature under an EMPTY signer identifier beside the genuine quorum is refused as well (key "" sorts before "NODE")
    const withEmptyId = (): UnicitySeal => {
      const mapStart = bytes.length - 73;
      const tail = bytes.subarray(mapStart + 1);
      const real = bytes.subarray(bytes.length - 67);
      return UnicitySeal.fromCBOR(new Uint8Array([...bytes.subarray(0, mapStart), 0xa2, 0x60, ...real, ...tail]));
    };
    expect((await rule.verify(trustBase, withEmptyId())).status).toEqual(VerificationStatus.FAIL);
    for (const width of [1, 63, 64, 66]) {
      const odd = new Uint8Array(width).fill(7);
      expect((await rule.verify(trustBase, withWitness(odd))).status).toEqual(VerificationStatus.FAIL); // no weight: the quorum is short
    }
  });

  it('keeps separate rules from sharing a memo', async () => {
    const trustBase = createTrustBase(rootNode.publicKey);
    const seal = await sealSignedBy(rootNode);

    await rule.verify(trustBase, seal);
    expect(verifySpy).toHaveBeenCalledTimes(1);

    const otherVerifier = new Secp256k1SignatureVerifier();
    const otherSpy = jest.spyOn(otherVerifier, 'verify');
    const otherRule = new UnicitySealQuorumSignaturesVerificationRule(otherVerifier, new VerifiedSealCache(256));

    expect((await otherRule.verify(trustBase, seal)).status).toEqual(VerificationStatus.OK);
    expect(otherSpy).toHaveBeenCalledTimes(1);
  });

  it('does not memoise a seal that fails to reach quorum', async () => {
    const trustBase = createTrustBase(rootNode.publicKey);
    const seal = await sealSignedBy(impostor);

    // a signature under another key counts zero (one recovery: the carried recovery byte is binding)
    expect((await rule.verify(trustBase, seal)).status).toEqual(VerificationStatus.FAIL);
    expect(verifySpy).toHaveBeenCalledTimes(1);

    expect((await rule.verify(trustBase, seal)).status).toEqual(VerificationStatus.FAIL);
    expect(verifySpy).toHaveBeenCalledTimes(2);
  });

  it('evicts the oldest entry once the cache is full', async () => {
    const trustBase = createTrustBase(rootNode.publicKey);
    const small = new UnicitySealQuorumSignaturesVerificationRule(signatureVerifier, new VerifiedSealCache(1));
    const first = await sealSignedBy(rootNode);
    const second = await UnicitySeal.create(
      NetworkId.LOCAL,
      1n,
      BigInt(TEST_EPOCH),
      0n,
      null,
      SEAL_CONTENT_HASH,
      new Map([['NODE', rootNode]]),
    );

    await small.verify(trustBase, first);
    await small.verify(trustBase, second);
    expect(verifySpy).toHaveBeenCalledTimes(2);

    // `first` was evicted by `second`, so it must be verified again.
    await small.verify(trustBase, first);
    expect(verifySpy).toHaveBeenCalledTimes(3);
  });
});

describe('VerifiedSealCache', () => {
  it('rejects a non-positive bound', () => {
    expect(() => new VerifiedSealCache(0)).toThrow('VerifiedSealCache maxEntries must be a positive integer');
    expect(() => new VerifiedSealCache(1.5)).toThrow('VerifiedSealCache maxEntries must be a positive integer');
  });
});
