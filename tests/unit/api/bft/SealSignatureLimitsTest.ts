import { RootTrustBaseV2 } from '../../../../src/api/bft/trustbase/RootTrustBaseV2.js';
import { UnicitySeal } from '../../../../src/api/bft/UnicitySeal.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../../../../src/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { NetworkId } from '../../../../src/api/NetworkId.js';
import { Secp256k1SignatureVerifier } from '../../../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { SigningService } from '../../../../src/crypto/secp256k1/SigningService.js';
import { HexConverter } from '../../../../src/util/HexConverter.js';
import { VerificationStatus } from '../../../../src/verification/VerificationStatus.js';
import { EpochListAuthority } from '../../../utils/EpochListAuthority.js';

/**
 * §49 seal ceilings of the integration branch: 256 supplied signatures as the resource ceiling of a seal. The 16 of the B1 bridge registry is a gas
 * bound of that registry, kept by configuration (`maxSignatures: 16`). The entry limits (256 members, 128 KiB) are tested with the trust-base
 * history tests.
 */
interface IMember {
  readonly nodeId: string;
  readonly service: SigningService;
}

/** `count` members with the private keys 1..count; node ids padded with zeros to `idBytes`. */
function members(count: number, idBytes: number): IMember[] {
  return Array.from({ length: count }, (_, i) => {
    const key = new Uint8Array(32);
    new DataView(key.buffer).setUint32(28, i + 1);
    return { nodeId: String(i + 1).padStart(idBytes, '0'), service: new SigningService(key) };
  });
}

describe('the seal signature ceilings (§49)', () => {
  const rule = new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier());
  const CONTENT = new Uint8Array(32).fill(0x11);
  const entryOf = (committee: readonly IMember[]): RootTrustBaseV2 =>
    new EpochListAuthority(NetworkId.LOCAL, [
      {
        end: null,
        epoch: 1,
        members: committee.map((m) => ({ key: HexConverter.encode(m.service.publicKey), nodeId: m.nodeId, weight: 1 })),
        start: 0,
        threshold: Math.floor((committee.length * 2) / 3) + 1,
      },
    ]).entryForEpoch(1n) as RootTrustBaseV2;
  const sealBy = (signers: readonly IMember[]): Promise<UnicitySeal> =>
    UnicitySeal.create(
      NetworkId.LOCAL,
      0n,
      1n,
      0n,
      null,
      CONTENT,
      new Map(signers.map((s) => [s.nodeId, s.service] as const)),
    );

  it('constants: 256 members and 256 supplied signatures', () => {
    expect(RootTrustBaseV2.MAX_MEMBERS).toBe(256);
    expect(UnicitySealQuorumSignaturesVerificationRule.MAX_SIGNATURES).toBe(256);
    expect(rule.maxSignatures).toBe(256);
  });

  it.each([128, 256])('a seal signed by all %i members verifies', async (count) => {
    const committee = members(count, 128);
    const result = await rule.verify(entryOf(committee), await sealBy(committee));
    expect(result.status).toBe(VerificationStatus.OK);
  });

  it('256 signatures are the last count accepted; 257 is refused before any signature is checked', async () => {
    const committee = members(256, 128);
    const extra = members(257, 128)[256];
    const ok = await sealBy(committee);
    expect(UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat(ok)).toBeNull();
    const over = await sealBy([...committee, extra]);
    expect(over.witnesses?.size).toBe(257);
    expect(UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat(over)).toMatch(/257 signatures exceed 256/);
    const verifier = new Secp256k1SignatureVerifier();
    const spy = jest.spyOn(verifier, 'verify');
    const result = await new UnicitySealQuorumSignaturesVerificationRule(verifier).verify(entryOf(committee), over);
    expect(result.status).not.toBe(VerificationStatus.OK);
    expect(spy).not.toHaveBeenCalled();
  });

  it('the B1 profile keeps 16: the same 17-signature seal is malformed for a rule configured with 16 and verifies for the default', async () => {
    const committee = members(17, 128);
    const seal = await sealBy(committee);
    const b1 = new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier(), undefined, {
      maxSignatures: 16,
    });
    expect(UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat(seal, 16)).toMatch(
      /17 signatures exceed 16/,
    );
    const refused = await b1.verify(entryOf(committee), seal);
    expect((refused as { verdict?: string }).verdict).toBe('malformed');
    expect((await rule.verify(entryOf(committee), seal)).status).toBe(VerificationStatus.OK);
  });

  it('unknown signers count against the 256 like any other: 4 members and 252 strangers pass, 253 strangers are refused', async () => {
    const committee = members(4, 128);
    const strangers = members(300, 128).slice(4);
    const at = await sealBy([...committee, ...strangers.slice(0, 252)]);
    expect(at.witnesses?.size).toBe(256);
    expect((await rule.verify(entryOf(committee), at)).status).toBe(VerificationStatus.OK);
    const over = await sealBy([...committee, ...strangers.slice(0, 253)]);
    expect(UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat(over)).toMatch(/257 signatures exceed/);
    expect((await rule.verify(entryOf(committee), over)).status).not.toBe(VerificationStatus.OK);
  });
});
