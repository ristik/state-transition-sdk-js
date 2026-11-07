import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { RootTrustBaseV2 } from '../../../../../src/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseError } from '../../../../../src/api/bft/trustbase/TrustBaseError.js';
import { TrustBaseHistory } from '../../../../../src/api/bft/trustbase/TrustBaseHistory.js';
import { TrustBaseResponse } from '../../../../../src/api/bft/trustbase/TrustBaseResponse.js';
import { UnicitySeal } from '../../../../../src/api/bft/UnicitySeal.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../../../../../src/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { NetworkId } from '../../../../../src/api/NetworkId.js';
import { DataHasher } from '../../../../../src/crypto/hash/DataHasher.js';
import { HashAlgorithm } from '../../../../../src/crypto/hash/HashAlgorithm.js';
import { Secp256k1SignatureVerifier } from '../../../../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { SigningService } from '../../../../../src/crypto/secp256k1/SigningService.js';
import { HexConverter } from '../../../../../src/util/HexConverter.js';
import { VerificationStatus } from '../../../../../src/verification/VerificationStatus.js';
import { EpochListAuthority } from '../../../../utils/EpochListAuthority.js';

/**
 * §49 committee limits of the integration branch: 256 members and 256 supplied signatures as resource ceilings, 128 KiB per entry. The 16 of the
 * B1 bridge registry is a gas bound of that registry and not a bound here.
 */
interface IMaxEntry {
  bundle: string;
  entry: string;
  entryBytes: number;
  entryId: string;
  genesis: string;
  genesisId: string;
}
const fixture = JSON.parse(
  readFileSync(join(process.cwd(), 'tests/fixtures/utb/max-entry/v1/max-entry.json'), 'utf8'),
) as IMaxEntry;

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

const NETWORK = 5;
const unsignedEntry = (epoch: bigint, committee: readonly IMember[], previousEntryId: Uint8Array): RootTrustBaseV2 =>
  RootTrustBaseV2.create({
    changeRecordHash: null,
    epoch,
    epochStartRound: epoch * 1000n,
    networkId: NETWORK,
    previousEntryId,
    quorumThreshold: (BigInt(committee.length) * 2n) / 3n + 1n,
    rootNodes: committee.map((m) => ({ nodeId: m.nodeId, signingKey: m.service.publicKey, weight: 1n })),
    stateHash: null,
  });

async function signedBy(entry: RootTrustBaseV2, signers: readonly IMember[]): Promise<RootTrustBaseV2> {
  const hash = await new DataHasher(HashAlgorithm.SHA256).update(entry.sigBytes()).digest();
  const signatures = new Map<string, Uint8Array>();
  for (const signer of signers) {
    signatures.set(signer.nodeId, (await signer.service.sign(hash)).encode());
  }
  return entry.withSignatures(signatures);
}

async function genesisHistory(committee: readonly IMember[]): Promise<TrustBaseHistory> {
  const genesis = unsignedEntry(1n, committee, new Uint8Array(32));
  return TrustBaseHistory.fromGenesis(genesis.toCBOR(), await genesis.entryId());
}

const refusal = async (promise: Promise<unknown>): Promise<TrustBaseError> => {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(TrustBaseError.is(error)).toBe(true);
  return error as TrustBaseError;
};

describe('the committee ceilings (§49): 256 members, 256 supplied signatures, 128 KiB per entry', () => {
  it('constants: 256 members, 128 KiB, and no separate admission bound', () => {
    expect(RootTrustBaseV2.MAX_MEMBERS).toBe(256);
    expect(RootTrustBaseV2.MAX_ENCODED_LENGTH).toBe(128 * 1024);
    expect(UnicitySealQuorumSignaturesVerificationRule.MAX_SIGNATURES).toBe(256);
    expect('MAX_ADMITTED_MEMBERS' in RootTrustBaseV2).toBe(false);
  });

  describe('the shared maximum-size entry (bft-go-base 81ee667: 256 members, 128-byte ids, 256 predecessor signatures)', () => {
    const decodeHex = HexConverter.decode;

    it('is the largest valid entry and below the bound', () => {
      expect(fixture.entryBytes).toBe(95365);
      expect(decodeHex(fixture.entry).length).toBe(fixture.entryBytes);
      expect(fixture.entryBytes).toBeLessThan(RootTrustBaseV2.MAX_ENCODED_LENGTH);
    });

    it('decodes and re-encodes to the same bytes with the shared entry ids', async () => {
      for (const [bytes, id] of [
        [fixture.genesis, fixture.genesisId],
        [fixture.entry, fixture.entryId],
      ]) {
        const entry = RootTrustBaseV2.fromCBOR(decodeHex(bytes));
        expect(entry.rootNodes).toHaveLength(256);
        expect(HexConverter.encode(entry.toCBOR())).toBe(bytes);
        expect(HexConverter.encode(await entry.entryId())).toBe(id);
      }
    });

    it('installs as a history: genesis under its pin, then the successor signed by all 256 members', async () => {
      const history = await TrustBaseHistory.fromGenesis(decodeHex(fixture.genesis), decodeHex(fixture.genesisId));
      await expect(history.append(decodeHex(fixture.entry))).resolves.toBe(true);
      expect(history.tip.epoch).toBe(2n);
    });

    it('loads as a two-entry bundle under its pin', async () => {
      const history = await TrustBaseHistory.fromBundle(decodeHex(fixture.bundle), decodeHex(fixture.genesisId));
      expect(history.tip.epoch).toBe(2n);
      const response = await TrustBaseResponse.decodeBundle(decodeHex(fixture.bundle), TrustBaseResponse.PAGE_LIMITS);
      expect(response.entries).toHaveLength(2);
    });

    it('is refused as an entry above 128 KiB, before decoding, and not for size at exactly 128 KiB', () => {
      const atBound = new Uint8Array(RootTrustBaseV2.MAX_ENCODED_LENGTH);
      expect(() => RootTrustBaseV2.fromCBOR(new Uint8Array(RootTrustBaseV2.MAX_ENCODED_LENGTH + 1))).toThrow(
        /exceed 131072/,
      );
      expect(() => RootTrustBaseV2.fromCBOR(atBound)).toThrow(TrustBaseError);
      let message = '';
      try {
        RootTrustBaseV2.fromCBOR(atBound);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).not.toMatch(/exceed/);
    });
  });

  describe('histories of 128 and 256 members', () => {
    it.each([128, 256])('%i members: a successor signed by every member of the predecessor installs', async (count) => {
      const committee = members(count, count === 256 ? 128 : 16);
      const history = await genesisHistory(committee);
      const next = await signedBy(unsignedEntry(2n, committee, history.tip.entryId), committee);
      await expect(history.append(next.toCBOR())).resolves.toBe(true);
      expect(history.tip.epoch).toBe(2n);
      expect(history.committee(2n)?.members.size).toBe(count);
    });

    it('256 members shrinking to 4: the 256 predecessor signatures carry it, and a quorum of the 4 alone does not', async () => {
      const big = members(256, 128);
      const history = await genesisHistory(big);
      const small = members(4, 128);
      const successor = unsignedEntry(2n, small, history.tip.entryId);
      // 256 signatures count against the predecessor's committee, not the successor's size.
      await expect(history.append((await signedBy(successor, big)).toCBOR())).resolves.toBe(true);

      const history2 = await genesisHistory(big);
      const successor2 = unsignedEntry(2n, small, history2.tip.entryId);
      const error = await refusal(history2.append((await signedBy(successor2, small)).toCBOR()));
      expect(error.reason).toBe('invalid');
      expect(history2.tip.epoch).toBe(1n);
    });

    it('257 members are refused, as a new entry and at the decoder', () => {
      const committee = members(257, 128);
      expect(() => unsignedEntry(1n, committee, new Uint8Array(32))).toThrow(/257 members \(1\.\.256\)/);
    });

    it('a successor of 256 members whose signatures are one short of the quorum is refused', async () => {
      const committee = members(256, 128);
      const history = await genesisHistory(committee);
      const next = unsignedEntry(2n, committee, history.tip.entryId);
      // quorum is 171 of 256
      await refusal(history.append((await signedBy(next, committee.slice(0, 170))).toCBOR()));
      await expect(history.append((await signedBy(next, committee.slice(0, 171))).toCBOR())).resolves.toBe(true);
    });
  });

  describe('seals with up to 256 supplied signatures', () => {
    const rule = new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier());
    const CONTENT = new Uint8Array(32).fill(0x11);
    const authority = (committee: readonly IMember[]): EpochListAuthority =>
      new EpochListAuthority(NetworkId.LOCAL, [
        {
          end: null,
          epoch: 1,
          members: committee.map((m) => ({
            key: HexConverter.encode(m.service.publicKey),
            nodeId: m.nodeId,
            weight: 1,
          })),
          start: 0,
          threshold: Math.floor((committee.length * 2) / 3) + 1,
        },
      ]);
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

    it.each([128, 256])('a seal signed by all %i members verifies', async (count) => {
      const committee = members(count, 128);
      const result = await rule.verify(authority(committee), await sealBy(committee));
      expect(result.status).toBe(VerificationStatus.OK);
    });

    it('256 signatures are the last count accepted; 257 is malformed before any signature is checked', async () => {
      const committee = members(256, 128);
      const extra = members(257, 128)[256];
      const ok = await sealBy(committee);
      expect(UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat(ok)).toBeNull();
      const over = await sealBy([...committee, extra]);
      expect(over.witnesses?.size).toBe(257);
      expect(UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat(over)).toMatch(
        /257 signatures exceed 256/,
      );
      const verifier = new Secp256k1SignatureVerifier();
      const spy = jest.spyOn(verifier, 'verify');
      const result = await new UnicitySealQuorumSignaturesVerificationRule(verifier).verify(authority(committee), over);
      expect(result.status).not.toBe(VerificationStatus.OK);
      expect(spy).not.toHaveBeenCalled();
    });

    it('the B1 profile keeps 16: the same 17-signature seal is malformed for a rule configured with 16 and verifies for the wallet default', async () => {
      const committee = members(17, 128);
      const seal = await sealBy(committee);
      const b1 = new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier(), undefined, {
        maxSignatures: 16,
      });
      expect(UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat(seal, 16)).toMatch(
        /17 signatures exceed 16/,
      );
      const refused = await b1.verify(authority(committee), seal);
      expect(refused.verdict).toBe('malformed');
      expect((await rule.verify(authority(committee), seal)).status).toBe(VerificationStatus.OK);
    });

    it('unknown signers count against the 256 like any other: 4 members and 252 strangers pass, 253 strangers are malformed', async () => {
      const committee = members(4, 128);
      const strangers = members(300, 128).slice(4);
      const at = await sealBy([...committee, ...strangers.slice(0, 252)]);
      expect(at.witnesses?.size).toBe(256);
      expect((await rule.verify(authority(committee), at)).status).toBe(VerificationStatus.OK);
      const over = await sealBy([...committee, ...strangers.slice(0, 253)]);
      expect(UnicitySealQuorumSignaturesVerificationRule.checkSignatureFormat(over)).toMatch(/257 signatures exceed/);
      expect((await rule.verify(authority(committee), over)).status).not.toBe(VerificationStatus.OK);
    });
  });
});
