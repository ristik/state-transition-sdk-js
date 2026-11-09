import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { UnicityCertificate } from '../../../../src/api/bft/UnicityCertificate.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../../../../src/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { UnicityCertificateVerifier } from '../../../../src/api/bft/verification/UnicityCertificateVerifier.js';
import { NetworkId } from '../../../../src/api/NetworkId.js';
import { Secp256k1SignatureVerifier } from '../../../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { HexConverter } from '../../../../src/util/HexConverter.js';
import { EpochListAuthority, ITestEpoch } from '../../../utils/EpochListAuthority.js';

interface ICase {
  epochs: ITestEpoch[];
  expectedPartition: number;
  id: string;
  network: number;
  uc: string;
}

const cases = (
  JSON.parse(readFileSync(join(process.cwd(), 'tests/fixtures/b1-seals/v1/b1-seal-vectors-v1.json'), 'utf8')) as {
    cases: ICase[];
  }
).cases;
const byId = (id: string): ICase => cases.find((c) => c.id === id) as ICase;
const B1_DECODING = { allowNullSignatures: true };

const verifier = new UnicityCertificateVerifier(
  new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier(), undefined, { maxSignatures: 16 }),
);

function verify(
  c: ICase,
  epochs: ITestEpoch[],
  network: number = c.network,
): ReturnType<typeof verifier.verifyCertificate> {
  return verifier.verifyCertificate(
    new EpochListAuthority(NetworkId.fromId(network), epochs),
    UnicityCertificate.decodeWithOptions(HexConverter.decode(c.uc), B1_DECODING),
    { partitionId: BigInt(c.expectedPartition) },
  );
}

describe('B1 verdict classes under the registry variants', () => {
  // The signature bound is a property of the seal alone (B1: ErrTooManySigs): whatever the registry holds, the verdict is `malformed`.
  describe.each(['bound.signatures-17', 'quorum.sigs-17'])('%s (17 signatures, limit 16)', (id) => {
    const c = byId(id);
    const registries: [string, ITestEpoch[], number][] = [
      ['as is', c.epochs, c.network],
      ['the seal epoch above the tip', [{ ...c.epochs[0], end: null, epoch: 3, start: 1 }], c.network],
      ['an empty registry', [], c.network],
      ['another network', c.epochs, c.network + 1],
      ['a round before the epoch start', [{ ...c.epochs[0], start: 1_000_000_000 }], c.network],
    ];
    it.each(registries)('is malformed with %s', async (_name, epochs, network) => {
      const result = await verify(c, epochs, network);
      expect({ missing: result.missing, verdict: result.verdict }).toEqual({ missing: null, verdict: 'malformed' });
    });
  });

  // The retryable class: the seal's epoch is newer than the latest held entry, with the missing epoch and the latest held one (null if none).
  describe('no_entry_for_epoch', () => {
    const c = byId('cert.single.ok');

    it('accepts the certificate with its own entry', async () => {
      expect((await verify(c, c.epochs)).verdict).toBe('ok');
    });

    it('reports the missing epoch and the latest held one for a seal above the tip', async () => {
      const held = [{ ...c.epochs[0], end: null, epoch: 3, start: 1 }];
      const result = await verify(c, held);
      expect(result.verdict).toBe('no_entry_for_epoch');
      expect(result.missing).toEqual({ epoch: 7n, latest: 3n });
    });

    it('reports latest null for an empty history', async () => {
      const result = await verify(c, []);
      expect(result.verdict).toBe('no_entry_for_epoch');
      expect(result.missing).toEqual({ epoch: 7n, latest: null });
    });
  });
});
