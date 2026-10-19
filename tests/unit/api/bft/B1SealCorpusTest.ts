import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { UnicityCertificate } from '../../../../src/api/bft/UnicityCertificate.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../../../../src/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { UnicityCertificateVerifier } from '../../../../src/api/bft/verification/UnicityCertificateVerifier.js';
import { NetworkId } from '../../../../src/api/NetworkId.js';
import { Secp256k1SignatureVerifier } from '../../../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { HexConverter } from '../../../../src/util/HexConverter.js';
import { EpochListAuthority, ITestEpoch } from '../../../utils/EpochListAuthority.js';

/** tests/fixtures/b1-seals/v1: unicity certificates with B1's verdicts, derived from the bft-core any-age corpus (shared with the Rust SDK). */
interface ICorpus {
  cases: {
    b1Sentinel?: string;
    epochs: ITestEpoch[];
    expectedPartition: number;
    id: string;
    network: number;
    uc: string;
    verdict: 'invalid' | 'malformed' | 'valid';
  }[];
  format: string;
}

const corpus = JSON.parse(
  readFileSync(join(process.cwd(), 'tests/fixtures/b1-seals/v1/b1-seal-vectors-v1.json'), 'utf8'),
) as ICorpus;

describe('B1 seal corpus: certificate acceptance equals the native any-age verifier', () => {
  const verifier = new UnicityCertificateVerifier(
    new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier()),
  );

  it('has the expected format', () => {
    expect(corpus.format).toBe('b1-seal-vectors/v1');
  });

  // B1 requires the certificate to re-encode byte for byte (b1ref decodeUC, ErrReencode): every certificate that decodes must do so here too,
  // including a null path collection, which stays null
  it.each(corpus.cases.filter((c) => c.verdict !== 'malformed'))('$id re-encodes byte for byte', (c) => {
    expect(HexConverter.encode(UnicityCertificate.fromCBOR(HexConverter.decode(c.uc)).toCBOR())).toBe(c.uc);
  });

  it.each(corpus.cases)('$id ($verdict $b1Sentinel)', async (c) => {
    let verdict: string;
    let detail = '';
    let certificate: UnicityCertificate | null = null;
    try {
      certificate = UnicityCertificate.fromCBOR(HexConverter.decode(c.uc));
    } catch (error) {
      verdict = 'malformed';
      detail = String(error);
    }
    if (certificate !== null) {
      const result = await verifier.verifyCertificate(
        new EpochListAuthority(NetworkId.fromId(c.network), c.epochs),
        certificate,
        { partitionId: BigInt(c.expectedPartition) },
      );
      verdict = result.verdict === 'ok' ? 'valid' : result.verdict;
      detail = result.toString();
    }
    expect({ detail: verdict! === c.verdict ? '' : detail, verdict: verdict! }).toEqual({
      detail: '',
      verdict: c.verdict,
    });
  });
});
