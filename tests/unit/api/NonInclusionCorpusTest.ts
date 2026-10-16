import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { RootTrustBase } from '../../../src/api/bft/RootTrustBase.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../../../src/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { UnicityCertificateVerifier } from '../../../src/api/bft/verification/UnicityCertificateVerifier.js';
import { NonInclusionCertificate } from '../../../src/api/NonInclusionCertificate.js';
import { NonInclusionProof } from '../../../src/api/NonInclusionProof.js';
import { verifyNonInclusion } from '../../../src/api/NonInclusionVerification.js';
import { StateId } from '../../../src/api/StateId.js';
import { Secp256k1SignatureVerifier } from '../../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { CborSerializer } from '../../../src/serialization/cbor/CborSerializer.js';
import { HexConverter } from '../../../src/util/HexConverter.js';

/** Corpus aggregator-go `testdata/non-inclusion/v1`, vendored byte for byte, see PROVENANCE.md. */
const ROOT = join(process.cwd(), 'tests/fixtures/non-inclusion/v1');

interface ICase {
  readonly block: string;
  readonly certificate: string;
  readonly context: string;
  readonly expected: { readonly acceptable?: string[]; readonly verdict: string };
  readonly name: string;
  readonly query: string;
  readonly root: string;
  readonly uc: string;
  readonly wrapper: string;
}

interface IContext {
  readonly minRootRound: string;
  readonly nextEpochStart: string;
  readonly partition: number;
  readonly shardConfHash: string;
  readonly trustBaseJson: string;
}

const read = (path: string): string => readFileSync(join(ROOT, path), 'utf8');
const json = <T>(path: string): T => JSON.parse(read(path)) as T;
const contexts = json<Record<string, IContext>>('contexts.json');
const files = (dir: string): string[] =>
  readdirSync(join(ROOT, dir))
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => `${dir}/${f}`);

function stateIdOf(hex: string): StateId {
  return StateId.fromCBOR(CborSerializer.encodeByteString(HexConverter.decode(hex)));
}

/** The verdict of this SDK for a wrapper, in the vocabulary of the corpus. */
async function verdictOf(c: ICase): Promise<string> {
  const context = contexts[c.context];
  let proof: NonInclusionProof;
  try {
    proof = NonInclusionProof.decode(stateIdOf(c.query), HexConverter.decode(c.wrapper));
  } catch {
    return 'malformed';
  }
  const trustBase = RootTrustBase.fromJSON(JSON.parse(read(context.trustBaseJson)));
  const verifier = new UnicityCertificateVerifier(
    new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier()),
  );
  const result = await verifyNonInclusion(
    proof,
    { trustBase, unicityCertificateVerifier: verifier },
    {
      expectedPartition: BigInt(context.partition),
      minRound: BigInt(context.minRootRound),
      ...(BigInt(context.nextEpochStart) > 0n ? { nextEpochStartRound: BigInt(context.nextEpochStart) } : {}),
      ...(context.shardConfHash ? { shardConfigurationHash: HexConverter.decode(context.shardConfHash) } : {}),
    },
  );
  return result.verdict;
}

describe('non-inclusion corpus v1', () => {
  it('is the vendored corpus, unchanged', () => {
    const manifest = json<{ sha256: Record<string, string> }>('manifest.json');
    for (const [path, sha] of Object.entries(manifest.sha256)) {
      expect(
        createHash('sha256')
          .update(readFileSync(join(ROOT, path)))
          .digest('hex'),
      ).toEqual(sha);
    }
  });

  describe('positive cases', () => {
    it.each(files('cases'))('%s', async (path) => {
      const c = json<ICase>(path);
      expect(await verdictOf(c)).toEqual(c.expected.verdict);
      if (c.certificate.length > 0 || c.root === '') {
        // the codec reproduces the bytes of the producers
        const bytes = HexConverter.decode(c.certificate);
        expect(NonInclusionCertificate.fromBytes(bytes).toBytes()).toEqual(bytes);
      }
      const wrapper = HexConverter.decode(c.wrapper);
      expect(NonInclusionProof.decode(stateIdOf(c.query), wrapper).toCBOR()).toEqual(wrapper);
      // the building block alone agrees with the verdict on the authenticated root of the case
      const relation = await NonInclusionCertificate.fromBytes(
        HexConverter.decode(c.certificate),
      ).verifyAgainstTrustedRoot(stateIdOf(c.query), c.root === '' ? null : HexConverter.decode(c.root));
      expect(relation === 'certificate_invalid' ? 'certificate_invalid' : relation).toEqual(
        c.expected.verdict === 'absent' || c.expected.verdict === 'state_included' ? c.expected.verdict : relation,
      );
    });
  });

  describe('negative cases never loosen a decoder to reach a later class', () => {
    it.each(files('negative'))('%s', async (path) => {
      const c = json<ICase>(path);
      const verdict = await verdictOf(c);
      if (c.expected.verdict === 'absent' || c.expected.verdict === 'state_included') {
        expect(verdict).toEqual(c.expected.verdict);
      } else {
        expect(verdict).not.toEqual('absent');
        expect(verdict).not.toEqual('state_included');
        expect([c.expected.verdict, ...(c.expected.acceptable ?? [])]).toContain(verdict);
      }
    });
  });
});
