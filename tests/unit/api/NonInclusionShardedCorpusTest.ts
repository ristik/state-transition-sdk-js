import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { RootTrustBase } from '../../../src/api/bft/RootTrustBase.js';
import { ShardId } from '../../../src/api/bft/ShardId.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '../../../src/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { UnicityCertificateVerifier } from '../../../src/api/bft/verification/UnicityCertificateVerifier.js';
import { NonInclusionProof } from '../../../src/api/NonInclusionProof.js';
import { verifyNonInclusion } from '../../../src/api/NonInclusionVerification.js';
import { StateId } from '../../../src/api/StateId.js';
import { Secp256k1SignatureVerifier } from '../../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { CborSerializer } from '../../../src/serialization/cbor/CborSerializer.js';
import { HexConverter } from '../../../src/util/HexConverter.js';

/** Go-generated sharded vectors, see PROVENANCE.md. */
interface IVectors {
  readonly cases: readonly {
    readonly authorityBits: number;
    readonly name: string;
    readonly query: string;
    readonly ucShard: string;
    readonly verdicts: Record<'other' | 'own' | 'unsharded', { expected: string; shard: string }>;
    readonly wrapper: string;
  }[];
  readonly partition: number;
  readonly trustBases: Record<string, unknown>;
}

const vectors = JSON.parse(
  readFileSync(join(process.cwd(), 'tests/fixtures/non-inclusion-sharded/v1/sharded-vectors.json'), 'utf8'),
) as IVectors;

const verifier = new UnicityCertificateVerifier(
  new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier()),
);

function stateIdOf(hex: string): StateId {
  return StateId.fromCBOR(CborSerializer.encodeByteString(HexConverter.decode(hex)));
}

describe('sharded non-inclusion proofs against the Go verifier', () => {
  it('has the expected spread of vectors', () => {
    const own = vectors.cases.map((c) => c.verdicts.own.expected);
    expect(vectors.cases.length).toBeGreaterThanOrEqual(200);
    expect(own.filter((v) => v === 'absent').length).toBeGreaterThan(30);
    expect(own.filter((v) => v === 'state_included').length).toBeGreaterThan(30);
    expect(own.filter((v) => v === 'certificate_invalid').length).toBeGreaterThan(30);
  });

  it('gives Go verdict for every vector under the certified shard, another shard and the unsharded context', async () => {
    const mismatches: string[] = [];
    for (const c of vectors.cases) {
      const trustBase = RootTrustBase.fromJSON(vectors.trustBases[String(c.authorityBits)]);
      const proof = NonInclusionProof.decode(stateIdOf(c.query), HexConverter.decode(c.wrapper));
      for (const [context, verdict] of Object.entries(c.verdicts)) {
        const result = await verifyNonInclusion(
          proof,
          { trustBase, unicityCertificateVerifier: verifier },
          {
            expectedPartition: BigInt(vectors.partition),
            ...(verdict.shard === '' ? {} : { shard: ShardId.fromBits(verdict.shard) }),
          },
        );
        if (result.verdict !== verdict.expected) {
          mismatches.push(`${c.name} [${context}]: ${result.verdict} (${result.message}), Go says ${verdict.expected}`);
        }
      }
    }
    expect(mismatches).toEqual([]);
  });
});
