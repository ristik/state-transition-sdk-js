import { BatchProofError } from '../../../src/api/BatchProofError.js';
import { PartitionView } from '../../../src/api/bft/PartitionView.js';
import { UnicityCertificate } from '../../../src/api/bft/UnicityCertificate.js';
import { UnicitySeal } from '../../../src/api/bft/UnicitySeal.js';
import { CertificationResponse } from '../../../src/api/CertificationResponse.js';
import { InclusionProofBatch } from '../../../src/api/IBatchAggregatorClient.js';
import { InclusionProof } from '../../../src/api/InclusionProof.js';
import { InclusionProofResponse } from '../../../src/api/InclusionProofResponse.js';
import { ConsolidationError } from '../../../src/consolidation/ConsolidationError.js';
import { ConsolidationResult } from '../../../src/consolidation/ConsolidationResult.js';
import { ShardRouting } from '../../../src/consolidation/ShardRouting.js';
import { TokenProofClient } from '../../../src/consolidation/TokenProofClient.js';
import { Secp256k1SignatureVerifier } from '../../../src/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { Token } from '../../../src/transaction/Token.js';
import { HexConverter } from '../../../src/util/HexConverter.js';
import { VerificationStatus } from '../../../src/verification/VerificationStatus.js';
import { IScenario, scenario, NestedTokenJustification } from '../../utils/ConsolidationScenario.js';
import { shardIdFromBits, WORLD_PARTITION } from '../../utils/ShardedWorld.js';

jest.setTimeout(120_000);

function routingOf(s: IScenario): ShardRouting {
  return new ShardRouting({
    endpoints: s.world.bits.map((b) => ({ client: s.world.client(b), shard: shardIdFromBits(b) })),
    networkId: s.world.network,
    partitionId: WORLD_PARTITION,
    scheme: s.world.scheme,
  });
}

function clientOf(s: IScenario, signatureVerifier?: Secp256k1SignatureVerifier): TokenProofClient {
  return new TokenProofClient({ routing: routingOf(s), signatureVerifier, verificationContext: s.context });
}

function shardsOf(token: Token): Set<string> {
  return new Set(
    [token.genesis, ...token.transactions].map((t) =>
      t.inclusionProof.unicityCertificate.shardTreeCertificate.shard.toString(),
    ),
  );
}

function sealsOf(token: Token): Set<string> {
  return new Set(
    [token.genesis, ...token.transactions].map((t) =>
      HexConverter.encode(t.inclusionProof.unicityCertificate.unicitySeal.toCBOR()),
    ),
  );
}

/** A token whose proofs sit in at least `shards` different shards. */
async function spanning(s: IScenario, transfers: number, shards: number): Promise<Token> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const token = await s.history(transfers);
    if (shardsOf(token).size >= shards) {
      return token;
    }
  }
  throw new Error('could not build a token spanning enough shards');
}

function unavailable(result: ConsolidationResult): { reason: string; retryable: boolean } {
  expect(result.status).toEqual('unavailable');
  return result as { reason: string; retryable: boolean };
}

async function expectError(promise: Promise<unknown>, kind: string, outcome?: string): Promise<ConsolidationError> {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(ConsolidationError);
  expect((error as ConsolidationError).kind).toEqual(kind);
  if (outcome) {
    expect((error as ConsolidationError).outcome).toEqual(outcome);
  }
  return error as ConsolidationError;
}

describe('TokenProofClient', () => {
  describe('consolidation', () => {
    it.each([0, 1, 2])('replaces the outer history of a token over %i shard bits', async (bits) => {
      const s = await scenario(bits);
      const token = await spanning(s, 4, bits === 0 ? 1 : 2);
      const before = token.toCBOR();
      expect(sealsOf(token).size).toBeGreaterThan(1);
      s.world.requests.length = 0;
      const verifier = new Secp256k1SignatureVerifier();
      const verifySpy = jest.spyOn(verifier, 'verify');

      const result = await clientOf(s, verifier).consolidate(token);
      expect(result.status).toEqual('consolidated');
      if (result.status !== 'consolidated') {
        return;
      }

      // fully verified, immutable, one seal over the outer history
      expect((await result.token.verify(s.context)).status).toEqual(VerificationStatus.OK);
      expect(sealsOf(result.token).size).toEqual(1);
      expect(result.summary.consolidatedSeals).toEqual(1);
      expect(result.summary.originalSeals).toEqual(sealsOf(token).size);
      expect(result.summary.alreadyConsolidated).toBe(false);

      // the input is untouched and signed bytes, identities and reference times are preserved
      expect(token.toCBOR()).toEqual(before);
      expect(result.token.id.toString()).toEqual(token.id.toString());
      expect(result.token.transactions).toHaveLength(token.transactions.length);
      const pairs = [
        [token.genesis, result.token.genesis],
        ...token.transactions.map((t, i) => [t, result.token.transactions[i]]),
      ] as [typeof token.genesis, typeof token.genesis][];
      for (const [original, replaced] of pairs) {
        expect(replaced.referenceTime).toEqual(original.referenceTime);
        expect(replaced.inclusionProof.certificationData.toCBOR()).toEqual(
          original.inclusionProof.certificationData.toCBOR(),
        );
        expect((await replaced.calculateTransactionHash()).equals(await original.calculateTransactionHash())).toBe(
          true,
        );
        expect((await replaced.calculateStateHash()).equals(await original.calculateStateHash())).toBe(true);
      }

      // one master wave and one parallel exact-root wave: m requests, m = participating shards
      const batches = s.world.requests.filter((r) => r.method === 'getInclusionProofs');
      expect(batches).toHaveLength(shardsOf(token).size);
      expect(batches[0].exactRoot).toBeNull();
      expect(batches.slice(1).every((r) => r.exactRoot !== null)).toBe(true);
      expect(s.world.requests.filter((r) => r.method !== 'getInclusionProofs')).toHaveLength(0);
      expect(result.summary.requests).toEqual(batches.length);

      // one quorum check per distinct complete seal, one signature each: the master seal here is the seal of the
      // newest original proof (nothing was certified since), so it is a memo hit, not a second check
      expect(verifySpy).toHaveBeenCalledTimes(sealsOf(token).size);
      expect(result.summary.quorumChecks).toEqual(0);
      expect(result.summary.evidenceQuorumChecks).toEqual(sealsOf(token).size);
    });

    it('checks a fresh master seal once, however many proofs carry it', async () => {
      const s = await scenario(2);
      const token = await spanning(s, 5, 2);
      await s.world.idle(2); // the root chain moved on: the master seal is a seal no original proof carries
      const verifier = new Secp256k1SignatureVerifier();
      const verifySpy = jest.spyOn(verifier, 'verify');
      const result = await clientOf(s, verifier).consolidate(token);
      expect(result.status).toEqual('consolidated');
      if (result.status === 'consolidated') {
        expect(result.summary.quorumChecks).toEqual(1);
        expect(result.summary.masterRound).toBeGreaterThan(result.summary.requiredRound);
        // originals once each, plus exactly one check of the master seal for the whole consolidated history
        expect(verifySpy).toHaveBeenCalledTimes(sealsOf(token).size + 1);
        expect(sealsOf(result.token).size).toEqual(1);
      }
    });

    it('returns an already consolidated token without any request', async () => {
      const s = await scenario(1);
      const token = await spanning(s, 3, 1);
      const first = await clientOf(s).consolidate(token);
      if (first.status !== 'consolidated') {
        throw new Error('expected consolidation');
      }
      s.world.requests.length = 0;
      const again = await clientOf(s).consolidate(first.token);
      expect(again.status).toEqual('consolidated');
      if (again.status === 'consolidated') {
        expect(again.summary.alreadyConsolidated).toBe(true);
        expect(again.summary.requests).toEqual(0);
        expect(again.token).toBe(first.token);
      }
      expect(s.world.requests).toHaveLength(0);
    });

    it('keeps proofs nested in a signed mint justification byte for byte', async () => {
      const s = await scenario(1);
      const nested = await s.history(2);
      const outer = await s.history(2, new NestedTokenJustification(nested));
      s.world.requests.length = 0;

      const result = await clientOf(s).consolidate(outer);
      expect(result.status).toEqual('consolidated');
      if (result.status !== 'consolidated') {
        return;
      }
      expect(result.token.genesis.justification).toEqual(outer.genesis.justification);
      expect(result.token.genesis.justification).toEqual(new NestedTokenJustification(nested).toCBOR());
      // the nested token still carries its own, different seals: the one-seal claim is for the outer history only
      expect(sealsOf(nested).size).toBeGreaterThan(1);
      expect(sealsOf(result.token).size).toEqual(1);
      expect((await result.token.verify(s.context)).status).toEqual(VerificationStatus.OK);
      // nested proofs were not requested
      const requested = s.world.requests.filter((r) => r.method === 'getInclusionProofs').length;
      expect(requested).toEqual(shardsOf(outer).size);
    });

    it('performs no consolidation request in ordinary flows', async () => {
      const s = await scenario(2);
      const token = await s.history(3);
      await token.verify(s.context);
      expect(s.world.requests.some((r) => r.method === 'getInclusionProofs')).toBe(false);
    });
  });

  describe('unavailable outcomes leave the token intact', () => {
    const failing =
      (...errors: BatchProofError[]) =>
      (s: IScenario): void => {
        s.world.faults.set('', { failBatch: errors });
      };
    const cases: [string, (s: IScenario) => void, string, boolean][] = [
      [
        'busy',
        failing(
          new BatchProofError('unavailable', 'busy', { code: -32006, detail: 'busy:pinned_views', retryable: true }),
        ),
        'busy',
        true,
      ],
      [
        'unsupported configuration',
        failing(new BatchProofError('unsupported', 'x', { code: -32008, detail: 'unsupported_configuration' })),
        'unsupported_configuration',
        false,
      ],
      [
        'method not found',
        failing(new BatchProofError('unsupported', 'x', { code: -32601, detail: 'method_not_found' })),
        'unsupported_capability',
        false,
      ],
      [
        'view not retained',
        failing(
          new BatchProofError('unavailable', 'x', { code: -32008, detail: 'view_not_retained', retryable: true }),
        ),
        'target_not_retained',
        true,
      ],
      [
        'no finalized view',
        failing(
          new BatchProofError('unavailable', 'x', { code: -32008, detail: 'no_finalized_view', retryable: true }),
        ),
        'pending_publication',
        true,
      ],
      [
        'limit exceeded',
        failing(new BatchProofError('limit_exceeded', 'x', { code: -32007, detail: 'response_bytes' })),
        'limit_exceeded',
        false,
      ],
      [
        'withheld partition view',
        (s): void => void s.world.faults.set('', { withholdView: true }),
        'partition_view_unavailable',
        true,
      ],
      ['publication lag', (s): void => void s.world.faults.set('', { lag: 1 }), 'pending_publication', true],
    ];

    it.each(cases)('%s', async (_name, arrange, reason, retryable) => {
      const s = await scenario(0);
      const token = await s.history(3);
      const before = token.toCBOR();
      arrange(s);
      const result = unavailable(await clientOf(s).consolidate(token));
      expect(result.reason).toEqual(reason);
      expect(result.retryable).toEqual(retryable);
      expect(token.toCBOR()).toEqual(before);
    });

    it('reports an evicted peer root as not retained', async () => {
      const s = await scenario(2);
      const token = await spanning(s, 5, 2);
      const routing = new ShardRouting({
        endpoints: s.world.bits.map((b) => {
          const client = s.world.client(b);
          const call = client.getInclusionProofs.bind(client);
          client.getInclusionProofs = (ids, options): Promise<InclusionProofBatch> =>
            options?.stateRoot
              ? Promise.reject(
                  new BatchProofError('unavailable', 'x', {
                    code: -32008,
                    detail: 'view_not_retained',
                    retryable: true,
                  }),
                )
              : call(ids, options);
          return { client, shard: shardIdFromBits(b) };
        }),
        partitionId: WORLD_PARTITION,
        scheme: s.world.scheme,
      });
      const result = unavailable(
        await new TokenProofClient({ routing, verificationContext: s.context }).consolidate(token),
      );
      expect(result.reason).toEqual('target_not_retained');
    });

    it('does not emulate a missing batch capability, and makes no request', async () => {
      const s = await scenario(1);
      const token = await spanning(s, 3, 1);
      s.world.requests.length = 0;
      const routing = new ShardRouting({
        endpoints: s.world.bits.map((b) => {
          const full = s.world.client(b);
          // a custom transport that only has the required methods
          return {
            client: {
              getInclusionProof: (id, o): Promise<InclusionProofResponse> => full.getInclusionProof(id, o),
              submitCertificationRequest: (d): Promise<CertificationResponse> => full.submitCertificationRequest(d),
            },
            shard: shardIdFromBits(b),
          };
        }),
        partitionId: WORLD_PARTITION,
        scheme: s.world.scheme,
      });
      const result = unavailable(
        await new TokenProofClient({ routing, verificationContext: s.context }).consolidate(token),
      );
      expect(result.reason).toEqual('unsupported_capability');
      expect(s.world.requests).toHaveLength(0);
    });
  });

  describe('typed errors', () => {
    it.each([
      ['transport', new BatchProofError('transport', 'down', { retryable: true }), 'transport'],
      ['server', new BatchProofError('server', 'db', { code: -32004 }), 'server'],
      ['rejected', new BatchProofError('rejected', 'bad', { code: -32602, detail: 'wrong_shard' }), 'rejected'],
      ['invalid response', new BatchProofError('invalid_response', 'garbage'), 'invalid_response'],
    ])('%s failures are errors, never unavailability', async (_n, failure, kind) => {
      const s = await scenario(0);
      const token = await s.history(2);
      const before = token.toCBOR();
      s.world.faults.set('', { failBatch: [failure] });
      await expectError(clientOf(s).consolidate(token), kind);
      expect(token.toCBOR()).toEqual(before);
    });

    it('a plain network error from a custom client is a retryable transport failure', async () => {
      const s = await scenario(0);
      const token = await s.history(2);
      s.world.faults.set('', { failBatch: [new TypeError('fetch failed')] });
      const error = await expectError(clientOf(s).consolidate(token), 'transport');
      expect(error.retryable).toBe(true);
    });

    it('rejects a token that does not verify before any request', async () => {
      const s = await scenario(0);
      const token = await s.history(2);
      const other = await scenario(0); // another authority
      s.world.requests.length = 0;
      const foreign = new TokenProofClient({
        routing: routingOf(s),
        verificationContext: other.context,
      });
      await expectError(foreign.consolidate(token), 'integrity', 'invalid_input');
      expect(s.world.requests).toHaveLength(0);
    });

    it('refuses a routing for another network than the trust base', async () => {
      const s = await scenario(0);
      const routing = new ShardRouting({
        endpoints: [{ client: s.world.client(''), shard: shardIdFromBits('') }],
        networkId: (await import('../../../src/api/NetworkId.js')).NetworkId.MAINNET,
        partitionId: WORLD_PARTITION,
        scheme: [],
      });
      expect(() => new TokenProofClient({ routing, verificationContext: s.context })).toThrow(ConsolidationError);
    });

    it('refuses a master that does not take part', async () => {
      const s = await scenario(1);
      const token = await spanning(s, 1, 1);
      const missing = s.world.bits.find((b) => !shardsOf(token).has(b)) ?? '0';
      if (shardsOf(token).has(missing)) {
        return;
      }
      await expectError(clientOf(s).consolidate(token, { master: shardIdFromBits(missing) }), 'input', 'invalid_input');
    });
  });

  describe('integrity failures are never unavailability', () => {
    function mutate(
      batch: InclusionProofBatch,
      change: (r: InclusionProofResponse) => InclusionProofResponse,
    ): InclusionProofBatch {
      return new InclusionProofBatch(batch.proofs.map(change), batch.partitionViewBytes);
    }

    it('a tampered partition view', async () => {
      const s = await scenario(1);
      const token = await spanning(s, 4, 2);
      for (const bits of s.world.bits) {
        s.world.faults.set(bits, {
          tamper: (batch) => {
            const view = batch.partitionViewBytes;
            if (!view) {
              return batch;
            }
            const bytes = new Uint8Array(view);
            bytes[bytes.length - 5] ^= 1; // a committed hash inside a leaf
            return new InclusionProofBatch(batch.proofs, bytes);
          },
        });
      }
      const error = await expectError(clientOf(s).consolidate(token), 'integrity');
      expect(['invalid_input', 'binding_mismatch']).toContain(error.outcome);
    });

    it('a master seal with an altered signature', async () => {
      const s = await scenario(0);
      const token = await s.history(3);
      s.world.faults.set('', {
        tamper: (batch) =>
          mutate(batch, (response) => {
            const proof = response.inclusionProof;
            if (!proof) {
              return response;
            }
            const uc = proof.unicityCertificate;
            const sealBytes = uc.unicitySeal.toCBOR();
            // flip a byte inside the signature map
            sealBytes[sealBytes.length - 3] ^= 1;
            const forged = new UnicityCertificate(
              uc.inputRecord,
              uc.technicalRecordHash,
              uc.shardConfigurationHash,
              uc.shardTreeCertificate,
              uc.unicityTreeCertificate,
              UnicitySeal.fromCBOR(sealBytes),
            );
            return InclusionProofResponse.certified(
              response.blockNumber,
              new InclusionProof(proof.certificationData, proof.referenceTime, proof.inclusionCertificate, forged),
            );
          }),
      });
      const error = await expectError(clientOf(s).consolidate(token), 'integrity');
      expect(error.outcome).toEqual('unauthenticated');
    });

    it('a peer answering at another root than the view commits to', async () => {
      const s = await scenario(1);
      const token = await spanning(s, 6, 2);
      // peers serve their newest state although the view of the master points at an older root
      await s.world.idle(2);
      for (const bits of s.world.bits) {
        s.world.faults.set(bits, {
          tamper: (batch, exact) => {
            if (!exact) {
              return batch;
            }
            const rounds = s.world.retained();
            const latest = rounds.at(-1);
            return mutate(batch, (response) => {
              const proof = response.inclusionProof;
              if (!proof || !latest) {
                return response;
              }
              const uc = latest.ucs.get(proof.unicityCertificate.shardTreeCertificate.shard.toString());
              if (!uc) {
                return response;
              }
              return InclusionProofResponse.certified(
                response.blockNumber,
                new InclusionProof(proof.certificationData, proof.referenceTime, proof.inclusionCertificate, uc),
              );
            });
          },
        });
      }
      const result = await clientOf(s)
        .consolidate(token)
        .then(
          (r) => r,
          (e: unknown) => e,
        );
      // either the roots happen to coincide (no later write changed the shard) or the binding is refused
      if (result instanceof ConsolidationError) {
        expect(result.kind).toEqual('integrity');
        expect(result.outcome).toEqual('binding_mismatch');
      } else {
        expect((result as ConsolidationResult).status).toEqual('consolidated');
      }
    });

    it('a response proof of another leaf value', async () => {
      const s = await scenario(0);
      const token = await s.history(3);
      s.world.faults.set('', {
        tamper: (batch) =>
          mutate(batch, (response) => {
            const proof = response.inclusionProof;
            if (!proof) {
              return response;
            }
            return InclusionProofResponse.certified(
              response.blockNumber,
              new InclusionProof(
                proof.certificationData,
                proof.referenceTime + 1n,
                proof.inclusionCertificate,
                proof.unicityCertificate,
              ),
            );
          }),
      });
      const error = await expectError(clientOf(s).consolidate(token), 'integrity');
      expect(error.outcome).toEqual('binding_mismatch');
    });
  });

  describe('deadline, cancellation and parallelism', () => {
    it('times out under one total deadline and aborts outstanding requests', async () => {
      const s = await scenario(2);
      const token = await spanning(s, 5, 2);
      const before = token.toCBOR();
      for (const bits of s.world.bits) {
        s.world.faults.set(bits, { gate: new Promise<void>(() => undefined) }); // never released
      }
      const started = Date.now();
      const error = await expectError(clientOf(s).consolidate(token, { timeoutMs: 150 }), 'timeout');
      expect(Date.now() - started).toBeLessThan(5000);
      expect(error.retryable).toBe(true);
      expect(s.world.inFlight).toEqual(0);
      expect(token.toCBOR()).toEqual(before);
    });

    it('cancels through the caller signal, typed as cancelled and never retryable', async () => {
      const s = await scenario(2);
      const token = await spanning(s, 5, 2);
      for (const bits of s.world.bits) {
        s.world.faults.set(bits, { gate: new Promise<void>(() => undefined) });
      }
      const controller = new AbortController();
      const pending = clientOf(s).consolidate(token, { signal: controller.signal, timeoutMs: 60_000 });
      setTimeout(() => controller.abort(), 100);
      const error = await expectError(pending, 'cancelled');
      expect(error.retryable).toBe(false);
      expect(s.world.inFlight).toEqual(0);

      // an already aborted signal makes no request at all
      s.world.requests.length = 0;
      const aborted = new AbortController();
      aborted.abort();
      await expectError(clientOf(s).consolidate(token, { signal: aborted.signal }), 'cancelled');
      expect(s.world.requests.filter((r) => r.method === 'getInclusionProofs')).toHaveLength(0);
    });

    it('bounds the exact-root wave and reports the originating failure of a failing peer', async () => {
      const s = await scenario(3);
      const token = await spanning(s, 14, 4);
      s.world.maxInFlight = 0;
      const ok = await clientOf(s).consolidate(token, { maxParallel: 2 });
      expect(ok.status).toEqual('consolidated');
      expect(s.world.maxInFlight).toBeLessThanOrEqual(2);

      // one peer fails with a typed error: that error is reported, not the cancellation of its siblings
      const newest = token.transactions.length > 0 ? token.transactions.at(-1) : token.genesis;
      const master = newest?.inclusionProof.unicityCertificate.shardTreeCertificate.shard.toString();
      const failing = [...shardsOf(token)].filter((b) => b !== master).at(-1) as string;
      const routing = new ShardRouting({
        endpoints: s.world.bits.map((b) => {
          const client = s.world.client(b);
          const call = client.getInclusionProofs.bind(client);
          client.getInclusionProofs = async (ids, options): Promise<InclusionProofBatch> => {
            if (b === failing && options?.stateRoot) {
              throw new BatchProofError('server', 'database', { code: -32004 });
            }
            if (options?.stateRoot) {
              await new Promise((resolve) => setTimeout(resolve, 20));
            }
            return call(ids, options);
          };
          return { client, shard: shardIdFromBits(b) };
        }),
        partitionId: WORLD_PARTITION,
        scheme: s.world.scheme,
      });
      await expectError(
        new TokenProofClient({ routing, verificationContext: s.context }).consolidate(token, { maxParallel: 3 }),
        'server',
      );
    });
  });

  describe('views of the exact roots', () => {
    it('never replaces an exact root by the latest view', async () => {
      const s = await scenario(1);
      const token = await spanning(s, 5, 2);
      const exactRoots: string[] = [];
      const routing = new ShardRouting({
        endpoints: s.world.bits.map((b) => {
          const client = s.world.client(b);
          const call = client.getInclusionProofs.bind(client);
          client.getInclusionProofs = (ids, options): Promise<InclusionProofBatch> => {
            if (options?.stateRoot) {
              exactRoots.push(HexConverter.encode(options.stateRoot.data));
            }
            return call(ids, options);
          };
          return { client, shard: shardIdFromBits(b) };
        }),
        partitionId: WORLD_PARTITION,
        scheme: s.world.scheme,
      });
      const result = await new TokenProofClient({ routing, verificationContext: s.context }).consolidate(token);
      expect(result.status).toEqual('consolidated');
      // the roots requested are the ones of the authenticated view
      const view = PartitionView.fromCBOR(s.world.latest.view.toCBOR());
      const committed = view.leaves.map((l) => HexConverter.encode(l.inputRecord.hash));
      expect(exactRoots.length).toBeGreaterThan(0);
      for (const root of exactRoots) {
        expect(committed).toContain(root);
      }
    });
  });
});
