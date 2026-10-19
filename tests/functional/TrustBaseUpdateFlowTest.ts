import { TestAggregatorClient } from './TestAggregatorClient.js';
import { RootTrustBaseV2 } from '../../src/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseHistory } from '../../src/api/bft/trustbase/TrustBaseHistory.js';
import { CertificateVerificationResult } from '../../src/api/bft/verification/CertificateVerdict.js';
import { CertificationData } from '../../src/api/CertificationData.js';
import { NetworkId } from '../../src/api/NetworkId.js';
import { DataHasher } from '../../src/crypto/hash/DataHasher.js';
import { HashAlgorithm } from '../../src/crypto/hash/HashAlgorithm.js';
import { SigningService } from '../../src/crypto/secp256k1/SigningService.js';
import { SignaturePredicate } from '../../src/predicate/builtin/SignaturePredicate.js';
import { PredicateVerifierService } from '../../src/predicate/verification/PredicateVerifierService.js';
import { StateTransitionClient } from '../../src/StateTransitionClient.js';
import { MintTransaction } from '../../src/transaction/MintTransaction.js';
import { Token } from '../../src/transaction/Token.js';
import { MintJustificationVerifierService } from '../../src/transaction/verification/MintJustificationVerifierService.js';
import { TokenIssuanceVerifierService } from '../../src/transaction/verification/TokenIssuanceVerifierService.js';
import { VerificationContext } from '../../src/transaction/verification/VerificationContext.js';
import { waitInclusionProof } from '../../src/util/InclusionProofUtils.js';
import { verifyWithTrustBaseUpdate } from '../../src/util/TrustBaseUtils.js';
import { VerificationStatus } from '../../src/verification/VerificationStatus.js';
import { StaticTrustBaseSource } from '../utils/TrustBaseSourceFixture.js';
import { createUnicityCertificateVerifier } from '../utils/UnicityCertificateVerifierFixture.js';

/**
 * The §30 usage pattern end to end: the root committee changed (epoch 1 → 2) after the client's history was shipped. The aggregator seals with the
 * epoch-2 committee; the client learns that committee only from the signed epoch-2 entry, fetched from the source and authenticated by the epoch-1
 * committee.
 */
describe('verify → no entry for epoch → update the trust base → verify again', () => {
  const epoch1 = SigningService.generate();
  const epoch2Key = SigningService.generatePrivateKey();
  const epoch2 = new SigningService(epoch2Key);

  async function chain(): Promise<{ entries: Map<bigint, Uint8Array>; pin: Uint8Array }> {
    const genesis = RootTrustBaseV2.create({
      changeRecordHash: null,
      epoch: 1n,
      epochStartRound: 0n,
      networkId: NetworkId.LOCAL.id,
      previousEntryId: new Uint8Array(32),
      quorumThreshold: 1n,
      rootNodes: [{ nodeId: 'NODE', signingKey: epoch1.publicKey, weight: 1n }],
      stateHash: null,
    });
    const next = RootTrustBaseV2.create({
      changeRecordHash: new Uint8Array(32).fill(2),
      epoch: 2n,
      epochStartRound: 3n,
      networkId: NetworkId.LOCAL.id,
      previousEntryId: await genesis.entryId(),
      quorumThreshold: 1n,
      rootNodes: [{ nodeId: 'NODE', signingKey: epoch2.publicKey, weight: 1n }],
      stateHash: new Uint8Array(32).fill(1),
    });
    const witness = await epoch1.sign(await new DataHasher(HashAlgorithm.SHA256).update(next.sigBytes()).digest());
    return {
      entries: new Map([
        [1n, genesis.toCBOR()],
        [2n, next.withSignatures(new Map([['NODE', witness.encode()]])).toCBOR()],
      ]),
      pin: await genesis.entryId(),
    };
  }

  async function setup(): Promise<{
    client: StateTransitionClient;
    history: TrustBaseHistory;
    source: StaticTrustBaseSource;
    transaction: MintTransaction;
  }> {
    const { entries, pin } = await chain();
    const aggregator = TestAggregatorClient.create(epoch2Key);
    aggregator.setCertificateOptions({ sealEpoch: 2n, sealRound: 5n });
    const client = new StateTransitionClient(aggregator);
    const transaction = await MintTransaction.create(
      NetworkId.LOCAL,
      SignaturePredicate.create(SigningService.generate().publicKey),
    );
    await client.submitCertificationRequest(await CertificationData.fromMintTransaction(transaction));
    return {
      client,
      history: await TrustBaseHistory.fromGenesis(entries.get(1n)!, pin),
      source: new StaticTrustBaseSource(NetworkId.LOCAL.id, entries),
      transaction,
    };
  }

  it('waitInclusionProof without a source fails on the unknown epoch', async () => {
    const { client, history, transaction } = await setup();
    await expect(
      waitInclusionProof(
        client,
        history,
        PredicateVerifierService.create(),
        createUnicityCertificateVerifier(),
        transaction,
        {
          timeoutMs: 2000,
        },
      ),
    ).rejects.toThrow('NO_ENTRY_FOR_EPOCH');
    expect(history.tipEpoch).toBe(1n);
  });

  it('waitInclusionProof with a source appends the epoch-2 entry and returns the verified proof', async () => {
    const { client, history, source, transaction } = await setup();
    const proof = await waitInclusionProof(
      client,
      history,
      PredicateVerifierService.create(),
      createUnicityCertificateVerifier(),
      transaction,
      { timeoutMs: 5000, trustBaseSource: source },
    );
    expect(proof.unicityCertificate.unicitySeal.epoch).toBe(2n);
    expect(history.tipEpoch).toBe(2n);
    expect(source.calls).toEqual([{ fromEpoch: 2n, maxEntries: 64 }]);
  });

  it('a token sealed in the new epoch verifies after the update, and the stale history reports the missing epoch', async () => {
    const { client, history, source, transaction } = await setup();
    const predicateVerifier = PredicateVerifierService.create();
    const certificateVerifier = createUnicityCertificateVerifier();
    const proof = await waitInclusionProof(client, history, predicateVerifier, certificateVerifier, transaction, {
      timeoutMs: 5000,
      trustBaseSource: source,
    });
    const contextOf = (trustBase: TrustBaseHistory): VerificationContext =>
      new VerificationContext(
        trustBase,
        predicateVerifier,
        certificateVerifier,
        new MintJustificationVerifierService(),
        new TokenIssuanceVerifierService(false),
      );
    const token = await Token.mint(
      await transaction.toCertifiedTransaction(history, predicateVerifier, certificateVerifier, proof),
      contextOf(history),
    );

    // a wallet that still holds only the shipped (epoch-1) history
    const { entries, pin } = await chain();
    const stale = await TrustBaseHistory.fromGenesis(entries.get(1n)!, pin);
    const before = await token.verify(contextOf(stale));
    expect(before.status).toEqual(VerificationStatus.FAIL);
    expect(CertificateVerificationResult.findMissingEpoch(before)?.missing).toEqual({ epoch: 2n, latest: 1n });

    const after = await verifyWithTrustBaseUpdate(
      (h) => token.verify(contextOf(h)),
      stale,
      new StaticTrustBaseSource(NetworkId.LOCAL.id, entries),
    );
    expect(after.status).toEqual(VerificationStatus.OK);
    expect(stale.tipEpoch).toBe(2n);
  });
});
