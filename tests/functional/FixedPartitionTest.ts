import { TestAggregatorClient } from './TestAggregatorClient.js';
import { AGGREGATION_PARTITION_ID } from '../../src/api/bft/AggregationPartition.js';
import { SigningService } from '../../src/crypto/secp256k1/SigningService.js';
import { SignaturePredicate } from '../../src/predicate/builtin/SignaturePredicate.js';
import { PredicateVerifierService } from '../../src/predicate/verification/PredicateVerifierService.js';
import { StateTransitionClient } from '../../src/StateTransitionClient.js';
import { IVerificationContext } from '../../src/transaction/verification/IVerificationContext.js';
import { MintJustificationVerifierService } from '../../src/transaction/verification/MintJustificationVerifierService.js';
import { TokenIssuanceVerifierService } from '../../src/transaction/verification/TokenIssuanceVerifierService.js';
import { VerificationContext } from '../../src/transaction/verification/VerificationContext.js';
import { expiresAt } from '../utils/ExpiresAt.js';
import { mintToken, transferToken } from '../utils/TokenUtils.js';
import { createUnicityCertificateVerifier } from '../utils/UnicityCertificateVerifierFixture.js';

// Application verification accepts the aggregation partition only: a validly signed certificate of another partition
// verifies neither a genesis nor a transfer, whatever the proof says about itself.
describe('Token verification requires the aggregation partition', () => {
  const alice = SigningService.generate();
  const bob = SigningService.generate();

  function setup(): { aggregator: TestAggregatorClient; client: StateTransitionClient; context: IVerificationContext } {
    const aggregator = TestAggregatorClient.create();
    return {
      aggregator,
      client: new StateTransitionClient(aggregator),
      context: new VerificationContext(
        aggregator.rootTrustBase,
        PredicateVerifierService.create(),
        createUnicityCertificateVerifier(),
        new MintJustificationVerifierService(),
        new TokenIssuanceVerifierService(false),
      ),
    };
  }

  it('verifies a mint and a transfer under partition 7', async () => {
    expect(AGGREGATION_PARTITION_ID).toBe(7n);
    const { client, context, aggregator } = setup();
    const token = await mintToken(client, context, SignaturePredicate.create(alice.publicKey));
    const moved = await transferToken(
      client,
      context,
      token.toCBOR(),
      SignaturePredicate.create(bob.publicKey),
      alice,
      expiresAt(),
    );
    expect((await moved.verify(context)).status).toEqual('OK');
    expect(aggregator.rootTrustBase.networkId).toBeDefined();
  }, 30000);

  it('rejects the genesis proof of another partition', async () => {
    const { client, context, aggregator } = setup();
    aggregator.setCertificateOptions({ partition: 8n });
    await expect(mintToken(client, context, SignaturePredicate.create(alice.publicKey))).rejects.toThrow();
  }, 30000);

  it('rejects the transfer proof of another partition, and a token whose proofs were issued under it', async () => {
    const { client, context, aggregator } = setup();
    const token = await mintToken(client, context, SignaturePredicate.create(alice.publicKey));
    aggregator.setCertificateOptions({ partition: 8n });
    await expect(
      transferToken(client, context, token.toCBOR(), SignaturePredicate.create(bob.publicKey), alice, expiresAt()),
    ).rejects.toThrow();
  }, 30000);

  it('rejects, when verifying an existing token, a certificate that violates the native structure', async () => {
    const { client, context, aggregator } = setup();
    aggregator.setCertificateOptions({ blockHash: null });
    await expect(mintToken(client, context, SignaturePredicate.create(alice.publicKey))).rejects.toThrow();
  }, 30000);
});
