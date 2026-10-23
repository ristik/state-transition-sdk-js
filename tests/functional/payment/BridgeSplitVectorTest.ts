import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { CertificationData } from '../../../src/api/CertificationData.js';
import { CertificationStatus } from '../../../src/api/CertificationResponse.js';
import { NetworkId } from '../../../src/api/NetworkId.js';
import { SigningService } from '../../../src/crypto/secp256k1/SigningService.js';
import { Asset } from '../../../src/payment/asset/Asset.js';
import { AssetId } from '../../../src/payment/asset/AssetId.js';
import { PaymentAssetCollection } from '../../../src/payment/asset/PaymentAssetCollection.js';
import { IPaymentData } from '../../../src/payment/IPaymentData.js';
import { SplitMintJustification } from '../../../src/payment/SplitMintJustification.js';
import { SplitMintJustificationVerifier } from '../../../src/payment/SplitMintJustificationVerifier.js';
import { SplitTokenRequest } from '../../../src/payment/SplitTokenRequest.js';
import { ISplit, TokenSplit } from '../../../src/payment/TokenSplit.js';
import { SignaturePredicate } from '../../../src/predicate/builtin/SignaturePredicate.js';
import { SignaturePredicateUnlockScript } from '../../../src/predicate/builtin/SignaturePredicateUnlockScript.js';
import { EncodedPredicate } from '../../../src/predicate/EncodedPredicate.js';
import { PredicateVerifierService } from '../../../src/predicate/verification/PredicateVerifierService.js';
import { CborDeserializer } from '../../../src/serialization/cbor/CborDeserializer.js';
import { CborSerializer } from '../../../src/serialization/cbor/CborSerializer.js';
import { StateTransitionClient } from '../../../src/StateTransitionClient.js';
import { MintTransaction } from '../../../src/transaction/MintTransaction.js';
import { StateMask } from '../../../src/transaction/StateMask.js';
import { Token } from '../../../src/transaction/Token.js';
import { TokenId } from '../../../src/transaction/TokenId.js';
import { TokenSalt } from '../../../src/transaction/TokenSalt.js';
import { TokenType } from '../../../src/transaction/TokenType.js';
import { MintJustificationVerifierService } from '../../../src/transaction/verification/MintJustificationVerifierService.js';
import { TokenIssuanceVerifierService } from '../../../src/transaction/verification/TokenIssuanceVerifierService.js';
import { VerificationContext } from '../../../src/transaction/verification/VerificationContext.js';
import { HexConverter } from '../../../src/util/HexConverter.js';
import { waitInclusionProof } from '../../../src/util/InclusionProofUtils.js';
import { VerificationStatus } from '../../../src/verification/VerificationStatus.js';
import { mintToken } from '../../utils/TokenUtils.js';
import { createUnicityCertificateVerifier } from '../../utils/UnicityCertificateVerifierFixture.js';
import { TestAggregatorClient } from '../TestAggregatorClient.js';

/**
 * Cross-SDK vectors for the native bridge's split tokens (tests/fixtures/bridge-split/v1): a token whose payment data is
 * the bridge's wallet value envelope `tag(39050, [1, [[b(aid32), b(amount)]], null])` is split, one output is minted and
 * split again, and both generations are minted and verified. The Rust SDK reproduces every split byte for byte and
 * verifies the minted tokens from the same file.
 *
 * Set BRIDGE_SPLIT_VECTOR_OUT to regenerate (the certified tokens carry wall-clock proofs, so the file changes); without
 * it the test checks the committed file: each split rebuilt from its committed source equals the recorded bytes, and
 * every committed token verifies.
 */

const FIXTURE = join(__dirname, '../../fixtures/bridge-split/v1/bridge_split.json');
const OUT = process.env.BRIDGE_SPLIT_VECTOR_OUT;
const WALLET_VALUE_TAG = 39050n;

/** The bridge's wallet value envelope; the bridge plug-ins define it, not the SDK. One asset, no memo. */
class WalletValue implements IPaymentData {
  public constructor(public readonly assets: PaymentAssetCollection) {}

  public static decode(bytes: Uint8Array): Promise<WalletValue> {
    const { tag, data } = CborDeserializer.decodeTag(bytes);
    if (tag !== WALLET_VALUE_TAG) {
      throw new Error('not a wallet value envelope');
    }
    const fields = CborDeserializer.decodeArray(data, 3);
    if (
      CborDeserializer.decodeUnsignedInteger(fields[0]) !== 1n ||
      CborDeserializer.decodeNullable(fields[2], () => true) !== null
    ) {
      throw new Error('unsupported wallet value envelope');
    }
    const value = new WalletValue(PaymentAssetCollection.fromCBOR(fields[1]));
    if (value.assets.toArray().length !== 1) {
      throw new Error('a wallet value carries exactly one asset');
    }
    return Promise.resolve(value);
  }

  public encode(): Promise<Uint8Array> {
    return Promise.resolve(
      CborSerializer.encodeTag(
        WALLET_VALUE_TAG,
        CborSerializer.encodeArray(
          CborSerializer.encodeUnsignedInteger(1),
          this.assets.toCBOR(),
          CborSerializer.encodeNull(),
        ),
      ),
    );
  }
}

function key(n: number): Uint8Array {
  const bytes = new Uint8Array(32);
  bytes[31] = n;
  return bytes;
}
function filled(n: number): Uint8Array {
  return new Uint8Array(32).fill(n);
}
const hex = HexConverter.encode;
const unhex = HexConverter.decode;

const AGGREGATOR_KEY = 9;
const TOKEN_TYPE = filled(0xc0);
const AID = filled(0xa1);
const BURN_EXPIRES_AT = 4102444800n;
const WEI = 10n ** 15n;

interface IRecordedSplit {
  name: string;
  outputs: { payload: string; tokenId: string }[];
  sourceToken: string;
}
interface IVectors {
  aggregatorKey: number;
  leaves: string[];
  splits: IRecordedSplit[];
}

interface IOutputSpec {
  amount: bigint;
  recipientKey: number;
  salt: number;
}
interface ISplitSpec {
  burnStateMask: number;
  name: string;
  outputs: IOutputSpec[];
  ownerKey: number;
}

/** Lock 100 -> split 40 + 60 -> split the 40 into 15 + 25 (the split plan's lane amounts, in units of 10^15 wei). */
const SOURCE = { amount: 100n * WEI, ownerKey: 1, salt: 0x01 };
const SPLITS: ISplitSpec[] = [
  {
    burnStateMask: 0x07,
    name: 'root_100_into_40_60',
    outputs: [
      { amount: 40n * WEI, recipientKey: 2, salt: 0x10 },
      { amount: 60n * WEI, recipientKey: 3, salt: 0x20 },
    ],
    ownerKey: 1,
  },
  {
    burnStateMask: 0x08,
    name: 'child_40_into_15_25',
    outputs: [
      { amount: 15n * WEI, recipientKey: 4, salt: 0x30 },
      { amount: 25n * WEI, recipientKey: 5, salt: 0x40 },
    ],
    ownerKey: 2,
  },
];

const value = (amount: bigint): WalletValue =>
  new WalletValue(PaymentAssetCollection.create(new Asset(new AssetId(AID), amount)));

function context(aggregator: TestAggregatorClient): VerificationContext {
  const mintJustificationVerifier = new MintJustificationVerifierService();
  mintJustificationVerifier.register(new SplitMintJustificationVerifier(WalletValue.decode));
  return new VerificationContext(
    aggregator.rootTrustBase,
    PredicateVerifierService.create(),
    createUnicityCertificateVerifier(),
    mintJustificationVerifier,
    new TokenIssuanceVerifierService(false),
  );
}

function split(source: Token, spec: ISplitSpec): Promise<ISplit> {
  return TokenSplit.split(
    source,
    WalletValue.decode,
    spec.outputs.map((o) =>
      SplitTokenRequest.create(
        SignaturePredicate.create(new SigningService(key(o.recipientKey)).publicKey),
        value(o.amount),
        TokenSalt.fromBytes(filled(o.salt)),
      ),
    ),
    { burnStateMask: StateMask.fromBytes(filled(spec.burnStateMask)), expiresAt: BURN_EXPIRES_AT },
  );
}

/** The recorded bytes of one split of `source`. */
async function record(source: Token, spec: ISplitSpec, result: ISplit): Promise<Record<string, unknown>> {
  const outputs = [];
  for (const [i, out] of result.tokens.entries()) {
    const payload = await out.paymentData.encode();
    const tokenId = await TokenId.fromSalt(source.networkId, out.salt);
    outputs.push({
      amount: spec.outputs[i].amount.toString(),
      commitment: hex(
        await SplitMintJustification.calculateLeafData(
          source,
          EncodedPredicate.fromPredicate(out.recipient),
          out.salt,
          tokenId,
          payload,
        ),
      ),
      payload: hex(payload),
      proofs: out.proofs.map((p) => hex(p.toCBOR())),
      recipientKey: spec.outputs[i].recipientKey,
      salt: hex(out.salt.toBytes()),
      tokenId: hex(tokenId.bytes),
    });
  }
  return {
    burnExpiresAt: Number(BURN_EXPIRES_AT),
    burnStateMask: hex(filled(spec.burnStateMask)),
    burnTransaction: hex(result.burn.transaction.toCBOR()),
    manifest: hex(result.burn.transaction.data!),
    name: spec.name,
    outputs,
    ownerKey: spec.ownerKey,
    sourceToken: hex(source.toCBOR()),
  };
}

async function generate(): Promise<unknown> {
  const aggregator = TestAggregatorClient.create(key(AGGREGATOR_KEY));
  const client = new StateTransitionClient(aggregator);
  const ctx = context(aggregator);
  const certified = (tx: Parameters<typeof waitInclusionProof>[4]): ReturnType<typeof waitInclusionProof> =>
    waitInclusionProof(client, ctx.trustBase, ctx.predicateVerifier, ctx.unicityCertificateVerifier, tx);

  let source = await mintToken(
    client,
    ctx,
    SignaturePredicate.create(new SigningService(key(SOURCE.ownerKey)).publicKey),
    await value(SOURCE.amount).encode(),
    NetworkId.LOCAL,
    new TokenType(TOKEN_TYPE),
    TokenSalt.fromBytes(filled(SOURCE.salt)),
  );
  const splits = [];
  let minted: Token[] = [];
  for (const spec of SPLITS) {
    const result = await split(source, spec);
    splits.push(await record(source, spec, result));

    const burn = result.burn.transaction;
    const owner = new SigningService(key(spec.ownerKey));
    const response = await client.submitCertificationRequest(
      await CertificationData.fromTransaction(burn, await SignaturePredicateUnlockScript.create(burn, owner)),
    );
    expect(response.status).toEqual(CertificationStatus.SUCCESS);
    const burned = await source.transfer(
      await burn.toCertifiedTransaction(
        ctx.trustBase,
        ctx.predicateVerifier,
        ctx.unicityCertificateVerifier,
        await certified(burn),
      ),
      ctx,
    );

    minted = [];
    for (const out of result.tokens) {
      const mint = await MintTransaction.create(out.networkId, out.recipient, {
        data: await out.paymentData.encode(),
        justification: SplitMintJustification.create(burned, out.proofs).toCBOR(),
        salt: out.salt,
        tokenType: out.tokenType,
      });
      const minting = await client.submitCertificationRequest(await CertificationData.fromMintTransaction(mint));
      expect(minting.status).toEqual(CertificationStatus.SUCCESS);
      minted.push(
        await Token.mint(
          await mint.toCertifiedTransaction(
            ctx.trustBase,
            ctx.predicateVerifier,
            ctx.unicityCertificateVerifier,
            await certified(mint),
          ),
          ctx,
        ),
      );
    }
    // the next split divides this split's first output (owned by the next spec's owner)
    source = minted[0];
  }
  return {
    __comment:
      'generated by state-transition-sdk-js tests/functional/payment/BridgeSplitVectorTest.ts (BRIDGE_SPLIT_VECTOR_OUT)',
    aggregatorKey: AGGREGATOR_KEY,
    aid: hex(AID),
    // the second generation's outputs, each with the complete ancestry in its mint justification
    leaves: minted.map((t) => hex(t.toCBOR())),
    networkId: NetworkId.LOCAL.id,
    splits,
    tokenType: hex(TOKEN_TYPE),
  };
}

describe('Bridge split cross-SDK vectors', () => {
  it('rebuilds every recorded split byte for byte and verifies the minted tokens', async () => {
    if (OUT) {
      writeFileSync(OUT, `${JSON.stringify(await generate(), null, 2)}\n`);
    }
    const vectors = JSON.parse(readFileSync(OUT ?? FIXTURE, 'utf8')) as IVectors;
    const aggregator = TestAggregatorClient.create(key(vectors.aggregatorKey));
    const ctx = context(aggregator);

    expect(vectors.splits.map((s) => s.name)).toEqual(SPLITS.map((s) => s.name));
    for (const [i, spec] of SPLITS.entries()) {
      const recorded = vectors.splits[i];
      const source = await Token.fromCBOR(unhex(recorded.sourceToken));
      expect((await source.verify(ctx)).status).toEqual(VerificationStatus.OK);
      expect(await record(source, spec, await split(source, spec))).toEqual(recorded);
      // every output payload is exactly the bridge envelope of its amount
      for (const [j, out] of recorded.outputs.entries()) {
        expect(out.payload).toEqual(hex(await value(spec.outputs[j].amount).encode()));
      }
    }
    // the second split's source is the first split's first output
    expect(HexConverter.encode((await Token.fromCBOR(unhex(vectors.splits[1].sourceToken))).id.bytes)).toEqual(
      vectors.splits[0].outputs[0].tokenId,
    );

    expect(vectors.leaves).toHaveLength(2);
    for (const [j, leaf] of vectors.leaves.entries()) {
      const token = await Token.fromCBOR(unhex(leaf));
      expect(hex(token.id.bytes)).toEqual(vectors.splits[1].outputs[j].tokenId);
      expect((await token.verify(ctx)).status).toEqual(VerificationStatus.OK);
    }
  }, 120000);
});
