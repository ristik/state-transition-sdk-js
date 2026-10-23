import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { TestPaymentData } from './TestPaymentData.js';
import { WrappedPaymentData } from './WrappedPaymentData.js';
import { NetworkId } from '../../../src/api/NetworkId.js';
import { SigningService } from '../../../src/crypto/secp256k1/SigningService.js';
import { Asset } from '../../../src/payment/asset/Asset.js';
import { AssetId } from '../../../src/payment/asset/AssetId.js';
import { PaymentAssetCollection } from '../../../src/payment/asset/PaymentAssetCollection.js';
import { SplitPayloadMismatchError } from '../../../src/payment/error/SplitPayloadMismatchError.js';
import { IPaymentData } from '../../../src/payment/IPaymentData.js';
import { SplitMintJustification } from '../../../src/payment/SplitMintJustification.js';
import { SplitMintJustificationVerifier } from '../../../src/payment/SplitMintJustificationVerifier.js';
import { SplitTokenRequest } from '../../../src/payment/SplitTokenRequest.js';
import { ISplit, TokenSplit } from '../../../src/payment/TokenSplit.js';
import { SignaturePredicate } from '../../../src/predicate/builtin/SignaturePredicate.js';
import { SignaturePredicateUnlockScript } from '../../../src/predicate/builtin/SignaturePredicateUnlockScript.js';
import { EncodedPredicate } from '../../../src/predicate/EncodedPredicate.js';
import { PredicateVerifierService } from '../../../src/predicate/verification/PredicateVerifierService.js';
import { StateTransitionClient } from '../../../src/StateTransitionClient.js';
import { StateMask } from '../../../src/transaction/StateMask.js';
import { Token } from '../../../src/transaction/Token.js';
import { TokenId } from '../../../src/transaction/TokenId.js';
import { TokenSalt } from '../../../src/transaction/TokenSalt.js';
import { MintJustificationVerifierService } from '../../../src/transaction/verification/MintJustificationVerifierService.js';
import { TokenIssuanceVerifierService } from '../../../src/transaction/verification/TokenIssuanceVerifierService.js';
import { VerificationContext } from '../../../src/transaction/verification/VerificationContext.js';
import { HexConverter } from '../../../src/util/HexConverter.js';
import { VerificationStatus } from '../../../src/verification/VerificationStatus.js';
import { expiresAt } from '../../utils/ExpiresAt.js';
import { mintToken, transferTokenWithTransaction } from '../../utils/TokenUtils.js';
import { createUnicityCertificateVerifier } from '../../utils/UnicityCertificateVerifierFixture.js';
import { TestAggregatorClient } from '../TestAggregatorClient.js';

const hex = HexConverter.encode;
const unhex = HexConverter.decode;

function setup(decode: (bytes: Uint8Array) => Promise<IPaymentData>): {
  client: StateTransitionClient;
  ctx: VerificationContext;
} {
  const aggregator = TestAggregatorClient.create();
  const mintJustificationVerifier = new MintJustificationVerifierService();
  mintJustificationVerifier.register(new SplitMintJustificationVerifier(decode));
  return {
    client: new StateTransitionClient(aggregator),
    ctx: new VerificationContext(
      aggregator.rootTrustBase,
      PredicateVerifierService.create(),
      createUnicityCertificateVerifier(),
      mintJustificationVerifier,
      new TokenIssuanceVerifierService(false),
    ),
  };
}

/** Burns the source, then mints and verifies every output of the split; returns the minted tokens. */
async function mintSplit(
  client: StateTransitionClient,
  ctx: VerificationContext,
  source: Token,
  split: ISplit,
  owner: SigningService,
): Promise<Token[]> {
  const burned = await transferTokenWithTransaction(
    client,
    ctx,
    source,
    split.burn.transaction,
    await SignaturePredicateUnlockScript.create(split.burn.transaction, owner),
  );
  const minted: Token[] = [];
  for (const out of split.tokens) {
    const token = await mintToken(
      client,
      ctx,
      out.recipient,
      await out.paymentData.encode(),
      out.networkId,
      out.tokenType,
      out.salt,
      SplitMintJustification.create(burned, out.proofs),
      expiresAt(),
    );
    expect((await Token.fromCBOR(token.toCBOR()).then((t) => t.verify(ctx))).status).toEqual(VerificationStatus.OK);
    minted.push(token);
  }
  return minted;
}

const assetId = new AssetId(new Uint8Array(32).fill(0xaa));
const assets = (value: bigint): PaymentAssetCollection => PaymentAssetCollection.create(new Asset(assetId, value));

describe('Split payload validation and freezing', () => {
  const owner = new SigningService(SigningService.generatePrivateKey());
  const predicate = SignaturePredicate.fromSigningService(owner);

  it('splits wrapped 10 into 3 + 7, verifies both outputs and a re-split child', async () => {
    const { client, ctx } = setup(WrappedPaymentData.decode);
    const source = await mintToken(
      client,
      ctx,
      predicate,
      await new WrappedPaymentData(assets(10n)).encode(),
      NetworkId.LOCAL,
      undefined,
      undefined,
      null,
      expiresAt(),
    );

    const split = await TokenSplit.split(
      source,
      WrappedPaymentData.decode,
      [
        SplitTokenRequest.create(predicate, new WrappedPaymentData(assets(3n))),
        SplitTokenRequest.create(predicate, new WrappedPaymentData(assets(7n))),
      ],
      { expiresAt: expiresAt() },
    );
    const [three, seven] = await mintSplit(client, ctx, source, split, owner);
    expect(three.genesis.data).toEqual(await new WrappedPaymentData(assets(3n)).encode());
    expect(seven.genesis.data).toEqual(await new WrappedPaymentData(assets(7n)).encode());

    const second = await TokenSplit.split(
      seven,
      WrappedPaymentData.decode,
      [
        SplitTokenRequest.create(predicate, new WrappedPaymentData(assets(2n))),
        SplitTokenRequest.create(predicate, new WrappedPaymentData(assets(5n))),
      ],
      { expiresAt: expiresAt() },
    );
    const grandchildren = await mintSplit(client, ctx, seven, second, owner);
    expect(grandchildren).toHaveLength(2);
  });

  describe('mismatch rejection before any burn is returned', () => {
    let source: Token;

    beforeAll(async () => {
      const { client, ctx } = setup(WrappedPaymentData.decode);
      source = await mintToken(
        client,
        ctx,
        predicate,
        await new WrappedPaymentData(assets(10n)).encode(),
        NetworkId.LOCAL,
        undefined,
        undefined,
        null,
        expiresAt(),
      );
    });

    it('rejects a bare output under a wrapped decoder', async () => {
      await expect(
        TokenSplit.split(
          source,
          WrappedPaymentData.decode,
          [
            SplitTokenRequest.create(predicate, new TestPaymentData(assets(3n))),
            SplitTokenRequest.create(predicate, new WrappedPaymentData(assets(7n))),
          ],
          { expiresAt: expiresAt() },
        ),
      ).rejects.toThrow(SplitPayloadMismatchError);
    });

    it('rejects a decoder that skews amounts', async () => {
      const skewing = async (bytes: Uint8Array): Promise<IPaymentData> => {
        const decoded = await WrappedPaymentData.decode(bytes);
        const skewed = decoded.assets.toArray().map((a) => new Asset(a.id, a.value + 1n));
        return new WrappedPaymentData(PaymentAssetCollection.create(...skewed));
      };
      // The source decodes as 11 under the skewing decoder, so only the output check can reject here.
      await expect(
        TokenSplit.split(source, skewing, [SplitTokenRequest.create(predicate, new WrappedPaymentData(assets(11n)))], {
          expiresAt: expiresAt(),
        }),
      ).rejects.toThrow(SplitPayloadMismatchError);
    });

    it('rejects an encoder whose bytes decode to other assets', async () => {
      const lying: IPaymentData = {
        assets: assets(3n),
        encode: () => new WrappedPaymentData(assets(4n)).encode(),
      };
      await expect(
        TokenSplit.split(
          source,
          WrappedPaymentData.decode,
          [
            SplitTokenRequest.create(predicate, lying),
            SplitTokenRequest.create(predicate, new WrappedPaymentData(assets(7n))),
          ],
          { expiresAt: expiresAt() },
        ),
      ).rejects.toThrow(SplitPayloadMismatchError);
    });
  });

  it('keeps minted bytes fixed against mutable and nondeterministic encoders', async () => {
    const { client, ctx } = setup(WrappedPaymentData.decode);
    const source = await mintToken(
      client,
      ctx,
      predicate,
      await new WrappedPaymentData(assets(10n)).encode(),
      NetworkId.LOCAL,
      undefined,
      undefined,
      null,
      expiresAt(),
    );

    // Valid first encoding; every later call returns different (and shared, mutable) bytes.
    const buffers: Uint8Array[] = [];
    let calls = 0;
    const hostile = (value: bigint): IPaymentData => {
      let own = 0;
      return {
        assets: assets(value),
        encode: async (): Promise<Uint8Array> => {
          calls++;
          own++;
          const good = await new WrappedPaymentData(assets(value)).encode();
          const out = own === 1 ? good : new Uint8Array(good.length).fill(own);
          buffers.push(out);
          return out;
        },
      };
    };

    const split = await TokenSplit.split(
      source,
      WrappedPaymentData.decode,
      [SplitTokenRequest.create(predicate, hostile(3n)), SplitTokenRequest.create(predicate, hostile(7n))],
      { expiresAt: expiresAt() },
    );
    expect(calls).toEqual(2);

    // Scribble over every buffer the encoder ever handed out.
    for (const buffer of buffers) {
      buffer.fill(0xff);
    }

    const [first, second] = split.tokens;
    expect(Object.isFrozen(first.paymentData)).toBe(true);
    const bytes = await first.paymentData.encode();
    bytes.fill(0);
    expect(await first.paymentData.encode()).toEqual(await new WrappedPaymentData(assets(3n)).encode());
    expect(await second.paymentData.encode()).toEqual(await new WrappedPaymentData(assets(7n)).encode());
    expect(calls).toEqual(2);

    // The frozen bytes are what the burn commits to: both outputs mint and verify.
    await mintSplit(client, ctx, source, split, owner);
  });

  describe('Rust cross-language vectors', () => {
    const vectors = JSON.parse(
      readFileSync(join(process.cwd(), 'tests/fixtures/split-payload/split_payload.json'), 'utf8'),
    ) as {
      cases: {
        burnExpiresAt: number;
        burnStateMask: string;
        burnTransaction: string;
        manifest: string;
        name: string;
        sourceToken: string;
        tokens: {
          assets: { id: string; value: string }[];
          commitment: string;
          payload: string;
          proofs: string[];
          recipientKey: number;
          salt: string;
          tokenId: string;
        }[];
        wrapped: boolean;
      }[];
    };

    function key(n: number): Uint8Array {
      const bytes = new Uint8Array(32);
      bytes[31] = n;
      return bytes;
    }

    it.each(['wrapped_10_into_3_7', 'bare_two_assets'])('%s matches byte for byte', async (name) => {
      const c = vectors.cases.find((v) => v.name === name)!;
      const Payload = c.wrapped ? WrappedPaymentData : TestPaymentData;
      const source = await Token.fromCBOR(unhex(c.sourceToken));

      const requests = c.tokens.map((o) =>
        SplitTokenRequest.create(
          SignaturePredicate.create(new SigningService(key(o.recipientKey)).publicKey),
          new Payload(
            PaymentAssetCollection.create(...o.assets.map((a) => new Asset(new AssetId(unhex(a.id)), BigInt(a.value)))),
          ),
          TokenSalt.fromBytes(unhex(o.salt)),
        ),
      );
      const split = await TokenSplit.split(source, Payload.decode, requests, {
        burnStateMask: StateMask.fromBytes(unhex(c.burnStateMask)),
        expiresAt: BigInt(c.burnExpiresAt),
      });

      expect(hex(split.burn.transaction.toCBOR())).toEqual(c.burnTransaction);
      expect(hex(split.burn.transaction.data!)).toEqual(c.manifest);

      expect(split.tokens).toHaveLength(c.tokens.length);
      for (const [i, out] of split.tokens.entries()) {
        const expected = c.tokens[i];
        const payload = await out.paymentData.encode();
        expect(hex(payload)).toEqual(expected.payload);

        const tokenId = await TokenId.fromSalt(source.networkId, out.salt);
        expect(hex(tokenId.bytes)).toEqual(expected.tokenId);
        const commitment = await SplitMintJustification.calculateLeafData(
          source,
          EncodedPredicate.fromPredicate(out.recipient),
          out.salt,
          tokenId,
          payload,
        );
        expect(hex(commitment)).toEqual(expected.commitment);
        expect(out.proofs.map((p) => hex(p.toCBOR()))).toEqual(expected.proofs);
      }
    });
  });
});
