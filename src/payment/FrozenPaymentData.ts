import { PaymentAssetCollection } from './asset/PaymentAssetCollection.js';
import { SplitPayloadMismatchError } from './error/SplitPayloadMismatchError.js';
import { IPaymentData } from './IPaymentData.js';
import { HexConverter } from '../util/HexConverter.js';

/**
 * Immutable payment data whose encoding is a fixed byte string. Obtained by
 * {@link FrozenPaymentData.freeze}, which guarantees that the bytes decode, with the
 * caller's decoder, to exactly the assets held here.
 */
export class FrozenPaymentData implements IPaymentData {
  private constructor(
    public readonly assets: PaymentAssetCollection,
    private readonly _bytes: Uint8Array,
  ) {
    Object.freeze(this);
  }

  /**
   * Encode `paymentData` once, copy the bytes, decode a copy with `decode` and require the
   * decoded assets to equal the declared assets. `paymentData` is not consulted again.
   *
   * @param {IPaymentData} paymentData Declared payment data.
   * @param {(bytes: Uint8Array) => Promise<IPaymentData>} decode Decoder the verifier will use.
   * @returns {Promise<FrozenPaymentData>} Frozen payload over the exact encoded bytes.
   * @throws {SplitPayloadMismatchError} If the bytes do not decode to the declared assets.
   */
  public static async freeze(
    paymentData: IPaymentData,
    decode: (bytes: Uint8Array) => Promise<IPaymentData>,
  ): Promise<FrozenPaymentData> {
    const declared = paymentData.assets;
    const bytes = new Uint8Array(await paymentData.encode());

    let decoded: PaymentAssetCollection;
    try {
      decoded = (await decode(new Uint8Array(bytes))).assets;
    } catch (cause) {
      throw new SplitPayloadMismatchError('payload does not decode', { cause });
    }

    if (HexConverter.encode(decoded.toCBOR()) !== HexConverter.encode(declared.toCBOR())) {
      throw new SplitPayloadMismatchError('decoded assets differ');
    }

    return new FrozenPaymentData(decoded, bytes);
  }

  /**
   * @returns {Promise<Uint8Array>} Copy of the frozen encoded bytes.
   */
  public encode(): Promise<Uint8Array> {
    return Promise.resolve(new Uint8Array(this._bytes));
  }
}
