import { PaymentAssetCollection } from '../../../src/payment/asset/PaymentAssetCollection.js';
import { IPaymentData } from '../../../src/payment/IPaymentData.js';
import { CborDeserializer } from '../../../src/serialization/cbor/CborDeserializer.js';
import { CborSerializer } from '../../../src/serialization/cbor/CborSerializer.js';

const WRAP_TAG = 39050n;

/** Application envelope `tag(39050, [1, assets, null])`; defined by the tests, not by the SDK. */
export class WrappedPaymentData implements IPaymentData {
  public constructor(public readonly assets: PaymentAssetCollection) {}

  public static decode(bytes: Uint8Array): Promise<WrappedPaymentData> {
    const { tag, data } = CborDeserializer.decodeTag(bytes);
    if (tag !== WRAP_TAG) {
      throw new Error('bad tag');
    }
    const fields = CborDeserializer.decodeArray(data, 3);
    if (CborDeserializer.decodeUnsignedInteger(fields[0]) !== 1n) {
      throw new Error('bad version');
    }
    return Promise.resolve(new WrappedPaymentData(PaymentAssetCollection.fromCBOR(fields[1])));
  }

  public encode(): Promise<Uint8Array> {
    return Promise.resolve(
      CborSerializer.encodeTag(
        WRAP_TAG,
        CborSerializer.encodeArray(
          CborSerializer.encodeUnsignedInteger(1),
          this.assets.toCBOR(),
          CborSerializer.encodeNull(),
        ),
      ),
    );
  }
}
