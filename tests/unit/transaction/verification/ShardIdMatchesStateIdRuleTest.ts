import { ShardId } from '../../../../src/api/bft/ShardId.js';
import { ShardTreeCertificate } from '../../../../src/api/bft/ShardTreeCertificate.js';
import { StateId } from '../../../../src/api/StateId.js';
import { CborSerializer } from '../../../../src/serialization/cbor/CborSerializer.js';
import { ShardIdMatchesStateIdRule } from '../../../../src/transaction/verification/rule/ShardIdMatchesStateIdRule.js';
import { VerificationStatus } from '../../../../src/verification/VerificationStatus.js';

function stateId(firstByte: number): StateId {
  const data = new Uint8Array(32).fill(0x11);
  data[0] = firstByte;
  return StateId.fromCBOR(CborSerializer.encodeByteString(data));
}

function certificate(bits: string, siblings: number): ShardTreeCertificate {
  return new ShardTreeCertificate(
    ShardId.fromBits(bits),
    Array.from({ length: siblings }, () => new Uint8Array(32).fill(0xaa)),
  );
}

describe('ShardIdMatchesStateIdRule', () => {
  it('accepts an unsharded certificate and honest shard labels', () => {
    expect(ShardIdMatchesStateIdRule.verify(stateId(0x40), certificate('', 0)).status).toBe(VerificationStatus.OK);
    expect(ShardIdMatchesStateIdRule.verify(stateId(0x40), certificate('0', 1)).status).toBe(VerificationStatus.OK);
    expect(ShardIdMatchesStateIdRule.verify(stateId(0x40), certificate('01', 2)).status).toBe(VerificationStatus.OK);
    expect(ShardIdMatchesStateIdRule.verify(stateId(0xc0), certificate('11', 2)).status).toBe(VerificationStatus.OK);
  });

  it('rejects a relabelled shard whose sibling count is shorter than the label (reviewer repro)', () => {
    // Faulty shard "1" relabels its 1-sibling certificate to "01", a prefix of the state id 0x40...
    const relabelled = certificate('01', 1);
    expect(ShardIdMatchesStateIdRule.verify(stateId(0x40), relabelled).status).toBe(VerificationStatus.FAIL);
  });

  it('rejects any sibling count different from the label length', () => {
    expect(ShardIdMatchesStateIdRule.verify(stateId(0x40), certificate('01', 3)).status).toBe(VerificationStatus.FAIL);
    expect(ShardIdMatchesStateIdRule.verify(stateId(0x40), certificate('', 1)).status).toBe(VerificationStatus.FAIL);
    expect(ShardIdMatchesStateIdRule.verify(stateId(0x40), certificate('0', 0)).status).toBe(VerificationStatus.FAIL);
  });
});
