import { ShardId } from '../../../src/api/bft/ShardId.js';
import { IBatchAggregatorClient } from '../../../src/api/IBatchAggregatorClient.js';
import { StateId } from '../../../src/api/StateId.js';
import { ConsolidationError } from '../../../src/consolidation/ConsolidationError.js';
import { IShardEndpoint, ShardRouting } from '../../../src/consolidation/ShardRouting.js';
import { CborSerializer } from '../../../src/serialization/cbor/CborSerializer.js';
import { shardIdFromBits } from '../../utils/ShardedWorld.js';

function client(): IBatchAggregatorClient {
  return {
    getInclusionProof: jest.fn(),
    getInclusionProofs: jest.fn(),
    submitCertificationRequest: jest.fn(),
  };
}

function stateId(firstByte: number): StateId {
  const data = new Uint8Array(32).fill(0x11);
  data[0] = firstByte;
  return StateId.fromCBOR(CborSerializer.encodeByteString(data));
}

describe('ShardRouting snapshots its endpoint records', () => {
  it('keeps routing as validated when the caller mutates an endpoint afterwards', () => {
    const zero = client();
    const one = client();
    const endpoints: IShardEndpoint[] = [
      { client: zero, shard: shardIdFromBits('0') },
      { client: one, shard: shardIdFromBits('1') },
    ];
    const routing = new ShardRouting({
      endpoints,
      partitionId: 1n,
      scheme: [shardIdFromBits('0'), shardIdFromBits('1')],
    });

    // the reviewer's repro: shard "1" is re-pointed at shard 0's client, and shard 0 at the empty shard
    (endpoints[1] as { client: IBatchAggregatorClient }).client = zero;
    (endpoints[0] as { shard: ShardId }).shard = ShardId.ROOT;
    endpoints.reverse();
    endpoints.pop();

    expect(routing.route(stateId(0x80)).client).toBe(one);
    expect(routing.route(stateId(0x40)).client).toBe(zero);
  });

  it('is not changed by mutating a record it returned, or the shard bits of the input', () => {
    const zero = client();
    const routing = new ShardRouting({
      endpoints: [{ client: zero, shard: shardIdFromBits('') }],
      partitionId: 1n,
      scheme: [],
    });
    const record = routing.route(stateId(0x80));
    expect(() => {
      (record as { client: IBatchAggregatorClient }).client = client();
    }).toThrow(TypeError);
    expect(routing.route(stateId(0x80)).client).toBe(zero);
    expect(() => routing.route(stateId(0x80))).not.toThrow(ConsolidationError);
  });
});
