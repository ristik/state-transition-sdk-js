import { AuthenticatedPartitionView } from '../../../src/api/bft/AuthenticatedPartitionView.js';
import { InputRecord } from '../../../src/api/bft/InputRecord.js';
import { PartitionView, PartitionViewLeaf } from '../../../src/api/bft/PartitionView.js';
import { PartitionViewError } from '../../../src/api/bft/PartitionViewError.js';
import { UnicityCertificate } from '../../../src/api/bft/UnicityCertificate.js';
import { ConsolidationError } from '../../../src/consolidation/ConsolidationError.js';
import { ShardRouting } from '../../../src/consolidation/ShardRouting.js';
import { TokenProofClient } from '../../../src/consolidation/TokenProofClient.js';
import { scenario } from '../../utils/ConsolidationScenario.js';
import { shardIdFromBits } from '../../utils/ShardedWorld.js';

jest.setTimeout(120_000);

const H = new Uint8Array(32).fill(7);
const leafOf = (ir: InputRecord, trHash: Uint8Array = H): PartitionViewLeaf =>
  new PartitionViewLeaf(shardIdFromBits(''), ir, trHash, H);
const record = (
  round: bigint,
  summary: Uint8Array | null,
  timestamp: bigint,
  previous: Uint8Array | null,
  hash: Uint8Array | null,
  block: Uint8Array | null,
): InputRecord => new InputRecord(round, 0n, previous, hash, summary, timestamp, block, 0n, null);

// The certificates consolidation hands on are derived from a partition view (#185 review). The view codec already holds
// every leaf to the native structure rules, and ProofConsolidator checks each target again before it replaces a proof,
// so a target that is not a valid certificate can never become a "consolidated" result.
describe('Consolidation view targets satisfy the certificate structure rule', () => {
  describe('a partition view cannot carry a malformed leaf record', () => {
    it.each([
      ['a nil summary value from round 1', record(1n, null, 9n, null, H, H), H],
      ['an unassigned timestamp from round 1', record(1n, new Uint8Array(0), 0n, null, H, H), H],
      ['a block hash although the state hash did not change', record(0n, null, 0n, H, H, H), H],
      ['no block hash although the state hash changed', record(0n, null, 0n, null, H, null), H],
      ['a technical record hash of 31 bytes', record(1n, new Uint8Array(0), 9n, null, H, H), new Uint8Array(31)],
    ])('rejects %s', (_name, ir, trHash) => {
      expect(() => new PartitionView(7n, [leafOf(ir, trHash)])).toThrow(PartitionViewError);
    });

    it('accepts the legal null fields', () => {
      expect(() => new PartitionView(7n, [leafOf(record(0n, null, 0n, null, null, null))])).not.toThrow();
      expect(() => new PartitionView(7n, [leafOf(record(1n, new Uint8Array(0), 9n, H, H, null))])).not.toThrow();
    });
  });

  it('a target that violates the structure rule is an integrity error, never "consolidated"', async () => {
    const s = await scenario(2);
    const token = await s.history(6);
    const client = new TokenProofClient({
      routing: new ShardRouting({
        endpoints: s.world.bits.map((b) => ({ client: s.world.client(b), shard: shardIdFromBits(b) })),
        scheme: s.world.scheme,
      }),
      verificationContext: s.context,
    });
    // control: the view as the world serves it consolidates
    await expect(client.consolidate(token)).resolves.toMatchObject({ status: 'consolidated' });

    // the derived certificate of every shard is made structurally invalid (nil summary from round 1), as a defect of the
    // derivation or of the view codec would
    // eslint-disable-next-line @typescript-eslint/unbound-method -- called with the instance as receiver below
    const original = AuthenticatedPartitionView.prototype.certificateOf;
    jest.spyOn(AuthenticatedPartitionView.prototype, 'certificateOf').mockImplementation(function (
      this: AuthenticatedPartitionView,
      ...args: Parameters<typeof original>
    ): UnicityCertificate {
      const uc = original.apply(this, args);
      const ir = uc.inputRecord;
      return new UnicityCertificate(
        new InputRecord(
          1n,
          ir.epoch,
          ir.previousHash,
          ir.nullableHash,
          null,
          ir.timestamp,
          ir.blockHash,
          ir.sumOfEarnedFees,
          ir.executedTransactionsHash,
        ),
        uc.technicalRecordHash,
        uc.shardConfigurationHash,
        uc.shardTreeCertificate,
        uc.unicityTreeCertificate,
        uc.unicitySeal,
      );
    });
    const outcome = await client.consolidate(token).then(
      (r) => r,
      (e: unknown) => e,
    );
    jest.restoreAllMocks();
    expect(outcome).toBeInstanceOf(ConsolidationError);
    expect((outcome as ConsolidationError).kind).toEqual('integrity');
    expect((outcome as ConsolidationError).message).toMatch(
      /Target certificate: Invalid input record: .*summary value is nil/,
    );
  });
});
