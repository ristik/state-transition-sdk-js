import { EpochListAuthority } from './EpochListAuthority.js';
import { RootTrustBaseV2 } from '../../src/api/bft/trustbase/RootTrustBaseV2.js';
import { ITrustBaseAuthority } from '../../src/api/bft/trustbase/TrustBaseAuthority.js';
import { TrustBaseHistory } from '../../src/api/bft/trustbase/TrustBaseHistory.js';
import { NetworkId } from '../../src/api/NetworkId.js';
import { HexConverter } from '../../src/util/HexConverter.js';

/** The epoch the test certificates are sealed in (`UnicityCertificateFixture`, `ShardedWorld`). */
export const TEST_EPOCH = 1;

/**
 * The single-member local test authority: node `NODE` with the given key, weight 1, epoch {@link TEST_EPOCH} from round 0, open-ended.
 *
 * @param {Uint8Array} publicKey Compressed signing key of `NODE`.
 * @returns {ITrustBaseAuthority} The authority.
 */
export function createTrustBase(publicKey: Uint8Array): ITrustBaseAuthority {
  return new EpochListAuthority(NetworkId.LOCAL, [
    {
      end: null,
      epoch: TEST_EPOCH,
      members: [{ key: HexConverter.encode(publicKey), nodeId: 'NODE', weight: 1 }],
      start: 0,
      threshold: 1,
    },
  ]);
}

/**
 * The same authority as a real held history: the version-2 genesis entry of `NODE`, pinned by its own EntryID.
 *
 * @param {Uint8Array} publicKey Compressed signing key of `NODE`.
 * @returns {Promise<TrustBaseHistory>} The history.
 */
export async function createTrustBaseHistory(publicKey: Uint8Array): Promise<TrustBaseHistory> {
  const genesis = RootTrustBaseV2.create({
    changeRecordHash: null,
    epoch: BigInt(TEST_EPOCH),
    epochStartRound: 0n,
    networkId: NetworkId.LOCAL.id,
    previousEntryId: new Uint8Array(32),
    quorumThreshold: 1n,
    rootNodes: [{ nodeId: 'NODE', signingKey: publicKey, weight: 1n }],
    stateHash: null,
  });
  return TrustBaseHistory.fromGenesis(genesis.toCBOR(), await genesis.entryId());
}

/**
 * The same committee as a version-1 JSON trust base, for the released 3.0.1 package that the compatibility runners spawn (it reads JSON only).
 *
 * @param {Uint8Array} publicKey Compressed signing key of `NODE`.
 * @returns {object} The JSON trust base.
 */
export function createLegacyTrustBaseJson(publicKey: Uint8Array): object {
  return {
    changeRecordHash: null,
    epoch: String(TEST_EPOCH),
    epochStartRound: '0',
    networkId: NetworkId.LOCAL.id,
    previousEntryHash: null,
    quorumThreshold: '1',
    rootNodes: [{ nodeId: 'NODE', sigKey: HexConverter.encode(publicKey), stake: '1' }],
    signatures: {},
    // empty, as the published genesis files: an absent hash (a 1-byte hash is not a valid version-2 genesis)
    stateHash: '',
    version: '1',
  };
}
