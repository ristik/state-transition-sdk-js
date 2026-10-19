import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { RootTrustBase } from '../../../../../src/api/bft/RootTrustBase.js';
import { RootTrustBaseV2 } from '../../../../../src/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseHistory } from '../../../../../src/api/bft/trustbase/TrustBaseHistory.js';
import { NetworkId } from '../../../../../src/api/NetworkId.js';
import { HexConverter } from '../../../../../src/util/HexConverter.js';

const dir = join(process.cwd(), 'tests/fixtures/utb/legacy-genesis');
const legacy = RootTrustBase.fromJSON(JSON.parse(readFileSync(join(dir, 'bft-trustbase.testnet2.json'), 'utf8')));
const goBytes = readFileSync(join(dir, 'bft-trustbase.testnet2.v2.cbor.hex'), 'utf8').trim();
const goEntryId = '4b49eb2bb0729051b89a48668fd6ef1fda284aad2e10b7d5f23aad4b5faef37f';

describe('version-2 genesis from an on-disk JSON genesis trust base', () => {
  it('equals the Go-derived entry byte for byte (testnet2)', async () => {
    const genesis = RootTrustBaseV2.genesisFromLegacy(legacy);
    expect(HexConverter.encode(genesis.toCBOR())).toBe(goBytes);
    expect(HexConverter.encode(await genesis.entryId())).toBe(goEntryId);
    expect(genesis.isGenesis).toBe(true);
    expect(genesis.signatures).toBeNull();
    expect(genesis.stateHash).toBeNull();
    expect(genesis.changeRecordHash).toBeNull();
  });

  it('opens a history pinned by that EntryID', async () => {
    const genesis = RootTrustBaseV2.genesisFromLegacy(legacy);
    const history = await TrustBaseHistory.fromGenesis(genesis.toCBOR(), HexConverter.decode(goEntryId));
    expect(history.tip.epoch).toBe(1n);
    expect(history.networkId).toBe(NetworkId.TESTNET);
  });
});

describe('NetworkId', () => {
  it('TESTNET is testnet2, network 4', () => {
    expect(NetworkId.TESTNET.id).toBe(4);
    expect(NetworkId.fromId(4)).toBe(NetworkId.TESTNET);
    expect(legacy.networkId.id).toBe(NetworkId.TESTNET.id);
  });
});

describe('absent state and change-record hashes', () => {
  it('have one byte form: an in-memory empty value is held and encoded as null, with the same EntryID', async () => {
    const genesis = RootTrustBaseV2.genesisFromLegacy(legacy);
    const fields = {
      epoch: genesis.epoch,
      epochStartRound: genesis.epochStartRound,
      networkId: genesis.networkId,
      previousEntryId: genesis.previousEntryId,
      quorumThreshold: genesis.quorumThreshold,
      rootNodes: genesis.rootNodes,
    };
    const empty = RootTrustBaseV2.create({
      ...fields,
      changeRecordHash: new Uint8Array(0),
      stateHash: new Uint8Array(0),
    });
    const absent = RootTrustBaseV2.create({ ...fields, changeRecordHash: null, stateHash: null });
    expect(empty.stateHash).toBeNull();
    expect(HexConverter.encode(empty.toCBOR())).toBe(HexConverter.encode(absent.toCBOR()));
    expect(HexConverter.encode(await empty.entryId())).toBe(goEntryId);
  });
});
