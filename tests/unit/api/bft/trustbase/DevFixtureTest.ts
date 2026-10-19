import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { TrustBaseHistory } from '../../../../../src/api/bft/trustbase/TrustBaseHistory.js';
import { HexConverter } from '../../../../../src/util/HexConverter.js';

const DIR = join(process.cwd(), 'tests/fixtures/utb/dev');

describe('shared dev trust-base fixture', () => {
  it('loads the release bundle under its pin, epochs 1 to 4', async () => {
    const pin = HexConverter.decode(readFileSync(join(DIR, 'bft-trustbase.dev.genesis.entryid'), 'utf8').trim());
    const history = await TrustBaseHistory.fromBundle(
      new Uint8Array(readFileSync(join(DIR, 'bft-trustbase.dev.bundle.cbor'))),
      pin,
    );
    expect(history.genesisEpoch).toBe(1n);
    expect(history.tip.epoch).toBe(4n);
    expect(history.committee(1n)!.id).toBe(HexConverter.encode(pin));
  });

  it('refuses the bundle under another pin', async () => {
    const bundle = new Uint8Array(readFileSync(join(DIR, 'bft-trustbase.dev.bundle.cbor')));
    await expect(TrustBaseHistory.fromBundle(bundle, new Uint8Array(32))).rejects.toThrow();
  });
});
