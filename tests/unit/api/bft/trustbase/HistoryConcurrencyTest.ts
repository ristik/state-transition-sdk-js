import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { TrustBaseHistory } from '../../../../../src/api/bft/trustbase/TrustBaseHistory.js';
import { TrustBaseResponse } from '../../../../../src/api/bft/trustbase/TrustBaseResponse.js';
import { HexConverter } from '../../../../../src/util/HexConverter.js';

const vectors = JSON.parse(readFileSync(join(process.cwd(), 'tests/fixtures/utb/v1/utb-vectors-v1.json'), 'utf8')) as {
  bundleCases: { id: string; input: string }[];
  chain: { epoch: number; hex: string }[];
  pin: string;
};
const entry = (epoch: number): Uint8Array => HexConverter.decode(vectors.chain[epoch - 1].hex);

function genesis(): Promise<TrustBaseHistory> {
  return TrustBaseHistory.fromGenesis(entry(1), HexConverter.decode(vectors.pin));
}

/** Every held epoch is stored once, at its own position. */
function expectConsistent(history: TrustBaseHistory, tip: number): void {
  expect(history.tip.epoch).toBe(BigInt(tip));
  for (let e = 1; e <= tip; e++) {
    expect(HexConverter.encode(history.bytes(BigInt(e))!)).toBe(vectors.chain[e - 1].hex);
    expect(history.entry(BigInt(e))!.epoch).toBe(BigInt(e));
  }
  expect(history.bytes(BigInt(tip + 1))).toBeNull();
}

describe('TrustBaseHistory under concurrent appends', () => {
  it('stores an epoch once when the same entry is appended twice at the same time', async () => {
    const history = await genesis();
    const results = await Promise.all([history.append(entry(2)), history.append(entry(2))]);
    expect(results.sort()).toEqual([false, true]);
    expectConsistent(history, 2);
  });

  it('applies interleaved appends of consecutive epochs in call order', async () => {
    const history = await genesis();
    expect(await Promise.all([history.append(entry(2)), history.append(entry(3)), history.append(entry(4))])).toEqual([
      true,
      true,
      true,
    ]);
    expectConsistent(history, 4);
  });

  it('serialises a bundle install with overlapping single appends', async () => {
    const history = await genesis();
    const complete = HexConverter.decode(vectors.bundleCases.find((c) => c.id === 'bundle.complete')!.input);
    const bundle = await TrustBaseResponse.decodeBundle(complete, TrustBaseResponse.PAGE_LIMITS);
    const [first, installed, last] = await Promise.all([
      history.append(entry(2)),
      history.installBundle(bundle),
      history.append(entry(3)),
    ]);
    expect([first, installed, last]).toEqual([true, 2, false]);
    expectConsistent(history, 4);
  });

  it('keeps serving later appends after a refused one', async () => {
    const history = await genesis();
    const results = await Promise.allSettled([history.append(entry(3)), history.append(entry(2))]);
    expect(results.map((r) => r.status)).toEqual(['rejected', 'fulfilled']);
    expectConsistent(history, 2);
  });
});
