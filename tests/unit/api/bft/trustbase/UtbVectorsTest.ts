import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { RootTrustBaseV2 } from '../../../../../src/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseError } from '../../../../../src/api/bft/trustbase/TrustBaseError.js';
import { TrustBaseHistory } from '../../../../../src/api/bft/trustbase/TrustBaseHistory.js';
import { TrustBaseResponse } from '../../../../../src/api/bft/trustbase/TrustBaseResponse.js';
import { HexConverter } from '../../../../../src/util/HexConverter.js';

/** tests/fixtures/utb/v1: the shared Go-generated UTB vector set (identical in the Rust SDK; see its generator/README.md). */
interface IVectors {
  bundleCases: {
    decodes: boolean;
    held?: number;
    id: string;
    input: string;
    install?: 'appended' | 'noop' | 'refused';
    tipAfter?: number;
    verifies: boolean;
  }[];
  chain: { entryId: string; epoch: number; hex: string; sigBytes: string }[];
  entryCases: {
    expected: { result: 'appended' | 'conflict' | 'gap' | 'noop' | 'refused'; tipAfter: number };
    held: number;
    heldBytesAfter?: string;
    id: string;
    input: string;
  }[];
  format: string;
  genesisCases: { id: string; input: string; pin: string; valid: boolean }[];
  network: number;
  pin: string;
}

const vectors = JSON.parse(
  readFileSync(join(process.cwd(), 'tests/fixtures/utb/v1/utb-vectors-v1.json'), 'utf8'),
) as IVectors;
const hex = HexConverter.decode;
const pin = hex(vectors.pin);

async function historyAt(held: number): Promise<TrustBaseHistory> {
  const history = await TrustBaseHistory.fromGenesis(hex(vectors.chain[0].hex), pin);
  for (const entry of vectors.chain.slice(1, held)) {
    await history.append(hex(entry.hex));
  }
  return history;
}

async function outcome(history: TrustBaseHistory, input: Uint8Array): Promise<string> {
  try {
    return (await history.append(input)) ? 'appended' : 'noop';
  } catch (error) {
    if (!TrustBaseError.is(error)) {
      throw error;
    }
    return error.reason === 'gap' || error.reason === 'conflict' ? error.reason : 'refused';
  }
}

describe('UTB v1 vectors (Go-generated, shared with the Rust SDK)', () => {
  it('has the expected format', () => {
    expect(vectors.format).toBe('utb-vectors/v1');
  });

  it.each(vectors.chain)('chain epoch $epoch: canonical bytes, sigBytes and EntryID', async (c) => {
    const entry = RootTrustBaseV2.fromCBOR(hex(c.hex));
    expect(entry.epoch).toBe(BigInt(c.epoch));
    expect(entry.networkId).toBe(vectors.network);
    expect(HexConverter.encode(entry.toCBOR())).toBe(c.hex);
    expect(HexConverter.encode(entry.sigBytes())).toBe(c.sigBytes);
    expect(HexConverter.encode(await entry.entryId())).toBe(c.entryId);
  });

  it.each(vectors.genesisCases)('genesis $id', async (c) => {
    const opened = TrustBaseHistory.fromGenesis(hex(c.input), hex(c.pin));
    if (c.valid) {
      await expect(opened).resolves.toBeInstanceOf(TrustBaseHistory);
    } else {
      await expect(opened).rejects.toBeInstanceOf(TrustBaseError);
    }
  });

  it.each(vectors.entryCases)('entry $id', async (c) => {
    const history = await historyAt(c.held);
    expect(await outcome(history, hex(c.input))).toBe(c.expected.result);
    expect(history.tip.epoch).toBe(BigInt(c.expected.tipAfter));
    if (c.heldBytesAfter) {
      const epoch = RootTrustBaseV2.fromCBOR(hex(c.heldBytesAfter)).epoch;
      expect(HexConverter.encode(history.bytes(epoch)!)).toBe(c.heldBytesAfter);
    }
  });

  it.each(vectors.bundleCases)('bundle $id', async (c) => {
    const limits = { maxBytes: 1 << 20, maxEntries: 1 << 10 };
    let bundle: TrustBaseResponse | null = null;
    try {
      bundle = await TrustBaseResponse.decodeBundle(hex(c.input), limits);
    } catch (error) {
      expect(TrustBaseError.is(error)).toBe(true);
    }
    expect(bundle !== null).toBe(c.decodes);
    if (bundle === null) {
      return;
    }
    await (c.verifies
      ? expect(TrustBaseResponse.verifyBundle(bundle, pin)).resolves.toBeUndefined()
      : expect(TrustBaseResponse.verifyBundle(bundle, pin)).rejects.toBeInstanceOf(TrustBaseError));
    if (c.held) {
      const history = await historyAt(c.held);
      let install: string;
      try {
        install = (await history.installBundle(bundle)) > 0 ? 'appended' : 'noop';
      } catch (error) {
        expect(TrustBaseError.is(error)).toBe(true);
        install = 'refused';
      }
      expect(install).toBe(c.install);
      expect(history.tip.epoch).toBe(BigInt(c.tipAfter!));
    }
  });

  it('round-trips the complete history through a bundle', async () => {
    const history = await historyAt(vectors.chain.length);
    const bundle = await history.exportBundle();
    const reloaded = await TrustBaseHistory.fromBundle(bundle, pin);
    expect(reloaded.tip.epoch).toBe(BigInt(vectors.chain.length));
    expect(HexConverter.encode(reloaded.tip.entryId)).toBe(vectors.chain[vectors.chain.length - 1].entryId);
    const fromGo = vectors.bundleCases.find((c) => c.id === 'bundle.complete')!;
    expect(HexConverter.encode(bundle)).toBe(fromGo.input); // byte-identical with bft-core gettrustbase.EncodeBundle
  });
});
