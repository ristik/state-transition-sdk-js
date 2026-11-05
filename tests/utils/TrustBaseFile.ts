import { readFileSync } from 'node:fs';

import { TrustBaseBundle } from '../../src/api/bft/trustbase/TrustBaseBundle.js';
import { TrustBaseHistory } from '../../src/api/bft/trustbase/TrustBaseHistory.js';
import { HexConverter } from '../../src/util/HexConverter.js';

/** Budget for a test deployment's bundle file. */
const LIMITS = { maxBytes: 1 << 20, maxEntries: 1024 };

/**
 * The trust-base history of a deployment under test, from a trust-base bundle file (tag 39015, one-entry for a fresh network) and the genesis
 * entry id the test pins. Built synchronously so a suite can use it at describe level: `history` is filled when `ready` settles, so wait for
 * `ready` (for example in `beforeAll`) before verifying.
 *
 * @param {string} path Bundle file.
 * @param {string} genesisPinHex Genesis entry id, hex.
 * @returns {object} The history and the promise that settles when it holds the bundle.
 */
export function loadTrustBaseHistorySync(
  path: string,
  genesisPinHex: string,
): { history: TrustBaseHistory; ready: Promise<void> } {
  const pin = HexConverter.decode(genesisPinHex);
  const history = TrustBaseHistory.create(pin);
  const ready = TrustBaseBundle.decode(new Uint8Array(readFileSync(path)), LIMITS).then(async (bundle) => {
    for (const entry of bundle.entries) {
      await history.append(entry);
    }
  });
  return { history, ready };
}

/**
 * @param {string} name Environment variable.
 * @returns {string} Its value.
 * @throws {Error} If it is unset.
 */
export function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is unset (a trust-base bundle file and its genesis entry id are needed).`);
  }
  return value;
}
