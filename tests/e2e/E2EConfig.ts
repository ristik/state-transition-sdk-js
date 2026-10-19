import { readFileSync } from 'node:fs';

import defaultTrustBaseJson from './trust-base.json' with { type: 'json' };
import { AggregatorClient } from '../../src/api/AggregatorClient.js';
import { RootTrustBase } from '../../src/api/bft/RootTrustBase.js';
import { IAggregatorClient } from '../../src/api/IAggregatorClient.js';
import { StateTransitionClient } from '../../src/StateTransitionClient.js';

/**
 * Aggregator endpoint under test. Defaults to a local aggregator; point
 * `AGGREGATOR_URL` at a real network (together with `TRUST_BASE_PATH` and,
 * when the endpoint requires one, `AGGREGATOR_API_KEY`) to run against it.
 */
export const AGGREGATOR_URL = process.env.AGGREGATOR_URL ?? 'http://localhost:3000';

const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]', '::1', 'host.docker.internal']);

/**
 * Whether the client may send an API key over plaintext `http://`: only to a local stack or gateway
 * (`localhost`, `127.0.0.1`, `::1`, `host.docker.internal`), or to a remote host when `E2E_ALLOW_INSECURE=1`
 * says so explicitly. `https://` never needs it.
 *
 * @param {string} url Aggregator URL.
 * @param {NodeJS.ProcessEnv} env Environment to read `E2E_ALLOW_INSECURE` from.
 * @returns {boolean} The value for the client's `allowInsecureTransport` argument.
 */
export function allowInsecureTransportFor(url: string, env: NodeJS.ProcessEnv = process.env): boolean {
  const parsed = new URL(url);
  if (parsed.protocol !== 'http:') {
    return false;
  }
  return LOCAL_HOSTNAMES.has(parsed.hostname) || env.E2E_ALLOW_INSECURE === '1';
}

/**
 * Build the client and trust base the e2e suite runs against.
 *
 * @returns {object} Aggregator client, state transition client and trust base for the configured endpoint.
 */
export function createE2EContext(): {
  aggregatorClient: IAggregatorClient;
  client: StateTransitionClient;
  trustBase: RootTrustBase;
} {
  const aggregatorClient = new AggregatorClient(
    AGGREGATOR_URL,
    process.env.AGGREGATOR_API_KEY ?? null,
    // a local stack or gateway on http://: the client refuses to send an API key over plaintext otherwise
    allowInsecureTransportFor(AGGREGATOR_URL),
  );
  const trustBasePath = process.env.TRUST_BASE_PATH ?? null;

  return {
    aggregatorClient,
    client: new StateTransitionClient(aggregatorClient),
    trustBase: RootTrustBase.fromJSON(
      trustBasePath ? JSON.parse(readFileSync(trustBasePath, 'utf-8')) : defaultTrustBaseJson,
    ),
  };
}
