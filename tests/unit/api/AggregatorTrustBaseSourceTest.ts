import { createServer, IncomingMessage, Server } from 'node:http';
import { AddressInfo } from 'node:net';

import { AggregatorClient } from '../../../src/api/AggregatorClient.js';
import { JsonRpcNetworkError } from '../../../src/api/json-rpc/JsonRpcNetworkError.js';
import { JsonRpcResponseError } from '../../../src/api/json-rpc/JsonRpcResponseError.js';

describe('AggregatorClient as a trust-base source', () => {
  let server: Server;
  let base: string;
  let seen: IncomingMessage[];
  let reply: { body: Uint8Array; status: number };

  beforeAll(async () => {
    server = createServer((req, res) => {
      seen.push(req);
      res.writeHead(reply.status, { 'content-type': 'application/cbor' }).end(Buffer.from(reply.body));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  beforeEach(() => {
    seen = [];
    reply = { body: new Uint8Array([0xd9, 0x98, 0x67]), status: 200 };
  });

  it('GETs /api/v1/trustbases on the aggregator origin with from and maxEntries, and returns the body bytes', async () => {
    const client = new AggregatorClient(`${base}/rpc`, 'secret', true);
    const bytes = await client.getTrustBaseEntries(7n, 64);
    expect(Array.from(bytes)).toEqual([0xd9, 0x98, 0x67]);
    expect(seen).toHaveLength(1);
    expect(seen[0].method).toBe('GET');
    expect(seen[0].url).toBe('/api/v1/trustbases?from=7&maxEntries=64');
    expect(seen[0].headers['x-api-key']).toBe('secret');
    expect(seen[0].headers.accept).toBe('application/cbor');
  });

  it('reports a non-success status as a network error', async () => {
    reply = { body: new TextEncoder().encode('bad query'), status: 400 };
    await expect(new AggregatorClient(base).getTrustBaseEntries(1n, 1)).rejects.toMatchObject({ status: 400 });
    await expect(new AggregatorClient(base).getTrustBaseEntries(1n, 1)).rejects.toBeInstanceOf(JsonRpcNetworkError);
  });

  it('refuses a body above the page cap without buffering it', async () => {
    reply = { body: new Uint8Array(AggregatorClient.MAX_TRUST_BASE_RESPONSE_BYTES + 1), status: 200 };
    await expect(new AggregatorClient(base).getTrustBaseEntries(1n, 64)).rejects.toBeInstanceOf(JsonRpcResponseError);
  });
});
