/* eslint-disable @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { CertificationData } from '../../../src/api/CertificationData.js';
import { StateId } from '../../../src/api/StateId.js';
import { CborDeserializer } from '../../../src/serialization/cbor/CborDeserializer.js';
import { HexConverter } from '../../../src/util/HexConverter.js';
import { ShardedWorld } from '../../utils/ShardedWorld.js';

/**
 * Self-test of `scripts/lp-interop/run.mjs` against an in-process aggregator with the legacy wire (bare string proofs, no
 * echo, no batch method): the "server ignores waitMs" column. Needs `npm run build` (the script imports `lib/`); skipped
 * without it.
 */
const SCRIPT = join(__dirname, '../../../scripts/lp-interop/run.mjs');
const built = existsSync(join(__dirname, '../../../lib/api/AggregatorClient.js'));

jest.setTimeout(180_000);

(built ? describe : describe.skip)('long-poll interop runner (JS)', () => {
  it('runs every scenario against a server that ignores waitMs and reports honest counts', async () => {
    const world = await ShardedWorld.create(0);
    const shard = world.client('');
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        void (async (): Promise<void> => {
          const body = JSON.parse(Buffer.concat(chunks).toString()) as { id: string; method: string; params: unknown };
          let reply: object;
          if (body.method === 'get_inclusion_proof.v2') {
            const id = StateId.fromCBOR(
              new Uint8Array([0x58, 0x20, ...HexConverter.decode((body.params as { stateId: string }).stateId)]),
            );
            reply = { result: HexConverter.encode((await shard.getInclusionProof(id)).toCBOR()) };
          } else if (body.method === 'certification_request') {
            const tag = CborDeserializer.decodeTag(HexConverter.decode(body.params as string));
            const fields = CborDeserializer.decodeArray(tag.data, 4);
            reply = {
              result: (await shard.submitCertificationRequest(CertificationData.fromCBOR(fields[2]))).toJSON(),
            };
          } else {
            reply = { error: { code: -32601, message: 'Method not found' } };
          }
          res
            .writeHead(200, { 'content-type': 'application/json' })
            .end(JSON.stringify({ ...reply, id: body.id, jsonrpc: '2.0' }));
        })();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const dir = mkdtempSync(join(tmpdir(), 'lp-interop-'));
    writeFileSync(join(dir, 'trust-base.json'), JSON.stringify(world.trustBase.toJSON()));
    try {
      const code = await new Promise<number | null>((resolve) => {
        const child = spawn(
          process.execPath,
          [
            SCRIPT,
            '--url',
            `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
            '--trust-base',
            join(dir, 'trust-base.json'),
            '--report',
            join(dir, 'report.json'),
            '--wait-ms',
            '300',
            '--states',
            '4',
            '--concurrency',
            '2',
            '--interval-ms',
            '50',
          ],
          { stdio: 'inherit' },
        );
        child.on('exit', resolve);
      });
      const report = JSON.parse(readFileSync(join(dir, 'report.json'), 'utf8')) as {
        results: Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
      };
      expect(code).toBe(0);
      expect(Object.keys(report.results)).toEqual(['l2', 'l3', 'l4', 'l5', 'l6', 'l7']);
      // a server that ignores the wait: the first poll carries waitMs, no echo comes back, and polling goes on at the interval
      expect(report.results.l2.proofRequestsWithWait).toBe(1);
      expect(report.results.l2.echoes.every((e: unknown) => e === null)).toBe(true);
      expect(report.results.l2.minGapMs === null || report.results.l2.minGapMs >= 40).toBe(true);
      expect(report.results.l7.polling.proofRequestsPerVerifiedState).toBeGreaterThanOrEqual(1);
      expect(report.results.l7.longPoll.verified).toBe(4);
      // batch method absent: unsupported, one request, no retry
      expect(report.results.l5.batchParserProbe).toMatchObject({ errorKind: 'unsupported', httpRequests: 1 });
    } finally {
      server.close();
    }
  });
});
