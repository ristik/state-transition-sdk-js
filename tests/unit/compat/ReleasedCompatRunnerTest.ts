import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { CertificationData } from '../../../src/api/CertificationData.js';
import { CborDeserializer } from '../../../src/serialization/cbor/CborDeserializer.js';
import { HexConverter } from '../../../src/util/HexConverter.js';
import { ShardedWorld } from '../../utils/ShardedWorld.js';

/**
 * Self-test of `compat/released-3.0.1/run.mjs`: the runner (which drives the npm release 3.0.1) against an in-process
 * aggregator that serves exactly what the released client understands. Needs `npm ci --ignore-scripts` in
 * `compat/released-3.0.1`; skipped without it. It proves the runner itself, not any server.
 */
const DIR = join(__dirname, '../../../compat/released-3.0.1');
const installed = existsSync(join(DIR, 'node_modules/@unicitylabs/state-transition-sdk/package.json'));

jest.setTimeout(180_000);

describe('released 3.0.1 compatibility runner', () => {
  (installed ? it : it.skip)('passes against a server with the legacy wire', async () => {
    const world = await ShardedWorld.create(0);
    const shard = world.client('');
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        void (async (): Promise<void> => {
          const body = JSON.parse(Buffer.concat(chunks).toString()) as {
            id: string;
            method: string;
            params: unknown;
          };
          let result: unknown;
          if (body.method === 'get_inclusion_proof.v2') {
            const { StateId } = await import('../../../src/api/StateId.js');
            const id = StateId.fromCBOR(
              new Uint8Array([0x58, 0x20, ...HexConverter.decode((body.params as { stateId: string }).stateId)]),
            );
            result = HexConverter.encode((await shard.getInclusionProof(id)).toCBOR());
          } else if (body.method === 'certification_request') {
            // tag(CertificationRequest) [version, stateId, certificationData, 0]
            const tag = CborDeserializer.decodeTag(HexConverter.decode(body.params as string));
            const fields = CborDeserializer.decodeArray(tag.data, 4);
            const status = await shard.submitCertificationRequest(CertificationData.fromCBOR(fields[2]));
            result = status.toJSON();
          }
          res
            .writeHead(200, { 'content-type': 'application/json' })
            .end(JSON.stringify({ id: body.id, jsonrpc: '2.0', result }));
        })();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const dir = mkdtempSync(join(tmpdir(), 'compat-'));
    writeFileSync(join(dir, 'trust-base.json'), JSON.stringify(world.trustBase.toJSON()));
    const report = join(dir, 'report.json');
    try {
      const code = await new Promise<number | null>((resolve) => {
        const child = spawn(
          process.execPath,
          [
            join(DIR, 'run.mjs'),
            '--url',
            `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
            '--trust-base',
            join(dir, 'trust-base.json'),
            '--report',
            report,
            '--timeout-ms',
            '20000',
          ],
          { cwd: DIR, stdio: 'inherit' },
        );
        child.on('exit', resolve);
      });
      const parsed = JSON.parse(readFileSync(report, 'utf8')) as {
        package: { integrity: string; version: string };
        steps: { name: string; status: string }[];
        verdict: string;
      };
      expect(parsed.steps.filter((s) => s.status !== 'pass')).toEqual([]);
      expect(parsed.verdict).toBe('pass');
      expect(parsed.package.version).toBe('3.0.1');
      expect(code).toBe(0);
    } finally {
      server.close();
    }
  });
});
