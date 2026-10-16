#!/usr/bin/env node
// Long-poll interop driver for the CURRENT JS SDK (build it first: `npm run build`, the script imports ../../lib).
// Counts every HTTP request the SDK makes and reports per scenario; see scripts/lp-interop/README.md.
//
//   node scripts/lp-interop/run.mjs --url http://host:3000 --trust-base tests/e2e/trust-base.json \
//        [--api-key K] [--label S2-LP] [--scenario l2,l3,l4,l5,l6,l7] [--wait-ms 5000] [--states 50] [--concurrency 10]
//        [--interval-ms 1000] [--timeout-ms 60000] [--report out.json]
//
// Scenarios (brief-lp-interop.md): l2 happy path, l3 timeout, l4 batch, l5 fallback/pacing/parser retry, l6 cap (the same
// flow as l2, read the echoes against a server started with LONG_POLL_MAX_WAITERS=0), l7 polling vs long poll under load.
// The verdict of a scenario is facts (counts, echoes, timings), judged by the interop matrix owner; `ok` only says the
// flow completed and every proof verified.
import { AsyncLocalStorage } from 'node:async_hooks';
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

const { values } = parseArgs({
  options: {
    'api-key': { type: 'string' },
    concurrency: { default: '10', type: 'string' },
    'interval-ms': { default: '1000', type: 'string' },
    label: { default: 'server', type: 'string' },
    report: { type: 'string' },
    scenario: { default: 'l2,l3,l4,l5,l6,l7', type: 'string' },
    states: { default: '50', type: 'string' },
    'timeout-ms': { default: '60000', type: 'string' },
    'trust-base': { type: 'string' },
    url: { type: 'string' },
    'wait-ms': { default: '5000', type: 'string' },
  },
});
const num = (name) => {
  const n = Number(values[name]);
  if (!Number.isInteger(n) || n <= 0) {
    console.error(`--${name} must be a positive integer`);
    process.exit(2);
  }
  return n;
};
if (!values.url || !values['trust-base']) {
  console.error('usage: node scripts/lp-interop/run.mjs --url <aggregator> --trust-base <file> [options], see the header');
  process.exit(2);
}
const WAIT_MS = num('wait-ms');
const STATES = num('states');
const CONCURRENCY = num('concurrency');
const INTERVAL_MS = num('interval-ms');
const TIMEOUT_MS = num('timeout-ms');

// ---- request counting: every fetch of the SDK, attributed to the scenario/state that is running (AsyncLocalStorage)
const scope = new AsyncLocalStorage();
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const rec = scope.getStore();
  const t0 = performance.now();
  let method = '?';
  let params = {};
  try {
    ({ method, params } = JSON.parse(init?.body ?? '{}'));
  } catch {}
  const entry = {
    at: t0,
    hasWait: params && typeof params === 'object' && 'waitMs' in params,
    method,
    waitMs: params?.waitMs ?? null,
  };
  rec?.requests.push(entry);
  try {
    const response = await realFetch(url, init);
    entry.ms = performance.now() - t0;
    entry.status = response.status;
    try {
      const body = await response.clone().json();
      entry.waitedMs = body?.result?.waitedMs ?? body?.error?.data?.waitedMs ?? null;
      entry.rpcError = body?.error ? { code: body.error.code, detail: body.error.data?.detail ?? null } : null;
    } catch {}
    return response;
  } catch (e) {
    entry.ms = performance.now() - t0;
    entry.failed = String(e?.name ?? e);
    throw e;
  }
};
const counted = (fn) => {
  const rec = { requests: [] };
  return scope.run(rec, fn).then(
    (value) => ({ rec, value }),
    (error) => ({ error, rec }),
  );
};
const summarize = (requests) => {
  const proofs = requests.filter((r) => r.method?.startsWith('get_inclusion_proof'));
  const sorted = proofs.map((r) => r.at).sort((a, b) => a - b);
  const gaps = sorted.slice(1).map((t, i) => t - sorted[i]);
  return {
    proofRequests: proofs.length,
    proofRequestsWithWait: proofs.filter((r) => r.hasWait).length,
    submissions: requests.filter((r) => r.method === 'certification_request').length,
    echoes: proofs.map((r) => r.waitedMs),
    minGapMs: gaps.length ? Math.round(Math.min(...gaps)) : null,
    httpStatuses: [...new Set(proofs.map((r) => r.status))],
  };
};
const pct = (xs, p) => (xs.length ? [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor((p / 100) * xs.length))] : null);

// ---- the SDK under test
const lib = (path) => import(`../../lib/${path}`);
const [
  { AggregatorClient },
  { StateTransitionClient },
  { RootTrustBase },
  { UnicityCertificateVerifier },
  { UnicitySealQuorumSignaturesVerificationRule },
  { VerifiedSealCache },
  { Secp256k1SignatureVerifier },
  { SigningService },
  { SignaturePredicate },
  { PredicateVerifierService },
  { MintTransaction },
  { TokenSalt },
  { TokenType },
  { CertificationData },
  { StateId },
  { waitInclusionProof },
  { NetworkId },
] = await Promise.all([
  lib('api/AggregatorClient.js'),
  lib('StateTransitionClient.js'),
  lib('api/bft/RootTrustBase.js'),
  lib('api/bft/verification/UnicityCertificateVerifier.js'),
  lib('api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js'),
  lib('api/bft/verification/VerifiedSealCache.js'),
  lib('crypto/secp256k1/Secp256k1SignatureVerifier.js'),
  lib('crypto/secp256k1/SigningService.js'),
  lib('predicate/builtin/SignaturePredicate.js'),
  lib('predicate/verification/PredicateVerifierService.js'),
  lib('transaction/MintTransaction.js'),
  lib('transaction/TokenSalt.js'),
  lib('transaction/TokenType.js'),
  lib('api/CertificationData.js'),
  lib('api/StateId.js'),
  lib('util/InclusionProofUtils.js'),
  lib('api/NetworkId.js'),
]);

const trustBase = RootTrustBase.fromJSON(JSON.parse(readFileSync(values['trust-base'], 'utf8')));
const predicateVerifier = PredicateVerifierService.create();
const certificateVerifier = new UnicityCertificateVerifier(
  new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier(), new VerifiedSealCache(256)),
);
const aggregator = new AggregatorClient(values.url, values['api-key'] ?? null, new URL(values.url).protocol !== 'https:');
const client = new StateTransitionClient(aggregator);
const signer = SigningService.generate();
const mint = () =>
  MintTransaction.create(NetworkId.fromId(trustBase.networkId.id), SignaturePredicate.create(signer.publicKey), {
    salt: TokenSalt.generate(),
    tokenType: TokenType.generate(),
  });
const submit = async (tx) => {
  const response = await client.submitCertificationRequest(await CertificationData.fromMintTransaction(tx));
  if (response.status !== 'SUCCESS') throw new Error(`submission status ${response.status}`);
};
const wait = (tx, options) =>
  waitInclusionProof(client, trustBase, predicateVerifier, certificateVerifier, tx, { timeoutMs: TIMEOUT_MS, ...options });

// ---- scenarios
async function happyPath(options = {}) {
  const tx = await mint();
  const begun = performance.now();
  const { rec, value, error } = await counted(async () => {
    await submit(tx);
    const submitted = performance.now();
    const proof = await wait(tx, { intervalMs: INTERVAL_MS, ...options });
    return { proof, sinceSubmitMs: Math.round(performance.now() - submitted) };
  });
  return {
    ok: !error && !!value?.proof,
    error: error ? String(error?.message ?? error) : undefined,
    sinceSubmitMs: value?.sinceSubmitMs,
    totalMs: Math.round(performance.now() - begun),
    ...summarize(rec.requests),
  };
}

const scenarios = {
  // submit, then a waited read: proof requests per state and the echoes
  async l2() {
    return happyPath();
  },
  // a short waitMs on a freshly submitted (pending) state: normal pending + echo about equal to the wait, or already included
  async l3() {
    const tx = await mint();
    const id = await StateId.fromTransaction(tx);
    const { rec, value, error } = await counted(async () => {
      await submit(tx);
      const begun = performance.now();
      const response = await client.getInclusionProof(id, { includeStatusHint: true, waitMs: WAIT_MS });
      return { elapsedMs: Math.round(performance.now() - begun), response };
    });
    const r = value?.response;
    await wait(tx, { intervalMs: INTERVAL_MS }).catch(() => undefined); // let it finish, leave no pending request behind
    return {
      ok: !error,
      error: error ? String(error?.message ?? error) : undefined,
      requestedWaitMs: WAIT_MS,
      outcome: r ? (r.inclusionProof ? 'included' : `pending(${r.statusHint ?? 'no hint'})`) : null,
      waitedMs: r?.waitedMs ?? null,
      elapsedMs: value?.elapsedMs,
      withinDeadline: value ? value.elapsedMs <= WAIT_MS + 2000 : null,
      ...summarize(rec.requests),
    };
  },
  // wait-all over pending ids; then one unknown id ends the wait at once
  async l4() {
    const txs = await Promise.all([mint(), mint(), mint()]);
    const ids = await Promise.all(txs.map((t) => StateId.fromTransaction(t)));
    const unknown = await StateId.fromTransaction(await mint());
    const batch = async (list) => {
      const begun = performance.now();
      try {
        const result = await aggregator.getInclusionProofs(list, { waitMs: WAIT_MS });
        return { kind: 'success', proofs: result.proofs.length, waitedMs: result.waitedMs, requests: result.requests, elapsedMs: Math.round(performance.now() - begun) };
      } catch (e) {
        return { kind: 'error', errorKind: e?.kind, code: e?.code, detail: e?.detail, waitedMs: e?.waitedMs ?? null, requests: e?.requests, elapsedMs: Math.round(performance.now() - begun) };
      }
    };
    const { rec, value, error } = await counted(async () => {
      for (const tx of txs) await submit(tx);
      const pendingAll = await batch(ids);
      const withUnknown = await batch([...ids, unknown]);
      return { pendingAll, withUnknown };
    });
    for (const tx of txs) await wait(tx, { intervalMs: INTERVAL_MS }).catch(() => undefined);
    return { ok: !error, error: error ? String(error?.message ?? error) : undefined, requestedWaitMs: WAIT_MS, ...value, ...summarize(rec.requests) };
  },
  // fallback: pacing of the wait helper (min gap between proof requests) and the batch parser retry count
  async l5() {
    const polled = await happyPath({ intervalMs: INTERVAL_MS });
    const unknown = await StateId.fromTransaction(await mint());
    const { rec, value } = await counted(async () => {
      try {
        await aggregator.getInclusionProofs([unknown], { waitMs: WAIT_MS });
        return { kind: 'success' };
      } catch (e) {
        return { kind: 'error', errorKind: e?.kind, code: e?.code, detail: e?.detail, requests: e?.requests };
      }
    });
    return {
      ok: polled.ok,
      helper: polled,
      batchParserProbe: { ...value, httpRequests: rec.requests.length, expectOneRetryOnlyAgainstAStrictParser: true },
      intervalMs: INTERVAL_MS,
    };
  },
  // cap: identical flow to l2; against LONG_POLL_MAX_WAITERS=0 the echoes are all 0 and gaps >= the interval
  async l6() {
    return { ...(await happyPath()), intervalMs: INTERVAL_MS, note: 'expect echoes 0 and minGapMs >= intervalMs (capacity 0)' };
  },
  // polling vs long poll at the same offered load
  async l7() {
    const run = async (name, options) => {
      const txs = await Promise.all(Array.from({ length: STATES }, () => mint()));
      const latencies = [];
      let verified = 0;
      let failed = 0;
      const all = { requests: [] };
      let next = 0;
      const begun = performance.now();
      const worker = async () => {
        while (next < txs.length) {
          const tx = txs[next++];
          const { rec, error } = await counted(async () => {
            await submit(tx);
            const t = performance.now();
            await wait(tx, options);
            latencies.push(performance.now() - t);
          });
          all.requests.push(...rec.requests);
          if (error) failed++;
          else verified++;
        }
      };
      await Promise.all(Array.from({ length: CONCURRENCY }, worker));
      const s = summarize(all.requests);
      return {
        mode: name,
        states: STATES,
        concurrency: CONCURRENCY,
        verified,
        failed,
        totalMs: Math.round(performance.now() - begun),
        proofRequests: s.proofRequests,
        proofRequestsPerVerifiedState: verified ? +(s.proofRequests / verified).toFixed(2) : null,
        submissions: s.submissions,
        latencyMs: { p50: Math.round(pct(latencies, 50)), p90: Math.round(pct(latencies, 90)), p99: Math.round(pct(latencies, 99)), max: Math.round(Math.max(0, ...latencies)) },
      };
    };
    const polling = await run('polling', { intervalMs: INTERVAL_MS, longPoll: false });
    const longPoll = await run('long-poll', { intervalMs: INTERVAL_MS });
    return { ok: polling.failed === 0 && longPoll.failed === 0, polling, longPoll };
  },
};

const report = { label: values.label, url: values.url, sdk: 'state-transition-sdk-js (this checkout)', started: new Date().toISOString(), results: {} };
for (const name of values.scenario.split(',').map((s) => s.trim())) {
  if (!scenarios[name]) {
    console.error(`unknown scenario ${name}`);
    process.exit(2);
  }
  try {
    report.results[name] = await scenarios[name]();
  } catch (e) {
    report.results[name] = { ok: false, error: String(e?.stack ?? e) };
  }
  console.log(`${report.results[name].ok ? 'ok  ' : 'FAIL'} ${name} ${JSON.stringify(report.results[name])}`);
}
if (values.report) writeFileSync(values.report, `${JSON.stringify(report, null, 2)}\n`);
process.exit(Object.values(report.results).every((r) => r.ok) ? 0 : 1);
