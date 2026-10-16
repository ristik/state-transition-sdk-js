# JS long-poll interop driver

`run.mjs` drives the **current** JS SDK (`lib/`, so `npm run build` first) against an aggregator URL and counts every HTTP
request the SDK makes. Scenarios follow `orchestration/brief-lp-interop.md`: `l2` happy path (proof requests per state, echoes),
`l3` short wait on a pending state, `l4` batch wait-all and batch with an unknown id, `l5` fallback pacing and batch parser retry
count, `l6` cap (run `l2`'s flow against `LONG_POLL_MAX_WAITERS=0`), `l7` polling vs long poll at the same offered load
(states, concurrency, p50/p90/p99, proof requests per verified state).

```sh
npm ci && npm run build
node scripts/lp-interop/run.mjs --url http://localhost:3000 --trust-base tests/e2e/trust-base.json --label S2-LP \
  --scenario l2,l3,l4,l5,l6,l7 --wait-ms 5000 --states 50 --concurrency 10 --report /tmp/js-s2-lp.json
```

The released 3.0.1 runner is `compat/released-3.0.1` (`run.mjs`, `--report` now includes `requestCounts`). The driver reports
facts; it does not decide PASS/FAIL of a matrix cell. `tests/unit/compat/LpInteropRunnerTest.ts` self-tests it against a
server that ignores `waitMs` (needs the build).
