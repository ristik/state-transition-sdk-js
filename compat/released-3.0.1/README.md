# Released-package compatibility runner (3.0.1)

Runs the **published** npm package `@unicitylabs/state-transition-sdk@3.0.1` against an aggregator, to prove that clients which
never send `waitMs` keep working byte for byte. Nothing here is built from this repository's sources.

- Pinned: version `3.0.1`, integrity `sha512-ND4mW7nQjgr8yDdxvHNFheHH3gPijD4y0NS7XU2YPzjsdyDs4LDCYlRG/ZSSEDbz3xVgMh1biL3BY60nGPIsXQ==`,
  tag `v3.0.1` = git `f5f0737306901215860aa920a6ab570b699efba8` (recorded in `package-lock.json` and `check-integrity.mjs`;
  `npm ci` verifies the tarball against it, `run.mjs` refuses to run if the wiring differs).

```sh
cd compat/released-3.0.1
npm ci --ignore-scripts
node check-integrity.mjs
node run.mjs --url http://localhost:3000 --trust-base ../../tests/e2e/trust-base.json [--api-key K] [--report out.json]
```

Steps (exit code 0 only if all pass): unknown state answer / HTTP 404; submission `SUCCESS`; empty-to-included polling with
full proof verification (`waitInclusionProof` and `toCertifiedTransaction`); the released client sends only
`get_inclusion_proof.v2` with `{stateId}` (no `waitMs`, no `includeStatus`); cancellation; proofs corrupted in transit (bit
flips, truncation, through a local proxy) are rejected; HTTP 404 on proof requests keeps the wait polling. The JSON report
records the step outcomes and the package identity, for the interop matrix.

The released package knows neither status hints nor the batch method, so those need the raw golden clients
(`tests/fixtures/longpoll/golden`). `tests/unit/compat/ReleasedCompatRunnerTest.ts` self-tests the runner against an
in-process legacy-wire server (skipped when `npm ci` was not run).
