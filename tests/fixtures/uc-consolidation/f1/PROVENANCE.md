# F1 fixture corpus (aggregator-go `testdata/uc-consolidation/v1`)

Copied verbatim (no edits) from `unicitynetwork/aggregator-go`, branch `uc-consolidation`, commit
`e5bdd7a86d56e2d9a8fbe2ef9a22f777b52a68d2`, directory `testdata/uc-consolidation/v1/`. The manifest records the
generator commits (aggregator-go `b063f164b1bda06fc6ad89f18cba85e19a7f8bfa`, bft-core `39340692da3a`, bft-go-base
`6251c1d73eee`) and a SHA-256 of every payload file; `tests/unit/consolidation/F1CorpusTest.ts` re-checks them.

The corpus describes proof bundles (`get_inclusion_proof.v2` results and certification requests), so it drives
`ProofConsolidator` directly; token level behaviour is tested with locally built tokens.
