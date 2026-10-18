`v2/` is vendored byte for byte from aggregator-go PR #252 (owner decision D), commit
`363960a17dbda5a6e4745ef2b72d7833f46a012c` (`CORPUS`), directory `testdata/non-inclusion/v2`, schema 2: discriminated snapshot
outcomes, fixed partition 7, no freshness option or `stale` verdict, sharded positives, large uint64 snapshot values,
`policy.json` and `sequences.json`. Generator: `UC_FIXTURE_AGGREGATOR_COMMIT=dd52a67ae77d4984f632b8dc9ad23925ee6541a4 go run
./cmd/gen-ni-fixtures -out testdata/non-inclusion/v2` (the manifest records it and the module versions).
`manifest.json` lists the SHA-256 of every file (checked by `tests/unit/api/NonInclusionCorpusTest.ts`). It replaces the
earlier `v1` corpus and the locally generated sharded vectors (`non-inclusion-sharded`), which the shared corpus now covers.
PR #252 is not merged yet: re-vendor from its merge commit if the corpus changes there.
