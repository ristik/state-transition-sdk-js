`v2/` is vendored byte for byte from aggregator-go PR #252 (owner decision D), final head
`13496d41bd056948696d4ebc13a1d2cb3a4379ab`, directory `testdata/non-inclusion/v2`, schema 2: discriminated snapshot
outcomes, fixed partition 7, no freshness option or `stale` verdict, sharded positives, large uint64 snapshot values,
`policy.json` and `sequences.json`. Generator: `UC_FIXTURE_AGGREGATOR_COMMIT=b25dd916fba88b18066bf239b6130b386d3347dd go run
./cmd/gen-ni-fixtures -out testdata/non-inclusion/v2` (the manifest records it and the module versions).
`manifest.json` lists the SHA-256 of every other file, and the manifest's own SHA-256 is pinned in
`tests/unit/api/NonInclusionCorpusTest.ts`: `996b14db7519e1a7619923d58214a3993e269bf613177e45bf3f656e578ee598`. Both are checked by that test. It replaces the earlier `v1` corpus
and the locally generated sharded vectors (`non-inclusion-sharded`), which the shared corpus now covers.
