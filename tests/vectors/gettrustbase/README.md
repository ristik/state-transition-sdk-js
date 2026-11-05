# Shared GetTrustBase response vectors

`vectors.json` is vendored byte for byte, not generated here:

- source: `ristik/bft-core` PR #928, branch `dev2/gettrustbase-vectors`, commit `6296cb63ee12c060c8d2b48bb76dfea1f102dd03`, `gettrustbase/testdata/v1/vectors.json` (reference codec: `gettrustbase/codec.go`). Not merged at the time of vendoring.
- sha256: `3f9732fa5d5bed202d326f452f732d625040dbfac81857e19574df25bde3734c`
- never edit this copy; regenerate at the source.

Layout: `{spec[], entries[3], network, cases[]}`. An accept case names the decoded fields (`status`, `fromEpoch`, `effectiveEnd`, `endEntryId`, `entryEpochs`, `nextEpoch`); a reject case names the class (`encoding`: not a well-formed deterministic response; `response`: a consistency rule). Used by `tests/unit/api/bft/trustbase/TrustBaseRangeVectorsTest.ts`.
