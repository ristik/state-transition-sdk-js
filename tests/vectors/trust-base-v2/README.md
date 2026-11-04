# Shared trust-base V2 vectors

`vectors.json` is vendored byte for byte, not generated here:

- source: `ristik/bft-go-base`, branch `utb/upstream-v2`, commit `c32454f` (on upstream `cc768d1`; c202b48 plus the shared rule that network id 0 is an `invalid` entry), `testdata/trust-base-v2/v1/vectors.json`
- sha256: `dfcf63a085de29be9141821c3089f0f08548314470df8e96e4be43d4da466c09`
- regenerate there with `UPDATE_VECTORS=1 go test ./types -run TestTrustBaseV2SharedVectors`; never edit this copy.

Used by this PR: `entries`, `decode` and `bundles`. `history` and `weightedQuorum` belong to the history verifier (the next PR of the stack).
