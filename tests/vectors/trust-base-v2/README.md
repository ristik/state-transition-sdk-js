# Shared trust-base V2 vectors

`vectors.json` is vendored byte for byte, not generated here:

- source: `ristik/bft-go-base`, branch `utb/upstream-v2`, commit `c202b48` (on upstream `cc768d1`), `testdata/trust-base-v2/v1/vectors.json`
- sha256: `ccbca86863b2082a856c589169dad1a04128621ae0a8c0190c2e53ce98a2a257`
- regenerate there with `UPDATE_VECTORS=1 go test ./types -run TestTrustBaseV2SharedVectors`; never edit this copy.

Used by this PR: `entries`, `decode` and `bundles`. `history` and `weightedQuorum` belong to the history verifier (the next PR of the stack).
