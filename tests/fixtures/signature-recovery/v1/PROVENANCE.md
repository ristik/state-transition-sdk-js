# Provenance

`vectors.json` is vendored byte-identical (sha256 `268c49429f2579ec89b17ed392e6d8ce8609a30b2a2338dec2b732d2e0739ff8`)
from `unicitynetwork/bft-go-base` PR #11, branch `uc/o3-strict-recovery`, commit `7a1d36673dd646475cf6ec4e074d0f47beac021c`,
path `testdata/signature-recovery/v1/vectors.json`.

Do not edit. Re-vendor (and update this file) when dev-base extends the corpus. Rule (arch-o3.md §4): 65-byte `r||s||v`,
low-S, `v` in 0..3, the key recovered with `v` must equal the trusted key.
