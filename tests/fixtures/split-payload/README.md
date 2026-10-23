# Split payload cross-SDK vectors

`split_payload.json` is vendored unchanged from `tests/vectors/split-payload/` on
`state-transition-sdk-rust` main (ae0a58a, PR #68). Rust generated it from this SDK at
`6bd409bcdd2d312c814f7b9b8b91982c2c16253c` using `generate-split-vector.ts` (same directory in the Rust repo), so
`tests/functional/payment/SplitPayloadFreezeTest.ts` must reproduce it byte for byte: burn transaction, split manifest,
output payloads, commitments and allocation proofs.

The application envelope `tag(39050, [1, assets, null])` of the wrapped case is defined by the test helper
`tests/functional/payment/WrappedPaymentData.ts`, not by the SDK. Do not hand-edit the JSON; refresh it from Rust.
