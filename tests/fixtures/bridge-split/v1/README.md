# Bridge split cross-SDK vectors (v1)

`bridge_split.json` is written by `tests/functional/payment/BridgeSplitVectorTest.ts` with
`BRIDGE_SPLIT_VECTOR_OUT` set; without it the test checks this file. The Rust SDK
(ristik/state-transition-sdk-rust `tests/split_bridge_vectors.rs`) consumes the same file.

The payment data is the native bridge's wallet value envelope
`tag(39050, [1, [[b(aid32), b(amount)]], null])` (one asset, no memo; defined by the bridge
plug-ins, not the SDK). Amounts follow the split plan's lane in units of 10^15 wei:

- `root_100_into_40_60`: the source (100, owner key 1) is split into 40 (key 2) and 60 (key 3).
- `child_40_into_15_25`: the minted 40 is split again into 15 (key 4) and 25 (key 5).
- `leaves`: the two minted second-generation tokens, each carrying the whole ancestry
  (its burned 40 parent, which carries the burned 100 source) in its mint justification.

Fixed inputs: aggregator key 9 (trust base: network LOCAL, epoch 1, node `NODE`, weight 1),
secp256k1 private keys `1..5`, token type `0xc0..`, asset id `0xa1..`, salts, burn state
masks `0x07..` / `0x08..` and burn deadline 4102444800. Each split is a pure function of its
`sourceToken` and these inputs; the certified tokens carry wall-clock proofs, so regenerating
changes them.
