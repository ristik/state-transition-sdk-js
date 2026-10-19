# Legacy (JSON, version 1) genesis → version 2 genesis entry

- `bft-trustbase.testnet2.json`: unicity-ids `44c6214`, verbatim.
- `bft-trustbase.testnet2.v2.cbor.hex`: the version-2 genesis entry of that JSON, encoded by the merged Go codec (ristik/bft-go-base `RootTrustBaseV2`, #1). It comes from `briefs/unicity-ids-proposal/v2-format-examples`.
  - EntryID: `4b49eb2bb0729051b89a48668fd6ef1fda284aad2e10b7d5f23aad4b5faef37f` (= SHA-256 of the bytes, since signatures are null).
  - Empty state and change-record hashes are encoded as CBOR null.
