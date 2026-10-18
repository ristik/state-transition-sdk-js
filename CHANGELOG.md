# Changelog

## Unreleased

### Breaking for TypeScript consumers

- `CertificationStatus` has two new members, `STATE_ID_QUEUED` and `ALREADY_SUBMITTED`. An exhaustive `switch` over
  `CertificationStatus` no longer compiles until it has a case for each (a compile-time break only; the wire format is
  unchanged).

- `ShardRouting` no longer takes `partitionId` (and `ShardRouting.single(client)` no longer takes a partition), and
  `PartitionViewAuthenticator` no longer takes a partition as its first constructor argument: the partition is the
  fixed `AGGREGATION_PARTITION_ID`. Delete the argument.

### Added

- `AGGREGATION_PARTITION_ID` (`7n`, `lib/api/bft/AggregationPartition.js`): the aggregation partition of every network
  (mainnet network 1, testnet2 network 4, local network 3). It cannot be configured.

### Behaviour

- Application verification requires the authenticated unicity certificate to be of partition 7: genesis, transfers and
  nested tokens (also when the certificate verification is served from the operation's memo), consolidation evidence and
  partition views. A certificate of another partition, however validly signed, no longer verifies.
- Tokens whose certificates violate the native structural rules no longer verify (bft-go-base `IsValid`, with its
  conditional semantics): input record (from round 1 a summary value and a timestamp; an unchanged state hash needs a nil
  block hash, a changed one a non-nil block hash), a 32 byte technical record hash, and the seal (hash, root round at
  least 1, timestamp not before the genesis time, signatures with a signer id and bytes). A null field alone is not
  malformed. All 48 certificates fetched from the public mainnet and testnet2 gateways satisfy the rules.

- `waitInclusionProof` can reject earlier with `InclusionProofExpiredError` / `InclusionProofUnknownError` (opt out with
  `statusHints: false`). `InclusionProofConflictError` is raised only for a proof that authenticates against the trust
  base; any other mismatching proof is a generic invalid-proof error.
- Ordinary inclusion-proof verification requires the shard tree certificate to hold exactly one sibling per shard id bit.
- `getInclusionProofs` sends the configured `X-API-Key`; HTTP 401/403 on it are `transport` failures that are not retryable.
- The `get_inclusion_proofs.v1` result decoder ignores unknown result fields, so fields a service adds later do not break
  deployed clients. Known fields, the proof count and order, and CBOR versions stay strictly validated.
- The shared JSON-RPC transport throws `JsonRpcResponseError` (instead of `JsonRpcDataError`) for an error envelope whose
  id does not match the request. The behaviour is kept; callers of other methods that match on the old class should
  catch both.
- `get_inclusion_proofs.v1` has to be sent to the shard aggregators directly; the aggregator-subscription proxy cannot
  route it yet (see the README).
