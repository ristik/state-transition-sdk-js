# Changelog

## Unreleased

### Breaking for TypeScript consumers

- `CertificationStatus` has two new members, `STATE_ID_QUEUED` and `ALREADY_SUBMITTED`. An exhaustive `switch` over
  `CertificationStatus` no longer compiles until it has a case for each (a compile-time break only; the wire format is
  unchanged).

### Behaviour

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
