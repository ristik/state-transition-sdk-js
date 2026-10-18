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
