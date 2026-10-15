/**
 * Stable machine-readable reasons of {@link PartitionViewError}. Tests and callers must bind to these rather than to
 * message text.
 */
export type PartitionViewErrorReason =
  | 'authority'
  | 'bounds'
  | 'config_not_admitted'
  | 'enclosing_certificate_mismatch'
  | 'malformed'
  | 'seal_invalid'
  | 'topology'
  | 'tree_mismatch'
  | 'unsupported_version';

/**
 * Thrown when a partition view is malformed, out of bounds, does not match the trusted topology, does not hash into
 * the enclosing seal, or its seal cannot be authenticated.
 */
export class PartitionViewError extends Error {
  public constructor(
    public readonly reason: PartitionViewErrorReason,
    message: string,
  ) {
    super(message);
    this.name = 'PartitionViewError';
  }
}
