/**
 * Base class of the errors the Unicity Trust Base (UTB) codec raises. The subclasses are the error CLASSES a caller (and the shared
 * vectors) distinguish; the message carries the detail.
 */
export abstract class TrustBaseError extends Error {
  protected constructor(
    public readonly errorClass: string,
    message: string,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * The bytes are not a well-formed deterministic UTB record: wrong tag, version or arity, truncated, trailing bytes, out-of-bounds sizes,
 * a second byte form of the same value.
 */
export class TrustBaseEncodingError extends TrustBaseError {
  public constructor(message: string) {
    super('encoding', message);
  }
}

/**
 * The record is well formed but a structure rule fails: epoch zero, member list, weights, keys, quorum threshold, hash lengths, genesis versus
 * non-genesis shape.
 */
export class TrustBaseInvalidError extends TrustBaseError {
  public constructor(message: string) {
    super('invalid', message);
  }
}

/**
 * The bytes are a well-formed trust-base response but not a complete bundle: a status other than OK, a continuation cursor, a partial range
 * (not starting at a genesis entry), a gap or a broken predecessor link, a header that disagrees with its entries.
 */
export class TrustBaseBundleError extends TrustBaseError {
  public constructor(message: string) {
    super('bundle', message);
  }
}

/**
 * A well-formed entry that does not extend its predecessor: a genesis entry where a successor is expected, another network, an epoch that is not
 * the predecessor's plus one, a start round that does not advance, a predecessor id that does not match, or a genesis that is not the pinned one.
 */
export class TrustBaseChainError extends TrustBaseError {
  public constructor(message: string) {
    super('chain', message);
  }
}

/**
 * A signature check failed: a signer that is not a member, a malformed or invalid signature (even among enough valid ones), or a signed weight
 * below the quorum threshold.
 */
export class TrustBaseSignatureError extends TrustBaseError {
  public constructor(message: string) {
    super('signature', message);
  }
}

/**
 * The history already holds a different entry for this epoch. Not retryable: one of the two histories is not the network's.
 */
export class TrustBaseConflictError extends TrustBaseError {
  public constructor(
    public readonly epoch: bigint,
    message: string,
  ) {
    super('conflict', message);
  }
}

/**
 * The entry is more than one epoch ahead of the history's tip. Retryable once the missing entries are fetched.
 */
export class TrustBaseGapError extends TrustBaseError {
  public constructor(
    public readonly epoch: bigint,
    public readonly tipEpoch: bigint,
    message: string,
  ) {
    super('gap', message);
  }
}

/**
 * No source served the entries that were wanted: every source failed, answered with a refusal status, or served an entry the history refuses. The
 * causes are kept, in the order they happened. Not the same as "nothing newer": that is a result (no entries appended), not an error.
 */
export class TrustBaseUpdateError extends TrustBaseError {
  public constructor(
    message: string,
    public readonly causes: readonly unknown[],
  ) {
    super('update', message);
  }
}
