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
