/**
 * Aggregator JSON-RPC error codes that answer a proof lookup for a state that has no proof yet.
 */
export const JsonRpcProofErrorCode = {
  /** Accepted but not yet certified: keep waiting. */
  CERTIFICATION_PENDING: -32021,
  /** No proof known for the state (same meaning as HTTP 404). */
  NOT_FOUND: -32020,
} as const;

/**
 * JSON-RPC error object.
 */
export class JsonRpcDataError extends Error {
  public readonly code: number;

  /** Structured `error.data` of the response, if the server sent any. Untrusted. */
  public readonly data: unknown;

  public readonly name: string = 'JsonRpcError';

  /**
   * JSON-RPC error object constructor.
   * @param {{code: number; message: string; data?: unknown}} data Error data.
   */
  public constructor({ code, data, message }: { code: number; data?: unknown; message: string }) {
    super(message);
    this.code = code;
    this.data = data;
  }

  /**
   * @returns {boolean} True for the aggregator's "certification is pending" answer (-32021): not an error, poll again.
   */
  public get isCertificationPending(): boolean {
    return this.code === JsonRpcProofErrorCode.CERTIFICATION_PENDING;
  }

  /**
   * @returns {boolean} True for the aggregator's "not found" answer (-32020), the JSON-RPC form of HTTP 404.
   */
  public get isNotFound(): boolean {
    return this.code === JsonRpcProofErrorCode.NOT_FOUND;
  }

  /**
   * Error info to string.
   */
  public toString(): string {
    return `{ code: ${this.code}, message: ${this.message} }`;
  }
}
