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
   * @param {boolean} idMatched Whether the envelope carried the id of the request (false: a null id).
   * @param {number} [retryAfterMs] The `Retry-After` header of the HTTP response in milliseconds (capped at 60 s).
   */
  public constructor(
    { code, data, message }: { code: number; data?: unknown; message: string },
    public readonly idMatched: boolean = true,
    public readonly retryAfterMs?: number,
  ) {
    super(message);
    this.code = code;
    this.data = data;
  }

  /**
   * Error info to string.
   */
  public toString(): string {
    return `{ code: ${this.code}, message: ${this.message} }`;
  }
}
