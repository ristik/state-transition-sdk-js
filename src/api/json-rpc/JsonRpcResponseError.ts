/**
 * Thrown when a JSON-RPC response is malformed — wrong protocol version,
 * mismatched id, not exactly one of result/error, oversized, or not valid JSON.
 */
export class JsonRpcResponseError extends Error {
  public readonly name: string = 'JsonRpcResponseError';

  /** The `Retry-After` of that response in milliseconds (capped at 60 s). */
  public readonly retryAfterMs?: number;

  /** The HTTP status of a non-2xx response whose body could not be read (oversized): it still classifies the answer. */
  public readonly status?: number;

  /**
   * @param {string} message Error message.
   * @param {ErrorOptions & {status?: number; retryAfterMs?: number}} [options] Cause and response details.
   */
  public constructor(message: string, options?: ErrorOptions & { retryAfterMs?: number; status?: number }) {
    super(message, options);
    this.status = options?.status;
    this.retryAfterMs = options?.retryAfterMs;
  }
}
