/**
 * Wire rules of the optional long-poll metadata of the inclusion proof reads (`waitMs` in the request, `waitedMs` in the
 * answer).
 *
 * The wait is a request to the aggregator, never an obligation: a server that does not know the field ignores it and
 * answers at once without an echo. The echo is **unauthenticated** timing metadata. It is not part of any proof, it
 * never authenticates state and the SDK never lets it extend a deadline.
 *
 * Internal: not part of the public API (`./lib/internal/*` is not exported), the negotiation heuristic may change.
 */

/**
 * @param {unknown} value Candidate wait duration or echo.
 * @returns {boolean} True for a non negative safe integer. `-0`, fractions, `NaN`, `Infinity` and anything that is not a
 *   number are not wire integers.
 */
export function isWireMilliseconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
}

/**
 * Check a caller supplied `waitMs`, which is validated before anything is sent.
 *
 * @param {unknown} value Value of the `waitMs` option.
 * @returns {number} The value.
 * @throws {RangeError} If it is not an integer in `[0, Number.MAX_SAFE_INTEGER]`.
 */
export function checkWaitMs(value: unknown): number {
  if (!isWireMilliseconds(value)) {
    throw new RangeError('waitMs must be an integer in [0, Number.MAX_SAFE_INTEGER].');
  }
  return value;
}

/**
 * Whether an error is the answer of a batch endpoint whose strict parser does not know a request field: the generic
 * `-32602` / `invalid_request` / `malformed_params`. The answer does not name the field, so the match is on the generic
 * class, and only for a response that carries the id of the request. An answer with `data.waitedMs` is not it: the
 * server understood the wait.
 *
 * @param {unknown} code JSON-RPC error code.
 * @param {unknown} data The `error.data` member.
 * @returns {boolean} True for exactly that class.
 */
export function isMalformedParams(code: unknown, data: unknown): boolean {
  if (code !== -32602 || typeof data !== 'object' || data === null) {
    return false;
  }
  const { detail, reason } = data as { detail?: unknown; reason?: unknown };
  // an answer that carries the echo comes from a server that understood `waitMs`: its rejection is about something else
  return reason === 'invalid_request' && detail === 'malformed_params' && !('waitedMs' in data);
}
