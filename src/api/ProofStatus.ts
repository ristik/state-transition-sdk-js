/**
 * Hint of an aggregator about a state id it has no proof for (`get_inclusion_proof.v2` with `includeStatus`).
 *
 * - `included`: the aggregator reports the state as certified (the proof, not this word, is what counts).
 * - `pending`: accepted by this aggregator and not yet in a published certified state; keep waiting.
 * - `expired`: admitted but dropped because its deadline passed before inclusion (bounded, best-effort memory).
 * - `unknown`: neither of the above at this node (never seen, misrouted, lost, wiped by a restart, or an HA instance
 *   that has not seen the request yet).
 *
 * **The status is an unauthenticated hint** for control flow and user feedback only. It is not signed, not bound to any
 * certificate and not a proof of absence: `unknown` or `expired` never means the state is unspent, and no verification
 * of a token, proof or transaction depends on it. A proof that is present is verified exactly as before, whatever the
 * status says.
 */
export type ProofStatus = 'expired' | 'included' | 'pending' | 'unknown';

const STATUSES: ReadonlySet<string> = new Set<ProofStatus>(['expired', 'included', 'pending', 'unknown']);

/**
 * @param {unknown} value Status of a response.
 * @returns {ProofStatus|null} The status, or `null` for a missing or unrecognized value, which means legacy behavior.
 */
export function parseProofStatus(value: unknown): ProofStatus | null {
  return typeof value === 'string' && STATUSES.has(value) ? (value as ProofStatus) : null;
}
