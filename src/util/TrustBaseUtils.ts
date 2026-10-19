import { TrustBaseError } from '../api/bft/trustbase/TrustBaseError.js';
import { TrustBaseHistory } from '../api/bft/trustbase/TrustBaseHistory.js';
import { TrustBaseResponse, TrustBaseResponseStatus } from '../api/bft/trustbase/TrustBaseResponse.js';
import { TrustBaseUpdateError } from '../api/bft/trustbase/TrustBaseUpdateError.js';
import { CertificateVerificationResult } from '../api/bft/verification/CertificateVerdict.js';
import { ITrustBaseSource } from '../api/ITrustBaseSource.js';
import { joinSignals, sleep, SleepError } from '../internal/abortable.js';
import { VerificationResult } from '../verification/VerificationResult.js';

/**
 * Bounds of a trust-base update. The defaults are shared with the Rust SDK: a fetch every 2 s at most, 5 fetches, 10 s overall, 64 entries per fetch.
 */
export interface ITrustBaseUpdateOptions {
  /** Fetches at most. Defaults to 5. */
  readonly attempts?: number;
  /** Pause after a fetch that brought nothing new, in milliseconds. Defaults to 2000. */
  readonly intervalMs?: number;
  /** Entries asked for per fetch, 1..64. Defaults to 64. */
  readonly maxEntries?: number;
  /** Caller cancellation; aborting it throws. */
  readonly signal?: AbortSignal;
  /** Overall budget in milliseconds; when it runs out the last result is returned, not thrown. Defaults to 10000. */
  readonly timeoutMs?: number;
}

const DEFAULTS = { attempts: 5, intervalMs: 2000, maxEntries: 64, timeoutMs: 10_000 };

const inFlight = new WeakMap<TrustBaseHistory, Promise<number>>();

/**
 * Fetch the entries after the latest held one (from held epoch + 1, at most `maxEntries`) and append them through the history's single append
 * path, which authenticates each entry from the one before it. Concurrent calls for one history share one fetch.
 *
 * @param {TrustBaseHistory} history Held history; appended to in place.
 * @param {ITrustBaseSource} source Untrusted source (e.g. the aggregator client).
 * @param {object} [options] Options.
 * @param {number} [options.maxEntries] Entries asked for, 1..64. Defaults to 64.
 * @param {AbortSignal} [options.signal] Cancellation.
 * @returns {Promise<number>} Entries appended; 0 when the source has nothing newer yet.
 * @throws {TrustBaseUpdateError} When the response is malformed, of another network, refused, or carries an entry that does not authenticate.
 */
export function fetchTrustBaseEntries(
  history: TrustBaseHistory,
  source: ITrustBaseSource,
  options: { readonly maxEntries?: number; readonly signal?: AbortSignal } = {},
): Promise<number> {
  const running = inFlight.get(history);
  if (running) {
    return running;
  }
  const fetch = fetchOnce(history, source, options).finally(() => inFlight.delete(history));
  inFlight.set(history, fetch);
  return fetch;
}

async function fetchOnce(
  history: TrustBaseHistory,
  source: ITrustBaseSource,
  options: { readonly maxEntries?: number; readonly signal?: AbortSignal },
): Promise<number> {
  const maxEntries = options.maxEntries ?? DEFAULTS.maxEntries;
  if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > TrustBaseResponse.PAGE_LIMITS.maxEntries) {
    throw new RangeError(`maxEntries must be 1..${TrustBaseResponse.PAGE_LIMITS.maxEntries}.`);
  }
  const from = history.tipEpoch + 1n;
  const bytes = await source.getTrustBaseEntries(from, maxEntries, { signal: options.signal });
  let response: TrustBaseResponse;
  try {
    response = await TrustBaseResponse.fromCBOR(bytes, TrustBaseResponse.PAGE_LIMITS);
  } catch (error) {
    throw new TrustBaseUpdateError('malformed', 'The trust-base response does not decode.', { cause: error });
  }
  if (response.networkId !== history.networkId.id) {
    throw new TrustBaseUpdateError('wrong_network', `The trust-base response is for network ${response.networkId}.`);
  }
  if (response.status === TrustBaseResponseStatus.NOT_YET_AVAILABLE) {
    return 0;
  }
  if (response.status !== TrustBaseResponseStatus.OK) {
    throw new TrustBaseUpdateError(
      'refused',
      `The trust-base source answered ${TrustBaseResponseStatus[response.status]}.`,
    );
  }
  if (response.fromEpoch !== from) {
    throw new TrustBaseUpdateError(
      'malformed',
      `The trust-base response starts at epoch ${response.fromEpoch}, not ${from}.`,
    );
  }
  try {
    return await history.installBundle(response);
  } catch (error) {
    if (TrustBaseError.is(error)) {
      throw new TrustBaseUpdateError('rejected', `A fetched trust-base entry was refused: ${error.message}`, {
        cause: error,
      });
    }
    throw error;
  }
}

/**
 * Verify, and when the verification reports "no entry for epoch e" (a certificate of an epoch newer than the latest held trust-base entry), fetch
 * the newer entries from `source`, append them (each authenticated from the one before) and verify again: the trust-base analogue of
 * {@link waitInclusionProof}.
 *
 * Every fetch asks for the entries after the latest held one. A fetch that brings nothing new (the source does not have epoch e yet) is followed by
 * a pause; one that appends entries but stops short of e (the per-fetch cap) is followed at once by the next. The loop ends with the first result
 * that is not "no entry for epoch", or after `attempts` fetches, or when `timeoutMs` runs out; it then returns the last result, which still names
 * the missing epoch, so the caller can retry later. Other results (`ok`, invalid, malformed) are returned at once and never retried. Held entries are
 * never replaced: a fetched entry that conflicts with one is refused.
 *
 * @param {Function} verify Verification against the history, e.g. `(trustBase) => token.verify(contextWith(trustBase))`.
 * @param {TrustBaseHistory} history Held history; appended to in place (persist it with `exportBundle`).
 * @param {ITrustBaseSource} source Untrusted source, e.g. the `AggregatorClient`.
 * @param {ITrustBaseUpdateOptions} [options] Bounds.
 * @returns {Promise<R>} The last verification result.
 * @throws {TrustBaseUpdateError} When the source misbehaves (see the reasons); entries appended before stay held.
 * @throws {SleepError} When the caller's `signal` aborts.
 */
export async function verifyWithTrustBaseUpdate<R extends VerificationResult<unknown>>(
  verify: (trustBase: TrustBaseHistory) => Promise<R>,
  history: TrustBaseHistory,
  source: ITrustBaseSource,
  options: ITrustBaseUpdateOptions = {},
): Promise<R> {
  const attempts = options.attempts ?? DEFAULTS.attempts;
  const intervalMs = options.intervalMs ?? DEFAULTS.intervalMs;
  const budget = AbortSignal.timeout(Math.max(1, Math.floor(options.timeoutMs ?? DEFAULTS.timeoutMs)));
  const deadline = options.signal ? joinSignals(options.signal, budget) : { dispose: (): void => {}, signal: budget };
  try {
    let result = await verify(history);
    for (let fetches = 0; ;) {
      const missing = CertificateVerificationResult.findMissingEpoch(result)?.missing ?? null;
      if (missing === null) {
        return result;
      }
      if (missing.epoch <= history.tipEpoch) {
        // appended meanwhile (a shared history): verify again at once
        result = await verify(history);
        continue;
      }
      if (fetches >= attempts) {
        return result;
      }
      fetches++;
      let added: number;
      try {
        added = await fetchTrustBaseEntries(history, source, {
          maxEntries: options.maxEntries,
          signal: deadline.signal,
        });
      } catch (error) {
        if (budget.aborted && !options.signal?.aborted && !TrustBaseUpdateError.is(error)) {
          return result;
        }
        throw error;
      }
      if (history.tipEpoch >= missing.epoch) {
        result = await verify(history);
        continue;
      }
      if (added === 0) {
        try {
          await sleep(intervalMs, deadline.signal);
        } catch (error) {
          if (error instanceof SleepError && budget.aborted && !options.signal?.aborted) {
            return result;
          }
          throw error;
        }
      }
    }
  } finally {
    deadline.dispose();
  }
}
