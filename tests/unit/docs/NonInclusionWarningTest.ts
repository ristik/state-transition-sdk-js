import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** The identical D2 warning of every non-inclusion entry point (owner decision D2). */
const WARNING =
  'Non-inclusion proves absence only at the authenticated snapshot returned by verification. It does not prove absence now, continuous absence, or that a token can be spent. Compare the snapshot’s network and root round (or its certified seal timestamp under your application’s time policy) with an independently trusted requirement. The seal timestamp is a consensus-certified time, not proof of real-time freshness. Do not use unverified response metadata for this check.';

const read = (path: string): string => readFileSync(join(process.cwd(), path), 'utf8');

/** A doc comment or markdown text flattened to one line: comment stars, quote markers and wrapping removed. */
const flatten = (text: string): string => text.replace(/\n\s*(?:\*|>)\s?/g, ' ').replace(/\s+/g, ' ');

describe('the non-inclusion warning', () => {
  it.each([
    ['README.md', 1],
    ['src/api/NonInclusionVerification.ts', 3],
    ['src/api/NonInclusionProof.ts', 1],
    ['src/api/INonInclusionAggregatorClient.ts', 2],
  ])('is verbatim in %s (%i times)', (path, count) => {
    expect(flatten(read(path)).split(WARNING)).toHaveLength(count + 1);
  });

  it('is shown with the policy example on the entry points of the verification', () => {
    const example = "if (r.verdict !== 'absent_at_snapshot') throw new Error('No verified absence');";
    expect(read('README.md')).toContain(example);
    expect(read('src/api/NonInclusionVerification.ts')).toContain(example);
  });
});
