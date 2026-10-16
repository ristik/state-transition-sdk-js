// Verifies that this directory is wired to the RELEASED package and nothing else: the pinned version, the recorded npm
// integrity and git head, and that the lock file agrees. `npm ci --ignore-scripts` then makes npm itself verify the
// tarball against that integrity. Run before the compatibility run; `run.mjs` calls it too.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const RELEASED = Object.freeze({
  gitHead: 'f5f0737306901215860aa920a6ab570b699efba8',
  integrity: 'sha512-ND4mW7nQjgr8yDdxvHNFheHH3gPijD4y0NS7XU2YPzjsdyDs4LDCYlRG/ZSSEDbz3xVgMh1biL3BY60nGPIsXQ==',
  name: '@unicitylabs/state-transition-sdk',
  tarball: 'https://registry.npmjs.org/@unicitylabs/state-transition-sdk/-/state-transition-sdk-3.0.1.tgz',
  version: '3.0.1',
});

/** @returns {string[]} Problems found, empty if the wiring is the released package. */
export function integrityProblems(dir = dirname(fileURLToPath(import.meta.url))) {
  const problems = [];
  const read = (...p) => JSON.parse(readFileSync(join(dir, ...p), 'utf8'));
  const manifest = read('package.json');
  if (manifest.dependencies?.[RELEASED.name] !== RELEASED.version) {
    problems.push(`package.json must pin ${RELEASED.name} to exactly ${RELEASED.version}`);
  }
  const entry = read('package-lock.json').packages?.[`node_modules/${RELEASED.name}`];
  if (!entry) {
    problems.push('package-lock.json has no entry for the package');
  } else {
    if (entry.version !== RELEASED.version) problems.push(`lock version ${entry.version}`);
    if (entry.integrity !== RELEASED.integrity) problems.push(`lock integrity ${entry.integrity}`);
    if (entry.resolved !== RELEASED.tarball) problems.push(`lock tarball ${entry.resolved}`);
  }
  try {
    const installed = read('node_modules', ...RELEASED.name.split('/'), 'package.json');
    if (installed.version !== RELEASED.version) problems.push(`installed version ${installed.version}`);
    if (installed.gitHead !== undefined && installed.gitHead !== RELEASED.gitHead) {
      problems.push(`installed gitHead ${installed.gitHead}`);
    }
  } catch {
    problems.push('package not installed: run `npm ci --ignore-scripts` in this directory');
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const problems = integrityProblems();
  if (problems.length > 0) {
    console.error(`NOT the released ${RELEASED.name}@${RELEASED.version}:\n- ${problems.join('\n- ')}`);
    process.exit(1);
  }
  console.log(`${RELEASED.name}@${RELEASED.version} ${RELEASED.integrity} (git ${RELEASED.gitHead})`);
}
