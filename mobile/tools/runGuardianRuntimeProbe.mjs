/**
 * Prove guardian recovery runs with no Node crypto — by executing it, not by testing around it.
 *
 * ===========================================================================
 * WHAT THIS CHECKS THAT A UNIT TEST CANNOT
 * ===========================================================================
 * #355: `slip39` requires Node's `crypto` inside a try/catch, so Metro treats it
 * as an optional dependency and emits a RUNTIME throw instead of failing the
 * build. Bundling therefore proves nothing, and a Node unit test proves less —
 * Node has `crypto`, so the failure is unreachable there.
 *
 * So this does two things in order:
 *   1. Bundles `guardianRuntimeProbe.js` with `expo export:embed`, which uses the
 *      project's real metro.config.js, resolver and Hermes transform profile.
 *   2. Runs that bundle inside a `vm` context stripped of every Node affordance —
 *      no `require`, no `process`, no `Buffer`, no `module`. The only globals it
 *      gets are ones Hermes on a device also has.
 *
 * A `require` reaching outside the bundle therefore cannot resolve, and any
 * Node-only global is a ReferenceError. That is the property we want to assert.
 *
 * ===========================================================================
 * WHAT IT STILL DOES NOT PROVE
 * ===========================================================================
 * This is V8, not Hermes, and it is a bare context, not a React Native host.
 * It proves the module graph is free of Node dependencies and that the crypto
 * arithmetic produces a correct round trip. It does NOT prove Hermes-specific
 * behaviour, and it is not a substitute for running the wallet on a handset.
 * Claims made from this run are "runs without Node crypto", not "runs on device".
 *
 * Usage: node tools/runGuardianRuntimeProbe.mjs
 */

import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const toolsDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(toolsDir, '..');

const workDir = mkdtempSync(path.join(tmpdir(), 'guardian-runtime-probe-'));
const bundlePath = path.join(workDir, 'probe.bundle.js');

/**
 * The official Trezor vectors, read from the ONE copy in the repo.
 *
 * They are handed to the sandbox as a global rather than bundled, so this probe
 * and `packages/backend/tests/fast/guardianShares.test.ts` cannot drift onto
 * different fixtures and both claim to have run "the official vectors".
 */
const OFFICIAL_VECTORS_PATH = path.resolve(
  projectRoot,
  '../backend/tests/fast/fixtures/slip39-official-vectors.json',
);
const EXPECTED_POSITIVE_VECTORS = 15;
const EXPECTED_NEGATIVE_VECTORS = 30;

function loadOfficialVectors() {
  const vectors = JSON.parse(readFileSync(OFFICIAL_VECTORS_PATH, 'utf8'));
  const positive = vectors.filter((vector) => vector[2] !== '').length;
  const negative = vectors.length - positive;
  if (positive !== EXPECTED_POSITIVE_VECTORS || negative !== EXPECTED_NEGATIVE_VECTORS) {
    throw new Error(
      `Fixture has ${positive} positive and ${negative} negative vectors; expected ` +
        `${EXPECTED_POSITIVE_VECTORS} and ${EXPECTED_NEGATIVE_VECTORS}. Refusing to report a ` +
        'pass over a fixture that is not the one this check was calibrated against.',
    );
  }
  return vectors;
}

function bundle() {
  execFileSync(
    'npx',
    [
      'expo',
      'export:embed',
      '--platform',
      'android',
      '--dev',
      'false',
      '--minify',
      'false',
      '--unstable-transform-profile',
      'hermes',
      '--entry-file',
      path.join(toolsDir, 'guardianRuntimeProbe.js'),
      '--bundle-output',
      bundlePath,
      '--assets-dest',
      path.join(workDir, 'assets'),
    ],
    { cwd: projectRoot, stdio: ['ignore', 'inherit', 'inherit'] },
  );
}

/**
 * A context with Hermes-ish globals and nothing else.
 *
 * `crypto.getRandomValues` is included because `recoveryKey.ts` already requires
 * it and documents it as present in both Node and Hermes — excluding it would
 * test a different runtime than the one the wallet ships to. Everything Node-only
 * is deliberately absent, and `require` most of all.
 */
function makeStrippedContext() {
  const sandbox = {
    __DEV__: false,
    console,
    globalThis: undefined,
    crypto: { getRandomValues: (array) => webcrypto.getRandomValues(array) },
    // Web globals, not Node ones: React Native ships TextEncoder/TextDecoder and
    // Expo's runtime guarantees them. Withholding them would fail the probe for a
    // reason the device does not have.
    TextEncoder,
    TextDecoder,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    setImmediate,
    clearImmediate,
    performance: { now: () => Date.now() },
    // A trap, not an affordance. Metro bundles carry their own module registry
    // (`_$$_REQUIRE`) and never need the host's `require`; a module reaching for
    // this one is reaching for Node. Throwing here names the culprit, where
    // simply omitting `require` would give an anonymous ReferenceError. This is
    // an observation rather than a text scan of the bundle — an earlier version
    // grepped the output and flagged the word "crypto" inside a doc comment.
    require: (moduleName) => {
      throw new Error(
        `Bundle reached for the Node host's require("${moduleName}"). No such thing exists on a device.`,
      );
    },
  };
  sandbox.global = sandbox;
  sandbox.globalThis = sandbox;
  return vm.createContext(sandbox);
}

function main() {
  console.log('[probe] bundling with the project metro config...');
  bundle();

  const source = readFileSync(bundlePath, 'utf8');
  console.log(`[probe] bundle is ${(source.length / 1024).toFixed(0)} KiB`);

  const context = makeStrippedContext();
  context.__SLIP39_OFFICIAL_VECTORS__ = loadOfficialVectors();
  console.log('[probe] executing in a context with no require, no process, no Buffer...');
  vm.runInContext(source, context, { filename: bundlePath });

  const result = context.__GUARDIAN_PROBE__;
  console.log('[probe] result:', JSON.stringify(result, null, 2));

  if (!result || result.status !== 'ok') {
    throw new Error('Guardian recovery did not complete without Node crypto.');
  }
  if (!result.roundTripped) {
    throw new Error('Guardian shares did not reconstruct the seed they were made from.');
  }
  if (!result.belowThresholdRefused) {
    throw new Error('A below-threshold share set reconstructed. The threshold is not enforced.');
  }

  const vectors = result.officialVectors;
  if (vectors.failures.length > 0) {
    throw new Error(`Official SLIP-39 vectors failed:\n  ${vectors.failures.join('\n  ')}`);
  }
  if (vectors.recovered !== EXPECTED_POSITIVE_VECTORS || vectors.refused !== EXPECTED_NEGATIVE_VECTORS) {
    throw new Error(
      `Expected ${EXPECTED_POSITIVE_VECTORS} recovered and ${EXPECTED_NEGATIVE_VECTORS} refused, ` +
        `got ${vectors.recovered} and ${vectors.refused}. The vectors did not all run.`,
    );
  }

  console.log(
    `[probe] PASS — guardian round trip and all ${vectors.total} official SLIP-39 vectors ` +
      '(15 recovered, 30 refused) ran with no Node crypto available.',
  );
}

try {
  main();
} finally {
  rmSync(workDir, { recursive: true, force: true });
}
