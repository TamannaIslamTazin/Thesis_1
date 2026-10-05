/**
 * Prove the passphrase-wrapped recovery key envelope runs with no Node crypto
 * — by executing it, not by testing around it. Same technique as
 * `runGuardianRuntimeProbe.mjs`; see that file's header for why bundling and a
 * Node unit test both fall short of answering this.
 *
 * Usage: node tools/runPassphraseEnvelopeProbe.mjs
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

const workDir = mkdtempSync(path.join(tmpdir(), 'passphrase-envelope-probe-'));
const bundlePath = path.join(workDir, 'probe.bundle.js');

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
      path.join(toolsDir, 'passphraseEnvelopeProbe.js'),
      '--bundle-output',
      bundlePath,
      '--assets-dest',
      path.join(workDir, 'assets'),
    ],
    { cwd: projectRoot, stdio: ['ignore', 'inherit', 'inherit'] },
  );
}

/**
 * Same shape as the guardian probe's stripped context. `setTimeout` is real
 * here (not a fake), because scrypt's async tick genuinely schedules work on
 * it — the whole point of `scryptAsync` over `scrypt` is that it yields
 * instead of blocking, so the probe has to let it actually yield.
 */
function makeStrippedContext() {
  const sandbox = {
    __DEV__: false,
    console,
    globalThis: undefined,
    crypto: { getRandomValues: (array) => webcrypto.getRandomValues(array) },
    TextEncoder,
    TextDecoder,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    setImmediate,
    clearImmediate,
    performance: { now: () => Date.now() },
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

async function waitForResult(context, timeoutMillis) {
  const start = Date.now();
  while (context.__PASSPHRASE_PROBE__ === undefined) {
    if (Date.now() - start > timeoutMillis) {
      throw new Error(`No result after ${timeoutMillis}ms — the probe promise never settled.`);
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return context.__PASSPHRASE_PROBE__;
}

async function main() {
  console.log('[probe] bundling with the project metro config...');
  bundle();

  const source = readFileSync(bundlePath, 'utf8');
  console.log(`[probe] bundle is ${(source.length / 1024).toFixed(0)} KiB`);

  const context = makeStrippedContext();
  console.log('[probe] executing in a context with no require, no process, no Buffer...');
  vm.runInContext(source, context, { filename: bundlePath });

  const result = await waitForResult(context, 30_000);
  console.log('[probe] result:', JSON.stringify(result, null, 2));

  if (!result || result.status !== 'ok') {
    throw new Error(
      `The passphrase envelope did not complete without Node crypto: ${JSON.stringify(result)}`,
    );
  }
  if (!result.roundTripped) {
    throw new Error('The envelope did not open back to the seed it was wrapped from.');
  }
  if (!result.wrongPassphraseRefused) {
    throw new Error('A wrong passphrase opened the envelope. AEAD authentication is not working.');
  }

  console.log(
    `[probe] PASS — passphrase envelope wrap+unwrap round-tripped with no Node crypto ` +
      `available (scrypt N=${result.kdf.N} r=${result.kdf.r} p=${result.kdf.p}, ${result.wrapMillis}ms to wrap).`,
  );
}

try {
  await main();
} finally {
  rmSync(workDir, { recursive: true, force: true });
}
