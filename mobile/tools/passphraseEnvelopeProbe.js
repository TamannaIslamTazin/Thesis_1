/**
 * Bundle entry that exercises the passphrase-wrapped recovery key envelope and
 * nothing else, on the same principle as `guardianRuntimeProbe.js` next to it:
 * a Node unit test cannot answer "does this run without Node's `crypto`",
 * because Node has `crypto`. This runs the real Metro bundle in a host with
 * none.
 *
 * Imports `@ssi-healthcare/shared` directly, which is the dependency added to
 * `packages/mobile/package.json` for this round, rather than through
 * `@ssi-healthcare/sdk/shared` as `guardianRuntimeProbe.js` does — proving the
 * direct path resolves too, since nothing in the mobile app used it before now.
 *
 * Deliberately no `react-native` import, same reasoning as the guardian probe:
 * this must be executable outside a native host. `deviceKeyGate.ts` and
 * `recoveryKeyRelease.ts` pull in `expo-local-authentication` /
 * `expo-secure-store` / `react-native`, which is exactly the part this
 * technique cannot exercise — that is what stays unverified without a device.
 */

import {
  RECOVERY_KEY_SEED_BYTES,
  generateRecoveryKeySeed,
  wrapRecoveryKeyWithPassphrase,
  unwrapRecoveryKeyWithPassphrase,
  PASSPHRASE_KDF_N,
  PASSPHRASE_KDF_R,
  PASSPHRASE_KDF_P,
  PASSPHRASE_KDF_DKLEN,
} from '@ssi-healthcare/shared';

function sameBytes(a, b) {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

async function runProbe() {
  const seed = generateRecoveryKeySeed();
  if (seed.length !== RECOVERY_KEY_SEED_BYTES) {
    throw new Error(`Seed is ${seed.length} bytes, expected ${RECOVERY_KEY_SEED_BYTES}.`);
  }

  const started = Date.now();
  const envelope = await wrapRecoveryKeyWithPassphrase(seed, 'probe passphrase');
  const wrapMillis = Date.now() - started;

  const opened = await unwrapRecoveryKeyWithPassphrase(envelope, 'probe passphrase');
  const roundTripped = sameBytes(opened, seed);

  let wrongPassphraseRefused = false;
  try {
    await unwrapRecoveryKeyWithPassphrase(envelope, 'the wrong passphrase');
  } catch {
    wrongPassphraseRefused = true;
  }

  return {
    status: 'ok',
    roundTripped,
    wrongPassphraseRefused,
    wrapMillis,
    kdf: { N: PASSPHRASE_KDF_N, r: PASSPHRASE_KDF_R, p: PASSPHRASE_KDF_P, dkLen: PASSPHRASE_KDF_DKLEN },
  };
}

runProbe()
  .then((result) => {
    globalThis.__PASSPHRASE_PROBE__ = result;
  })
  .catch((error) => {
    globalThis.__PASSPHRASE_PROBE__ = {
      status: 'threw',
      name: error && error.name,
      message: String((error && error.message) || error),
    };
  });
