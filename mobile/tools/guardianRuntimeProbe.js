/**
 * Bundle entry that exercises the guardian recovery round trip and nothing else.
 *
 * WHY THIS EXISTS. A unit test in Node cannot answer the question #355 asks,
 * because Node HAS `crypto`. The only honest check is to run the real Metro
 * bundle — same metro.config.js, same resolver, same platform as the app — in a
 * host that has no Node builtins at all. `runGuardianRuntimeProbe.mjs` does the
 * running; this file is what it runs.
 *
 * It imports through `@ssi-healthcare/sdk/shared`, which is the path the wallet
 * itself reaches `packages/shared` by, so a resolution fix that only worked for
 * a direct import would not pass here.
 *
 * Deliberately no `react-native` import: this must be executable outside a
 * native host, and the recovery code has no UI surface.
 */

import Slip39 from 'slip39';

import {
  DEFAULT_GUARDIAN_POLICY,
  RECOVERY_KEY_SEED_BYTES,
  combineGuardianShares,
  splitRecoveryKey,
  withSlip39Runtime,
} from '@ssi-healthcare/sdk/shared';

function sameBytes(a, b) {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * The interop question, answered where it actually matters.
 *
 * A round trip only proves the shim agrees with ITSELF — a subtly wrong PBKDF2
 * would split and recombine perfectly and still be unable to read a share issued
 * by the backend. The 45 official Trezor vectors are the external reference, so
 * running them HERE, in a bundle with no Node crypto, is what proves shares
 * already in circulation still recover on a handset.
 *
 * The vectors are handed in by the runner rather than bundled, so the fixture
 * has exactly one copy in the repo (packages/backend/tests/fast/fixtures).
 * Shape: [description, mnemonics[], masterSecretHex, xprv]; an EMPTY
 * masterSecretHex means the set must be REFUSED.
 */
function runOfficialVectors(vectors) {
  let recovered = 0;
  let refused = 0;
  const failures = [];

  for (const [description, mnemonics, expectedHex] of vectors) {
    const mustRecover = expectedHex !== '';
    try {
      const secret = withSlip39Runtime(() => Slip39.recoverSecret([...mnemonics], 'TREZOR'));
      const actualHex = toHex(Uint8Array.from(secret));
      if (!mustRecover) {
        failures.push(`accepted an invalid set: ${description}`);
      } else if (actualHex !== expectedHex) {
        failures.push(`wrong secret for: ${description} (${actualHex} != ${expectedHex})`);
      } else {
        recovered += 1;
      }
    } catch (error) {
      if (mustRecover) {
        failures.push(`failed to recover: ${description} — ${String(error && error.message)}`);
      } else {
        refused += 1;
      }
    }
  }

  return { total: vectors.length, recovered, refused, failures };
}

function runProbe() {
  const seed = new Uint8Array(RECOVERY_KEY_SEED_BYTES);
  globalThis.crypto.getRandomValues(seed);

  const split = splitRecoveryKey(seed, DEFAULT_GUARDIAN_POLICY);
  const threshold = DEFAULT_GUARDIAN_POLICY.threshold;

  const recovered = combineGuardianShares(
    split.shares.slice(0, threshold).map((share) => share.mnemonic),
  );

  // Below the threshold must refuse. A shim that quietly returned constant bytes
  // would satisfy the round trip above and fail here, so this is the check that
  // distinguishes "works" from "appears to work".
  let belowThresholdRefused = false;
  try {
    combineGuardianShares(split.shares.slice(0, threshold - 1).map((share) => share.mnemonic));
  } catch {
    belowThresholdRefused = true;
  }

  return {
    status: 'ok',
    roundTripped: sameBytes(recovered.seed, seed),
    belowThresholdRefused,
    shareCount: split.shares.length,
    wordsPerShare: split.shares[0].mnemonic.split(' ').length,
    splitId: split.splitId,
    officialVectors: runOfficialVectors(globalThis.__SLIP39_OFFICIAL_VECTORS__ ?? []),
  };
}

try {
  globalThis.__GUARDIAN_PROBE__ = runProbe();
} catch (error) {
  globalThis.__GUARDIAN_PROBE__ = {
    status: 'threw',
    name: error && error.name,
    message: String((error && error.message) || error),
  };
}
