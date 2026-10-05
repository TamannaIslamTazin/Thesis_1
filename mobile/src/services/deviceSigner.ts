/**
 * The holder's signing component, on the handset.
 *
 * WHY THIS EXISTS AT ALL
 * ----------------------
 * `packages/backend` carries components for three roles — issuer, verifier and
 * holder — and the wallet had been a thin HTTP client to all three. That put the
 * HOLDER's signing on the issuer's server, which is a custodian by another name:
 * `/api/wallet/locker-session` and `/api/wallet/capability` existed only because
 * the key was over there. The holder's backend is never going to be hosted
 * anywhere; it has to be the holder's own device running it, and this module is
 * where that starts.
 *
 * WHAT IT HOLDS, AND HOW
 * ----------------------
 * The patient's `#key-1` seed. It is written under `requireAuthentication`, so
 * the platform releases it only after a Class-3 biometric match, and the key
 * protecting it is invalidated when the enrolled set changes. That is the
 * on-device half of the owner's requirement that "some keys are simply not
 * recoverable and must live somewhere protected by a PIN, password or
 * biometrics"; the other half is the passphrase-wrapped copy in the keystore
 * locker, which is what makes a lost handset survivable.
 *
 * The seed is never returned to callers. `withSeed` lends it for the duration of
 * one operation and zeroises it afterwards, so a caller cannot accidentally
 * retain it, and `signPayload` is the only shape most callers need.
 */
import {
  bytesToBase64Url,
  base64UrlToBytes,
  signWithRecoveryKey,
  zeroise,
} from '@ssi-healthcare/shared';

import { secureStorage, STORAGE_KEYS } from './secureStorage';

export class DeviceSignerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DeviceSignerError';
  }
}

/**
 * Persist the seed for this device.
 *
 * Called once, at enrolment, with the seed whose public half is about to become
 * the DID's `#key-1`.
 */
export async function storeDeviceSeed(seed: Uint8Array): Promise<void> {
  await secureStorage.set(STORAGE_KEYS.DEVICE_SIGNING_SEED, bytesToBase64Url(seed), {
    requireAuthentication: true,
  });
}

/**
 * The seed this device signs with, generating one only if it has none.
 *
 * WHY REUSE MATTERS, and why generating unconditionally was a real defect.
 * `setupWallet` is idempotent: an account that already has a DID gets it back
 * UNCHANGED and its `#key-1` is NOT retrofitted. So a second run of enrolment
 * that minted a fresh seed stored a key the DID document does not contain —
 * the handset then holds a key that authenticates nothing, which is exactly
 * the silently-unrecoverable state the patient shape exists to prevent. It
 * showed up as the locker's BAD_SIGNATURE against a DID whose published key
 * was perfectly valid, just not this one (measured 8 Sep 2026).
 *
 * Reusing makes retrying enrolment safe and idempotent on BOTH sides.
 */
export async function loadOrCreateDeviceSeed(
  generate: () => Uint8Array,
): Promise<{ seed: Uint8Array; created: boolean }> {
  const existing = await secureStorage.getRequiringAuthentication(
    STORAGE_KEYS.DEVICE_SIGNING_SEED,
    'Authenticate to use your wallet key',
  );
  if (existing !== null) return { seed: base64UrlToBytes(existing), created: false };

  const seed = generate();
  await storeDeviceSeed(seed);
  return { seed, created: true };
}

/** True when this handset can sign for its own DID. */
export async function hasDeviceSeed(): Promise<boolean> {
  try {
    return (await secureStorage.get(STORAGE_KEYS.DEVICE_SIGNING_SEED)) !== null;
  } catch {
    // A read that throws is a read that failed, not a proof of absence — but the
    // only safe answer to "can this device sign" when we cannot tell is no.
    return false;
  }
}

/** Forget the key. Used on sign-out and account deletion. */
export async function clearDeviceSeed(): Promise<void> {
  await secureStorage.delete(STORAGE_KEYS.DEVICE_SIGNING_SEED);
}

/**
 * Lend the seed for one operation.
 *
 * The seed is zeroised in a `finally`, so it is gone whether the operation
 * succeeded, threw, or was abandoned partway.
 */
export async function withSeed<T>(fn: (seed: Uint8Array) => Promise<T>): Promise<T> {
  // READ IT THE WAY IT WAS WRITTEN. `storeDeviceSeed` writes under
  // `requireAuthentication: true`, and on Android that is a DIFFERENT keystore
  // entry from the unauthenticated one — not the same value behind a prompt.
  // Reading without the flag therefore does not fail; it returns whatever an
  // earlier unauthenticated write left behind, so signing silently used a
  // STALE seed and produced a perfectly valid signature by the wrong key.
  // Measured 8 Sep 2026: enrolment failed with the locker's BAD_SIGNATURE
  // against a freshly rotated `#key-1` whose public half matched the chain,
  // and only one biometric prompt appeared per attempt — the write's — which
  // is the tell that the read never touched the gated entry.
  const stored = await secureStorage.getRequiringAuthentication(
    STORAGE_KEYS.DEVICE_SIGNING_SEED,
    'Authenticate to sign with your wallet key',
  );
  if (stored === null) {
    throw new DeviceSignerError(
      'This device holds no signing key. Sign in with your passphrase, or restore the wallet.',
    );
  }
  const seed = base64UrlToBytes(stored);
  try {
    return await fn(seed);
  } finally {
    zeroise(seed);
  }
}

/**
 * Unlock the key ONCE, then sign without prompting again.
 *
 * WHY THIS EXISTS. `signPayload` prompts for a biometric on every call, and the
 * locker's challenge is valid for 120 SECONDS. Opening a session runs
 * challenge -> sign -> token, so with the prompt inside `sign` the clock is
 * running while the handset waits for a finger. Measured 8 Sep 2026: sign-in
 * took 129s and the locker refused the nonce with CHALLENGE_REFUSED — not a
 * signing fault at all, an expiry one, and it reads like a signing fault.
 *
 * Prompt first, then spend the challenge window on arithmetic and one round
 * trip. `dispose` zeroises; call it in a `finally`.
 */
export async function prepareDeviceSigner(): Promise<{
  sign: (payload: Uint8Array) => Promise<string>;
  withSeed: <T>(fn: (seed: Uint8Array) => Promise<T>) => Promise<T>;
  dispose: () => void;
}> {
  const stored = await secureStorage.getRequiringAuthentication(
    STORAGE_KEYS.DEVICE_SIGNING_SEED,
    'Authenticate to use your wallet key',
  );
  if (stored === null) {
    throw new DeviceSignerError(
      'This device holds no signing key. Sign in with your passphrase, or restore the wallet.',
    );
  }
  const seed = base64UrlToBytes(stored);
  let disposed = false;

  const assertLive = (): void => {
    if (disposed) {
      throw new DeviceSignerError('The signing key was disposed; unlock it again.');
    }
  };

  return {
    sign: async (payload: Uint8Array) => {
      assertLive();
      return bytesToBase64Url(signWithRecoveryKey(seed, payload));
    },
    // THE SEED IS ALREADY UNLOCKED HERE. Calling the free `withSeed` would make
    // the holder satisfy a SECOND biometric prompt for the same secret — one
    // to open the session and one for the recovery wrap. Measured on the
    // handset 21 Sep 2026: two consecutive fingerprints on every launch. Lend
    // this copy; `dispose` zeroises it, this call deliberately does not.
    withSeed: async (fn) => {
      assertLive();
      return fn(seed);
    },
    dispose: () => {
      disposed = true;
      zeroise(seed);
    },
  };
}

/**
 * Sign exact bytes and return the signature base64url-encoded.
 *
 * Callers pass a payload a server GAVE them — both the backend and the locker
 * echo a fully materialised canonical payload for this reason, so a wallet
 * cannot reconstruct the signed form wrong.
 */
export async function signPayload(payload: Uint8Array): Promise<string> {
  return withSeed(async (seed) => bytesToBase64Url(signWithRecoveryKey(seed, payload)));
}
