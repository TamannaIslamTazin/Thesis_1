/**
 * The Recovery Controller Key (RCK) itself — 32 random bytes, and nothing else.
 *
 * ===========================================================================
 * WHY THIS IS RANDOM AND NOT DERIVED (#240)
 * ===========================================================================
 * The RCK is the patient's half of a 2-of-2 controller set that S-1 §5.4 proved
 * is mutable only by unanimous consent and therefore CANNOT BE REPAIRED. Any
 * input to a derivation — a passkey, a salt, a KDF choice, a Google account —
 * would become a permanent, unrepairable dependency of an unrepairable
 * identifier.
 *
 * So the seed is the root. PRF wraps it (see `prfEnvelope.ts`) and SLIP-39
 * splits it (see `guardianShares.ts`); both are ENVELOPES that can be redone at
 * will without the on-chain key ever moving. That asymmetry is the whole design.
 *
 * ===========================================================================
 * THIS MODULE KNOWS NOTHING ABOUT CHEQD, ON PURPOSE
 * ===========================================================================
 * It deals in raw bytes. Multibase encoding, DID URLs and signer plumbing live
 * in the backend, because this code has to run on a device that has no ledger
 * client. Keeping the boundary here is what makes "the key never leaves the
 * device" checkable rather than asserted.
 */

import { ed25519 } from '@noble/curves/ed25519';

/** Ed25519 seed length. Not configurable: it is the curve's, not ours. */
export const RECOVERY_KEY_SEED_BYTES = 32;

export class RecoveryKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RecoveryKeyError';
  }
}

/**
 * A seed that is all zeroes, or the wrong length, is the signature of an
 * uninitialised buffer rather than of entropy. Refusing here means a
 * catastrophic caller bug fails at generation instead of at first recovery,
 * which is years later and unfixable.
 */
export function assertWellFormedSeed(seed: Uint8Array, what = 'recovery key seed'): void {
  if (!(seed instanceof Uint8Array)) {
    throw new RecoveryKeyError(`${what} must be a Uint8Array, got ${typeof seed}.`);
  }
  if (seed.length !== RECOVERY_KEY_SEED_BYTES) {
    throw new RecoveryKeyError(
      `${what} must be exactly ${RECOVERY_KEY_SEED_BYTES} bytes, got ${seed.length}.`,
    );
  }
  if (seed.every((byte) => byte === 0)) {
    throw new RecoveryKeyError(
      `${what} is all zeroes. That is an uninitialised buffer, not entropy; refusing to ` +
        'anchor an unrepairable identity to it.',
    );
  }
}

/**
 * Generate a fresh RCK seed.
 *
 * `crypto.getRandomValues` is required and not merely preferred, so that the
 * device and the backend mint seeds the same way.
 *
 * CORRECTED 7 Sep 2026: this comment previously claimed the global is present
 * in Hermes. It is not. Node supplies it, so every test passed, and on a real
 * handset this threw "Cannot read property 'getRandomValues' of undefined" and
 * recovery enrolment could not complete. React Native callers must install a
 * polyfill before importing this module; the wallet does so in
 * `packages/mobile/src/polyfills/crypto.ts`.
 */
export function generateRecoveryKeySeed(): Uint8Array {
  const seed = new Uint8Array(RECOVERY_KEY_SEED_BYTES);
  globalThis.crypto.getRandomValues(seed);
  assertWellFormedSeed(seed, 'freshly generated recovery key seed');
  return seed;
}

export function recoveryKeyPublicKey(seed: Uint8Array): Uint8Array {
  assertWellFormedSeed(seed);
  return ed25519.getPublicKey(seed);
}

export function signWithRecoveryKey(seed: Uint8Array, payload: Uint8Array): Uint8Array {
  assertWellFormedSeed(seed);
  return ed25519.sign(payload, seed);
}

export function verifyRecoveryKeySignature(
  publicKey: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
): boolean {
  return ed25519.verify(signature, payload, publicKey);
}

/**
 * Overwrite a seed in place.
 *
 * Best-effort by nature — a JS engine may have copied the buffer during GC and
 * we cannot reach those copies. It is still worth doing: it bounds the window
 * in the common case, and S-2 §8 requires the seed's lifetime be minimised
 * because it is necessarily a software key.
 */
export function zeroise(seed: Uint8Array): void {
  seed.fill(0);
}
