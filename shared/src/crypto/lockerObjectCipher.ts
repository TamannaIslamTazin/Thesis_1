/**
 * Document ciphertext framing — round 5's decision
 * (__docs__/backend/CONTENT-KEY-ENVELOPE-GAP.md §2).
 *
 * Round 4 chose this framing for its own fixture in
 * `packages/issuer-console/src/lib/documentCrypto.ts` and said plainly that it
 * was "not a contract another component depends on yet." Round 5 promotes it
 * to that contract: nonce-prefixed AES-256-GCM, AAD binding the object id, one
 * implementation here that the wallet (encrypt, before upload) and the issuer
 * console (decrypt, after the capability-gated fetch) both import — the same
 * "cannot drift" reasoning as `contentKeyWrap.ts` and `capability/index.ts`.
 *
 * No format change from round 4's convention: existing tooling
 * (`packages/locker/scripts/verify-locker.mjs`) already assumes AES-256-GCM
 * over locker object bytes, and there is no reason to invent a second one.
 */

import { gcm } from '@noble/ciphers/aes';

export class LockerObjectCipherError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LockerObjectCipherError';
  }
}

export const LOCKER_OBJECT_CIPHER_DOMAIN = 'bdhealthtrust/locker-object/v1';
export const OBJECT_NONCE_BYTES = 12;
export const OBJECT_CONTENT_KEY_BYTES = 32;

function aad(objectId: string): Uint8Array {
  return new TextEncoder().encode(`${LOCKER_OBJECT_CIPHER_DOMAIN}|${objectId}`);
}

/**
 * Encrypt plaintext for storage at a given locker object id.
 *
 * `nonce` is injectable for deterministic tests only; production callers must
 * omit it and get a fresh random one, which is what happens by default.
 */
export function encryptLockerObject(
  objectId: string,
  contentKey: Uint8Array,
  plaintext: Uint8Array,
  nonce?: Uint8Array,
): Uint8Array {
  if (contentKey.length !== OBJECT_CONTENT_KEY_BYTES) {
    throw new LockerObjectCipherError(
      `Content key must be ${OBJECT_CONTENT_KEY_BYTES} bytes, got ${contentKey.length}.`,
    );
  }
  const usedNonce = nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(OBJECT_NONCE_BYTES));
  if (usedNonce.length !== OBJECT_NONCE_BYTES) {
    throw new LockerObjectCipherError(`Nonce must be ${OBJECT_NONCE_BYTES} bytes, got ${usedNonce.length}.`);
  }
  const ciphertext = gcm(contentKey, usedNonce, aad(objectId)).encrypt(plaintext);
  const out = new Uint8Array(usedNonce.length + ciphertext.length);
  out.set(usedNonce, 0);
  out.set(ciphertext, usedNonce.length);
  return out;
}

/** Decrypt bytes read back from a locker object. Inverse of {@link encryptLockerObject}. */
export function decryptLockerObject(objectId: string, contentKey: Uint8Array, objectBytes: Uint8Array): Uint8Array {
  if (contentKey.length !== OBJECT_CONTENT_KEY_BYTES) {
    throw new LockerObjectCipherError(
      `Content key must be ${OBJECT_CONTENT_KEY_BYTES} bytes, got ${contentKey.length}.`,
    );
  }
  if (objectBytes.length < OBJECT_NONCE_BYTES) {
    throw new LockerObjectCipherError('Object is too short to contain a nonce.');
  }
  const nonce = objectBytes.slice(0, OBJECT_NONCE_BYTES);
  const ciphertext = objectBytes.slice(OBJECT_NONCE_BYTES);
  try {
    return gcm(contentKey, nonce, aad(objectId)).decrypt(ciphertext);
  } catch (error) {
    throw new LockerObjectCipherError(
      `The object did not decrypt under the given content key: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}
