/**
 * Sealed sync objects: the format the outbox uploads and a future restore reads.
 *
 * WHY THE AAD BINDS FOUR FIELDS (#343.4). An operator who cannot read two
 * ciphertexts can still SWAP them; AES-GCM without binding decrypts the wrong
 * object successfully, with a valid tag. Binding only the object id stops
 * cross-object swaps but not a version rollback at the SAME id: the v1 bytes
 * decrypt fine under a manifest that says v2. The tag therefore covers
 * (subjectRef, objectId, version, contentHash), and the reader recomputes the
 * plaintext hash afterwards — a substituted or stale object fails the tag
 * before it reaches the hash check.
 *
 * KEY DERIVATION: one holder KEK, one HKDF info per object id. The info string
 * is distinct from every envelope label (keyEnvelope.ts explains why labels
 * must never be shared across purposes).
 */
import { gcm } from '@noble/ciphers/aes';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

export const SYNC_OBJECT_DOMAIN = 'bdhealthtrust/sync-object/v1';
export const SYNC_OBJECT_NONCE_BYTES = 12;
export const SYNC_KEK_BYTES = 32;

export class SyncObjectCipherError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SyncObjectCipherError';
  }
}

export interface SyncObjectBinding {
  readonly subjectRef: string;
  readonly objectId: string;
  readonly version: number;
  readonly contentHash: string;
}

function objectInfo(objectId: string): Uint8Array {
  return new TextEncoder().encode(`${SYNC_OBJECT_DOMAIN}|${objectId}`);
}

function bindingAad(binding: SyncObjectBinding): Uint8Array {
  return new TextEncoder().encode(
    `${SYNC_OBJECT_DOMAIN}|${binding.subjectRef}|${binding.objectId}|${binding.version}|${binding.contentHash}`,
  );
}

export function deriveSyncObjectKey(kek: Uint8Array, objectId: string): Uint8Array {
  if (kek.length !== SYNC_KEK_BYTES) {
    throw new SyncObjectCipherError(`KEK must be ${SYNC_KEK_BYTES} bytes, got ${kek.length}.`);
  }
  return hkdf(sha256, kek, undefined, objectInfo(objectId), 32);
}

/** Nonce-prefixed AES-256-GCM, mirroring lockerObjectCipher's framing. */
export function sealSyncObject(
  kek: Uint8Array,
  binding: SyncObjectBinding,
  plaintext: Uint8Array,
  nonce?: Uint8Array,
): Uint8Array {
  const key = deriveSyncObjectKey(kek, binding.objectId);
  const usedNonce = nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(SYNC_OBJECT_NONCE_BYTES));
  if (usedNonce.length !== SYNC_OBJECT_NONCE_BYTES) {
    throw new SyncObjectCipherError(
      `Nonce must be ${SYNC_OBJECT_NONCE_BYTES} bytes, got ${usedNonce.length}.`,
    );
  }
  const ciphertext = gcm(key, usedNonce, bindingAad(binding)).encrypt(plaintext);
  const out = new Uint8Array(usedNonce.length + ciphertext.length);
  out.set(usedNonce, 0);
  out.set(ciphertext, usedNonce.length);
  return out;
}

export function openSyncObject(
  kek: Uint8Array,
  binding: SyncObjectBinding,
  sealed: Uint8Array,
): Uint8Array {
  const key = deriveSyncObjectKey(kek, binding.objectId);
  if (sealed.length < SYNC_OBJECT_NONCE_BYTES) {
    throw new SyncObjectCipherError('Object is too short to contain a nonce.');
  }
  const nonce = sealed.slice(0, SYNC_OBJECT_NONCE_BYTES);
  const ciphertext = sealed.slice(SYNC_OBJECT_NONCE_BYTES);
  try {
    return gcm(key, nonce, bindingAad(binding)).decrypt(ciphertext);
  } catch {
    throw new SyncObjectCipherError(
      'The object did not open under this KEK and binding — it was swapped, stale, or truncated.',
    );
  }
}
