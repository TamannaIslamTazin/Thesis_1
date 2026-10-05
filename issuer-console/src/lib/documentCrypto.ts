/**
 * The browser-side half of decrypting a released document.
 *
 * Round 4 built a placeholder pass-through here because no real content-key
 * wrap scheme existed yet (__docs__/backend/CONTENT-KEY-ENVELOPE-GAP.md).
 * Round 5 decided that scheme (`@ssi-healthcare/shared`
 * `crypto/contentKeyWrap.ts`, ECIES over X25519) and this module now consumes
 * it rather than a local copy — same reasoning as `lockerClient.ts` re-using
 * the shared `LockerCapabilityToken` type: one implementation, so the wallet
 * (which wraps) and this console (which unwraps) cannot silently drift.
 *
 * UNWRAPPING THE CONTENT KEY HAPPENS SERVER-SIDE, NOT HERE. The X25519
 * private key that opens a real ECIES wrap must never reach a browser tab —
 * the exact reasoning `src/app/console/locker/object/route.ts` already gives
 * for the Ed25519 locker-auth signing seed applies unchanged to this second
 * key. `unwrapReleasedContentKey` below calls the server route that holds it
 * (`/console/content-key`); this module's own job is only decrypting the
 * document bytes once the plaintext content key comes back — the part that
 * was always safe to do in the browser, because it needs no secret beyond
 * what this officer's own session already released.
 */
import { decryptLockerObject as sharedDecryptLockerObject, LockerObjectCipherError } from '@ssi-healthcare/shared';
import type { WrappedContentKey } from './api';

export class DocumentCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DocumentCryptoError';
  }
}

/**
 * Ask the console's own server to unwrap a released `wrappedContentKey`
 * (round 5's ECIES scheme) with the institution's X25519 private key. Returns
 * the raw 32-byte content key. See the module docblock for why this cannot
 * happen client-side.
 */
export async function unwrapReleasedContentKey(
  wrappedContentKey: WrappedContentKey,
  issuanceRequestId: string,
): Promise<Uint8Array> {
  const res = await fetch('/console/content-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ wrappedContentKey, issuanceRequestId }),
  });
  const body = (await res.json().catch(() => null)) as { contentKeyBase64Url?: string; error?: string } | null;
  if (!res.ok || !body?.contentKeyBase64Url) {
    throw new DocumentCryptoError(body?.error ?? `Content-key unwrap failed with status ${res.status}.`);
  }
  const padded = body.contentKeyBase64Url.replace(/-/g, '+').replace(/_/g, '/');
  const withPadding = padded + '='.repeat((4 - (padded.length % 4)) % 4);
  const binary = atob(withPadding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Decrypt a locker object under round 5's framing (`@ssi-healthcare/shared` `crypto/lockerObjectCipher.ts`). */
export function decryptLockerObject(objectId: string, contentKey: Uint8Array, objectBytes: Uint8Array): Uint8Array {
  try {
    return sharedDecryptLockerObject(objectId, contentKey, objectBytes);
  } catch (error) {
    throw new DocumentCryptoError(
      error instanceof LockerObjectCipherError ? error.message : String(error),
    );
  }
}
