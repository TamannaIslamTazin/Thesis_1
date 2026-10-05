/**
 * The content-key wrap scheme — round 5's decision
 * (__docs__/backend/CONTENT-KEY-ENVELOPE-GAP.md).
 *
 * ===========================================================================
 * WHAT WAS DECIDED, AND WHY THIS SHAPE
 * ===========================================================================
 * Round 4 built `wrappedContentKeyShape` (packages/backend/src/services/issuance.ts)
 * with `ephemeralPublicKey` and `nonce` reserved for "some ECIES-shaped scheme"
 * but implemented only a raw pass-through placeholder, explicitly refusing to
 * invent the real scheme unilaterally. Round 5 is that decision: X25519
 * ephemeral-static ECDH, HKDF-SHA256 key derivation, AES-256-GCM — the same
 * primitive family this package already uses everywhere else (`keyEnvelope.ts`,
 * `passphraseEnvelope.ts`, `prfEnvelope.ts`), applied to a new purpose rather
 * than inventing a new one. `sealKey`/`openKey` do the AEAD half; this module
 * only adds the ECDH step and the domain-separated binding around it.
 *
 * ONE IMPLEMENTATION, TWO CONSUMERS. The wallet calls {@link wrapContentKey}
 * to produce what `POST /api/issuance/requests` carries as
 * `wrappedContentKey`; the issuer console calls {@link unwrapContentKey} to
 * open what `GET /api/authority/requests/:id` releases. Both live in
 * `@ssi-healthcare/shared` so the two cannot independently drift, which is the
 * same reasoning `capability/index.ts`'s docblock gives for
 * `canonicalCapabilityPayload`.
 *
 * ===========================================================================
 * WHY THIS COULD NOT BE EXERCISED AGAINST A REAL RESOLVED AUTHORITY KEY
 * ===========================================================================
 * An X25519 public key needs somewhere to live that a wallet can fetch
 * without guessing. The natural place — a `keyAgreement` verification method
 * on the authority's DID document — does not exist: every DID this codebase
 * mints (`cheqdDid.ts`'s `createCheqdDID`) sets `authentication` and
 * `assertionMethod` only, and the four pinned L1 authority DIDs are already
 * literal, already-created placeholders (`documentTypes.ts`,
 * `accreditation/index.ts`) that a later PATCH cannot safely retrofit — this
 * codebase's own recorded reasoning is that a DID document's controller and
 * verification-method shape is fixed at creation and cannot be "secured
 * afterwards" (`patientEnrolment.ts`'s header, quoting S-1 §8.4).
 *
 * So round 5 carries the authority's X25519 public key as a NEW field on the
 * same frozen registry that already carries its DID and name
 * (`DocumentTypeDefinition.contentKeyPublicKey`) rather than pretending DID
 * resolution supplies it. This is the honest continuation of what round 4
 * already recorded as placeholder infrastructure, not a new kind of fake.
 */

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

import { base64UrlToBytes, bytesToBase64Url } from '../recovery/base64Url.js';
import { sealKey, openKey, type KeyEnvelope } from '../recovery/keyEnvelope.js';

export class ContentKeyWrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContentKeyWrapError';
  }
}

export const CONTENT_KEY_WRAP_DOMAIN = 'bdhealthtrust/content-key-wrap/v1';
export const CONTENT_KEY_BYTES = 32;
export const X25519_PUBLIC_KEY_BYTES = 32;

/** The wire shape `wrappedContentKeyShape` (backend) validates structurally. */
export interface WrappedContentKey {
  readonly version: 1;
  readonly wrappedToVerificationMethodId: string;
  readonly ephemeralPublicKey: string;
  readonly nonce: string;
  readonly salt: string;
  readonly ciphertext: string;
}

/**
 * Binds the wrap to the submission and the target key, so a wrapped key
 * lifted from one submission cannot be replayed as another's — the same
 * "slot binding" reasoning `backupVaultClient.ts` documents for its own AAD.
 */
function wrapAad(wrappedToVerificationMethodId: string, issuanceRequestId: string): Uint8Array {
  return new TextEncoder().encode(
    `${CONTENT_KEY_WRAP_DOMAIN}|${wrappedToVerificationMethodId}|${issuanceRequestId}`,
  );
}

/**
 * Wrap a 32-byte content key to an authority's X25519 public key.
 *
 * Fresh ephemeral X25519 keypair per call (never reused — reuse would let two
 * wraps to the same recipient be linked by their ECDH output). The ephemeral
 * public key travels in the clear (it is not secret; only the ECDH OUTPUT,
 * which never leaves this function, is) and doubles as the HKDF salt, binding
 * the derived key to this exact wrap without a second random value.
 */
export function wrapContentKey(args: {
  readonly recipientPublicKey: Uint8Array;
  readonly contentKey: Uint8Array;
  readonly wrappedToVerificationMethodId: string;
  readonly issuanceRequestId: string;
}): WrappedContentKey {
  if (args.recipientPublicKey.length !== X25519_PUBLIC_KEY_BYTES) {
    throw new ContentKeyWrapError(
      `recipientPublicKey must be ${X25519_PUBLIC_KEY_BYTES} bytes, got ${args.recipientPublicKey.length}.`,
    );
  }
  if (args.contentKey.length !== CONTENT_KEY_BYTES) {
    throw new ContentKeyWrapError(
      `contentKey must be ${CONTENT_KEY_BYTES} bytes, got ${args.contentKey.length}.`,
    );
  }

  const ephemeralSecret = x25519.utils.randomSecretKey();
  const ephemeralPublic = x25519.getPublicKey(ephemeralSecret);
  const shared = x25519.getSharedSecret(ephemeralSecret, args.recipientPublicKey);

  try {
    const envelope = sealKey(args.contentKey, shared, {
      info: CONTENT_KEY_WRAP_DOMAIN,
      aad: wrapAad(args.wrappedToVerificationMethodId, args.issuanceRequestId),
    });

    return {
      version: 1,
      wrappedToVerificationMethodId: args.wrappedToVerificationMethodId,
      ephemeralPublicKey: bytesToBase64Url(ephemeralPublic),
      nonce: envelope.nonce,
      salt: envelope.salt,
      ciphertext: envelope.ciphertext,
    };
  } finally {
    ephemeralSecret.fill(0);
    shared.fill(0);
  }
}

/**
 * Unwrap a content key with the authority's X25519 PRIVATE key.
 *
 * Refuses anything that is not this round's real scheme — an
 * `ephemeralPublicKey`/`nonce`/`salt`-absent envelope means a caller sent the
 * round-4 pass-through placeholder or something else entirely, and this
 * function does not guess.
 */
export function unwrapContentKey(args: {
  readonly recipientPrivateKey: Uint8Array;
  readonly wrapped: WrappedContentKey;
  readonly issuanceRequestId: string;
}): Uint8Array {
  const { wrapped } = args;
  if (wrapped.version !== 1) {
    throw new ContentKeyWrapError(`Unknown wrappedContentKey version ${String(wrapped.version)}.`);
  }
  if (!wrapped.ephemeralPublicKey || !wrapped.nonce || !wrapped.salt) {
    throw new ContentKeyWrapError(
      'wrappedContentKey is missing ephemeralPublicKey, nonce or salt — this is not round 5\'s ' +
        'ECIES scheme (@ssi-healthcare/shared crypto/contentKeyWrap.ts). Refusing rather than ' +
        'guessing at an older or different format.',
    );
  }

  const ephemeralPublic = base64UrlToBytes(wrapped.ephemeralPublicKey);
  const shared = x25519.getSharedSecret(args.recipientPrivateKey, ephemeralPublic);

  try {
    const envelope: KeyEnvelope = { version: 1, salt: wrapped.salt, nonce: wrapped.nonce, ciphertext: wrapped.ciphertext };
    return openKey(envelope, shared, {
      info: CONTENT_KEY_WRAP_DOMAIN,
      aad: wrapAad(wrapped.wrappedToVerificationMethodId, args.issuanceRequestId),
    });
  } finally {
    shared.fill(0);
  }
}

/** Convenience for callers that only have a seed and need the matching public key (e.g. env-var-seeded institution custody, same pattern as the console's Ed25519 signing seed). */
export function x25519PublicKeyFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) {
    throw new ContentKeyWrapError(`X25519 seed must be 32 bytes, got ${seed.length}.`);
  }
  return x25519.getPublicKey(seed);
}

export { sha256, hkdf };
