/**
 * The one envelope primitive: seal 32 secret bytes under a 32-byte wrapping
 * key, and open them again.
 *
 * ===========================================================================
 * WHY THIS EXISTS — DOMAIN SEPARATION, NOT TIDINESS
 * ===========================================================================
 * `prfEnvelope.ts` already implemented this shape for one caller: wrap the RCK
 * seed under a WebAuthn PRF output. The locker (#340) needs the same shape
 * twice more — the KEK wrapped under a device/PIN key, and the KEK wrapped
 * under a guardian-reconstructable recovery key.
 *
 * The tempting move was to call `wrapRecoveryKeyWithPrf` for all three. That
 * would have been a real cryptographic defect, not a naming quibble: its HKDF
 * info string is pinned to 'bdhealthtrust/rck-prf-envelope/v1', so three
 * different key purposes would derive through ONE domain-separation string.
 * Domain separation exists precisely so that a key derived for purpose A can
 * never coincide with one derived for purpose B; sharing the label discards
 * the property while keeping the ceremony of having it.
 *
 * So the primitive takes `info` FROM THE CALLER and has no default. There is
 * deliberately no fallback value — a caller that forgets to say what the key
 * is for does not get a generic label, it gets a type error.
 *
 * ===========================================================================
 * AAD IS REQUIRED, AND WHY
 * ===========================================================================
 * AES-GCM without AAD produces self-contained, INTERCHANGEABLE ciphertext. A
 * storage operator who cannot read two envelopes can still SWAP them, and the
 * holder decrypts the wrong one successfully with a valid tag. Binding the
 * slot the envelope belongs to makes relocation fail on the tag exactly as
 * tampering does. This was a live defect in the Phase C vault client, fixed
 * separately; the primitive takes `aad` as a required argument so the same
 * gap cannot be reintroduced by omission here.
 *
 * Callers with genuinely no slot to bind pass `EMPTY_AAD` explicitly. That is
 * a visible, greppable decision rather than a silent default.
 *
 * ===========================================================================
 * WHAT THIS DOES NOT DO
 * ===========================================================================
 * It does not derive the wrapping key. Where that key comes from — a PRF
 * output, Argon2id over a PIN, a secure-enclave key, a SLIP-39
 * reconstruction — is the caller's business and each has different failure
 * modes worth handling at the call site. This module only wraps and unwraps.
 */

import { gcm } from '@noble/ciphers/aes';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

import { base64UrlToBytes, bytesToBase64Url } from './base64Url.js';

/** Everything this module wraps is a 32-byte symmetric secret. */
export const SEALED_KEY_BYTES = 32;
/** The wrapping key is also 32 bytes: HKDF input keying material. */
export const WRAPPING_KEY_BYTES = 32;

const ENVELOPE_NONCE_BYTES = 12;
const ENVELOPE_SALT_BYTES = 16;
const DERIVED_KEY_BYTES = 32;

/** For callers with no slot identity to bind. Explicit, so the choice is greppable. */
export const EMPTY_AAD = new Uint8Array(0);

export class KeyEnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyEnvelopeError';
  }
}

export interface KeyEnvelope {
  readonly version: 1;
  /** base64url. Fresh per seal, so re-sealing never reuses a key stream. */
  readonly salt: string;
  readonly nonce: string;
  readonly ciphertext: string;
}

export interface EnvelopeContext {
  /**
   * HKDF info — what this key is FOR. No default, deliberately; see the module
   * docblock. Convention: 'bdhealthtrust/<purpose>/v<n>'.
   */
  readonly info: string;
  /**
   * Additional authenticated data binding the envelope to its slot. Pass
   * {@link EMPTY_AAD} if there is genuinely nothing to bind.
   */
  readonly aad: Uint8Array;
}

/**
 * All-zeroes is the signature of an uninitialised buffer rather than of
 * entropy. Refusing here turns a catastrophic caller bug into a loud failure
 * at seal time instead of a silent one discovered at recovery, which is years
 * later and unfixable.
 */
function assertKeyMaterial(bytes: Uint8Array, expectedLength: number, what: string): void {
  if (!(bytes instanceof Uint8Array)) {
    throw new KeyEnvelopeError(`${what} must be a Uint8Array, got ${typeof bytes}.`);
  }
  if (bytes.length !== expectedLength) {
    throw new KeyEnvelopeError(
      `${what} must be exactly ${expectedLength} bytes, got ${bytes.length}.`,
    );
  }
  if (bytes.every((byte) => byte === 0)) {
    throw new KeyEnvelopeError(
      `${what} is all zeroes, which is an uninitialised buffer rather than key material.`,
    );
  }
}

function assertContext(context: EnvelopeContext): void {
  if (typeof context?.info !== 'string' || context.info.trim().length === 0) {
    throw new KeyEnvelopeError(
      'An envelope context must name its HKDF `info`. There is no default: two key ' +
        'purposes sharing one info string discards the domain separation that makes ' +
        'them distinct.',
    );
  }
  if (!(context.aad instanceof Uint8Array)) {
    throw new KeyEnvelopeError(
      'An envelope context must supply `aad` (use EMPTY_AAD if there is genuinely no ' +
        'slot to bind). Omission is how unbound, interchangeable ciphertext gets ' +
        'reintroduced.',
    );
  }
}

function deriveWrappingKey(wrappingKey: Uint8Array, salt: Uint8Array, info: string): Uint8Array {
  return hkdf(sha256, wrappingKey, salt, info, DERIVED_KEY_BYTES);
}

/**
 * Seal 32 secret bytes.
 *
 * FAILSAFE: the envelope is REOPENED and compared before it is returned. An
 * envelope that does not open is a silent, terminal failure discovered only at
 * the one moment it is needed. Verifying costs one decryption and converts
 * that into a loud failure while the plaintext is still in hand — the same
 * discipline `splitRecoveryKey` applies to guardian shares.
 */
export function sealKey(
  secret: Uint8Array,
  wrappingKey: Uint8Array,
  context: EnvelopeContext,
): KeyEnvelope {
  assertKeyMaterial(secret, SEALED_KEY_BYTES, 'sealed secret');
  assertKeyMaterial(wrappingKey, WRAPPING_KEY_BYTES, 'wrapping key');
  assertContext(context);

  const salt = new Uint8Array(ENVELOPE_SALT_BYTES);
  globalThis.crypto.getRandomValues(salt);
  const nonce = new Uint8Array(ENVELOPE_NONCE_BYTES);
  globalThis.crypto.getRandomValues(nonce);

  const derived = deriveWrappingKey(wrappingKey, salt, context.info);
  const ciphertext = gcm(derived, nonce, context.aad).encrypt(secret);
  derived.fill(0);

  const envelope: KeyEnvelope = {
    version: 1,
    salt: bytesToBase64Url(salt),
    nonce: bytesToBase64Url(nonce),
    ciphertext: bytesToBase64Url(ciphertext),
  };

  const reopened = openKey(envelope, wrappingKey, context);
  if (reopened.length !== secret.length || !reopened.every((b, i) => b === secret[i])) {
    reopened.fill(0);
    throw new KeyEnvelopeError(
      'A freshly sealed envelope did not reopen to the key it wrapped. Refusing to store it.',
    );
  }
  reopened.fill(0);

  return envelope;
}

/**
 * Open a sealed envelope.
 *
 * AES-GCM authenticates, so a wrong wrapping key, a wrong `info`, a wrong
 * `aad` (an envelope lifted from another slot) or a tampered ciphertext all
 * fail on the tag rather than returning plausible garbage. There is no
 * silent-wrong-key outcome.
 */
export function openKey(
  envelope: KeyEnvelope,
  wrappingKey: Uint8Array,
  context: EnvelopeContext,
): Uint8Array {
  assertKeyMaterial(wrappingKey, WRAPPING_KEY_BYTES, 'wrapping key');
  assertContext(context);

  if (envelope?.version !== 1) {
    throw new KeyEnvelopeError(
      `Unknown key envelope version ${String(envelope?.version)}. Refusing to guess its layout.`,
    );
  }

  const salt = base64UrlToBytes(envelope.salt);
  const nonce = base64UrlToBytes(envelope.nonce);
  const ciphertext = base64UrlToBytes(envelope.ciphertext);

  const derived = deriveWrappingKey(wrappingKey, salt, context.info);
  let secret: Uint8Array;
  try {
    secret = gcm(derived, nonce, context.aad).decrypt(ciphertext);
  } catch (error) {
    throw new KeyEnvelopeError(
      'The key envelope did not authenticate. The wrapping key, the purpose (`info`) or ' +
        `the slot (\`aad\`) is not the one that sealed it, or the envelope was altered: ${
          error instanceof Error ? error.message : String(error)
        }`,
    );
  } finally {
    derived.fill(0);
  }

  if (secret.length !== SEALED_KEY_BYTES) {
    throw new KeyEnvelopeError(
      `The key envelope opened to ${secret.length} bytes, expected ${SEALED_KEY_BYTES}.`,
    );
  }

  return secret;
}
