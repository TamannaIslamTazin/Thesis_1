/**
 * WebCrypto primitives for the vendored SD-JWT implementation.
 *
 * ONE IMPLEMENTATION FOR BOTH TARGETS. `@sd-jwt` ships `@sd-jwt/crypto-nodejs`
 * and `@sd-jwt/crypto-browser` as separate packages; neither was vendored,
 * because this SDK is published for browsers AND Node and shipping the Node one
 * would put `node:crypto` into a browser bundle. `globalThis.crypto.subtle` is
 * present in every supported browser and in Node >= 18, so this file is the
 * whole platform story.
 */
import type { Hasher, SaltGenerator } from '../vendor/sd-jwt/types';
import { uint8ArrayToBase64Url } from '../vendor/sd-jwt/utils';

/**
 * IANA hash-algorithm names to WebCrypto's.
 *
 * DELIBERATELY PARTIAL, and it throws on anything absent rather than falling
 * back. `_sd_alg` comes off the wire; treating an unrecognised value as
 * "probably sha-256" would mean an attacker-chosen algorithm name silently
 * selecting our default, and every digest comparison downstream comparing the
 * wrong hashes. An algorithm we cannot compute is a presentation we cannot
 * verify, which is a refusal.
 */
const WEB_CRYPTO_DIGEST: Readonly<Record<string, string>> = Object.freeze({
  'sha-256': 'SHA-256',
  'sha-384': 'SHA-384',
  'sha-512': 'SHA-512',
});

function webCryptoOrThrow(): Crypto {
  const available = globalThis.crypto;
  if (!available?.subtle) {
    throw new Error(
      'WebCrypto (globalThis.crypto.subtle) is unavailable. In Node this needs >= 18; in a browser it needs a secure context (https or localhost).',
    );
  }
  return available;
}

/** The hasher the vendored library expects. Honours the artifact's `_sd_alg`. */
export const webCryptoHasher: Hasher = async (data, alg) => {
  const digestName = WEB_CRYPTO_DIGEST[alg.toLowerCase()];
  if (!digestName) {
    throw new Error(
      `Unsupported SD-JWT hash algorithm '${alg}'. Supported: ${Object.keys(WEB_CRYPTO_DIGEST).join(', ')}.`,
    );
  }
  const bytes =
    typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
  const digest = await webCryptoOrThrow().subtle.digest(digestName, bytes);
  return new Uint8Array(digest);
};

/**
 * Cryptographically random salts.
 *
 * `length` is a count of base64url CHARACTERS, matching how the library and
 * every caller in this repository use it — not a byte count. Over-generate then
 * truncate, so the result is always exactly `length` characters of entropy-
 * backed text.
 */
export const webCryptoSaltGenerator: SaltGenerator = (length) => {
  const bytes = new Uint8Array(length);
  webCryptoOrThrow().getRandomValues(bytes);
  return uint8ArrayToBase64Url(bytes).slice(0, length);
};
