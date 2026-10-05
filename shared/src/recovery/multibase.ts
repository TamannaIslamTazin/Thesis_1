/**
 * Ed25519 public key -> `publicKeyMultibase`, without a dependency.
 *
 * The backend reaches for `toMultibaseRaw` from `@cheqd/sdk/utils`, which is
 * correct there and far too heavy for the wallet bundle. The encoding is small
 * and fully specified, so the wallet computes it directly — the same reasoning
 * as `base64Url.ts`, which exists because React Native has no `btoa`.
 *
 * Format: multibase `z` (base58btc) over the multicodec prefix for an Ed25519
 * public key (0xed 0x01) followed by the 32 raw key bytes.
 */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_MULTICODEC_PREFIX = Uint8Array.from([0xed, 0x01]);
export const ED25519_PUBLIC_KEY_BYTES = 32;

/** base58btc, as used by multibase `z`. */
export function bytesToBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Leading zero bytes are not representable in the numeric conversion below;
  // base58 encodes each as the alphabet's first character.
  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) leadingZeros++;

  const digits: number[] = [];
  for (let i = leadingZeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = BASE58_ALPHABET[0]!.repeat(leadingZeros);
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]!];
  return out;
}

/**
 * The `publicKeyMultibase` for a raw Ed25519 public key.
 *
 * Rejects a wrong-length input rather than encoding it. A malformed value here
 * would be anchored on chain as a verification method nobody can sign for, and
 * a DID's verification method cannot be corrected without the key it names.
 */
export function ed25519PublicKeyToMultibase(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(
      `Expected a ${ED25519_PUBLIC_KEY_BYTES}-byte Ed25519 public key, got ${publicKey.length}.`,
    );
  }

  const prefixed = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + publicKey.length);
  prefixed.set(ED25519_MULTICODEC_PREFIX, 0);
  prefixed.set(publicKey, ED25519_MULTICODEC_PREFIX.length);

  return `z${bytesToBase58(prefixed)}`;
}
