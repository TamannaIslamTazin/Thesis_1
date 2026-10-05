/**
 * The `publicKeyMultibase` of an Ed25519VerificationKey2020, decoded and checked.
 *
 * These two functions were the part of the backend's `cheqdDidShapes` that could
 * not travel with the rest of the vocabulary: they needed Credo's
 * `MultiBaseEncoder`. `./multibase` replaces it, so they move here now.
 *
 * WHY A WALLET NEEDS THIS. A device that is about to rotate its own key has to
 * check the encoding it is about to publish BEFORE it broadcasts, because the
 * identifier it lands in cannot be repaired afterwards. That check has to run on
 * the device, which is the whole reason for the port.
 */

import { ERROR_CODES, SsiError } from '@ssi-healthcare/shared';

import { ED25519_MULTICODEC_PREFIX, ED25519_RAW_KEY_LENGTH } from './didDocument';
import { multibaseDecode, multibaseEncode, toHex } from './multibase';

/**
 * Decode a `publicKeyMultibase` to the RAW 32-byte Ed25519 key, with the
 * multicodec prefix stripped.
 *
 * Refuses anything that is not exactly `0xed 0x01` followed by 32 bytes. The
 * prefix is what distinguishes an Ed25519 key from every other key type sharing
 * this field, so a key of the wrong length or the wrong codec is a different
 * algorithm being passed off as this one — not something to trim and accept.
 */
export function ed25519PublicKeyFromMultibase(publicKeyMultibase: string): Uint8Array {
  const decoded = multibaseDecode(publicKeyMultibase).data;

  if (
    decoded.length !== ED25519_MULTICODEC_PREFIX.length + ED25519_RAW_KEY_LENGTH ||
    decoded[0] !== ED25519_MULTICODEC_PREFIX[0] ||
    decoded[1] !== ED25519_MULTICODEC_PREFIX[1]
  ) {
    throw new SsiError(
      ERROR_CODES.VALIDATION_ERROR,
      `publicKeyMultibase '${publicKeyMultibase}' does not carry the Ed25519 multicodec ` +
        `prefix ed01 followed by ${ED25519_RAW_KEY_LENGTH} bytes; it decoded to ` +
        `${decoded.length} bytes starting ${toHex(decoded.slice(0, 2))}. ` +
        'Refusing to guess at the key type.',
      400,
    );
  }

  return decoded.slice(ED25519_MULTICODEC_PREFIX.length);
}

/**
 * Validate a caller-supplied key encoding and hand back the original string.
 *
 * Used at DID creation, where the key comes from a device rather than from our
 * own KMS. A malformed key here would be written into an identifier that cannot
 * be repaired, so it is checked before the document is assembled.
 */
export function assertEd25519Multibase(publicKeyMultibase: string): string {
  ed25519PublicKeyFromMultibase(publicKeyMultibase);
  return publicKeyMultibase;
}

/**
 * The inverse: a raw 32-byte Ed25519 public key as a `publicKeyMultibase`.
 *
 * Refuses a key of the wrong length rather than padding or truncating it. This
 * is the form a wallet publishes when it mints its own device key, and the
 * backend's `deviceRecoveryKey` uses it for the same purpose.
 */
export function ed25519PublicKeyToMultibase(rawPublicKey: Uint8Array): string {
  if (rawPublicKey.length !== ED25519_RAW_KEY_LENGTH) {
    throw new SsiError(
      ERROR_CODES.VALIDATION_ERROR,
      `An Ed25519 public key is ${ED25519_RAW_KEY_LENGTH} bytes; got ${rawPublicKey.length}. ` +
        'Refusing to encode a key of the wrong length into an identifier that cannot be repaired.',
      400,
    );
  }
  const prefixed = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + rawPublicKey.length);
  prefixed.set(ED25519_MULTICODEC_PREFIX, 0);
  prefixed.set(rawPublicKey, ED25519_MULTICODEC_PREFIX.length);
  return multibaseEncode(prefixed, 'base58btc');
}
