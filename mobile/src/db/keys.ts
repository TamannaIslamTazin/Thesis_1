/**
 * The wallet database key.
 *
 * SQLCipher needs a key before it will read or write anything (see ./open.ts),
 * and this module is the only place that key exists outside the encrypted
 * pages: a random 32-byte value kept in the platform keystore via SecureStore.
 *
 * WHY NO `requireAuthentication` ON RETRIEVAL. The sync engine runs from
 * expo-background-task (#453), where no biometric prompt can be shown. A
 * biometric gate on the DB key would make every background sync fail closed —
 * a feature the owner has already approved (#366). The keystore's hardware
 * protection still applies; what is deliberately absent is a user-presence
 * requirement. The passphrase envelope and the device signing seed remain the
 * biometric-gated secrets (services/deviceSigner.ts).
 *
 * WHY THE KEY NAME IS NOT IN STORAGE_KEYS. secureStorage.clearAll() deletes
 * every key in that map on logout. If the DB key were in it, a logout would
 * orphan the encrypted database — undecryptable, but still on disk. The key's
 * lifecycle is owned here: create once, delete only together with the file.
 */
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';

const DB_KEY_NAME = 'ssi_db_key_v1';
const KEYCHAIN_SERVICE = 'com.ssihealthcare.wallet';
const KEY_HEX = /^[0-9a-f]{64}$/; // 32 bytes, hex-encoded

export class DbKeyError extends Error {}

/**
 * Read the existing key, or draw and persist one on first launch.
 *
 * Fails closed on a malformed stored value: a key-shaped thing that is not 32
 * hex-encoded bytes means something else wrote to this slot, and guessing
 * would silently replace whatever custody the user already has.
 */
export async function getOrCreateDbKeyHex(): Promise<string> {
  const existing = await SecureStore.getItemAsync(DB_KEY_NAME, {
    keychainService: KEYCHAIN_SERVICE,
  });
  if (existing !== null) {
    if (!KEY_HEX.test(existing)) {
      throw new DbKeyError('stored database key is malformed; refusing to guess');
    }
    return existing;
  }

  const bytes = await Crypto.getRandomBytesAsync(32);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  if (!KEY_HEX.test(hex)) {
    throw new DbKeyError('failed to draw a 32-byte database key');
  }
  await SecureStore.setItemAsync(DB_KEY_NAME, hex, {
    keychainService: KEYCHAIN_SERVICE,
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  return hex;
}

/**
 * Delete the key. Call ONLY together with deleting the database file — either
 * one alone leaves the other orphaned (and maybe undecryptable). The logout
 * and restore flows will pair them when they are wired.
 */
export async function deleteDbKey(): Promise<void> {
  await SecureStore.deleteItemAsync(DB_KEY_NAME, { keychainService: KEYCHAIN_SERVICE });
}
