/**
 * The holder's sync KEK — the one key every locker sync object is sealed under.
 *
 * DEVICE WRAP POLICY IS BACKGROUND-CAPABLE, ON PURPOSE (owner call, 20 Sep).
 * The sync drain runs from expo-background-task, where no biometric prompt can
 * appear; a user-presence-gated KEK would make every background drain fail
 * closed. The device copy therefore lives in the platform keystore via
 * SecureStore with NO requireAuthentication — the same policy, for the same
 * reason, as the database key (db/keys.ts). What preserves recovery is not the
 * prompt; it is the SECOND wrap (#340): the KEK is also sealed into the
 * recovery story, so losing the device does not lose the backups.
 *
 * NOT YET BUILT (#470 onward): the recovery envelope — seal under the identity
 * seed with info 'bdhealthtrust/locker-kek-recovery/v1' and upload to the
 * KEYSTORE locker, where a restored handset can fetch and open it. Until that
 * exists, the KEK is device-bound and the backups are not yet recoverable on a
 * new device; do not describe this as backup-complete before it lands.
 */
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  openKey,
  sealKey,
  type KeyEnvelope,
} from '@ssi-healthcare/shared';

const KEK_NAME = 'ssi_locker_kek_v1';
const KEYCHAIN_SERVICE = 'com.ssihealthcare.wallet';
const KEK_BYTES = 32;

export class LockerKekError extends Error {}

export async function getOrCreateLockerKek(): Promise<Uint8Array> {
  const existing = await SecureStore.getItemAsync(KEK_NAME, { keychainService: KEYCHAIN_SERVICE });
  if (existing !== null) {
    const kek = base64UrlToBytes(existing);
    if (kek.length !== KEK_BYTES) {
      throw new LockerKekError('stored sync KEK is malformed; refusing to guess');
    }
    return kek;
  }

  const kek = Crypto.getRandomBytes(KEK_BYTES);
  await SecureStore.setItemAsync(KEK_NAME, bytesToBase64Url(kek), {
    keychainService: KEYCHAIN_SERVICE,
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  return kek;
}


/** Reserved info string for the recovery wrap; distinct from every other purpose. */
export const KEK_RECOVERY_INFO = 'bdhealthtrust/locker-kek-recovery/v1';
/** Object id the recovery envelope is filed under in the KEYSTORE locker. */
export const KEK_RECOVERY_OBJECT_ID = 'locker-kek-recovery';

function recoveryAad(subjectRef: string): Uint8Array {
  return new TextEncoder().encode(`${KEK_RECOVERY_INFO}|${subjectRef}`);
}

/**
 * The SECOND wrap (#340): seal the KEK under a key derived from the identity
 * seed, which the passphrase envelope already recovers. This is what makes the
 * backups survivable across a lost device — the device wrap above is
 * deliberately prompt-free, so it cannot be the recovery path.
 */
export function sealKekForRecovery(
  kek: Uint8Array,
  seed: Uint8Array,
  subjectRef: string,
): KeyEnvelope {
  return sealKey(kek, seed, { info: KEK_RECOVERY_INFO, aad: recoveryAad(subjectRef) });
}

export function openKekFromRecovery(
  envelope: KeyEnvelope,
  seed: Uint8Array,
  subjectRef: string,
): Uint8Array {
  return openKey(envelope, seed, { info: KEK_RECOVERY_INFO, aad: recoveryAad(subjectRef) });
}
