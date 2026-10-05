/**
 * The passphrase-wrapped recovery envelope, and where it lives.
 *
 * CORRECTED 8 Sep 2026. This used to PUT the envelope to
 * `POST /api/keystore/envelope`, a table in the ISSUER backend's Postgres named
 * `keystoreVault`. That name made it look like the thing the owner specified
 * while being its opposite: a row in the operator's own database, which the
 * operator can read, which the user holds no key to, and which offers no "use my
 * own server instead" choice.
 *
 * The KEYSTORE is one of the two lockers. Ministry-run, but "the key belongs to
 * the user, not the ministry"; it stores opaque bytes and "the operator must not
 * be able to read what is stored"; and it is "an option, never the only path",
 * which is why the base URL is configuration and a user-hosted locker is a
 * first-class target rather than an afterthought.
 *
 * The locker's own keystore policy was written for exactly this object — 64 KiB
 * cap, no multipart, eight retained generations, with the comment "a KEK
 * envelope is ~200 bytes". It was always the intended home.
 *
 * WHAT THE OPERATOR CAN SEE: the object is the envelope, which is sealed under a
 * scrypt-derived key from the user's passphrase. The locker never receives the
 * passphrase or the seed.
 *
 * READS ARE ADDRESSED BY HANDLE; only the WRITE is session-authorised. #402:
 * a handset with no key must still be able to fetch the envelope (the key is
 * what it is recovering), so the read cannot be authenticated and is not. The
 * write is authorised by a signature from the holder's own device key, so the
 * issuer backend is not in this path at all.
 */
import {
  unwrapRecoveryKeyWithPassphrase,
  wrapRecoveryKeyWithPassphrase,
  signWithRecoveryKey,
  bytesToBase64Url,
  type PassphraseEnvelope,
} from '@ssi-healthcare/shared';

import { secureStorage, STORAGE_KEYS } from './secureStorage';
import { readBackupBinding, type BackupBinding } from '../db/sync/state';

/**
 * What a restore needs to open the snapshot: the two AEAD inputs, and nothing
 * else. `uploadedAt` is bookkeeping for the device that wrote the backup and is
 * deliberately not carried in the envelope.
 */
export type SnapshotBinding = Pick<BackupBinding, 'version' | 'contentHash'>;
import {
  openLockerSession,
  putLockerObject,
  resolveKeystoreBase,
  fetchRecoveryEnvelopeByHandle,
} from './lockerClient';
import { signPayload } from './deviceSigner';

export class RecoveryKeyReleaseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RecoveryKeyReleaseError';
  }
}

export interface RecoveryKeyReleasePort {
  provision(did: string, handle: string, seed: Uint8Array, passphrase: string): Promise<void>;
  /**
   * Returns the recovered seed AND the DID it belongs to.
   *
   * The DID is not an input any more. #402: the keystore answers by handle and
   * hands the DID back with the envelope, so the caller cannot supply a DID the
   * envelope does not belong to — the mismatch is unconstructable rather than
   * merely checked for.
   */
  releaseToWallet(handle: string, passphrase: string): Promise<{ seed: Uint8Array; did: string }>;
  clear(handle: string): Promise<void>;
}

/**
 * The object this subject's envelope is filed under.
 *
 * Stable and derived from the handle, so the same account finds its own envelope
 * again. The locker already namespaces every object under a keyed hash of the
 * subject DID, so this identifier is only unique WITHIN one subject and carries
 * no cross-subject meaning.
 */
function envelopeObjectId(handle: string): string {
  return `recovery-envelope-${bytesToBase64Url(new TextEncoder().encode(handle))}`;
}

class KeystoreLockerPassphraseKeyRelease implements RecoveryKeyReleasePort {
  private cacheKey(handle: string): string {
    // base64url is exactly SecureStore's permitted alphabet, and it keeps the
    // raw phone number out of the key name.
    return `${STORAGE_KEYS.RECOVERY_KEY_ENVELOPE}_${bytesToBase64Url(
      new TextEncoder().encode(handle),
    )}`;
  }

  /**
   * `sign` is a parameter, not always `signPayload`, and that matters at
   * ENROLMENT. There the caller has just generated the seed and the backend has
   * just rotated the DID's `#key-1` to its public half — so the correct signing
   * key is the one already in hand. Routing it back out through secure storage
   * to read it again adds a second biometric prompt and, worse, makes the
   * signature depend on storage returning the same bytes that were written.
   * It did not: `storeDeviceSeed` writes under `requireAuthentication` and a
   * plain read hits a DIFFERENT Android keystore entry, so an earlier
   * unauthenticated value came back and signing produced a valid signature by
   * the WRONG key — the locker's BAD_SIGNATURE, against a DID whose published
   * key matched the chain exactly (measured 8 Sep 2026).
   */
  private async session(did: string, sign: (payload: Uint8Array) => Promise<string> = signPayload) {
    const base = await resolveKeystoreBase();
    const { token } = await openLockerSession(base, did, sign);
    return { base, token };
  }

  async provision(
    did: string,
    handle: string,
    seed: Uint8Array,
    passphrase: string,
  ): Promise<void> {
    // The backup binding rides INSIDE the sealed envelope, not beside it.
    // `version` and `contentHash` are AEAD inputs to the database snapshot, and
    // a device that has never held that database cannot derive either — so a
    // restore on a fresh handset is impossible unless they travel with the
    // thing the passphrase unlocks. Inside keeps them under the same seal: a
    // reader who can open the envelope can read them, and nobody else can.
    // A wallet can provision a recovery key before it has ever written its
    // database, so an absent or unreadable binding is normal and not a failure:
    // the envelope simply carries none, and step 4 will answer "nothing to
    // fetch" rather than pretending a backup exists.
    const binding = await readBackupBinding().catch(() => null);
    const envelope = await wrapRecoveryKeyWithPassphrase(seed, passphrase, binding ?? undefined);
    // Sign with the seed we were handed — see `session` for why not `signPayload`.
    const { base, token } = await this.session(did, async (payload) =>
      bytesToBase64Url(signWithRecoveryKey(seed, payload)),
    );
    await putLockerObject(
      base,
      token,
      envelopeObjectId(handle),
      new TextEncoder().encode(JSON.stringify(envelope)),
      // The pointer is what makes a new handset able to find this at all.
      handle,
    );
  }

  /**
   * Signing in on a handset that already knows the DID: handle + passphrase.
   *
   * #402 STEP 2 — THE HANDLE-ADDRESSED READ, NOT A LOCKER SESSION.
   *
   * This used to open a DID-authenticated session first and then read the
   * envelope by object id: the device proved control of the DID in order to
   * read the thing that yields that DID's key. A new device cannot do it at
   * all — and a device that can does not need recovery for anything — so the
   * inversion only ever added a dependency, not a proof. Worse, the session
   * made sign-in depend on the LOCKER resolving the DID, which on this
   * deployment meant a dev-only stub resolver that only a bridge script kept
   * populated (steno #439).
   *
   * The keystore's `/v1/recovery/envelope` is the intended path: addressed by
   * HANDLE, needing no DID and no signature, answering with the sealed
   * envelope and the DID it belongs to. The envelope opens only under the
   * passphrase, which is exactly the factor the user just supplied.
   */
  async releaseToWallet(handle: string, passphrase: string): Promise<{ seed: Uint8Array; did: string }> {
    return recoverFromHandle(handle, passphrase);
  }

  async clear(handle: string): Promise<void> {
    await secureStorage.delete(this.cacheKey(handle));
  }
}

export const recoveryKeyRelease: RecoveryKeyReleasePort =
  new KeystoreLockerPassphraseKeyRelease();

/**
 * Step 1 of restoring on a NEW device: phone number and passphrase, nothing else.
 *
 * Returns the recovered seed AND the DID it belongs to, because a handset that
 * has just been unboxed knows neither. What happens next is a separate decision
 * and a separate screen: the caller checks the datastore for a locker under this
 * DID and, if one exists, ASKS before fetching anything. Data retrieval is its
 * own consent, never a side effect of signing in.
 */
export async function recoverFromHandle(
  handle: string,
  passphrase: string,
): Promise<{ seed: Uint8Array; did: string; backupBinding: SnapshotBinding | null }> {
  const base = await resolveKeystoreBase();
  const found = await fetchRecoveryEnvelopeByHandle(base, handle);
  if (!found) {
    throw new RecoveryKeyReleaseError('No recovery envelope is enrolled under this number.');
  }
  const envelope = found.envelope as PassphraseEnvelope;
  const seed = await unwrapRecoveryKeyWithPassphrase(envelope, passphrase);
  return { seed, did: found.did, backupBinding: envelope.backupBinding ?? null };
}
