/**
 * Restore a wallet's data from the holder's datastore locker onto a NEW device.
 *
 * STEP 4 OF 4 of the recovery flow (#402). Steps 1-3 prove who the caller is:
 * the keystore returns the sealed envelope BY HANDLE (no DID, no signature — a
 * new device has neither), the passphrase unwraps it to the recovery seed, and
 * the DID travels with the envelope. This file is what happens next, and until
 * now it did not exist: the screen verified the passphrase and then said restore
 * "is not supported yet", holding a correct key it had no way to use.
 *
 * RETRIEVAL IS ITS OWN CONSENT. Approving the fetch is a separate act from
 * proving identity, which is why a button calls this and never a sign-in path.
 *
 * WHAT THE LOCKER CAN AND CANNOT DO HERE. It cannot read the object: it holds
 * ciphertext sealed under a KEK it has never seen. It cannot substitute one
 * either — the subject, the object id, the version and the plaintext hash are
 * bound into the AEAD's additional data, so an object swapped for another fails
 * to open rather than opening as the wrong wallet.
 *
 * TWO OBJECT FAMILIES, TWO BINDINGS. The database snapshot is sealed by
 * `backup.ts` under a single well-known object id. Every other object is sealed
 * by `drain.ts`, whose `version` is the enqueue timestamp and whose `contentHash`
 * is the hash of that object's OWN plaintext. Neither is published, so the only
 * way to open those is to try the payload's real hash — which is what
 * `openPerObjectObject` does, and why it must not be confused with the snapshot
 * path.
 */
import { File } from 'expo-file-system';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { openSyncObject, type SyncObjectBinding } from '@ssi-healthcare/shared';
import { closeDb, getDb } from './open';
import { getOrCreateLockerKek } from '../services/lockerKek';
import {
  resolveLockerBase,
  openLockerSession,
  getLockerObject,
} from '../services/lockerClient';
import { signPayload } from '../services/deviceSigner';

/** Written by `backup.ts`. The whole encrypted wallet database. */
const BACKUP_OBJECT_ID = 'wallet-db-backup';

export class WalletRestoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WalletRestoreError';
  }
}

export interface WalletRestoreResult {
  readonly holderDid: string;
  readonly plaintextBytes: number;
  readonly contentHash: string;
}

/**
 * Replace the local database with the snapshot held in the locker.
 *
 * ORDER MATTERS. The object is fetched and OPENED — tag verified against the
 * binding, so it must be the right subject, object and version — before the live
 * database is touched. A refusal therefore leaves the device exactly as it was,
 * which is the only safe shape: a restore that half-replaces a wallet is worse
 * than one that does not start.
 */
export async function restoreWalletFromLocker(
  holderDid: string,
  options: { version: number; contentHash: string },
): Promise<WalletRestoreResult> {
  const base = await resolveLockerBase();

  // The challenge names the DID, so the locker asks for a proof of control.
  // On an unenrolled device the signer holds the RECOVERY key, not the
  // identity's registered key, so this is the point at which the flow either
  // proceeds (the recovery key is registered for the DID) or the locker refuses
  // with an unambiguous message. Both are answers; neither is silent.
  const session = await openLockerSession(base, holderDid, signPayload);

  const sealed = await getLockerObject(base, session.token, BACKUP_OBJECT_ID);
  if (sealed === null) {
    throw new WalletRestoreError(
      'No wallet backup is stored for this account yet, so there is nothing to restore.',
    );
  }

  const kek = await getOrCreateLockerKek();
  const binding: SyncObjectBinding = {
    subjectRef: holderDid,
    objectId: BACKUP_OBJECT_ID,
    version: options.version,
    contentHash: options.contentHash,
  };
  let snapshot: Uint8Array;
  try {
    snapshot = openSyncObject(kek, binding, sealed);
  } catch {
    throw new WalletRestoreError(
      'The backup was found but did not decrypt with this key. It may belong to a ' +
        'different account, or have been written by a newer version of this wallet.',
    );
  }

  if (bytesToHex(sha256(snapshot)) !== options.contentHash) {
    throw new WalletRestoreError(
      'The backup opened but its contents do not match the hash it was stored with.',
    );
  }

  await replaceDatabaseWith(snapshot);

  return {
    holderDid,
    plaintextBytes: snapshot.length,
    contentHash: options.contentHash,
  };
}

/**
 * SWAP THE LIVE DATABASE FOR THE RESTORED SNAPSHOT.
 *
 * The connection is closed first because SQLite will not have its file replaced
 * underneath it, and reopened afterwards so the caller reads restored rows. The
 * snapshot is the database — `VACUUM INTO` produced it on the source device — so
 * it is moved into place rather than replayed row by row, which would mean
 * re-deriving its schema and re-running migrations over data that already has
 * them.
 */
async function replaceDatabaseWith(snapshot: Uint8Array): Promise<void> {
  const db = await getDb();
  const databasePath = db.databasePath;
  await closeDb();

  // `.bak` FIRST, NOT DELETE. If writing the restored file fails partway, a
  // device with no database at all is unrecoverable, while a device with the
  // previous one renamed is a rename away from where it started.
  const live = new File(databasePath);
  if (live.exists) {
    const backupPath = `${databasePath}.pre-restore-${Date.now()}`;
    live.move(new File(backupPath));
  }

  const restored = new File(databasePath);
  restored.create();
  restored.write(snapshot);

  await getDb();
}
