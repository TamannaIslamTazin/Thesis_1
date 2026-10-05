/**
 * Backup the encrypted wallet database to the holder's datastore locker.
 *
 * THE SNAPSHOT IS CONSISTENT BECAUSE SQLITE MADE IT. The database runs in WAL
 * mode; copying the file while the app is live tears it. `VACUUM INTO` writes
 * a transactionally consistent single-file copy, which is then sealed UNDER
 * THE HOLDER'S KEK (syncObjectCipher) before any byte leaves the device. The
 * SQLCipher layer already encrypts the snapshot; the seal is the layer that
 * survives leaving the device, and it is the one carrying the AAD binding.
 *
 * The binding's `contentHash` is the hash of the PLAINTEXT snapshot, bound
 * into the tag: a swapped or stale object fails before the hash check.
 */
import { File } from 'expo-file-system';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { sealSyncObject, openSyncObject, type SyncObjectBinding } from '@ssi-healthcare/shared';
import { getDb } from '..';
import { getOrCreateLockerKek } from '../../services/lockerKek';
import {
  resolveLockerBase,
  openLockerSession,
  putLockerObject,
  getLockerObject,
} from '../../services/lockerClient';
import { prepareDeviceSigner } from '../../services/deviceSigner';
import { cacheLockerSession, recordBackupBinding, type CachedLockerSession } from './state';
import { secureStorage } from '../../services/secureStorage';

const BACKUP_OBJECT_ID = 'wallet-db-backup';

export interface DatabaseBackupResult {
  readonly objectId: string;
  readonly version: number;
  readonly contentHash: string;
  readonly plaintextBytes: number;
  readonly sealedBytes: number;
}

export async function backupDatabaseToLocker(
  preOpenedSession?: CachedLockerSession,
): Promise<DatabaseBackupResult> {
  const subjectRef = await secureStorage.getUserDid();
  if (!subjectRef) {
    throw new Error('This wallet has no DID yet, so it has nothing to back up.');
  }

  const snapshotPath = await snapshotDatabase();
  let plaintext: Uint8Array;
  try {
    plaintext = await new File(`file://${snapshotPath}`).bytes();
  } finally {
    const file = new File(`file://${snapshotPath}`);
    if (file.exists) file.delete();
  }

  const contentHash = bytesToHex(sha256(plaintext));
  const version = Date.now();
  const binding: SyncObjectBinding = { subjectRef, objectId: BACKUP_OBJECT_ID, version, contentHash };
  const kek = await getOrCreateLockerKek();
  const sealed = sealSyncObject(kek, binding, plaintext);

  let base: string;
  let token: string;
  if (preOpenedSession) {
    base = preOpenedSession.base;
    token = preOpenedSession.token;
  } else {
    base = await resolveLockerBase();
    const signer = await prepareDeviceSigner();
    try {
      const session = await openLockerSession(base, subjectRef, signer.sign);
      token = session.token;
      // Cache for the background drain, which cannot prompt (state.ts).
      await cacheLockerSession({ token: session.token, expiresAt: session.expiresAt, base });
    } finally {
      signer.dispose();
    }
  }

  await putLockerObject(base, token, BACKUP_OBJECT_ID, sealed);

  const readBack = await getLockerObject(base, token, BACKUP_OBJECT_ID);
  if (readBack === null) {
    throw new Error('The backup was uploaded but could not be read back.');
  }
  const opened = openSyncObject(kek, binding, readBack);
  const roundTripHash = bytesToHex(sha256(opened));
  if (roundTripHash !== contentHash) {
    throw new Error('The backup read back does not match what was uploaded.');
  }

  // Record the binding so a DIFFERENT device can open this. The two fields are
  // AEAD inputs and neither is derivable once the object is on the locker, so
  // this write is what makes the backup restorable at all — see BackupBinding.
  await recordBackupBinding({ version, contentHash, uploadedAt: new Date().toISOString() });

  return {
    objectId: BACKUP_OBJECT_ID,
    version,
    contentHash,
    plaintextBytes: plaintext.length,
    sealedBytes: sealed.length,
  };
}

/**
 * `VACUUM INTO` beside the live database so the path is one SQLite itself can
 * use. The name is unique per run, so no pre-delete race exists.
 */
async function snapshotDatabase(): Promise<string> {
  const db = await getDb();
  const directory = db.databasePath.slice(0, db.databasePath.lastIndexOf('/'));
  const path = `${directory}/wallet-snapshot-${Date.now()}.db`;
  await db.execAsync(`VACUUM INTO '${path}';`);
  return path;
}
