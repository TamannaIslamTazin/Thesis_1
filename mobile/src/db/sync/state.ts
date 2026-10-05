/**
 * Sync bookkeeping kept in the encrypted database's `sync_meta` table.
 *
 * TWO THINGS LIVE HERE, and both are about surviving a background run that
 * cannot ask the holder anything:
 *
 *  - The LOCKER SESSION CACHE. A locker session requires a signature from the
 *    device key, and that key is user-presence gated; a background drain can
 *    never obtain one. So a foreground session is cached with its expiry, and
 *    the drain uses it while it is valid. Absent or expired is a classified
 *    failure (#93), never a silent retry loop.
 *
 *  - The LAST SYNC STATUS. Per #93, a holder believing they have a backup when
 *    they do not is worse than one who knows they have none: the failure class
 *    and the last success are persisted so a settings banner can name them.
 */
import { getDb, withDbTransaction } from '../open';

const SESSION_KEY = 'locker_session';
const STATUS_KEY = 'sync_status';
const BACKUP_BINDING_KEY = 'backup_binding';

/**
 * The binding the database snapshot was SEALED with.
 *
 * `version` and `contentHash` are both inputs to the snapshot's AEAD additional
 * data, and NEITHER is derivable after the fact: the version is a timestamp from
 * the uploading device, and the hash is of a plaintext the restorer has not yet
 * decrypted. Without this record a second device can find the backup and has no
 * way to open it — which is exactly why restore stopped at "not supported yet".
 *
 * Recorded HERE, in the encrypted database, because this is the only place that
 * survives at the moment of upload; a copy placed anywhere else would be a
 * second source of truth for the same fact.
 */
export interface BackupBinding {
  readonly version: number;
  readonly contentHash: string;
  readonly uploadedAt: string;
}

export async function recordBackupBinding(binding: BackupBinding): Promise<void> {
  await writeMeta(BACKUP_BINDING_KEY, JSON.stringify(binding));
}

export async function readBackupBinding(): Promise<BackupBinding | null> {
  const raw = await readMeta(BACKUP_BINDING_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as BackupBinding;
  } catch {
    // A malformed row is not a binding. Returning null makes the caller report
    // "no restorable backup" rather than guessing at half-parsed bytes.
    return null;
  }
}

export interface CachedLockerSession {
  readonly token: string;
  readonly expiresAt: string;
  readonly base: string;
}

export interface SyncStatus {
  readonly lastError: string | null;
  readonly lastErrorClass: string | null;
  readonly lastSuccessAt: string | null;
}

const EMPTY_STATUS: SyncStatus = { lastError: null, lastErrorClass: null, lastSuccessAt: null };

async function readMeta(key: string): Promise<string | null> {
  const db = await getDb();
  const row = await db.getFirstAsync<{ value: string }>(
    'SELECT value FROM sync_meta WHERE key = ?;',
    key,
  );
  return row?.value ?? null;
}

async function writeMeta(key: string, value: string): Promise<void> {
  await withDbTransaction(async (db) => {
    await db.runAsync(
      `INSERT INTO sync_meta (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value;`,
      key,
      value,
    );
  });
}

export async function cacheLockerSession(session: CachedLockerSession): Promise<void> {
  await writeMeta(SESSION_KEY, JSON.stringify(session));
}

export async function getCachedLockerSession(): Promise<CachedLockerSession | null> {
  const raw = await readMeta(SESSION_KEY);
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as CachedLockerSession;
    if (!parsed.token || !parsed.base || !parsed.expiresAt) return null;
    if (new Date(parsed.expiresAt).getTime() <= Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

export async function getSyncStatus(): Promise<SyncStatus> {
  const raw = await readMeta(STATUS_KEY);
  if (raw === null) return EMPTY_STATUS;
  try {
    return { ...EMPTY_STATUS, ...(JSON.parse(raw) as Partial<SyncStatus>) };
  } catch {
    return EMPTY_STATUS;
  }
}

/** Merge a patch, treating `undefined` as "leave as it was" rather than as a value. */
export async function recordSyncStatus(patch: Partial<SyncStatus>): Promise<void> {
  const current = await getSyncStatus();
  const defined = Object.fromEntries(
    Object.entries(patch).filter(([, value]) => value !== undefined),
  ) as Partial<SyncStatus>;
  await writeMeta(STATUS_KEY, JSON.stringify({ ...current, ...defined }));
}
