/**
 * The sync journal (outbox), per #453.
 *
 * Every local write that must eventually reach the holder's locker lands here
 * IN THE SAME TRANSACTION as the write itself — a journal entry that can
 * diverge from the row it describes is worse than no journal, because the
 * drain would upload state the database never held.
 *
 * COALESCING: one row per object, latest state wins. The drain reads the live
 * payload from its own table at upload time, so the outbox stores a pointer
 * (object id + version + updated_at), never a copy. A burst of edits to one
 * consent produces one pending upload, not one per keystroke.
 *
 * TOMBSTONES: `deleted` marks a remove that must reach the locker before the
 * row disappears locally. No delete path enqueues one yet — the only deletes
 * today are whole-table wipes (logout), which are deliberate local-only
 * resets; the column and its contract exist so the first per-object delete
 * cannot be written without noticing this file.
 *
 * RETRY STATE lives on the row: `attempts` and `next_attempt_at` implement
 * bounded exponential backoff, and a per-run checkpoint in `sync_meta` bounds
 * how much one background execution processes (see the worker's executor).
 */
import type { SQLiteDatabase } from 'expo-sqlite';

export interface OutboxEntry {
  readonly object_id: string;
  readonly version: number;
  readonly updated_at: number;
  readonly deleted: number;
  readonly attempts: number;
  readonly next_attempt_at: number;
}

/**
 * Mark an object as needing upload. Call INSIDE the write's transaction, with
 * the same db handle — see the module header.
 *
 * `version` is the write's millisecond timestamp, which doubles as the LWW
 * clock: the drain compares (updatedAt, deviceId) when reconciling against a
 * remote manifest, matching #453.
 */
export async function enqueueObject(
  db: SQLiteDatabase,
  objectId: string,
  version: number,
): Promise<void> {
  await db.runAsync(
    `INSERT INTO outbox (object_id, version, updated_at, deleted, attempts, next_attempt_at)
     VALUES (?, ?, ?, 0, 0, 0)
     ON CONFLICT(object_id) DO UPDATE SET
       version = excluded.version,
       updated_at = excluded.updated_at,
       deleted = 0,
       attempts = 0,
       next_attempt_at = 0,
       last_error = NULL;`,
    objectId,
    version,
    version,
  );
}

export async function countPendingObjects(): Promise<number> {
  const { getDb } = await import('../open');
  const db = await getDb();
  const row = await db.getFirstAsync<{ pending: number }>(
    'SELECT COUNT(*) AS pending FROM outbox;',
  );
  return row?.pending ?? 0;
}
