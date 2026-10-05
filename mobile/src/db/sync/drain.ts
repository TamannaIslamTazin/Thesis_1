/**
 * The outbox drain: bounded, resumable, and classified (#90 / #93).
 *
 * WHAT IT DOES NOT DO: conflict resolution. The drain uploads the LOCAL latest
 * state of each object, sealed, and records what landed. Union-merge (#90 —
 * credential status by severity REVOKED > EXPIRED > SUSPENDED > ACTIVE,
 * consent withdrawal always winning) is a RESTORE-side decision: it needs two
 * replicas to merge, and there is only one here. What the drain must never do
 * is lose a revocation, and it does not: it uploads whatever the local row
 * says, including REVOKED, and the version/hash binding makes that object
 * verifiable on the far side.
 *
 * FAILURE CLASSES (#93) are persisted, not just logged: quota, auth-revoked,
 * object-gone, network and unknown each back off on the row and land in
 * sync_status so a banner can name the specific cause and the last success.
 *
 * AUTH IS THE HARD EDGE. The locker session needs a device-key signature, and
 * that key is user-presence gated; a background run cannot prompt. The drain
 * therefore uses the foreground-cached session (state.ts) and, when there is
 * none, returns `auth-unavailable` without touching the outbox — the rows stay
 * queued for the next run after the holder next opens the app.
 */
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { sealSyncObject, type SyncObjectBinding } from '@ssi-healthcare/shared';
import type { SQLiteDatabase } from 'expo-sqlite';
import { getDb, withDbTransaction } from '../open';
import { getOrCreateLockerKek } from '../../services/lockerKek';
import { LockerClientError, putLockerObject } from '../../services/lockerClient';
import { secureStorage } from '../../services/secureStorage';
import { getCachedLockerSession, recordSyncStatus } from './state';

export type FailureClass =
  | 'network'
  | 'auth-unavailable'
  | 'auth-revoked'
  | 'quota'
  | 'object-gone'
  | 'unknown';

export interface DrainResult {
  readonly uploaded: number;
  readonly failed: number;
  readonly pending: number;
  readonly skipped: FailureClass | null;
}

const BASE_BACKOFF_MS = 30_000;
const MAX_BACKOFF_MS = 60 * 60 * 1000;

interface DueRow {
  readonly object_id: string;
  readonly version: number;
  readonly attempts: number;
}

function classify(error: unknown): FailureClass {
  if (error instanceof LockerClientError) {
    const status = Number(/status (\d{3})/.exec(error.message)?.[1] ?? 0);
    if (status === 401 || status === 403) return 'auth-revoked';
    if (status === 402 || status === 413) return 'quota';
    if (status === 404) return 'object-gone';
    return 'unknown';
  }
  if (error instanceof TypeError || /network request failed|fetch failed|aborted/i.test(String(error))) {
    return 'network';
  }
  return 'unknown';
}

async function readPayload(db: SQLiteDatabase, objectId: string): Promise<Uint8Array | null> {
  const separator = objectId.indexOf(':');
  if (separator <= 0) return null;
  const namespace = objectId.slice(0, separator);
  const id = objectId.slice(separator + 1);

  if (namespace === 'credential') {
    const row = await db.getFirstAsync<{ envelope_json: string }>(
      'SELECT envelope_json FROM credentials WHERE id = ?;',
      id,
    );
    return row ? new TextEncoder().encode(row.envelope_json) : null;
  }
  if (namespace === 'consent') {
    const row = await db.getFirstAsync<{ record_json: string }>(
      'SELECT record_json FROM consents WHERE id = ?;',
      id,
    );
    return row ? new TextEncoder().encode(row.record_json) : null;
  }
  return null;
}

async function countPending(): Promise<number> {
  const db = await getDb();
  const row = await db.getFirstAsync<{ pending: number }>('SELECT COUNT(*) AS pending FROM outbox;');
  return row?.pending ?? 0;
}

export async function drainOutbox(limit = 20): Promise<DrainResult> {
  const pendingBefore = await countPending();

  const subjectRef = await secureStorage.getUserDid();
  if (!subjectRef) {
    return { uploaded: 0, failed: 0, pending: pendingBefore, skipped: 'auth-unavailable' };
  }

  const session = await getCachedLockerSession();
  if (session === null) {
    await recordSyncStatus({
      lastErrorClass: 'auth-unavailable',
      lastError: 'no locker session; open the app to sign one',
    });
    return { uploaded: 0, failed: 0, pending: pendingBefore, skipped: 'auth-unavailable' };
  }

  const kek = await getOrCreateLockerKek();
  const db = await getDb();
  const due = await db.getAllAsync<DueRow>(
    'SELECT object_id, version, attempts FROM outbox WHERE next_attempt_at <= ? ORDER BY updated_at LIMIT ?;',
    Date.now(),
    limit,
  );

  let uploaded = 0;
  let failed = 0;
  let lastClass: FailureClass | null = null;

  for (const row of due) {
    const payload = await readPayload(db, row.object_id);
    if (payload === null) {
      // No local row (or an unknown namespace): drop the entry rather than retry
      // forever. The next write to that object re-enqueues it.
      await withDbTransaction(async (tx) => {
        await tx.runAsync('DELETE FROM outbox WHERE object_id = ?;', row.object_id);
      });
      continue;
    }

    const contentHash = bytesToHex(sha256(payload));
    const binding: SyncObjectBinding = {
      subjectRef,
      objectId: row.object_id,
      version: row.version,
      contentHash,
    };

    try {
      const sealed = sealSyncObject(kek, binding, payload);
      await putLockerObject(session.base, session.token, row.object_id, sealed);
      await withDbTransaction(async (tx) => {
        await tx.runAsync(
          `INSERT INTO sync_objects (object_id, version, content_hash, uploaded_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(object_id) DO UPDATE SET
             version = excluded.version,
             content_hash = excluded.content_hash,
             uploaded_at = excluded.uploaded_at;`,
          row.object_id,
          row.version,
          contentHash,
          Date.now(),
        );
        await tx.runAsync('DELETE FROM outbox WHERE object_id = ?;', row.object_id);
      });
      uploaded += 1;
    } catch (error) {
      const failureClass = classify(error);
      lastClass = failureClass;
      const attempts = row.attempts + 1;
      const delay = Math.min(BASE_BACKOFF_MS * 2 ** attempts, MAX_BACKOFF_MS);
      const jitter = Math.floor(Math.random() * delay * 0.1);
      await withDbTransaction(async (tx) => {
        await tx.runAsync(
          'UPDATE outbox SET attempts = ?, next_attempt_at = ?, last_error = ? WHERE object_id = ?;',
          attempts,
          Date.now() + delay + jitter,
          `${failureClass}: ${String(error).slice(0, 300)}`,
          row.object_id,
        );
      });
      failed += 1;
    }
  }

  await recordSyncStatus({
    lastError: failed > 0 ? `${failed} object(s) failed (${lastClass})` : null,
    lastErrorClass: failed > 0 ? lastClass : null,
    lastSuccessAt: uploaded > 0 ? new Date().toISOString() : undefined,
  });

  return { uploaded, failed, pending: await countPending(), skipped: null };
}
