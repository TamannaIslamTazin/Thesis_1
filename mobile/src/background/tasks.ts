/**
 * The background task worker (expo-background-task), as the sync engine will
 * run it.
 *
 * ONE task, one job for now: record that the worker ran and reached the
 * encrypted database from a headless JS context. That last part is the real
 * assertion — no UI, no biometric prompt — and it is only possible because the
 * DB key deliberately carries no user-presence requirement (db/keys.ts). The
 * outbox drain (#453) plugs into this same executor; chunking and the per-run
 * checkpoint go in with it.
 *
 * defineTask MUST run at module scope: the OS can start the runtime with no
 * component mounted, so the task has to be registered during bundle evaluation.
 */
import * as BackgroundTask from 'expo-background-task';
import * as TaskManager from 'expo-task-manager';
import type { SQLiteDatabase } from 'expo-sqlite';
import { AppState, type AppStateStatus } from 'react-native';
import { getDb, withDbTransaction } from '../db';
import { drainOutbox } from '../db/sync/drain';

export const SYNC_TASK_NAME = 'ssi-sync-drain';

// Android's floor is 15 minutes, and the OS treats it as a minimum, not a schedule.
const MINIMUM_INTERVAL_MINUTES = 15;

/**
 * ONE object per background run, on purpose.
 *
 * The headless context stops at the network PUT (#488): the object is stored
 * and the client never resumes to commit. So the size of a run is the size of
 * what a suspension can cost. One row bounds that to a single object, and since
 * the PUT is idempotent by object id/version, a lost run costs nothing but a
 * retry. The foreground drain (#489) does the bulk work.
 */
const BACKGROUND_DRAIN_BATCH = 1;

async function ensureHeartbeatTable(db: SQLiteDatabase): Promise<void> {
  await db.execAsync(
    'CREATE TABLE IF NOT EXISTS _bg_heartbeat (id INTEGER PRIMARY KEY, ran_at TEXT NOT NULL);',
  );
}

/**
 * The drain's own result, written WITHOUT a transaction.
 *
 * WHY NOT sync_status. That is written by the drain through withDbTransaction,
 * and the whole question (#479) is whether transactional writes from the
 * headless context reach the database at all: the plain heartbeat INSERT does,
 * while the drain's BEGIN/COMMIT does not. Recording the outcome the same
 * NON-transactional way as the heartbeat makes the two separable — if a row
 * appears here and sync_status stays empty, the defect is the transaction, not
 * the context. Delete this table and its writer once #479 is answered.
 */
async function ensureDrainLogTable(db: SQLiteDatabase): Promise<void> {
  await db.execAsync(
    'CREATE TABLE IF NOT EXISTS _bg_drain_log (id INTEGER PRIMARY KEY, ran_at TEXT NOT NULL, outcome TEXT NOT NULL);',
  );
}

async function recordDrainOutcome(db: SQLiteDatabase, outcome: string): Promise<void> {
  await ensureDrainLogTable(db);
  await db.runAsync(
    'INSERT INTO _bg_drain_log (ran_at, outcome) VALUES (?, ?);',
    new Date().toISOString(),
    outcome,
  );
}

/**
 * The A/B for #479, in ONE headless run: write the same row through
 * `withDbTransaction` and see whether it settles. The heartbeat and the
 * outcome line above prove plain `runAsync` works from here, so if this row
 * never appears the transaction is the part that does not.
 *
 * The race exists so a transaction that BLOCKS rather than throws cannot wedge
 * the worker; a `tx-failed` row then names the timeout. Remove with the table.
 */
async function probeTransaction(db: SQLiteDatabase, outcome: string): Promise<void> {
  // The failing runs (06:58Z, 07:43Z) had real work, so a NETWORK call preceded
  // their transaction; the run that committed (08:00Z) had none. Reproduce that
  // shape: hit the datastore, then write twice. If the non-transactional row
  // lands after the fetch and the transactional one does not, the network leg
  // is what breaks the transaction, not the transaction itself.
  let net = 'net-skip';
  try {
    const res = await fetch('http://127.0.0.1:4540/healthz');
    net = `net-${res.status}`;
  } catch (error) {
    net = `net-err ${String(error).slice(0, 80)}`;
  }
  await recordDrainOutcome(db, `${net} ${outcome}`);

  const write = withDbTransaction(async (tx) => {
    await tx.runAsync(
      'INSERT INTO _bg_drain_log (ran_at, outcome) VALUES (?, ?);',
      new Date().toISOString(),
      `tx-after-net ${outcome}`,
    );
  });
  const settle = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error('transaction did not settle within 8s')), 8000),
  );
  try {
    await Promise.race([write, settle]);
  } catch (error) {
    await recordDrainOutcome(db, `tx-after-net-failed ${String(error).slice(0, 180)}`);
  }
}

TaskManager.defineTask(SYNC_TASK_NAME, async () => {
  try {
    const db = await getDb();
    await ensureHeartbeatTable(db);
    await db.runAsync('INSERT INTO _bg_heartbeat (ran_at) VALUES (?);', new Date().toISOString());
    console.log('[bg-task] heartbeat recorded');

    const drain = await drainOutbox(BACKGROUND_DRAIN_BATCH);
    const outcome =
      `uploaded=${drain.uploaded} failed=${drain.failed} pending=${drain.pending}` +
      (drain.skipped ? ` skipped=${drain.skipped}` : '');
    console.log(`[bg-task] drain ${outcome}`);
    await recordDrainOutcome(db, outcome);
    await probeTransaction(db, outcome);
    return BackgroundTask.BackgroundTaskResult.Success;
  } catch (error) {
    console.log(`[bg-task] failed: ${String(error)}`);
    try {
      await recordDrainOutcome(await getDb(), `threw: ${String(error).slice(0, 300)}`);
    } catch {
      // An absent row is itself an answer: it means even a plain INSERT could
      // not reach the database from here.
    }
    return BackgroundTask.BackgroundTaskResult.Failed;
  }
});

export async function registerSyncTask(): Promise<void> {
  const status = await BackgroundTask.getStatusAsync();
  if (status !== BackgroundTask.BackgroundTaskStatus.Available) {
    console.warn('[bg-task] background tasks unavailable on this device');
    return;
  }
  await BackgroundTask.registerTaskAsync(SYNC_TASK_NAME, {
    minimumInterval: MINIMUM_INTERVAL_MINUTES,
  });
  console.log('[bg-task] registered');
}

/**
 * Dev-only trigger plus a read of the previous heartbeat, so the device proof
 * is a log line AND a row that survives restarts. The trigger itself is a
 * no-op in release builds (see its own documentation).
 */
export function runBackgroundTaskProbe(): void {
  void (async () => {
    try {
      const db = await getDb();
      await ensureHeartbeatTable(db);
      const row = await db.getFirstAsync<{ ran_at: string }>(
        'SELECT ran_at FROM _bg_heartbeat ORDER BY id DESC LIMIT 1;',
      );
      console.log(`[bg-task] last heartbeat: ${row?.ran_at ?? '(none)'}`);
      const pending = await db.getFirstAsync<{ pending: number }>(
        'SELECT COUNT(*) AS pending FROM outbox;',
      );
      console.log(`[bg-task] outbox pending: ${pending?.pending ?? 0}`);
      const synced = await db.getFirstAsync<{ synced: number }>(
        'SELECT COUNT(*) AS synced FROM sync_objects;',
      );
      console.log(`[bg-task] synced objects: ${synced?.synced ?? 0}`);
      // WHY THIS IS LOGGED. A failed drain BACKS OFF on the row and records the
      // class in sync_meta (#93), but nothing surfaced either, so a drain that
      // PUTs an object and then fails its bookkeeping looked identical to one
      // that never ran. Measured 21 Sep 2026: the object landed in the locker
      // and these counts did not move.
      const errored = await db.getAllAsync<{
        object_id: string;
        attempts: number;
        last_error: string | null;
      }>('SELECT object_id, attempts, last_error FROM outbox WHERE last_error IS NOT NULL ORDER BY updated_at LIMIT 3;');
      for (const e of errored) {
        console.log(
          `[bg-task] outbox error ${e.object_id} attempts=${e.attempts}: ${String(e.last_error).slice(0, 240)}`,
        );
      }
      const meta = await db.getFirstAsync<{ value: string }>(
        "SELECT value FROM sync_meta WHERE key = 'sync_status';",
      );
      console.log(`[bg-task] sync_status: ${meta?.value ?? '(none)'}`);
      await ensureDrainLogTable(db);
      const drainLog = await db.getAllAsync<{ ran_at: string; outcome: string }>(
        'SELECT ran_at, outcome FROM _bg_drain_log ORDER BY id DESC LIMIT 3;',
      );
      if (drainLog.length === 0) console.log('[bg-task] drain log: (none)');
      for (const r of drainLog) console.log(`[bg-task] drain log: ${r.ran_at} ${r.outcome}`);
    } catch (error) {
      console.log(`[bg-task] heartbeat read failed: ${String(error)}`);
    }
    try {
      const triggered = await BackgroundTask.triggerTaskWorkerForTestingAsync();
      console.log(`[bg-task] dev trigger returned ${triggered}`);
    } catch (error) {
      console.log(`[bg-task] dev trigger failed: ${String(error)}`);
    }
  })();
}

/**
 * Drain whenever the holder brings the app to the foreground.
 *
 * WHY THIS EXISTS (#488). The background worker cannot complete the drain's
 * network PUT: the locker stores the object and the client never resumes to
 * commit the bookkeeping. Measured three times, most recently 17:58:20Z - the
 * object is in the bucket and the outbox is unchanged. The foreground path is
 * the one the backup probe proves works, and the holder is present, so this is
 * the path that actually moves the outbox. The background task stays as
 * best-effort; this is what makes progress.
 *
 * Returns an unsubscribe. Call once at startup.
 */
export function registerForegroundDrain(): () => void {
  const run = (why: string): void => {
    void drainOutbox(5)
      .then((result) =>
        console.log(
          `[fg-drain] ${why} uploaded=${result.uploaded} failed=${result.failed} ` +
            `pending=${result.pending}` +
            (result.skipped ? ` skipped=${result.skipped}` : ''),
        ),
      )
      .catch((error) => console.warn(`[fg-drain] ${why} threw: ${String(error)}`));
  };

  const subscription = AppState.addEventListener('change', (state: AppStateStatus) => {
    if (state === 'active') run('active');
  });

  // The app STARTS active and 'change' does not fire for that first state, so
  // one explicit attempt covers a cold start that still holds a cached session.
  run('startup');

  return () => subscription.remove();
}
