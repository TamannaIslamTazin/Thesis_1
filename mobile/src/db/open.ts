/**
 * The wallet's encrypted database connection.
 *
 * One SQLCipher database (expo-sqlite with the `useSQLCipher: true` plugin
 * option, app.json) opened once per app run. The order of operations in
 * `openAndMigrate` is load-bearing:
 *
 *   1. `PRAGMA key` BEFORE any read or migration, per the SQLCipher docs.
 *   2. `PRAGMA cipher_version` must return a value. If the installed build was
 *      compiled WITHOUT SQLCipher (plugin change not rebuilt), the pragma is
 *      empty and everything else would still WORK — on a plaintext file. That
 *      fail-open is what this check exists to stop.
 *   3. A schema read (done by migrate) proves the key actually opens THIS
 *      file: a wrong key fails with SQLITE_NOTADB, it does not return empty
 *      results.
 *
 * TRAP, from expo-sqlite's own docs: `withExclusiveTransactionAsync()` opens a
 * SEPARATE connection which gets no key. Do not use it on this database;
 * `withTransactionAsync()` is same-connection and is what migrations use.
 */
import * as SQLite from 'expo-sqlite';
import { DbKeyError, getOrCreateDbKeyHex } from './keys';
import { migrate } from './migrations';

export class SqlCipherUnavailableError extends Error {}

const DB_NAME = 'ssi_health.db';
const KEY_HEX = /^[0-9a-f]{64}$/;

let dbPromise: Promise<SQLite.SQLiteDatabase> | null = null;

/**
 * The one open handle. Concurrent callers share the in-flight promise; a
 * failure clears it so the next call retries instead of caching the failure.
 */
export async function getDb(): Promise<SQLite.SQLiteDatabase> {
  if (dbPromise === null) {
    dbPromise = openAndMigrate().catch((error: unknown) => {
      dbPromise = null;
      throw error;
    });
  }
  return dbPromise;
}

async function openAndMigrate(): Promise<SQLite.SQLiteDatabase> {
  const keyHex = await getOrCreateDbKeyHex();
  // `PRAGMA key` does not accept bound parameters (SQLCipher docs), so the
  // value is interpolated — safe only because it is a hex string this process
  // generated. Re-checked here so no future caller can widen it.
  if (!KEY_HEX.test(keyHex)) {
    throw new DbKeyError('database key is not 32 hex-encoded bytes');
  }

  const db = await SQLite.openDatabaseAsync(DB_NAME);
  await db.execAsync(`PRAGMA key = "x'${keyHex}'";`);

  const rows = await db.getAllAsync<Record<string, unknown>>('PRAGMA cipher_version;');
  const cipherVersion = rows.length > 0 ? String(Object.values(rows[0])[0] ?? '') : '';
  if (cipherVersion === '') {
    await db.closeAsync();
    throw new SqlCipherUnavailableError(
      'SQLCipher is not active in this build; refusing to open the wallet database unencrypted',
    );
  }

  await db.execAsync('PRAGMA journal_mode = WAL;');
  await db.execAsync('PRAGMA foreign_keys = ON;');
  await migrate(db);
  return db;
}

/**
 * Serialize transactions across the whole app.
 *
 * expo-sqlite runs every statement on ONE shared connection, and
 * `withTransactionAsync` is BEGIN…COMMIT on that connection. Two concurrent
 * callers therefore interleave: the second BEGIN lands inside the first
 * transaction, and the first ROLLBACK then finds no active transaction
 * ("cannot rollback - no transaction is active") — which is exactly how the
 * consent mirror lost its first device write while the credential mirror was
 * committing next to it. Every writer goes through this queue; reads do not.
 * Do NOT nest calls: `work` runs inside the queue, so a nested call deadlocks.
 *
 * `withExclusiveTransactionAsync` is NOT a fix: it opens a separate
 * connection that never received the SQLCipher key (see the module header).
 */
let txQueue: Promise<void> = Promise.resolve();

export async function withDbTransaction<T>(
  work: (db: SQLite.SQLiteDatabase) => Promise<T>,
): Promise<T> {
  const previous = txQueue;
  let release!: () => void;
  txQueue = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous;
  try {
    const db = await getDb();
    let result!: T;
    await db.withTransactionAsync(async () => {
      result = await work(db);
    });
    return result;
  } finally {
    release();
  }
}

export async function closeDb(): Promise<void> {
  if (dbPromise === null) return;
  const db = await dbPromise;
  await db.closeAsync();
  dbPromise = null;
}
