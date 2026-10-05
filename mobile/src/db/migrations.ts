/**
 * Schema migrations for the wallet database.
 *
 * Versioned with `PRAGMA user_version`: SQLite keeps it in the file header, it
 * survives reopens, and it needs no bookkeeping table. Each migration runs in
 * ONE transaction, so a crash mid-migration leaves the previous version intact
 * rather than a half-applied schema. (Same-connection transaction only —
 * `withExclusiveTransactionAsync` opens a connection the key never reaches,
 * see ./open.ts.)
 *
 * WHAT LIVES HERE (per #440): the per-holder tables that used to be backend
 * rows — credentials first. Consents, activity, emergency contacts and the
 * sync journal's outbox arrive WITH their first consumer; creating them now
 * would be speculative, and speculative schema is the expensive kind of rework.
 */
import type { SQLiteDatabase } from 'expo-sqlite';

interface Migration {
  readonly version: number;
  readonly statements: readonly string[];
}

const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    statements: [
      // The envelope is stored exactly as the server sent it: it is the only
      // artifact carrying the signed JWT (`credentialJwt`) needed to present
      // the credential later, and re-assembling it field by field has silently
      // dropped `credentialStatus` before (see credentialTransform.ts).
      `CREATE TABLE IF NOT EXISTS credentials (
         id TEXT PRIMARY KEY NOT NULL,
         envelope_json TEXT NOT NULL,
         updated_at INTEGER NOT NULL
       );`,
      `CREATE INDEX IF NOT EXISTS idx_credentials_updated_at ON credentials (updated_at DESC);`,
    ],
  },
  {
    version: 2,
    statements: [
      `CREATE TABLE IF NOT EXISTS consents (
         id TEXT PRIMARY KEY NOT NULL,
         record_json TEXT NOT NULL,
         updated_at INTEGER NOT NULL
       );`,
      `CREATE INDEX IF NOT EXISTS idx_consents_updated_at ON consents (updated_at DESC);`,
    ],
  },
  {
    version: 3,
    statements: [
      `CREATE TABLE IF NOT EXISTS outbox (
         object_id TEXT PRIMARY KEY NOT NULL,
         version INTEGER NOT NULL,
         updated_at INTEGER NOT NULL,
         deleted INTEGER NOT NULL DEFAULT 0,
         attempts INTEGER NOT NULL DEFAULT 0,
         next_attempt_at INTEGER NOT NULL DEFAULT 0,
         last_error TEXT
       );`,
      `CREATE INDEX IF NOT EXISTS idx_outbox_next_attempt ON outbox (next_attempt_at);`,
      `CREATE TABLE IF NOT EXISTS sync_objects (
         object_id TEXT PRIMARY KEY NOT NULL,
         version INTEGER NOT NULL,
         content_hash TEXT NOT NULL,
         uploaded_at INTEGER NOT NULL
       );`,
      `CREATE TABLE IF NOT EXISTS sync_meta (
         key TEXT PRIMARY KEY NOT NULL,
         value TEXT NOT NULL
       );`,
    ],
  },
];

export async function migrate(db: SQLiteDatabase): Promise<void> {
  const row = await db.getFirstAsync<{ user_version: number }>('PRAGMA user_version;');
  let current = row?.user_version ?? 0;

  for (const migration of MIGRATIONS) {
    if (migration.version <= current) continue;
    await db.withTransactionAsync(async () => {
      for (const statement of migration.statements) {
        await db.execAsync(statement);
      }
    });
    // PRAGMA does not accept bound parameters; the value is an integer this
    // module owns, never user input.
    await db.execAsync(`PRAGMA user_version = ${migration.version};`);
    current = migration.version;
  }
}
