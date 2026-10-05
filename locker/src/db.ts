/**
 * The locker's own small state: auth challenges, upload intents, and the
 * append-only receipt log.
 *
 * NONE OF THE USER'S BYTES ARE HERE. Objects live in MinIO; this database
 * holds only the bookkeeping that makes writes accountable. That split is why
 * the file stays tiny and why `PRAGMA secure_delete` is affordable.
 *
 * ===========================================================================
 * WHY node:sqlite AND NOT A DATABASE SERVER
 * ===========================================================================
 * Same reasoning as the Phase C vault, and measured again for this machine:
 * ~4.6GB available with a 3GB chain validator competing. An in-process store
 * holds ~0 memory between requests. The workload is a handful of rows per
 * request, not a relational one.
 *
 * ===========================================================================
 * ERASURE: WHAT `secure_delete` ACTUALLY GUARANTEES
 * ===========================================================================
 * It overwrites a deleted row's bytes with zeroes before freeing the page,
 * rather than unlinking the b-tree entry and leaving the old bytes in the
 * file. With journal_mode=DELETE there is no long-lived `-wal` holding a
 * second copy.
 *
 * IT PROMISES NOTHING BENEATH THE FILESYSTEM. Copy-on-write filesystems, SSD
 * wear-levelling, and filesystem or disk snapshots can all retain a prior copy
 * after SQLite has zeroed the logical content. This module deletes the bytes
 * SQLite controls and makes no claim about the medium underneath. The same
 * caveat applies with more force to MinIO, which is a plain filesystem tree.
 *
 * ===========================================================================
 * NO `||` INSIDE RAISE()
 * ===========================================================================
 * Every abort message below is a single literal. SQL string concatenation
 * inside `RAISE(ABORT, ...)` parses on SQLite 3.50 and is a syntax error on
 * 3.45 — and because SQLite re-parses the whole schema on OPEN, one such
 * trigger makes EVERY table in the file unreadable to older tooling. That was
 * a live defect in the Phase C vault (fixed separately); it is not being
 * inherited here.
 */

import { DatabaseSync } from 'node:sqlite';
import { createHmac, randomUUID } from 'node:crypto';

export class LockerError extends Error {
  constructor(
    message: string,
    readonly httpStatus: number,
    readonly code: string,
  ) {
    super(message);
    this.name = 'LockerError';
  }
}

export function openDatabase(dbPath: string): DatabaseSync {
  const db = new DatabaseSync(dbPath);

  db.exec('PRAGMA journal_mode = DELETE');
  db.exec('PRAGMA secure_delete = ON');
  db.exec('PRAGMA foreign_keys = ON');

  db.exec(`
    -- Auth challenges. Server-generated, single-use, short-lived.
    CREATE TABLE IF NOT EXISTS challenges (
      nonce       TEXT PRIMARY KEY,
      did         TEXT NOT NULL,
      audience    TEXT NOT NULL,
      state       TEXT NOT NULL DEFAULT 'ISSUED',
      issued_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      expires_at  TEXT NOT NULL
    );

    -- Upload intents. Written BEFORE any part is sent, so an interrupted
    -- upload leaves a countable record rather than an invisible orphan.
    CREATE TABLE IF NOT EXISTS upload_intents (
      upload_id     TEXT PRIMARY KEY,
      subject_ref   TEXT NOT NULL,
      object_key    TEXT NOT NULL,
      declared_hash TEXT NOT NULL,
      state         TEXT NOT NULL DEFAULT 'UPLOADING',
      started_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      settled_at    TEXT
    );

    -- Residue and erasure, in one immortal table. Immutable by construction:
    -- the record of what was destroyed must outlive edits to itself,
    -- including edits made in response to the destruction it records.
    -- WHERE A NEW DEVICE STARTS.
    --
    -- Objects are addressed under a pseudonymised SUBJECT, which a handset that
    -- has just been unboxed cannot compute: it knows a phone number and a
    -- passphrase and nothing else. This index maps a pseudonymised HANDLE onto
    -- the subject that owns it, so the recovery envelope can be found without
    -- first proving control of the very key it exists to restore.
    --
    -- It is written only by an AUTHENTICATED holder, on their own object. The
    -- read is unauthenticated by necessity, and the exposure that creates —
    -- anyone knowing a phone number may fetch a passphrase-sealed envelope and
    -- attempt to crack it offline — is the cost the owner accepted when the
    -- phone number was chosen as the handle (#380). It is not an oversight.
    CREATE TABLE IF NOT EXISTS recovery_index (
      handle_ref  TEXT PRIMARY KEY,
      subject_ref TEXT NOT NULL,
      did         TEXT NOT NULL,
      object_id   TEXT NOT NULL,
      -- The generation the envelope was written at. Generations start at ZERO,
      -- and the recovery lookup used to reconstruct the key with a hardcoded
      -- v1, so it missed every first write -- i.e. every newly enrolled
      -- holder, on the one path that exists for a handset that has nothing.
      generation  INTEGER NOT NULL DEFAULT 0,
      updated_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS receipts (
      id            TEXT PRIMARY KEY,
      kind          TEXT NOT NULL,
      subject_ref   TEXT NOT NULL,
      object_key    TEXT NOT NULL,
      byte_count    INTEGER NOT NULL DEFAULT 0,
      recorded_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      actor_ref     TEXT NOT NULL,
      reason        TEXT NOT NULL
    );

    CREATE TRIGGER IF NOT EXISTS receipts_immutable_u
    BEFORE UPDATE ON receipts
    BEGIN
      SELECT RAISE(ABORT, 'receipts is append-only and cannot be updated');
    END;

    CREATE TRIGGER IF NOT EXISTS receipts_immutable_d
    BEFORE DELETE ON receipts
    BEGIN
      SELECT RAISE(ABORT, 'receipts is append-only and cannot be deleted');
    END;

    CREATE INDEX IF NOT EXISTS receipts_by_subject ON receipts (subject_ref);
    CREATE INDEX IF NOT EXISTS intents_by_state ON upload_intents (state);

    -- Revoked capability jtis (OFFICER-DOCUMENT-ACCESS.md §5). Append-only,
    -- same reasoning as receipts: a revocation that could be un-inserted would
    -- let a withdrawn submission's capability start working again with no
    -- trace of that having happened. Expiry stays the backstop regardless —
    -- this table is the explicit act, not the only control.
    CREATE TABLE IF NOT EXISTS revoked_capabilities (
      subject_ref TEXT NOT NULL,
      jti         TEXT NOT NULL,
      revoked_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (subject_ref, jti)
    );

    CREATE TRIGGER IF NOT EXISTS revoked_capabilities_immutable_u
    BEFORE UPDATE ON revoked_capabilities
    BEGIN
      SELECT RAISE(ABORT, 'revoked_capabilities is append-only and cannot be updated');
    END;

    CREATE TRIGGER IF NOT EXISTS revoked_capabilities_immutable_d
    BEFORE DELETE ON revoked_capabilities
    BEGIN
      SELECT RAISE(ABORT, 'revoked_capabilities is append-only and cannot be deleted');
    END;
  `);

  return db;
}

/**
 * Pseudonymise a DID. Used for object key prefixes AND for receipt subjects,
 * so neither a bucket listing nor the immortal log carries a raw identifier.
 */
export function subjectRef(did: string, pepper: string): string {
  return createHmac('sha256', pepper).update(did, 'utf8').digest('hex');
}

/**
 * Pseudonymise a HANDLE. Domain-separated from {@link subjectRef} so the same
 * pepper cannot produce a value that is meaningful in both namespaces.
 */
export function handleRef(handle: string, pepper: string): string {
  return createHmac('sha256', pepper).update(`handle:${handle}`, 'utf8').digest('hex');
}

export interface RecoveryIndexEntry {
  readonly subjectRef: string;
  readonly did: string;
  readonly objectId: string;
  /** Generations start at 0; a lookup that assumes 1 misses every first write. */
  readonly generation: number;
}

/** Upsert: re-enrolling under the same handle replaces the pointer. */
export function putRecoveryIndex(
  db: DatabaseSync,
  entry: RecoveryIndexEntry & { readonly handleRef: string },
): void {
  db.prepare(
    `INSERT INTO recovery_index (handle_ref, subject_ref, did, object_id, generation, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(handle_ref) DO UPDATE SET
       subject_ref = excluded.subject_ref,
       did = excluded.did,
       object_id = excluded.object_id,
       generation = excluded.generation,
       updated_at = excluded.updated_at`,
  ).run(entry.handleRef, entry.subjectRef, entry.did, entry.objectId, entry.generation, Date.now());
}

export function findRecoveryIndex(
  db: DatabaseSync,
  handleRefValue: string,
): RecoveryIndexEntry | null {
  const row = db
    .prepare(
      'SELECT subject_ref, did, object_id, generation FROM recovery_index WHERE handle_ref = ?',
    )
    .get(handleRefValue) as
    | { subject_ref: string; did: string; object_id: string; generation: number }
    | undefined;
  if (!row) return null;
  return {
    subjectRef: row.subject_ref,
    did: row.did,
    objectId: row.object_id,
    generation: row.generation,
  };
}

// ---------------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------------

export interface IssuedChallenge {
  readonly nonce: string;
  readonly did: string;
  readonly audience: string;
  readonly expiresAt: string;
}

export function issueChallenge(
  db: DatabaseSync,
  args: { did: string; audience: string; nonce: string; ttlMs: number },
): IssuedChallenge {
  const expiresAt = new Date(Date.now() + args.ttlMs).toISOString();
  db.prepare('INSERT INTO challenges (nonce, did, audience, expires_at) VALUES (?, ?, ?, ?)').run(
    args.nonce,
    args.did,
    args.audience,
    expiresAt,
  );
  return { nonce: args.nonce, did: args.did, audience: args.audience, expiresAt };
}

export type ChallengeConsumption =
  | { readonly ok: true; readonly did: string; readonly audience: string }
  | { readonly ok: false; readonly reason: string };

/**
 * Spend a challenge, atomically.
 *
 * SINGLE USE BY COMPARE-AND-SWAP, the `professionalChallenge.ts` pattern: the
 * state moves out of ISSUED in ONE conditional UPDATE, and only the caller
 * that observes `changes === 1` proceeds. Two requests replaying the same
 * captured signature therefore cannot both win, which a read-then-write could
 * never promise — between its read and its write, the other request fits.
 */
export function consumeChallenge(db: DatabaseSync, nonce: string): ChallengeConsumption {
  const row = db
    .prepare('SELECT did, audience, state, expires_at FROM challenges WHERE nonce = ?')
    .get(nonce) as
    | { did: string; audience: string; state: string; expires_at: string }
    | undefined;

  if (!row) return { ok: false, reason: 'unknown challenge' };

  if (new Date(row.expires_at) <= new Date()) {
    db.prepare("UPDATE challenges SET state = 'EXPIRED' WHERE nonce = ? AND state = 'ISSUED'").run(
      nonce,
    );
    return { ok: false, reason: 'challenge expired' };
  }

  const claimed = db
    .prepare("UPDATE challenges SET state = 'SPENT' WHERE nonce = ? AND state = 'ISSUED'")
    .run(nonce);

  if (claimed.changes !== 1) {
    return { ok: false, reason: `challenge already ${row.state.toLowerCase()}` };
  }

  return { ok: true, did: row.did, audience: row.audience };
}

/** Housekeeping. Spent and expired rows carry no secret, but unbounded growth is its own defect. */
export function pruneChallenges(db: DatabaseSync, olderThanMs: number): number {
  const cutoff = new Date(Date.now() - olderThanMs).toISOString();
  return db.prepare('DELETE FROM challenges WHERE expires_at < ?').run(cutoff).changes as number;
}

// ---------------------------------------------------------------------------
// Upload intents — #315 applied to a two-phase write
// ---------------------------------------------------------------------------

export function recordUploadIntent(
  db: DatabaseSync,
  args: { uploadId: string; subjectRef: string; objectKey: string; declaredHash: string },
): void {
  db.prepare(
    'INSERT INTO upload_intents (upload_id, subject_ref, object_key, declared_hash) VALUES (?, ?, ?, ?)',
  ).run(args.uploadId, args.subjectRef, args.objectKey, args.declaredHash);
}

export function settleUploadIntent(
  db: DatabaseSync,
  uploadId: string,
  state: 'COMMITTED' | 'ABANDONED',
): void {
  db.prepare(
    "UPDATE upload_intents SET state = ?, settled_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') " +
      "WHERE upload_id = ? AND state = 'UPLOADING'",
  ).run(state, uploadId);
}

export interface OpenIntent {
  readonly uploadId: string;
  readonly subjectRef: string;
  readonly objectKey: string;
  readonly startedAt: string;
}

export function listOpenIntents(db: DatabaseSync): readonly OpenIntent[] {
  const rows = db
    .prepare(
      "SELECT upload_id, subject_ref, object_key, started_at FROM upload_intents WHERE state = 'UPLOADING'",
    )
    .all() as Array<{
    upload_id: string;
    subject_ref: string;
    object_key: string;
    started_at: string;
  }>;
  return rows.map((row) => ({
    uploadId: row.upload_id,
    subjectRef: row.subject_ref,
    objectKey: row.object_key,
    startedAt: row.started_at,
  }));
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

export type ReceiptKind = 'ERASURE' | 'ABANDONED_UPLOAD_REAPED';

export interface Receipt {
  readonly id: string;
  readonly kind: ReceiptKind;
  readonly objectKey: string;
  readonly byteCount: number;
  readonly recordedAt: string;
}

export function recordReceipt(
  db: DatabaseSync,
  args: {
    kind: ReceiptKind;
    subjectRef: string;
    objectKey: string;
    byteCount: number;
    actorRef: string;
    reason: string;
  },
): Receipt {
  const id = randomUUID();
  db.prepare(
    'INSERT INTO receipts (id, kind, subject_ref, object_key, byte_count, actor_ref, reason) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(
    id,
    args.kind,
    args.subjectRef,
    args.objectKey,
    args.byteCount,
    args.actorRef,
    args.reason,
  );

  const row = db
    .prepare('SELECT id, kind, object_key, byte_count, recorded_at FROM receipts WHERE id = ?')
    .get(id) as {
    id: string;
    kind: ReceiptKind;
    object_key: string;
    byte_count: number;
    recorded_at: string;
  };

  return {
    id: row.id,
    kind: row.kind,
    objectKey: row.object_key,
    byteCount: row.byte_count,
    recordedAt: row.recorded_at,
  };
}

export function countReceipts(db: DatabaseSync, kind: ReceiptKind): number {
  return (db.prepare('SELECT COUNT(*) c FROM receipts WHERE kind = ?').get(kind) as { c: number })
    .c;
}

// ---------------------------------------------------------------------------
// Revoked capabilities (OFFICER-DOCUMENT-ACCESS.md §5)
// ---------------------------------------------------------------------------

/**
 * Revoke a capability jti, scoped to the caller's own subjectRef.
 *
 * `INSERT OR IGNORE`: revoking twice (a retried request, or withdrawing a
 * submission whose capability was already revoked) is idempotent rather than
 * an error — the caller asked for a state, not an event, and asking for a
 * state that already holds should succeed the same way it would the first
 * time.
 */
export function revokeCapability(db: DatabaseSync, args: { subjectRef: string; jti: string }): void {
  db.prepare('INSERT OR IGNORE INTO revoked_capabilities (subject_ref, jti) VALUES (?, ?)').run(
    args.subjectRef,
    args.jti,
  );
}

export function isCapabilityRevoked(db: DatabaseSync, subjectRef: string, jti: string): boolean {
  const row = db
    .prepare('SELECT 1 FROM revoked_capabilities WHERE subject_ref = ? AND jti = ?')
    .get(subjectRef, jti);
  return row !== undefined;
}
