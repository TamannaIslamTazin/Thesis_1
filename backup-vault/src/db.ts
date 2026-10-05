/**
 * R5 Phase C — the vault's storage layer. This file is where the three
 * properties from the brief actually live: operator-blindness, below-
 * threshold-by-construction, and provable erasure. Everything in server.ts
 * is plumbing around this.
 *
 * ===========================================================================
 * WHY node:sqlite AND NOT A SERVER PROCESS
 * ===========================================================================
 * This machine has ~4.2GB available and the chain validator already wants a
 * meaningful share of it. A second database SERVER (Postgres, or anything
 * with its own background workers) is a standing memory tax whether or not
 * anyone queries it. `node:sqlite` is in-process and holds ~0 memory between
 * requests — the whole "database" is a file that sits on disk. The workload
 * here is a handful of small ciphertext blobs per patient, not a relational
 * workload that needs a query planner.
 *
 * ===========================================================================
 * ERASURE: WHAT `secure_delete` ACTUALLY GUARANTEES, STATED PRECISELY
 * ===========================================================================
 * `PRAGMA secure_delete = ON` makes SQLite overwrite a deleted row's bytes
 * with zeroes on the page BEFORE freeing it, rather than merely unlinking the
 * b-tree entry and leaving the old bytes sitting in the file until the page
 * happens to be reused. Combined with journal_mode=DELETE (no long-lived
 * `-wal` file holding a second copy of recently-written pages), this is a
 * real, verifiable "the bytes in this file are gone" property.
 *
 * IT DOES NOT GUARANTEE DESTRUCTION BENEATH THE FILESYSTEM. Copy-on-write
 * filesystems, SSD wear-levelling, and filesystem or disk snapshots can all
 * retain a prior copy of the page after SQLite has zeroed its logical
 * content. This module deletes the bytes SQLite controls; it makes no claim
 * about the storage medium underneath, and nobody reading this codebase
 * should repeat "the bytes are destroyed" as an unqualified claim.
 *
 * ===========================================================================
 * THE CAP IS ONE SHARE, NOT threshold - 1 (owner amendment, correcting the
 * Phase 1 design)
 * ===========================================================================
 * DEFAULT_GUARDIAN_POLICY is 3-of-5. A cap of `threshold - 1` would let this
 * vault hold TWO of the three shares needed to reconstruct a patient's
 * recovery key — a vault compromise plus one cooperating guardian would then
 * be a full compromise, concentrated in the one component an attacker would
 * target first. `guardianShares.ts` states the actual design intent: "one
 * share institutional, so the institution is ONE VOICE AMONG SEVERAL". One
 * voice is one share. The cap below is hard-coded to 1 and does NOT scale
 * with `threshold` — `threshold` is still recorded (a policy must exist
 * before any share can be stored, and it is useful metadata), but the trigger
 * ignores its value on purpose. Widening this cap must be a deliberate,
 * reviewed change to the trigger body, not a side effect of a policy edit
 * elsewhere.
 */

import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac, randomUUID } from 'node:crypto';

export class VaultError extends Error {
  constructor(
    message: string,
    readonly httpStatus: number,
    readonly code: string,
  ) {
    super(message);
    this.name = 'VaultError';
  }
}

/** The single share slot cap. See the module docblock — this does NOT scale with threshold. */
const MAX_SHARES_PER_PATIENT = 1;

/**
 * The cap's abort message, assembled HERE in TypeScript and injected into the
 * trigger as ONE quoted SQL literal.
 *
 * ===========================================================================
 * WHY NOT `||` INSIDE RAISE() — A MEASURED PORTABILITY DEFECT
 * ===========================================================================
 * The original trigger built this message with SQL `||` concatenation inside
 * `RAISE(ABORT, ...)`. SQLite's grammar wants a string LITERAL there, and
 * tolerance for an expression varies by version. Measured 26 Aug 2026:
 *
 *   SQLite 3.50.2 (bundled in Node 22.18 `node:sqlite`) — ACCEPTED
 *   SQLite 3.45.1 (system, via Python `sqlite3`)        — `near "||": syntax error`
 *
 * Because SQLite re-parses the whole schema when a database is OPENED, one
 * unparseable trigger does not merely disable that trigger — it makes EVERY
 * table in the file unreadable. Confirmed against the live vault: `policy`,
 * `shares` AND `erasure_receipts` all returned "malformed database schema
 * (enforce_single_share_cap)" under 3.45.1.
 *
 * That is a durability defect in the one service whose entire purpose is
 * durability. The bind-mount design promises "back up the vault" means "copy
 * one file"; a file only openable by a matching-or-newer SQLite breaks that
 * promise precisely when someone reaches for standard tooling — a recovery,
 * an audit, a forensic read — which is the worst moment to discover it.
 *
 * A single literal parses identically on every version. The substring
 * 'vault already holds a share' is load-bearing: `depositShare` matches on it
 * to map the abort onto a 409, so it must survive any future edit.
 */
const SHARE_CAP_ABORT_MESSAGE =
  'vault already holds a share for this recovery controller DID; the cap is ONE ' +
  'share regardless of threshold (one guardian voice, not the recovery authority) ' +
  '-- see guardianShares.ts DEFAULT_GUARDIAN_POLICY and db.ts module docblock';

/** Single-quote a string for safe inclusion as a SQL literal. */
function sqlLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

export function openDatabase(dbPath: string): DatabaseSync {
  const db = new DatabaseSync(dbPath);

  // No long-lived WAL file holding a second copy of recently-written pages —
  // see the erasure section of the module docblock.
  db.exec('PRAGMA journal_mode = DELETE');
  // Overwrite deleted bytes with zeroes before freeing the page.
  db.exec('PRAGMA secure_delete = ON');
  // Off by default in SQLite; the policy->shares FK is load-bearing (a share
  // cannot be stored before a threshold is registered) so this must be on.
  db.exec('PRAGMA foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS policy (
      recovery_controller_did TEXT PRIMARY KEY,
      threshold               INTEGER NOT NULL,
      registered_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );

    CREATE TABLE IF NOT EXISTS shares (
      recovery_controller_did TEXT NOT NULL REFERENCES policy(recovery_controller_did),
      share_index             INTEGER NOT NULL,
      nonce                   TEXT NOT NULL,
      ciphertext              TEXT NOT NULL,
      content_hash            TEXT NOT NULL,
      stored_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (recovery_controller_did, share_index)
    );

    -- SELF-HEAL for databases created before the RAISE() literal fix. A file
    -- written by the old code carries the unparseable '||' trigger in its
    -- stored schema, and CREATE TRIGGER IF NOT EXISTS would leave it there
    -- forever. Dropping first rewrites it on the next open.
    --
    -- This can only heal a file on a runtime that can still OPEN it (SQLite
    -- >= 3.50 / Node 22.18, which is what this service runs). A file carried
    -- to an older SQLite is already unopenable and cannot be repaired there —
    -- open it once under this service to rewrite the schema, then it is
    -- portable again.
    DROP TRIGGER IF EXISTS enforce_single_share_cap;

    -- Below-threshold-by-construction. See module docblock: cap is ONE,
    -- hard-coded, independent of the threshold column. Only fires on INSERT,
    -- so re-wrapping an existing slot (UPDATE) never counts against it.
    CREATE TRIGGER IF NOT EXISTS enforce_single_share_cap
    BEFORE INSERT ON shares
    FOR EACH ROW
    WHEN (
      SELECT COUNT(*) FROM shares WHERE recovery_controller_did = NEW.recovery_controller_did
    ) >= ${MAX_SHARES_PER_PATIENT}
    BEGIN
      SELECT RAISE(ABORT, ${sqlLiteral(SHARE_CAP_ABORT_MESSAGE)});
    END;

    -- Immutable by construction: the residue record must outlive edits to
    -- itself, including edits made in response to the erasure it records.
    CREATE TABLE IF NOT EXISTS erasure_receipts (
      id                   TEXT PRIMARY KEY,
      subject_ref          TEXT NOT NULL,
      share_index          INTEGER NOT NULL,
      content_hash         TEXT NOT NULL,
      deleted_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      deleted_by_actor_ref TEXT NOT NULL,
      reason               TEXT NOT NULL
    );

    CREATE TRIGGER IF NOT EXISTS erasure_receipts_immutable_u
    BEFORE UPDATE ON erasure_receipts
    BEGIN
      SELECT RAISE(ABORT, 'erasure_receipts is append-only and cannot be updated');
    END;

    CREATE TRIGGER IF NOT EXISTS erasure_receipts_immutable_d
    BEFORE DELETE ON erasure_receipts
    BEGIN
      SELECT RAISE(ABORT, 'erasure_receipts is append-only and cannot be deleted');
    END;
  `);

  return db;
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Pseudonymises a DID for the immortal receipts table. See config.ts for the key's isolation. */
function subjectRef(recoveryControllerDid: string, pepperKey: string): string {
  return createHmac('sha256', pepperKey).update(recoveryControllerDid, 'utf8').digest('hex');
}

function isConstraintError(error: unknown, needle: string): boolean {
  return error instanceof Error && error.message.includes(needle);
}

export function registerPolicy(
  db: DatabaseSync,
  recoveryControllerDid: string,
  threshold: number,
): void {
  if (!Number.isInteger(threshold) || threshold < 2) {
    throw new VaultError(`threshold must be an integer >= 2, got ${threshold}`, 400, 'INVALID_THRESHOLD');
  }

  const existing = db
    .prepare('SELECT threshold FROM policy WHERE recovery_controller_did = ?')
    .get(recoveryControllerDid) as { threshold: number } | undefined;

  if (existing) {
    if (existing.threshold !== threshold) {
      throw new VaultError(
        `policy for this recovery controller DID is already registered with threshold ` +
          `${existing.threshold}; policy is immutable and cannot be changed to ${threshold}`,
        409,
        'POLICY_IMMUTABLE',
      );
    }
    return; // idempotent re-registration with the same value
  }

  db.prepare('INSERT INTO policy (recovery_controller_did, threshold) VALUES (?, ?)').run(
    recoveryControllerDid,
    threshold,
  );
}

export interface DepositShareInput {
  readonly recoveryControllerDid: string;
  readonly index: number;
  readonly nonce: string;
  readonly ciphertext: string;
  /** SHA-256 hex of `ciphertext`, supplied by the caller. Recomputed and checked below. */
  readonly contentHash: string;
}

/**
 * Store or re-wrap one share slot.
 *
 * Recomputes the content hash server-side (owner amendment 4) — this is a
 * transport-integrity check, not the security boundary (AES-GCM's own tag
 * covers that on decrypt), but it turns a truncated or corrupted upload into
 * a loud failure at write time instead of a silent one discovered at
 * recovery time.
 */
export function depositShare(db: DatabaseSync, input: DepositShareInput): { readonly rewrapped: boolean } {
  const actualHash = sha256Hex(input.ciphertext);
  if (actualHash !== input.contentHash) {
    throw new VaultError(
      `contentHash mismatch: caller supplied ${input.contentHash}, vault computed ${actualHash}. ` +
        'Refusing a write that does not match its own declared hash.',
      400,
      'CONTENT_HASH_MISMATCH',
    );
  }

  const existing = db
    .prepare('SELECT 1 FROM shares WHERE recovery_controller_did = ? AND share_index = ?')
    .get(input.recoveryControllerDid, input.index);

  if (existing) {
    db.prepare(
      'UPDATE shares SET nonce = ?, ciphertext = ?, content_hash = ?, ' +
        "stored_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') " +
        'WHERE recovery_controller_did = ? AND share_index = ?',
    ).run(input.nonce, input.ciphertext, actualHash, input.recoveryControllerDid, input.index);
    return { rewrapped: true };
  }

  try {
    db.prepare(
      'INSERT INTO shares (recovery_controller_did, share_index, nonce, ciphertext, content_hash) ' +
        'VALUES (?, ?, ?, ?, ?)',
    ).run(input.recoveryControllerDid, input.index, input.nonce, input.ciphertext, actualHash);
  } catch (error) {
    if (isConstraintError(error, 'vault already holds a share')) {
      throw new VaultError((error as Error).message, 409, 'SHARE_CAP_EXCEEDED');
    }
    if (isConstraintError(error, 'FOREIGN KEY constraint failed')) {
      throw new VaultError(
        `no policy registered for recovery controller DID '${input.recoveryControllerDid}'; ` +
          'register a threshold before depositing a share',
        409,
        'NO_POLICY',
      );
    }
    throw error;
  }
  return { rewrapped: false };
}

export interface StoredShare {
  readonly index: number;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly contentHash: string;
  readonly storedAt: string;
}

export function getShare(db: DatabaseSync, recoveryControllerDid: string, index: number): StoredShare | undefined {
  const row = db
    .prepare(
      'SELECT share_index, nonce, ciphertext, content_hash, stored_at FROM shares ' +
        'WHERE recovery_controller_did = ? AND share_index = ?',
    )
    .get(recoveryControllerDid, index) as
    | { share_index: number; nonce: string; ciphertext: string; content_hash: string; stored_at: string }
    | undefined;

  if (!row) return undefined;
  return {
    index: row.share_index,
    nonce: row.nonce,
    ciphertext: row.ciphertext,
    contentHash: row.content_hash,
    storedAt: row.stored_at,
  };
}

export interface ShareSummary {
  readonly index: number;
  readonly contentHash: string;
  readonly storedAt: string;
}

export function listShares(db: DatabaseSync, recoveryControllerDid: string): readonly ShareSummary[] {
  const rows = db
    .prepare(
      'SELECT share_index, content_hash, stored_at FROM shares WHERE recovery_controller_did = ? ' +
        'ORDER BY share_index',
    )
    .all(recoveryControllerDid) as Array<{ share_index: number; content_hash: string; stored_at: string }>;

  return rows.map((row) => ({ index: row.share_index, contentHash: row.content_hash, storedAt: row.stored_at }));
}

export interface ErasureReceipt {
  readonly id: string;
  readonly index: number;
  readonly contentHash: string;
  readonly deletedAt: string;
}

/**
 * Delete-and-record as one transaction (#315 applied to this table): either
 * both the share row disappears and the receipt exists, or neither happens.
 * A deleted share with no receipt is unaccountable; a receipt with the share
 * still present is a false erasure claim.
 */
export function eraseShare(
  db: DatabaseSync,
  args: {
    readonly recoveryControllerDid: string;
    readonly index: number;
    readonly deletedByActorRef: string;
    readonly reason: string;
    readonly pepperKey: string;
  },
): ErasureReceipt {
  const existing = getShare(db, args.recoveryControllerDid, args.index);
  if (!existing) {
    throw new VaultError(
      `no share at index ${args.index} for this recovery controller DID`,
      404,
      'SHARE_NOT_FOUND',
    );
  }

  const id = randomUUID();
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare('DELETE FROM shares WHERE recovery_controller_did = ? AND share_index = ?').run(
      args.recoveryControllerDid,
      args.index,
    );
    db.prepare(
      'INSERT INTO erasure_receipts (id, subject_ref, share_index, content_hash, deleted_by_actor_ref, reason) ' +
        'VALUES (?, ?, ?, ?, ?, ?)',
    ).run(
      id,
      subjectRef(args.recoveryControllerDid, args.pepperKey),
      args.index,
      existing.contentHash,
      args.deletedByActorRef,
      args.reason,
    );
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }

  const receipt = db
    .prepare('SELECT id, share_index, content_hash, deleted_at FROM erasure_receipts WHERE id = ?')
    .get(id) as { id: string; share_index: number; content_hash: string; deleted_at: string };

  return {
    id: receipt.id,
    index: receipt.share_index,
    contentHash: receipt.content_hash,
    deletedAt: receipt.deleted_at,
  };
}

/**
 * Full-patient erasure: every share slot plus the policy row itself. Same
 * one-transaction shape as `eraseShare`, extended to N shares (N is at most
 * `MAX_SHARES_PER_PATIENT`, so this is never large).
 */
export function erasePatient(
  db: DatabaseSync,
  args: {
    readonly recoveryControllerDid: string;
    readonly deletedByActorRef: string;
    readonly reason: string;
    readonly pepperKey: string;
  },
): readonly ErasureReceipt[] {
  const shares = listShares(db, args.recoveryControllerDid);
  const ref = subjectRef(args.recoveryControllerDid, args.pepperKey);
  const receiptIds: string[] = [];

  db.exec('BEGIN IMMEDIATE');
  try {
    for (const share of shares) {
      const id = randomUUID();
      receiptIds.push(id);
      db.prepare('DELETE FROM shares WHERE recovery_controller_did = ? AND share_index = ?').run(
        args.recoveryControllerDid,
        share.index,
      );
      db.prepare(
        'INSERT INTO erasure_receipts (id, subject_ref, share_index, content_hash, deleted_by_actor_ref, reason) ' +
          'VALUES (?, ?, ?, ?, ?, ?)',
      ).run(id, ref, share.index, share.contentHash, args.deletedByActorRef, args.reason);
    }
    db.prepare('DELETE FROM policy WHERE recovery_controller_did = ?').run(args.recoveryControllerDid);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }

  if (receiptIds.length === 0) return [];

  const placeholders = receiptIds.map(() => '?').join(',');
  const rows = db
    .prepare(
      `SELECT id, share_index, content_hash, deleted_at FROM erasure_receipts WHERE id IN (${placeholders})`,
    )
    .all(...receiptIds) as Array<{ id: string; share_index: number; content_hash: string; deleted_at: string }>;

  return rows.map((row) => ({
    id: row.id,
    index: row.share_index,
    contentHash: row.content_hash,
    deletedAt: row.deleted_at,
  }));
}
