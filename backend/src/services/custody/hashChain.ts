/**
 * SSI Healthcare Backend — the hash chain under the signing audit log.
 *
 * Pure. No database, no clock, no configuration. Everything here is a function
 * of its arguments, so the tamper-detection property can be exercised in
 * `tests/fast` where a stopped Postgres cannot stop it from running.
 *
 * ===========================================================================
 * WHAT THIS CHAIN PROVES, AND WHAT IT DOES NOT
 * ===========================================================================
 * Read this before relying on it for anything.
 *
 * IT PROVES: no entry can be altered, removed, or inserted in the middle of the
 * log without invalidating every `entryHash` from that point onward. Detecting
 * that costs one linear pass ({@link verifyHashChain}). Combined with the
 * database trigger that refuses UPDATE/DELETE/TRUNCATE on the table, silently
 * editing history requires DDL rights AND a full recomputation of the tail.
 *
 * IT DOES NOT PROVE:
 *
 *   1. That the log is complete. An attacker who never called this backend
 *      leaves no entry to tamper with, and a perfect hash chain over an empty
 *      log verifies happily. This is the whole reason the chain watch exists as
 *      a SEPARATE source: a `MsgUpdateDidDoc` with no audit entry is a finding,
 *      and no property of this file could ever have surfaced it.
 *
 *   2. That the log is honest. Whoever can append can append a lie. The entries
 *      record what this process believed it was authorising; they are not
 *      evidence about the world.
 *
 *   3. That history was not rewritten WHOLESALE. A holder of the database who
 *      recomputes every hash from the genesis entry produces a chain that
 *      verifies. Only an anchor held outside this database — the head digest
 *      countersigned elsewhere, written to the ledger, or shipped to an
 *      append-only sink another party controls — closes that gap.
 *      {@link headDigest} exists so such an anchor can be added later without
 *      reshaping the log. NOTHING IN THIS PHASE ANCHORS IT. Do not describe the
 *      log as immutable; it is tamper-EVIDENT against everyone except the
 *      database owner.
 *
 *   4. Anything about time. `occurredAt` is a claim by the writer.
 */

import { createHash } from 'node:crypto';

/**
 * `prevHash` of the first entry. A recognisable constant rather than an empty
 * string, so "this is the genesis entry" and "prevHash was lost" cannot look
 * the same to a reader or to {@link verifyHashChain}.
 */
export const GENESIS_PREV_HASH = 'GENESIS' as const;

/** The fields that are bound into `entryHash`. Everything a reader must trust. */
export interface HashChainedFields {
  readonly seq: number;
  readonly prevHash: string;
  readonly kind: string;
  readonly correlationId: string;
  readonly versionId: string | null;
  readonly subjectDid: string;
  readonly operation: string;
  readonly signedByVerificationMethodId: string | null;
  readonly payloadDigest: string;
  readonly actorSource: string;
  readonly actorUserId: string | null;
  readonly sourceIp: string | null;
  readonly userAgent: string | null;
  readonly requestId: string | null;
  readonly txHash: string | null;
  readonly height: number | null;
  readonly failureReason: string | null;
  /** ISO 8601, millisecond precision, UTC. */
  readonly occurredAt: string;
}

/**
 * Deterministic JSON: object keys sorted at every depth.
 *
 * `JSON.stringify` preserves insertion order, so two structurally identical
 * payloads built by different code paths would otherwise hash differently and
 * a legitimate entry would read as tampered.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value instanceof Date) return JSON.stringify(value.toISOString());

  const entries = Object.entries(value as Record<string, unknown>)
    // `undefined` disappears under JSON.stringify; dropping it here keeps the
    // digest of `{a:1}` and `{a:1,b:undefined}` equal, which is what a reader
    // comparing a re-serialised payload expects.
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/** Digest of the authorised payload, so a truncated `payload` column is detectable. */
export function digestPayload(payload: unknown): string {
  return sha256Hex(canonicalJson(payload));
}

/**
 * The entry's hash.
 *
 * Field names are included, not just values, so that moving a value from one
 * field to another (say, `sourceIp` into `userAgent`) changes the digest.
 *
 * EVERY FIELD IS PROJECTED EXPLICITLY rather than spread. Spreading looked
 * equivalent and was not: callers pass a whole stored row here — which carries
 * `entryHash` and `payload` and `recordedAt` — so a spread hashed a different
 * object at verification time than at write time and NOTHING would ever
 * re-verify. Adding a field to {@link HashChainedFields} must be a deliberate
 * edit to this list, and the compiler will say so.
 */
export function computeEntryHash(fields: HashChainedFields): string {
  return sha256Hex(
    canonicalJson({
      v: 1,
      seq: fields.seq,
      prevHash: fields.prevHash,
      kind: fields.kind,
      correlationId: fields.correlationId,
      versionId: fields.versionId,
      subjectDid: fields.subjectDid,
      operation: fields.operation,
      signedByVerificationMethodId: fields.signedByVerificationMethodId,
      payloadDigest: fields.payloadDigest,
      actorSource: fields.actorSource,
      actorUserId: fields.actorUserId,
      sourceIp: fields.sourceIp,
      userAgent: fields.userAgent,
      requestId: fields.requestId,
      txHash: fields.txHash,
      height: fields.height,
      failureReason: fields.failureReason,
      occurredAt: fields.occurredAt,
    }),
  );
}

export interface HashChainBreak {
  readonly seq: number;
  readonly reason:
    | 'sequence-gap'
    | 'wrong-genesis-prev-hash'
    | 'prev-hash-mismatch'
    | 'entry-hash-mismatch';
  readonly detail: string;
}

export interface HashChainVerdict {
  readonly intact: boolean;
  readonly entriesChecked: number;
  readonly firstSeq: number | null;
  readonly lastSeq: number | null;
  readonly headDigest: string | null;
  readonly breaks: readonly HashChainBreak[];
}

export interface VerifiableEntry extends HashChainedFields {
  readonly entryHash: string;
}

/**
 * Walk the chain and report EVERY break, not the first.
 *
 * Returning only the first break would let a reader repair one row, re-run, and
 * conclude the log is now sound while the rest of the damage is still there —
 * the same "first unsatisfied signer" trap `assertSignersCoverRequiredSet`
 * exists to avoid on the ledger side.
 *
 * `entries` must be ordered by `seq` ascending. Pass `precedingEntry` to verify
 * a PAGE of a long log: it is the entry immediately before `entries[0]`, and it
 * is what keeps a paged verification from reporting a false break at every page
 * boundary. Omit it only when `entries[0]` really is the genesis entry.
 */
export function verifyHashChain(
  entries: readonly VerifiableEntry[],
  precedingEntry?: VerifiableEntry,
): HashChainVerdict {
  const breaks: HashChainBreak[] = [];
  let previous: VerifiableEntry | null = precedingEntry ?? null;

  for (const entry of entries) {
    if (previous === null) {
      if (entry.prevHash !== GENESIS_PREV_HASH) {
        breaks.push({
          seq: entry.seq,
          reason: 'wrong-genesis-prev-hash',
          detail:
            `the first entry carries prevHash '${entry.prevHash}' instead of ` +
            `'${GENESIS_PREV_HASH}'. Either entries before it were removed, or this is not ` +
            'the head of the log.',
        });
      }
    } else {
      if (entry.seq !== previous.seq + 1) {
        breaks.push({
          seq: entry.seq,
          reason: 'sequence-gap',
          detail: `seq jumps ${previous.seq} → ${entry.seq}; ${
            entry.seq - previous.seq - 1
          } entries are missing.`,
        });
      }
      if (entry.prevHash !== previous.entryHash) {
        breaks.push({
          seq: entry.seq,
          reason: 'prev-hash-mismatch',
          detail:
            `prevHash '${entry.prevHash}' does not match seq ${previous.seq}'s entryHash ` +
            `'${previous.entryHash}'.`,
        });
      }
    }

    const recomputed = computeEntryHash(entry);
    if (recomputed !== entry.entryHash) {
      breaks.push({
        seq: entry.seq,
        reason: 'entry-hash-mismatch',
        detail:
          `stored entryHash '${entry.entryHash}' but the fields hash to '${recomputed}'. This ` +
          'entry was altered after it was written.',
      });
    }

    previous = entry;
  }

  return {
    intact: breaks.length === 0,
    entriesChecked: entries.length,
    firstSeq: entries.length > 0 ? entries[0].seq : null,
    lastSeq: previous ? previous.seq : null,
    headDigest: previous ? previous.entryHash : null,
    breaks,
  };
}

/**
 * The single value that commits to the entire log.
 *
 * This is the value to anchor externally when someone builds that (see the
 * header, point 3). Publishing it periodically is what would upgrade this log
 * from "tamper-evident to anyone but the DB owner" to "tamper-evident, full
 * stop". Deliberately not done here.
 */
export function headDigest(entries: readonly VerifiableEntry[]): string {
  return entries.length === 0 ? GENESIS_PREV_HASH : entries[entries.length - 1].entryHash;
}
