/**
 * SSI Healthcare Backend — the append-only signing log (steno #277 (3), #293).
 *
 * ===========================================================================
 * WHAT THIS IS FOR
 * ===========================================================================
 * Institutional custody is 1-of-N verification methods, which means each of the
 * N is cryptographically equivalent to the whole institution (#291). There is
 * deliberately no cryptographic control preventing a single officer from acting
 * alone, so the log is the primary fraud-ATTRIBUTION mechanism: it is the only
 * thing that turns "the institution signed this" into "this key, from this
 * address, at this time, signed exactly this".
 *
 * ===========================================================================
 * THIS RECORDS INTENT. THE CHAIN WATCH RECORDS FACT. DO NOT MERGE THEM.
 * ===========================================================================
 * Everything here is written by us, about us. An attacker holding an officer
 * key never has to call this backend — they broadcast to the chain directly and
 * this file sees nothing. That is not a gap to be closed here; it is the reason
 * `chainWatch.ts` exists as an independent source, and why a chain event with
 * no entry in this log is the loudest signal the system can produce.
 *
 * ===========================================================================
 * APPEND-ONLY IS STRUCTURAL
 * ===========================================================================
 *   - This module exports no update and no delete. There is no `correctEntry`,
 *     no `redact`, no `purge`. A correction is a new entry.
 *   - The `SigningAuditEntry` table carries BEFORE UPDATE / BEFORE DELETE /
 *     BEFORE TRUNCATE triggers that raise, so the property survives a psql
 *     session, a future service, and a careless migration.
 *   - Entries are hash-chained (`hashChain.ts`), so dropping those triggers and
 *     rewriting history is detectable rather than merely discouraged.
 *
 * See the header of `hashChain.ts` for the precise limits of that guarantee —
 * in particular, it does NOT survive a database owner who recomputes the whole
 * chain, and nothing in this phase anchors the head digest externally.
 *
 * ===========================================================================
 * THE THREE-ENTRY SHAPE, AND WHY IT IS NOT ONE ROW UPDATED TWICE
 * ===========================================================================
 * A signing operation produces a SIGNING_INTENT before broadcast and then
 * exactly one of SIGNING_RESULT / SIGNING_REJECTED. The obvious design — one
 * row, updated with the txhash — is unavailable by construction, and that is a
 * feature: an INTENT with no successor is itself evidence (the process died
 * between broadcast and record), and under a single-row design that state would
 * be indistinguishable from "never broadcast".
 *
 * Both carry the same `versionId`: the uuid WE mint for the cheqd payload. It
 * appears verbatim in the on-chain `MsgUpdateDidDocPayload`, so it is the join
 * key that lets the watcher match a chain event to our intent even when the
 * process died before writing the result.
 */

import { randomUUID } from 'node:crypto';

import { db } from '../../db/index.js';
import { logger } from '../../utils/logger.js';
import { currentActorContext } from '../../utils/actorContext.js';
import { AppError } from '../../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import { SigningAuditKind, Prisma } from '../../../prisma/generated/client/index.js';
import {
  AlarmAttribution,
  AlarmKind,
  raiseAlarm,
} from './custodyAlarm.js';
import {
  computeEntryHash,
  digestPayload,
  GENESIS_PREV_HASH,
  verifyHashChain,
  type HashChainVerdict,
  type VerifiableEntry,
} from './hashChain.js';

export { SigningAuditKind };

/**
 * Postgres advisory-lock key for the log's tail.
 *
 * `seq` is part of the hashed content, so it cannot be an autoincrement the
 * database picks after the hash is computed; two concurrent appends reading the
 * same tip would fork the chain. This serialises the read-tip-then-insert
 * window. `pg_advisory_xact_lock` releases with the transaction, including on
 * rollback, so a crashed appender cannot wedge the log.
 */
const APPEND_LOCK_KEY = 0x5347_4c47; // 'SGLG'

/** Bounds memory when verifying a long log. */
const VERIFY_PAGE_SIZE = 1_000;

export interface SigningAuditContext {
  readonly subjectDid: string;
  /** `provision` | `add` | `rotate` | `retire` | … Human-meaningful, not an opcode. */
  readonly operation: string;
  /** The uuid minted for the cheqd payload. The join key to the chain. */
  readonly versionId: string;
  /** WHICH verification method is signing. Under 1-of-N this is all of attribution. */
  readonly signedByVerificationMethodId: string;
  /**
   * WHAT IS BEING AUTHORISED — the assembled document, the before/after
   * verification-method sets and the required signer set. Enough to reconstruct
   * the authorisation from the log alone. An opcode plus a DID would not be.
   */
  readonly payload: Record<string, unknown>;
}

export interface AppendedEntry {
  readonly seq: number;
  readonly entryHash: string;
  readonly correlationId: string;
}

// ---------------------------------------------------------------------------
// Append
// ---------------------------------------------------------------------------

interface AppendInput extends SigningAuditContext {
  readonly kind: SigningAuditKind;
  readonly correlationId: string;
  readonly txHash?: string | null;
  readonly height?: number | null;
  readonly failureReason?: string | null;
}

async function append(input: AppendInput): Promise<AppendedEntry> {
  const actor = currentActorContext();
  const occurredAt = new Date();
  const payloadDigest = digestPayload(input.payload);

  return db.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${APPEND_LOCK_KEY}::bigint)`;

    const tip = await tx.signingAuditEntry.findFirst({
      orderBy: { seq: 'desc' },
      select: { seq: true, entryHash: true },
    });

    const seq = (tip?.seq ?? 0) + 1;
    const prevHash = tip?.entryHash ?? GENESIS_PREV_HASH;

    const hashed = {
      seq,
      prevHash,
      kind: input.kind as string,
      correlationId: input.correlationId,
      versionId: input.versionId ?? null,
      subjectDid: input.subjectDid,
      operation: input.operation,
      signedByVerificationMethodId: input.signedByVerificationMethodId ?? null,
      payloadDigest,
      actorSource: actor.source,
      actorUserId: actor.userId ?? null,
      sourceIp: actor.sourceIp ?? null,
      userAgent: actor.userAgent ?? null,
      requestId: actor.requestId,
      txHash: input.txHash ?? null,
      height: input.height ?? null,
      failureReason: input.failureReason ?? null,
      occurredAt: occurredAt.toISOString(),
    };
    const entryHash = computeEntryHash(hashed);

    await tx.signingAuditEntry.create({
      data: {
        ...hashed,
        kind: input.kind,
        occurredAt,
        entryHash,
        payload: input.payload as Prisma.InputJsonValue,
      },
    });

    return { seq, entryHash, correlationId: input.correlationId };
  });
}

// ---------------------------------------------------------------------------
// The wrapper every signing path uses
// ---------------------------------------------------------------------------

/**
 * Log the intent, broadcast, log the outcome. The signing path calls THIS, not
 * {@link append}, so the result can never be forgotten by a new call site.
 *
 * FAIL-CLOSED ON THE INTENT. If the log cannot be written, the broadcast does
 * not happen. Under 1-of-N the log is not a report about the control — it IS
 * the control (#293), so signing with it unavailable would be signing with the
 * safety argument switched off. The exception propagates unchanged.
 *
 * FAIL-OPEN ON THE RESULT, AND THIS ASYMMETRY IS DELIBERATE. Once the ledger has
 * accepted the transaction the fact is on chain and irreversible; throwing here
 * would tell the caller their write failed and invite a retry that consumes
 * another block for nothing. So the successful result is returned and a CRITICAL
 * alarm is raised instead. The INTENT entry is already written and carries the
 * `versionId`, so the chain watch still matches the event to us rather than
 * reporting it as an outside actor.
 */
export async function recordSigningAttempt<T extends { transactionHash: string; height: number }>(
  context: SigningAuditContext,
  broadcast: () => Promise<T>,
): Promise<T> {
  const correlationId = randomUUID();

  const intent = await append({ ...context, kind: SigningAuditKind.SIGNING_INTENT, correlationId });

  logger.info('signing_audit_intent', {
    seq: intent.seq,
    correlationId,
    subjectDid: context.subjectDid,
    operation: context.operation,
    signedBy: context.signedByVerificationMethodId,
    versionId: context.versionId,
  });

  let result: T;
  try {
    result = await broadcast();
  } catch (error) {
    const failureReason = error instanceof Error ? error.message : String(error);
    try {
      await append({
        ...context,
        kind: SigningAuditKind.SIGNING_REJECTED,
        correlationId,
        failureReason,
      });
    } catch (appendError) {
      // The broadcast already failed; losing the rejection entry leaves an
      // unresolved intent, which the reconciler will surface. Do not let it
      // mask the original error.
      logger.error('signing_audit_rejection_append_failed', {
        correlationId,
        subjectDid: context.subjectDid,
        appendError: appendError instanceof Error ? appendError.message : String(appendError),
      });
    }
    throw error;
  }

  try {
    await append({
      ...context,
      kind: SigningAuditKind.SIGNING_RESULT,
      correlationId,
      txHash: result.transactionHash,
      height: result.height,
    });
  } catch (error) {
    await raiseAlarm({
      kind: AlarmKind.INTENT_UNRESOLVED,
      // UNMATCHED escalates this to CRITICAL. It is not "someone bypassed us",
      // but it has the same consequence: the log no longer states what the
      // chain did, and the headline says so explicitly.
      attribution: AlarmAttribution.UNMATCHED,
      subjectDid: context.subjectDid,
      txHash: result.transactionHash,
      height: result.height,
      signerVerificationMethodIds: [context.signedByVerificationMethodId],
      matchedAuditSeq: intent.seq,
      headline:
        `A ${context.operation} against ${context.subjectDid} WAS COMMITTED ON CHAIN ` +
        `(tx ${result.transactionHash}, height ${result.height}) but its SIGNING_RESULT entry ` +
        'could not be appended. The intent at seq ' +
        `${intent.seq} is on record and names the versionId, so this is a log-integrity ` +
        'failure rather than an outside actor — but the log is now incomplete and must not be ' +
        'read as a full record of signing.',
      detail: {
        correlationId,
        versionId: context.versionId,
        intentSeq: intent.seq,
        appendError: error instanceof Error ? error.message : String(error),
      },
    }).catch((alarmError: unknown) => {
      logger.error('signing_audit_result_alarm_failed', {
        correlationId,
        error: alarmError instanceof Error ? alarmError.message : String(alarmError),
      });
    });
  }

  logger.info('signing_audit_result', {
    correlationId,
    subjectDid: context.subjectDid,
    operation: context.operation,
    signedBy: context.signedByVerificationMethodId,
    versionId: context.versionId,
    txHash: result.transactionHash,
    height: result.height,
  });

  return result;
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

const VERIFIABLE_SELECT = {
  seq: true,
  entryHash: true,
  prevHash: true,
  kind: true,
  correlationId: true,
  versionId: true,
  subjectDid: true,
  operation: true,
  signedByVerificationMethodId: true,
  payloadDigest: true,
  actorSource: true,
  actorUserId: true,
  sourceIp: true,
  userAgent: true,
  requestId: true,
  txHash: true,
  height: true,
  failureReason: true,
  occurredAt: true,
} as const;

type StoredEntry = {
  [K in keyof typeof VERIFIABLE_SELECT]: K extends 'occurredAt'
    ? Date
    : K extends 'seq' | 'height'
      ? number | null
      : string | null;
};

function toVerifiable(row: StoredEntry): VerifiableEntry {
  return {
    seq: row.seq as number,
    entryHash: row.entryHash as string,
    prevHash: row.prevHash as string,
    kind: row.kind as string,
    correlationId: row.correlationId as string,
    versionId: row.versionId as string | null,
    subjectDid: row.subjectDid as string,
    operation: row.operation as string,
    signedByVerificationMethodId: row.signedByVerificationMethodId as string | null,
    payloadDigest: row.payloadDigest as string,
    actorSource: row.actorSource as string,
    actorUserId: row.actorUserId as string | null,
    sourceIp: row.sourceIp as string | null,
    userAgent: row.userAgent as string | null,
    requestId: row.requestId as string | null,
    txHash: row.txHash as string | null,
    height: row.height as number | null,
    failureReason: row.failureReason as string | null,
    occurredAt: (row.occurredAt as unknown as Date).toISOString(),
  };
}

/**
 * Verify the whole log and RAISE if it does not hold.
 *
 * Paged rather than loaded whole: the log grows without bound and an integrity
 * check that runs out of memory on a large log is a check that stops running
 * exactly when it starts to matter.
 */
export async function verifySigningLog(): Promise<HashChainVerdict> {
  let cursor = 0;
  let preceding: VerifiableEntry | undefined;
  const breaks: HashChainVerdict['breaks'][number][] = [];
  let entriesChecked = 0;
  let firstSeq: number | null = null;
  let lastSeq: number | null = null;
  let headDigest: string | null = null;

  for (;;) {
    const rows = (await db.signingAuditEntry.findMany({
      where: { seq: { gt: cursor } },
      orderBy: { seq: 'asc' },
      take: VERIFY_PAGE_SIZE,
      select: VERIFIABLE_SELECT,
    })) as unknown as StoredEntry[];
    if (rows.length === 0) break;

    const page = rows.map(toVerifiable);
    const verdict = verifyHashChain(page, preceding);
    breaks.push(...verdict.breaks);
    entriesChecked += verdict.entriesChecked;
    if (firstSeq === null) firstSeq = verdict.firstSeq;
    lastSeq = verdict.lastSeq;
    headDigest = verdict.headDigest;

    preceding = page[page.length - 1];
    cursor = preceding.seq;
  }

  const verdict: HashChainVerdict = {
    intact: breaks.length === 0,
    entriesChecked,
    firstSeq,
    lastSeq,
    headDigest,
    breaks,
  };

  if (!verdict.intact) {
    await raiseAlarm({
      kind: AlarmKind.AUDIT_CHAIN_TAMPERED,
      attribution: AlarmAttribution.NOT_APPLICABLE,
      detail: {
        entriesChecked,
        firstSeq,
        lastSeq,
        breaks: verdict.breaks,
        note:
          'The append-only triggers refuse UPDATE/DELETE/TRUNCATE, so reaching this state ' +
          'required DDL rights on the database.',
      },
    });
  }

  return verdict;
}

/** Intents (i.e. things this backend was about to authorise) by cheqd versionId. */
export async function findIntentByVersionId(versionId: string): Promise<{
  seq: number;
  correlationId: string;
  subjectDid: string;
  operation: string;
  signedByVerificationMethodId: string | null;
  actorSource: string;
  sourceIp: string | null;
  userAgent: string | null;
  actorUserId: string | null;
  occurredAt: Date;
} | null> {
  return db.signingAuditEntry.findFirst({
    where: { versionId, kind: SigningAuditKind.SIGNING_INTENT },
    orderBy: { seq: 'asc' },
    select: {
      seq: true,
      correlationId: true,
      subjectDid: true,
      operation: true,
      signedByVerificationMethodId: true,
      actorSource: true,
      sourceIp: true,
      userAgent: true,
      actorUserId: true,
      occurredAt: true,
    },
  });
}

export interface SigningLogPage {
  readonly entries: readonly {
    seq: number;
    entryHash: string;
    kind: SigningAuditKind;
    correlationId: string;
    versionId: string | null;
    subjectDid: string;
    operation: string;
    signedByVerificationMethodId: string | null;
    actorSource: string;
    actorUserId: string | null;
    sourceIp: string | null;
    userAgent: string | null;
    requestId: string | null;
    txHash: string | null;
    height: number | null;
    failureReason: string | null;
    payload: unknown;
    occurredAt: Date;
  }[];
  readonly headDigest: string;
}

export async function readSigningLog(options?: {
  subjectDid?: string;
  limit?: number;
}): Promise<SigningLogPage> {
  const limit = Math.min(Math.max(options?.limit ?? 100, 1), 500);
  const entries = await db.signingAuditEntry.findMany({
    where: options?.subjectDid ? { subjectDid: options.subjectDid } : undefined,
    orderBy: { seq: 'desc' },
    take: limit,
  });
  const tip = await db.signingAuditEntry.findFirst({
    orderBy: { seq: 'desc' },
    select: { entryHash: true },
  });
  return { entries, headDigest: tip?.entryHash ?? GENESIS_PREV_HASH };
}

/**
 * Guard for call sites that must not proceed without a working log.
 *
 * Not called from the signing path — {@link recordSigningAttempt} already fails
 * closed there. This exists for start-up and for the operator surface.
 */
export async function assertSigningLogIsUsable(): Promise<void> {
  try {
    await db.signingAuditEntry.count();
  } catch (error) {
    throw new AppError(
      ERROR_CODES.INTERNAL_ERROR,
      'The signing audit log is unreachable. Under 1-of-N custody it is the primary ' +
        'fraud-detection control (#293), not a report about one, so institutional signing ' +
        `must not proceed without it. Cause: ${
          error instanceof Error ? error.message : String(error)
        }`,
      503,
    );
  }
}
