/**
 * SSI Healthcare Backend — reconciling intent against fact.
 *
 * Two independent records, deliberately kept independent: `SigningAuditEntry`
 * is what this backend believed it was authorising, `ObservedDidTx` is what the
 * chain actually did. Disagreement in EITHER direction is a finding, and the
 * two directions mean very different things:
 *
 *   CHAIN WITHOUT LOG — a `MsgUpdateDidDoc` or `MsgDeactivateDidDoc` against a
 *   watched DID that no signing intent accounts for. Somebody exercised an
 *   officer key without going through us. This is the threat S-4 measured
 *   (#291) and it is raised INLINE by `chainWatch.ts` the moment the event is
 *   observed, never on this sweep — waiting for a periodic job would spend the
 *   only window the other officers have. Nothing in this file can downgrade it.
 *
 *   LOG WITHOUT CHAIN — we recorded a completed broadcast the watcher never
 *   saw. Either the write did not take effect (and something downstream is
 *   acting on a change that does not exist), or the watcher is pointed at a
 *   different chain from the one we write to. The second possibility is the
 *   dangerous one, because it makes every quiet alarm list meaningless.
 *
 * This module owns the second direction plus the unresolved-intent sweep. It
 * NEVER "reconciles away" a mismatch by writing one side to match the other.
 *
 * ===========================================================================
 * FAILSAFE FIRST (#302) — WHAT THIS DOES WHEN IT ITSELF FAILS
 * ===========================================================================
 * A sweep is exactly the kind of component that fails quietly and keeps
 * reporting green, so the failure path is specified rather than left to
 * whatever the exception does:
 *
 *   1. PER-ENTRY FAULT ISOLATION. One entry that cannot be checked does not
 *      abandon the remaining entries. Previously a single failed query on
 *      entry 3 of 500 propagated out and left 497 unexamined with nothing
 *      recording that they were unexamined — a sweep that had not run looked
 *      identical to one that found nothing.
 *
 *   2. A FAILED CHECK IS AN UNKNOWN, NOT A PASS. Every entry that could not be
 *      examined is counted in `checksFailed` and forces `complete: false`.
 *      "Clean" and "could not tell" are different values.
 *
 *   3. DE-DUPLICATION FAILS TOWARD RAISING. If the "is this already open"
 *      query errors, the alarm is raised anyway. A duplicate alarm costs an
 *      operator ten seconds; a suppressed one costs the institution. This is
 *      the direction that matters most in this file — getting it wrong toward
 *      "assume it matched" would defeat the whole component.
 *
 *   4. RESIDUE IS COUNTABLE AND SURFACED. `skippedOutsideWatchWindow`,
 *      `skippedBecauseWatchIsBehind`, `suppressedAsAlreadyOpen` and
 *      `checksFailed` are all reported, and `complete` is false whenever any
 *      of them is non-zero. `GET /api/custody/status` shows them, so an
 *      operator cannot read an empty findings list as an all-clear when part
 *      of the ledger was never examined.
 */

import { db } from '../../db/index.js';
import { logger } from '../../utils/logger.js';
import { SigningAuditKind } from '../../../prisma/generated/client/index.js';
import { AlarmAttribution, AlarmKind, raiseAlarm } from './custodyAlarm.js';

/**
 * How long after an intent we stop expecting its result.
 *
 * Generous on purpose: a DID write waits for a committed block, and calling a
 * slow-but-healthy broadcast "unresolved" is how an alarm channel gets ignored.
 */
const INTENT_GRACE_MS = 5 * 60_000;

export interface ReconciliationReport {
  /**
   * False whenever ANY entry was skipped, suppressed or unexaminable.
   *
   * The single field a caller should branch on. An empty `broadcastsNotOnChain`
   * with `complete: false` means "found nothing in the part I could see", which
   * is a different statement from "found nothing".
   */
  readonly complete: boolean;
  readonly checkedResults: number;
  readonly checkedIntents: number;
  readonly broadcastsNotOnChain: readonly string[];
  readonly unresolvedIntents: readonly string[];
  readonly watchCursorHeight: number | null;
  /** Written at a height the watcher has not reached. Not a finding yet. */
  readonly skippedBecauseWatchIsBehind: number;
  /** Written outside the window the watcher can honestly speak about. */
  readonly skippedOutsideWatchWindow: number;
  /** Already-open alarms for the same fact, not raised a second time. */
  readonly suppressedAsAlreadyOpen: number;
  /** Entries that could not be examined at all. An unknown, never a pass. */
  readonly checksFailed: number;
}

/**
 * Sweep the log-without-chain direction.
 *
 * ONLY EXAMINES ENTRIES THE WATCHER HAS ALREADY PASSED. An entry written at
 * height H is not missing until the watcher has scanned H; checking sooner
 * would raise a CRITICAL alarm for every write made while the watcher was
 * catching up, which is both wrong and the fastest way to make the channel
 * worthless.
 */
export async function reconcileLogAgainstChain(): Promise<ReconciliationReport> {
  const cursor = await db.chainWatchCursor.findUnique({ where: { id: 'default' } });
  const cursorHeight = cursor?.lastScannedHeight ?? null;

  if (cursorHeight === null) {
    logger.warn('custody_reconciliation_skipped', {
      reason: 'no chain-watch cursor exists yet, so nothing has been observed to compare against',
      consequence:
        'This is NOT an all-clear. Nothing was compared, and `complete` is false to say so.',
    });
    return {
      complete: false,
      checkedResults: 0,
      checkedIntents: 0,
      broadcastsNotOnChain: [],
      unresolvedIntents: [],
      watchCursorHeight: null,
      skippedBecauseWatchIsBehind: 0,
      skippedOutsideWatchWindow: 0,
      suppressedAsAlreadyOpen: 0,
      checksFailed: 0,
    };
  }

  const watchedRows = await db.watchedInstitutionalDid.findMany({
    select: { did: true, watchedFromHeight: true },
  });
  const watched = new Set(watchedRows.map((row) => row.did));
  const armedAt = new Map(watchedRows.map((row) => [row.did, row.watchedFromHeight]));

  /**
   * The window the watcher can honestly speak about.
   *
   * Below `startedFromHeight` it never looked, and at or below a DID's own
   * `watchedFromHeight` the arming had not completed — the create transaction
   * sits exactly there. Accusing a write in either range of "never reached the
   * chain" says more about our coverage than about the ledger, and it fired on
   * every single provisioning until this guard existed.
   *
   * The floor is a LIMIT ON WHAT THIS SWEEP CAN CLAIM, not a blind spot in the
   * alarm: the inline chain watch still alarms on anything at or below it that
   * it actually observed. Everything excluded here is counted.
   */
  const coverageFloor = (did: string): number =>
    Math.max(cursor?.startedFromHeight ?? 0, armedAt.get(did) ?? 0);

  const broadcastsNotOnChain: string[] = [];
  const unresolvedIntents: string[] = [];
  let skippedBecauseWatchIsBehind = 0;
  let skippedOutsideWatchWindow = 0;
  let suppressedAsAlreadyOpen = 0;
  let checksFailed = 0;

  // --- log without chain -------------------------------------------------
  const results = await db.signingAuditEntry.findMany({
    where: { kind: SigningAuditKind.SIGNING_RESULT, subjectDid: { in: [...watched] } },
    select: { seq: true, subjectDid: true, versionId: true, txHash: true, height: true },
    orderBy: { seq: 'asc' },
  });

  for (const result of results) {
    try {
      if (result.height !== null && result.height > cursorHeight) {
        skippedBecauseWatchIsBehind += 1;
        continue;
      }
      if (result.height !== null && result.height <= coverageFloor(result.subjectDid)) {
        skippedOutsideWatchWindow += 1;
        continue;
      }

      const observed = await db.observedDidTx.findFirst({
        where: result.txHash
          ? { txHash: result.txHash }
          : { versionId: result.versionId ?? '__no-version-id__' },
        select: { id: true },
      });
      if (observed) continue;

      broadcastsNotOnChain.push(result.txHash ?? `seq:${result.seq}`);

      // A sweep that re-raises what is already open turns a standing finding
      // into a stream, and a stream is what an operator learns to scroll past.
      if (await alarmAlreadyOpen(AlarmKind.BROADCAST_NOT_ON_CHAIN, result.seq)) {
        suppressedAsAlreadyOpen += 1;
        continue;
      }

      await raiseAlarm({
        kind: AlarmKind.BROADCAST_NOT_ON_CHAIN,
        // Not a chain event at all — there is nothing on chain to attribute.
        attribution: AlarmAttribution.NOT_APPLICABLE,
        subjectDid: result.subjectDid,
        txHash: result.txHash,
        height: result.height,
        // The identity of this finding, and what de-duplication keys on. It was
        // absent once, which made the txhash-less branch of `alarmAlreadyOpen`
        // unmatchable and re-raised such results on every single sweep.
        matchedAuditSeq: result.seq,
        detail: {
          auditSeq: result.seq,
          versionId: result.versionId,
          watchCursorHeight: cursorHeight,
          note:
            'The watcher has scanned past this height and never observed this transaction. ' +
            'Check that the watcher and the signing path address the same chain before ' +
            'concluding the write failed.',
        },
      });
    } catch (error) {
      // One unexaminable entry must not abandon the rest of the sweep, and must
      // not be silently counted as clean.
      checksFailed += 1;
      logger.error('custody_reconciliation_check_failed', {
        auditSeq: result.seq,
        subjectDid: result.subjectDid,
        direction: 'log-without-chain',
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // --- intents that never resolved ---------------------------------------
  const cutoff = new Date(Date.now() - INTENT_GRACE_MS);
  const intents = await db.signingAuditEntry.findMany({
    where: {
      kind: SigningAuditKind.SIGNING_INTENT,
      subjectDid: { in: [...watched] },
      occurredAt: { lt: cutoff },
    },
    select: { seq: true, correlationId: true, subjectDid: true, versionId: true, occurredAt: true },
    orderBy: { seq: 'asc' },
  });

  for (const intent of intents) {
    try {
      const successor = await db.signingAuditEntry.findFirst({
        where: {
          correlationId: intent.correlationId,
          kind: { in: [SigningAuditKind.SIGNING_RESULT, SigningAuditKind.SIGNING_REJECTED] },
        },
        select: { seq: true },
      });
      if (successor) continue;

      // It may still have reached the chain — the process can die between the
      // broadcast and the result append — so look before declaring it a no-op.
      const observed = intent.versionId
        ? await db.observedDidTx.findFirst({
            where: { versionId: intent.versionId },
            select: { txHash: true, height: true },
          })
        : null;

      unresolvedIntents.push(intent.correlationId);

      // Keyed on the intent's own seq, never on the txhash: the finding is
      // "THIS intent never resolved", and two intents can legitimately point at
      // the same transaction.
      if (await alarmAlreadyOpen(AlarmKind.INTENT_UNRESOLVED, intent.seq)) {
        suppressedAsAlreadyOpen += 1;
        continue;
      }

      await raiseAlarm({
        kind: AlarmKind.INTENT_UNRESOLVED,
        attribution: AlarmAttribution.NOT_APPLICABLE,
        subjectDid: intent.subjectDid,
        txHash: observed?.txHash ?? null,
        height: observed?.height ?? null,
        matchedAuditSeq: intent.seq,
        detail: {
          correlationId: intent.correlationId,
          versionId: intent.versionId,
          intentAt: intent.occurredAt.toISOString(),
          foundOnChain: observed !== null,
          note: observed
            ? 'It DID reach the chain. The gap is in our log, not in the ledger.'
            : 'Not observed on chain up to the watch cursor. The broadcast probably never left.',
        },
      });
    } catch (error) {
      checksFailed += 1;
      logger.error('custody_reconciliation_check_failed', {
        auditSeq: intent.seq,
        subjectDid: intent.subjectDid,
        direction: 'unresolved-intent',
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const report: ReconciliationReport = {
    complete:
      checksFailed === 0 &&
      skippedBecauseWatchIsBehind === 0 &&
      skippedOutsideWatchWindow === 0 &&
      suppressedAsAlreadyOpen === 0,
    checkedResults: results.length,
    checkedIntents: intents.length,
    broadcastsNotOnChain,
    unresolvedIntents,
    watchCursorHeight: cursorHeight,
    skippedBecauseWatchIsBehind,
    skippedOutsideWatchWindow,
    suppressedAsAlreadyOpen,
    checksFailed,
  };

  // WARN rather than INFO when the sweep could not see everything, so that an
  // incomplete pass is visible in a log search for problems and not only in the
  // response body of whoever happened to call it.
  if (report.complete) logger.info('custody_reconciliation_complete', report);
  else logger.warn('custody_reconciliation_incomplete', report);

  return report;
}

/**
 * Is this exact finding already sitting unacknowledged in front of an operator?
 *
 * Keyed on the audit entry's `seq`, which is the identity of the finding in
 * both directions — a txhash is not, because it can be absent (a result whose
 * broadcast never returned one) or shared (two intents against one transaction).
 *
 * FAILS TOWARD RAISING. If this query cannot answer, it reports "not already
 * open" so the caller raises. A duplicate alarm wastes an operator's attention
 * for ten seconds; a suppressed one is the eviction nobody was told about.
 */
async function alarmAlreadyOpen(kind: AlarmKind, auditSeq: number): Promise<boolean> {
  try {
    const existing = await db.custodyAlarm.findFirst({
      where: { kind, acknowledgedAt: null, matchedAuditSeq: auditSeq },
      select: { id: true },
    });
    return existing !== null;
  } catch (error) {
    logger.error('custody_alarm_dedupe_check_failed', {
      kind,
      auditSeq,
      error: error instanceof Error ? error.message : String(error),
      consequence: 'Raising the alarm anyway. A duplicate is cheaper than a silence.',
    });
    return false;
  }
}
