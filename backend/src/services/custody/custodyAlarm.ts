/**
 * SSI Healthcare Backend — raising the silent alarm: persist, log, deliver.
 *
 * The taxonomy — which kinds are CRITICAL, and why an unmatched event can never
 * be filed below a matched one — lives in `alarmSeverity.ts`, which is pure and
 * fast-testable. This file is the side effects.
 *
 * ORDER: persist, then log, then dispatch. The database row is the copy that
 * survives a crashed process and an unwatched console, so it is written first
 * and nothing downstream can un-raise it.
 *
 * Email, SMS and push are OUT OF SCOPE for this phase by the owner's ruling
 * (#293). {@link AlarmNotifier} is the seam they plug into later; building one
 * now was explicitly not asked for.
 */


import { db } from '../../db/index.js';
import { logger } from '../../utils/logger.js';
import {
  AlarmAttribution,
  AlarmKind,
  AlarmSeverity,
  headlineFor,
  severityFor,
  type AlarmInput,
} from './alarmSeverity.js';

export * from './alarmSeverity.js';

export interface RaisedAlarm {
  readonly id: string;
  readonly severity: AlarmSeverity;
  readonly kind: AlarmKind;
  readonly attribution: AlarmAttribution;
  readonly subjectDid: string | null;
  readonly txHash: string | null;
  readonly height: number | null;
  readonly signerVerificationMethodIds: readonly string[];
  readonly headline: string;
  readonly detail: Record<string, unknown>;
  readonly matchedAuditSeq: number | null;
  readonly raisedAt: Date;
}


// ---------------------------------------------------------------------------
// Notifiers — observer, with cleanup owned by the subscriber
// ---------------------------------------------------------------------------

export interface AlarmNotifier {
  readonly name: string;
  notify(alarm: RaisedAlarm): Promise<void> | void;
}

const notifiers = new Map<string, AlarmNotifier>();

/** Returns the unsubscribe. The caller owns cleanup — an emitter that outlives
 *  its subscribers is how long-running processes leak them. */
export function registerAlarmNotifier(notifier: AlarmNotifier): () => void {
  notifiers.set(notifier.name, notifier);
  return () => {
    notifiers.delete(notifier.name);
  };
}

export function registeredAlarmNotifierNames(): string[] {
  return [...notifiers.keys()];
}

// ---------------------------------------------------------------------------
// Raise
// ---------------------------------------------------------------------------

/** Just enough of the Prisma client to write one row, so a caller can pass a
 *  transaction handle and make the alarm atomic with what caused it. */
export interface AlarmWriter {
  custodyAlarm: {
    create(args: { data: Record<string, unknown> }): Promise<{
      id: string;
      subjectDid: string | null;
      txHash: string | null;
      height: number | null;
      matchedAuditSeq: number | null;
      raisedAt: Date;
    }>;
  };
}

/**
 * Write the alarm row — and nothing else.
 *
 * Split from {@link dispatchAlarm} so the chain watch can persist the alarm in
 * the SAME transaction as the `ObservedDidTx` row that caused it. Without that,
 * a crash between the two leaves an observation marked handled and an alarm
 * that was never raised — a silence indistinguishable from "nothing happened",
 * which is the failure mode this whole component exists to avoid.
 */
export async function persistAlarm(writer: AlarmWriter, input: AlarmInput): Promise<RaisedAlarm> {
  const severity = severityFor(input.kind, input.attribution);
  const headline = input.headline ?? headlineFor(input);
  const signerVerificationMethodIds = [...(input.signerVerificationMethodIds ?? [])];

  const row = await writer.custodyAlarm.create({
    data: {
      severity,
      kind: input.kind,
      attribution: input.attribution,
      subjectDid: input.subjectDid ?? null,
      txHash: input.txHash ?? null,
      height: input.height ?? null,
      signerVerificationMethodIds,
      headline,
      detail: input.detail,
      matchedAuditSeq: input.matchedAuditSeq ?? null,
    },
  });

  return {
    id: row.id,
    severity,
    kind: input.kind,
    attribution: input.attribution,
    subjectDid: row.subjectDid,
    txHash: row.txHash,
    height: row.height,
    signerVerificationMethodIds,
    headline,
    detail: input.detail,
    matchedAuditSeq: row.matchedAuditSeq,
    raisedAt: row.raisedAt,
  };
}

/**
 * Log and fan out to notifiers. Safe to call after the transaction commits.
 *
 * A notifier that throws must not prevent the other notifiers from firing, and
 * cannot un-raise the alarm — the row is already durable. Each failure is
 * itself logged, because a delivery channel that has silently stopped working
 * is the same silence again.
 */
export async function dispatchAlarm(alarm: RaisedAlarm): Promise<void> {
  const { severity, headline, signerVerificationMethodIds } = alarm;

  // Winston's npm levels stop at `error`; `severity` carries the distinction a
  // log pipeline should alert on, and the event name is stable for filtering.
  const line = {
    alarmId: alarm.id,
    severity,
    kind: alarm.kind,
    attribution: alarm.attribution,
    subjectDid: alarm.subjectDid,
    txHash: alarm.txHash,
    height: alarm.height,
    signers: signerVerificationMethodIds,
    matchedAuditSeq: alarm.matchedAuditSeq,
    headline,
    detail: alarm.detail,
  };
  if (severity === AlarmSeverity.CRITICAL) logger.error('custody_alarm', line);
  else if (severity === AlarmSeverity.WARNING) logger.warn('custody_alarm', line);
  else logger.info('custody_alarm', line);

  await Promise.all(
    [...notifiers.values()].map(async (notifier) => {
      try {
        await notifier.notify(alarm);
      } catch (error) {
        logger.error('custody_alarm_notifier_failed', {
          notifier: notifier.name,
          alarmId: alarm.id,
          severity,
          error: error instanceof Error ? error.message : String(error),
          note: 'The alarm IS persisted; only this delivery channel failed.',
        });
      }
    }),
  );
}

/** Persist then dispatch. For callers with nothing to be atomic with. */
export async function raiseAlarm(input: AlarmInput): Promise<RaisedAlarm> {
  const alarm = await persistAlarm(db as unknown as AlarmWriter, input);
  await dispatchAlarm(alarm);
  return alarm;
}

export async function openAlarms(limit = 100): Promise<RaisedAlarm[]> {
  const rows = await db.custodyAlarm.findMany({
    where: { acknowledgedAt: null },
    orderBy: [{ severity: 'asc' }, { raisedAt: 'desc' }],
    take: limit,
  });
  return rows.map((row) => ({
    id: row.id,
    severity: row.severity,
    kind: row.kind,
    attribution: row.attribution,
    subjectDid: row.subjectDid,
    txHash: row.txHash,
    height: row.height,
    signerVerificationMethodIds: row.signerVerificationMethodIds,
    headline: row.headline,
    detail: (row.detail ?? {}) as Record<string, unknown>,
    matchedAuditSeq: row.matchedAuditSeq,
    raisedAt: row.raisedAt,
  }));
}

/**
 * Acknowledgement records that a HUMAN SAW IT. It does not mean resolved, and
 * nothing here deletes an alarm — the alarm history is part of the evidence.
 */
export async function acknowledgeAlarm(id: string, acknowledgedBy: string): Promise<void> {
  await db.custodyAlarm.update({
    where: { id },
    data: { acknowledgedAt: new Date(), acknowledgedBy },
  });
}
