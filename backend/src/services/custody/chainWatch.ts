/**
 * SSI Healthcare Backend — the chain silent alarm (steno #291, #293, #304).
 *
 * ===========================================================================
 * WHAT THIS WATCHES, AND WHY IT IS NOT OUR OWN OUTBOUND CALLS
 * ===========================================================================
 * An attacker holding an officer key does not need this backend. They sign
 * locally and broadcast to a node, and nothing in `institutionalDid.ts` ever
 * sees it. Instrumenting our signing path would therefore produce a monitor
 * that is blind to the only adversary it exists for. So this watches THE CHAIN:
 * every committed block, every `MsgUpdateDidDoc` and `MsgDeactivateDidDoc`
 * against a watched institutional DID, whoever broadcast it.
 *
 * The signing log says what we intended. This says what happened. A chain event
 * with no matching audit entry is the loudest signal available and is raised as
 * such — never reconciled away.
 *
 * ===========================================================================
 * WHY POLLING RATHER THAN A WEBSOCKET SUBSCRIPTION (#304)
 * ===========================================================================
 * CometBFT can push `tm.event='Tx'` over a websocket and would shave roughly
 * one block time off detection. It cannot replay. A subscriber delivers only
 * what happens while it is connected, so a reconnect after downtime resumes at
 * "now" and the blocks in between are simply never seen — a watcher that looks
 * like it is working while missing exactly the window an attacker would choose.
 * The catch-up scan would have to exist regardless, so the catch-up scan IS the
 * watcher.
 *
 * The latency this costs is small and was measured, not assumed: block time on
 * bd-health-trust-1 is ~2.06s, so with a 2s poll the worst case is one block for
 * commitment plus one interval, ≈4s. Nothing prevents the transaction — H1 and
 * T1 are irreversible the moment they commit — so the entire value is in how
 * fast the OTHER officers learn, and a human response is minutes at best. Four
 * seconds is far inside that budget; a websocket's two would not change any
 * decision an operator makes.
 *
 * ===========================================================================
 * THE GAP RULE
 * ===========================================================================
 * `lastScannedHeight` advances only after every message at that height has been
 * committed together with its alarms. A crash re-scans the height; the
 * `(txHash, msgIndex)` unique constraint on `ObservedDidTx` makes that
 * idempotent. Heights the node has pruned CANNOT be scanned, and that case
 * raises `WATCH_GAP_UNRECOVERABLE` rather than jumping forward quietly — an
 * unexamined window must never present as an all-clear.
 */

import { config } from '../../config/index.js';
import { db } from '../../db/index.js';
import { logger } from '../../utils/logger.js';
import { AppError } from '../../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import { Prisma } from '../../../prisma/generated/client/index.js';
import {
  AlarmAttribution,
  AlarmKind,
  dispatchAlarm,
  persistAlarm,
  raiseAlarm,
  type AlarmInput,
  type AlarmWriter,
  type RaisedAlarm,
} from './custodyAlarm.js';
import { CometBftClient, CometBftRpcError } from './cometBftClient.js';
import {
  ALARMING_TYPE_URLS,
  classifyDidChange,
  decodeDidMessagesInTx,
  MSG_DEACTIVATE_DID_DOC,
  OBSERVED_TYPE_URLS,
  type DecodedDidMessage,
  type DidChange,
} from './didTxDecode.js';
import { advanceWatchState, watchedDidMap, type WatchedDid } from './institutionalWatchList.js';
import { findIntentByVersionId } from './signingAuditLog.js';

const CURSOR_ID = 'default';

/** One tick never scans more than this, so a long catch-up stays interruptible. */
const MAX_HEIGHTS_PER_TICK = 200;

/** Consecutive RPC failures before the watcher declares itself degraded. */
const STALL_AFTER_CONSECUTIVE_FAILURES = 5;

export interface ChainWatchOptions {
  readonly rpcUrl?: string;
  readonly pollIntervalMs?: number;
  /**
   * Where a FIRST-EVER start begins. `'latest'` arms from now and says so;
   * a number replays from that height, which is what a test wants.
   */
  readonly startFrom?: number | 'latest';
}

export interface ScanReport {
  readonly fromHeight: number;
  readonly toHeight: number;
  readonly heightsScanned: number;
  readonly messagesObserved: number;
  readonly alarmsRaised: number;
  readonly caughtUp: boolean;
}

export interface ChainWatchHealth {
  readonly running: boolean;
  readonly chainId: string | null;
  readonly lastScannedHeight: number | null;
  readonly chainHeight: number | null;
  readonly blocksBehind: number | null;
  readonly consecutiveFailures: number;
  readonly lastScanAt: Date | null;
}

// ---------------------------------------------------------------------------

export class ChainWatch {
  private readonly client: CometBftClient;
  private readonly pollIntervalMs: number;
  private readonly startFrom: number | 'latest';

  private timer: NodeJS.Timeout | null = null;
  private ticking = false;
  private consecutiveFailures = 0;
  private stallAlarmRaised = false;
  private lastScanAt: Date | null = null;
  private chainId: string | null = null;
  private chainHeight: number | null = null;

  constructor(options: ChainWatchOptions = {}) {
    this.client = new CometBftClient(options.rpcUrl ?? config.cheqdRpcUrl);
    this.pollIntervalMs = options.pollIntervalMs ?? 2_000;
    this.startFrom = options.startFrom ?? 'latest';
  }

  /**
   * Begin watching. Resolves once the cursor exists and the chain identity has
   * been checked, so a caller can be sure the watch is armed before it returns.
   *
   * The first catch-up runs in the background: after long downtime it can be
   * thousands of blocks, and blocking start-up on it would make the whole
   * service unavailable for the same reason the watcher was behind.
   */
  async start(): Promise<void> {
    await this.ensureCursor();
    if (this.timer) return;

    // `unref` so the watcher never keeps a finished process alive; a test that
    // hangs on shutdown gets skipped, and a skipped test proves nothing.
    this.timer = setInterval(() => void this.tick(), this.pollIntervalMs);
    this.timer.unref?.();
    logger.info('custody_chain_watch_started', {
      rpcUrl: config.cheqdRpcUrl,
      pollIntervalMs: this.pollIntervalMs,
      note: 'MsgUpdateDidDoc and MsgDeactivateDidDoc against watched institutional DIDs.',
    });
    void this.tick();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    logger.warn('custody_chain_watch_stopped', {
      note:
        'Detection latency is the control that makes 1-of-N custody safe (#291). While this ' +
        'is stopped there is no silent alarm; the cursor persists, so a restart re-scans the gap.',
    });
  }

  async health(): Promise<ChainWatchHealth> {
    const cursor = await db.chainWatchCursor.findUnique({ where: { id: CURSOR_ID } });
    return {
      running: this.timer !== null,
      chainId: this.chainId,
      lastScannedHeight: cursor?.lastScannedHeight ?? null,
      chainHeight: this.chainHeight,
      blocksBehind:
        cursor && this.chainHeight !== null ? this.chainHeight - cursor.lastScannedHeight : null,
      consecutiveFailures: this.consecutiveFailures,
      lastScanAt: this.lastScanAt,
    };
  }

  // -------------------------------------------------------------------------

  private async tick(): Promise<void> {
    // Overlapping ticks would double-scan a height and race on the cursor. A
    // slow catch-up must delay the next tick, not run beside it.
    if (this.ticking) return;
    this.ticking = true;
    try {
      await this.scanOnce();
      this.consecutiveFailures = 0;
      if (this.stallAlarmRaised) {
        this.stallAlarmRaised = false;
        logger.info('custody_chain_watch_recovered', { note: 'The watch is advancing again.' });
      }
    } catch (error) {
      this.consecutiveFailures += 1;
      logger.error('custody_chain_watch_tick_failed', {
        consecutiveFailures: this.consecutiveFailures,
        error: error instanceof Error ? error.message : String(error),
      });
      if (this.consecutiveFailures >= STALL_AFTER_CONSECUTIVE_FAILURES && !this.stallAlarmRaised) {
        this.stallAlarmRaised = true;
        await raiseAlarm({
          kind: AlarmKind.WATCHER_STALLED,
          attribution: AlarmAttribution.NOT_APPLICABLE,
          detail: {
            consecutiveFailures: this.consecutiveFailures,
            rpcUrl: config.cheqdRpcUrl,
            lastError: error instanceof Error ? error.message : String(error),
          },
        }).catch(() => undefined);
      }
    } finally {
      this.ticking = false;
    }
  }

  /**
   * One bounded pass. Public so the live suite can drive the watcher
   * deterministically instead of sleeping and hoping.
   */
  async scanOnce(): Promise<ScanReport> {
    const status = await this.client.status();
    this.chainId = status.chainId;
    this.chainHeight = status.latestHeight;

    const cursor = await this.ensureCursor(status.latestHeight);
    this.assertSameChain(cursor.chainId, status.chainId);

    let from = cursor.lastScannedHeight + 1;

    // Pruned heights cannot be examined. Say so loudly and move the cursor
    // rather than pretending the window was clean.
    if (from < status.earliestHeight) {
      const skipped = status.earliestHeight - from;
      await raiseAlarm({
        kind: AlarmKind.WATCH_GAP_UNRECOVERABLE,
        attribution: AlarmAttribution.NOT_APPLICABLE,
        height: status.earliestHeight,
        detail: {
          missedFromHeight: from,
          missedToHeight: status.earliestHeight - 1,
          blocksMissed: skipped,
          earliestAvailableHeight: status.earliestHeight,
          note:
            'The node has pruned these blocks. An eviction or deactivation inside this window ' +
            'is now permanently undetectable by this system. Reconcile the watched DIDs against ' +
            'their live on-chain documents by hand before treating the alarm list as complete.',
        },
      });
      from = status.earliestHeight;
    }

    if (from > status.latestHeight) {
      this.lastScanAt = new Date();
      return {
        fromHeight: from,
        toHeight: cursor.lastScannedHeight,
        heightsScanned: 0,
        messagesObserved: 0,
        alarmsRaised: 0,
        caughtUp: true,
      };
    }

    const to = Math.min(status.latestHeight, from + MAX_HEIGHTS_PER_TICK - 1);
    const watched = await watchedDidMap();

    let messagesObserved = 0;
    let alarmsRaised = 0;

    for (let height = from; height <= to; height += 1) {
      const outcome = await this.scanHeight(height, watched);
      messagesObserved += outcome.messagesObserved;
      alarmsRaised += outcome.alarms.length;
      // After the commit, so a delivery failure cannot roll back the record.
      for (const alarm of outcome.alarms) await dispatchAlarm(alarm);
    }

    this.lastScanAt = new Date();
    return {
      fromHeight: from,
      toHeight: to,
      heightsScanned: to - from + 1,
      messagesObserved,
      alarmsRaised,
      caughtUp: to >= status.latestHeight,
    };
  }

  /**
   * Scan one height and advance the cursor to it, atomically.
   *
   * The cursor update lives in the same transaction as the observation rows,
   * the watch-state advance and the alarm rows. That is the whole gap
   * guarantee: either a height is fully accounted for, or it will be re-scanned.
   */
  private async scanHeight(
    height: number,
    watched: Map<string, WatchedDid>,
  ): Promise<{ messagesObserved: number; alarms: RaisedAlarm[] }> {
    const block = await this.client.block(height);

    const relevant: DecodedDidMessage[] = [];
    for (const base64Tx of block.txs) {
      const { messages, decodeError, txHash } = decodeDidMessagesInTx(base64Tx);
      if (decodeError) {
        // Not fatal: an undecodable transaction is not evidence that nothing
        // happened, and dying here would let an attacker silence the watch with
        // one malformed broadcast.
        logger.warn('custody_chain_watch_tx_undecodable', { height, txHash, error: decodeError });
        continue;
      }
      for (const message of messages) {
        if (!OBSERVED_TYPE_URLS.includes(message.typeUrl)) continue;
        if (!watched.has(message.subjectDid)) continue;
        relevant.push(message);
      }
    }

    // Delivery codes are read outside the transaction: they are network calls,
    // and holding a database transaction open across them invites lock waits on
    // an unrelated node's latency.
    const deliveries = new Map<string, number | null>();
    for (const message of relevant) {
      if (deliveries.has(message.txHash)) continue;
      const result = await this.client.deliveredTxResult(message.txHash);
      deliveries.set(message.txHash, result?.code ?? null);
    }

    // Matching happens before the transaction too — it reads the audit log, and
    // the answer for a committed height cannot change underneath us.
    //
    // THE DIRECTION OF THIS LOOKUP IS THE WHOLE COMPONENT. A miss means
    // UNMATCHED, which escalates to CRITICAL; a hit only means we can name who
    // asked. So the failure modes all have to land on the loud side:
    //   - a message with NO versionId can never match, and is UNMATCHED;
    //   - a lookup that throws propagates and fails this tick, which re-scans
    //     the height rather than recording a match that was never established;
    //   - a match NEVER lowers severity (see `alarmSeverity.ts`), so even if an
    //     attacker inside our backend forged an intent carrying the versionId
    //     they were about to broadcast, the eviction still pages an operator.
    //     That last property is why matching by a value we mint is acceptable
    //     as an attribution CONVENIENCE and not as a trust decision.
    const matches = new Map<string, number | null>();
    for (const message of relevant) {
      if (!message.versionId || matches.has(message.versionId)) continue;
      const intent = await findIntentByVersionId(message.versionId);
      matches.set(message.versionId, intent?.seq ?? null);
    }

    const alarms = await db.$transaction(async (tx) => {
      const raised: RaisedAlarm[] = [];

      for (const message of relevant) {
        const inserted = await tx.observedDidTx.createMany({
          data: [
            {
              txHash: message.txHash,
              msgIndex: message.msgIndex,
              height,
              blockTime: block.time,
              typeUrl: message.typeUrl,
              subjectDid: message.subjectDid,
              versionId: message.versionId,
              deliveryCode: deliveries.get(message.txHash) ?? null,
              signerVerificationMethodIds: [...message.signerVerificationMethodIds],
              decoded: message as unknown as Prisma.InputJsonValue,
            },
          ],
          skipDuplicates: true,
        });

        // Already recorded on an earlier pass over this height, alarm included.
        // Re-alarming would train an operator to ignore the channel.
        if (inserted.count === 0) continue;

        const watchedDid = watched.get(message.subjectDid) as WatchedDid;
        const deliveryCode = deliveries.get(message.txHash) ?? null;
        const change = classifyDidChange(message, watchedDid);

        // Creation is RECORDED above but never alarmed: a DID coming into
        // existence cannot harm one that already exists, and the record is
        // what lets reconciliation account for a provisioning broadcast.
        if (ALARMING_TYPE_URLS.includes(message.typeUrl)) {
          raised.push(
            await persistAlarm(
              tx as unknown as AlarmWriter,
              buildAlarmInput({
                message,
                change,
                height,
                blockTime: block.time,
                deliveryCode,
                matchedAuditSeq: message.versionId
                  ? (matches.get(message.versionId) ?? null)
                  : null,
                watchedDid,
              }),
            ),
          );
        }

        // A rejected transaction changed nothing on chain, so the running
        // picture must NOT advance — advancing it would make the next genuine
        // change compare against a document that never existed.
        if (deliveryCode !== null && deliveryCode !== 0) continue;

        await advanceWatchState(tx, {
          did: message.subjectDid,
          height,
          versionId: message.versionId,
          verificationMethods:
            message.typeUrl === MSG_DEACTIVATE_DID_DOC
              ? watchedDid.verificationMethodIds.map((id) => ({ id, publicKeyMultibase: '' }))
              : message.verificationMethods,
          controllers:
            message.typeUrl === MSG_DEACTIVATE_DID_DOC
              ? watchedDid.controllers
              : message.controllers,
          deactivated: message.typeUrl === MSG_DEACTIVATE_DID_DOC || watchedDid.deactivated,
        });
      }

      await tx.chainWatchCursor.update({
        where: { id: CURSOR_ID },
        data: { lastScannedHeight: height },
      });

      return raised;
    });

    return { messagesObserved: relevant.length, alarms };
  }

  // -------------------------------------------------------------------------

  private async ensureCursor(latestHeight?: number): Promise<{
    lastScannedHeight: number;
    chainId: string;
  }> {
    const existing = await db.chainWatchCursor.findUnique({ where: { id: CURSOR_ID } });
    if (existing) return existing;

    const status = await this.client.status();
    this.chainId = status.chainId;
    const height = latestHeight ?? status.latestHeight;
    const start =
      this.startFrom === 'latest' ? height : Math.max(this.startFrom, status.earliestHeight);

    const created = await db.chainWatchCursor.create({
      data: {
        id: CURSOR_ID,
        // Minus one so the start height is itself scanned rather than skipped.
        lastScannedHeight: start - 1,
        chainId: status.chainId,
        startedFromHeight: start,
      },
    });

    logger.warn('custody_chain_watch_cursor_created', {
      chainId: status.chainId,
      startedFromHeight: start,
      note:
        `Nothing before height ${start} has been observed by this watcher. A quiet alarm list ` +
        'says nothing about earlier blocks.',
    });

    return created;
  }

  /**
   * Refuse to run against a different chain from the one the cursor was built
   * on. Heights from another chain are meaningless, and — worse — a watch
   * pointed at the wrong chain reports "no institutional activity" forever
   * while being technically correct.
   */
  private assertSameChain(cursorChainId: string, actualChainId: string): void {
    if (cursorChainId === actualChainId) return;
    throw new AppError(
      ERROR_CODES.INTERNAL_ERROR,
      `The chain watch cursor was built against '${cursorChainId}' but ${config.cheqdRpcUrl} ` +
        `identifies as '${actualChainId}'. Heights do not transfer between chains, and a watch ` +
        'on the wrong chain reports silence forever. Point CHEQD_RPC_URL back at the right ' +
        'node, or reset the cursor deliberately and accept that the old chain is unwatched.',
      500,
    );
  }
}

// ---------------------------------------------------------------------------
// Alarm construction — pure, so the taxonomy is testable without a chain
// ---------------------------------------------------------------------------

export function buildAlarmInput(input: {
  message: DecodedDidMessage;
  change: DidChange;
  height: number;
  blockTime: Date;
  deliveryCode: number | null;
  matchedAuditSeq: number | null;
  watchedDid: WatchedDid;
}): AlarmInput {
  const { message, change, deliveryCode, matchedAuditSeq } = input;

  const rejected = deliveryCode !== null && deliveryCode !== 0;
  const kind = rejected ? AlarmKind.REJECTED_ATTEMPT : kindForChange(change);

  return {
    kind,
    attribution:
      matchedAuditSeq === null ? AlarmAttribution.UNMATCHED : AlarmAttribution.MATCHED,
    subjectDid: message.subjectDid,
    txHash: message.txHash,
    height: input.height,
    signerVerificationMethodIds: message.signerVerificationMethodIds,
    matchedAuditSeq,
    detail: {
      label: input.watchedDid.label,
      typeUrl: message.typeUrl,
      versionId: message.versionId,
      blockTime: input.blockTime.toISOString(),
      deliveryCode,
      deliveryCodeKnown: deliveryCode !== null,
      change: change.kind,
      removedVerificationMethodIds: change.removedVerificationMethodIds,
      addedVerificationMethodIds: change.addedVerificationMethodIds,
      rotatedVerificationMethodIds: change.rotatedVerificationMethodIds,
      controllersBefore: change.controllersBefore,
      controllersAfter: change.controllersAfter,
      verificationMethodIdsBefore: input.watchedDid.verificationMethodIds,
      verificationMethodIdsAfter: message.verificationMethods.map((vm) => vm.id),
      // What the operator must do next, stated in the alarm rather than in a
      // runbook nobody will find at 03:00.
      remediation: remediationFor(kind, matchedAuditSeq !== null),
    },
  };
}

function kindForChange(change: DidChange): AlarmKind {
  switch (change.kind) {
    case 'deactivation':
      return AlarmKind.DID_DEACTIVATED;
    case 'eviction':
      return AlarmKind.OFFICER_EVICTED;
    case 'controller-change':
      return AlarmKind.CONTROLLER_CHANGED;
    case 'rotation':
      return AlarmKind.OFFICER_ROTATED;
    case 'addition':
      return AlarmKind.OFFICER_ADDED;
    case 'no-key-change':
      return AlarmKind.UPDATE_WITHOUT_KEY_CHANGE;
  }
}

function remediationFor(kind: AlarmKind, matched: boolean): string {
  if (!matched) {
    return (
      'Assume an officer key is held by someone outside this backend. Any surviving officer ' +
      'key can still act (1-of-N): rotate every remaining slot NOW, before another eviction ' +
      'removes the ability to rotate at all. Do not wait to confirm intent first — an eviction ' +
      'and a deactivation are each a single irreversible transaction.'
    );
  }
  switch (kind) {
    case AlarmKind.DID_DEACTIVATED:
      return (
        'Irreversible. Provision a replacement institutional DID and re-issue. Patients ' +
        'enrolled under the old one are NOT frozen (S-4 K1/K2), but it can never sign again.'
      );
    case AlarmKind.OFFICER_EVICTED:
      return (
        'Confirm with the named officer that this removal was intended. Check the remaining ' +
        'slot count: at one, the institution can no longer rotate a compromised key.'
      );
    case AlarmKind.CONTROLLER_CHANGED:
      return 'Confirm intent. A controller set cannot be repaired (S-1 §5.4).';
    default:
      return 'Routine, and accounted for by a signing audit entry. No action.';
  }
}

// ---------------------------------------------------------------------------
// Process-wide instance
// ---------------------------------------------------------------------------

let watch: ChainWatch | null = null;

export async function startChainWatch(options?: ChainWatchOptions): Promise<ChainWatch> {
  if (!watch) watch = new ChainWatch(options);
  await watch.start();
  return watch;
}

export function chainWatchInstance(): ChainWatch | null {
  return watch;
}

export function stopChainWatch(): void {
  watch?.stop();
  watch = null;
}

export { CometBftRpcError };
