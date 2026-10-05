/**
 * SSI Healthcare Backend — what an operator actually sees.
 *
 * READ-ONLY, WITH ONE EXCEPTION. Every endpoint here is a GET except
 * acknowledgement, which records that a human looked at an alarm. There is no
 * endpoint that edits or deletes a signing entry, no endpoint that clears an
 * alarm, and no endpoint that disarms the watch — the append-only property of
 * the log would mean very little if this router offered a way around it.
 *
 * `GET /api/custody/status` is the one to open first during an incident: it
 * answers "is the alarm actually armed", "how far behind is it", and "what is
 * outstanding" in a single response, because during an eviction the expensive
 * mistake is reading a quiet alarm list from a watcher that has been down.
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';

import { requireAuth, type AuthenticatedRequest } from '../middleware/auth.js';
import { db } from '../db/index.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import {
  acknowledgeAlarm,
  openAlarms,
  registeredAlarmNotifierNames,
} from '../services/custody/custodyAlarm.js';
import { chainWatchInstance } from '../services/custody/chainWatch.js';
import { listWatchedDids } from '../services/custody/institutionalWatchList.js';
import { reconcileLogAgainstChain } from '../services/custody/reconciliation.js';
import { readSigningLog, verifySigningLog } from '../services/custody/signingAuditLog.js';

export const custodyRouter: Router = Router();

custodyRouter.use(requireAuth);

function handle(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    fn(req, res).catch(next);
  };
}

/** Armed? Behind? Anything outstanding? */
custodyRouter.get(
  '/status',
  handle(async (_req, res) => {
    const watch = chainWatchInstance();
    const health = watch ? await watch.health() : null;
    const alarms = await openAlarms(50);

    const cursor = await db.chainWatchCursor.findUnique({ where: { id: 'default' } });

    res.json({
      success: true,
      data: {
        watch: health ?? {
          running: false,
          note:
            'THE CHAIN WATCH IS NOT RUNNING IN THIS PROCESS. There is no silent alarm. An ' +
            'empty alarm list below means nothing.',
        },
        // What the alarm list is and is not evidence about. Stated here because
        // the expensive mistake during an incident is reading a quiet list from
        // a watcher that only ever looked at part of the chain (#302).
        coverage: cursor
          ? {
              chainId: cursor.chainId,
              observedFromHeight: cursor.startedFromHeight,
              observedToHeight: cursor.lastScannedHeight,
              statement:
                `Alarms below cover heights ${cursor.startedFromHeight}–` +
                `${cursor.lastScannedHeight} on ${cursor.chainId}. NOTHING BEFORE ` +
                `${cursor.startedFromHeight} WAS EVER EXAMINED by this watcher, and each DID is ` +
                'only covered from its own armed height. Run GET /api/custody/reconcile and ' +
                'read its `complete` field before treating an empty list as an all-clear.',
            }
          : {
              statement:
                'NO CURSOR EXISTS. This watcher has never observed a single block. An empty ' +
                'alarm list says nothing whatsoever.',
            },
        notifiers: registeredAlarmNotifierNames(),
        watchedDids: await listWatchedDids(),
        openAlarms: alarms,
        criticalOpen: alarms.filter((alarm) => alarm.severity === 'CRITICAL').length,
      },
    });
  }),
);

/** The append-only signing log, newest first, with the head digest. */
custodyRouter.get(
  '/signing-log',
  handle(async (req, res) => {
    const query = z
      .object({
        did: z.string().startsWith('did:').optional(),
        limit: z.coerce.number().min(1).max(500).default(100),
      })
      .parse(req.query);

    res.json({
      success: true,
      data: await readSigningLog({ subjectDid: query.did, limit: query.limit }),
    });
  }),
);

/**
 * Verify the hash chain. Raises `AUDIT_CHAIN_TAMPERED` itself if it does not
 * hold, so calling this can never be a way to discover tampering quietly.
 */
custodyRouter.get(
  '/signing-log/verify',
  handle(async (_req, res) => {
    const verdict = await verifySigningLog();
    res.status(verdict.intact ? 200 : 409).json({ success: verdict.intact, data: verdict });
  }),
);

custodyRouter.get(
  '/reconcile',
  handle(async (_req, res) => {
    const report = await reconcileLogAgainstChain();
    res.json({
      success: true,
      // `success` says the sweep ran. `complete` says whether it could see
      // everything, and those are different questions — collapsing them is how
      // "no findings" gets read as "nothing happened" (#302).
      data: report,
      warning: report.complete
        ? undefined
        : `INCOMPLETE SWEEP — ${report.checksFailed} entries could not be examined, ` +
          `${report.skippedOutsideWatchWindow} fell outside the watch window, ` +
          `${report.skippedBecauseWatchIsBehind} are at heights the watcher has not reached, ` +
          `and ${report.suppressedAsAlreadyOpen} findings are already open. An empty ` +
          '`broadcastsNotOnChain` here does NOT mean there is nothing to find.',
    });
  }),
);

/**
 * Acknowledgement means SEEN, not resolved, and nothing here removes an alarm.
 * The alarm history is evidence.
 */
custodyRouter.post(
  '/alarms/:id/acknowledge',
  handle(async (req, res) => {
    const id = z.string().min(1).parse(req.params.id);
    const user = (req as AuthenticatedRequest).user;
    if (!user?.id) {
      throw new AppError(ERROR_CODES.AUTH_REQUIRED, 'Acknowledgement requires a named user.', 401);
    }
    await acknowledgeAlarm(id, user.id);
    res.json({ success: true, data: { id, acknowledgedBy: user.id } });
  }),
);
