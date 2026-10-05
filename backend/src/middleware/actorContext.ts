/**
 * SSI Healthcare Backend — establish WHO IS ASKING for the whole request.
 *
 * Mounted before the routers so that anything reached from an HTTP request —
 * including the institutional signing path several layers down — can record the
 * source IP and device without any service taking an Express `Request`.
 *
 * MOUNT ORDER MATTERS. If this runs after `requireAuth` the context carries no
 * `userId`; if it runs before the routers but after `trust proxy` is configured,
 * `req.ip` is the client rather than the load balancer. It is placed with the
 * other global middleware in `index.ts` for exactly that reason.
 */

import type { NextFunction, Request, Response } from 'express';
import { randomUUID } from 'node:crypto';

import { actorContextFromRequest, runWithActorContext } from '../utils/actorContext.js';

/** The header a caller may use to continue an existing trace. */
const REQUEST_ID_HEADER = 'x-request-id';

export function actorContext() {
  return function actorContextMiddleware(req: Request, res: Response, next: NextFunction): void {
    const inbound = req.header(REQUEST_ID_HEADER);
    // Inherit at the boundary, never regenerate mid-flight, so one request has
    // one id across every log line and audit entry it produces.
    const requestId = inbound && inbound.length <= 128 ? inbound : randomUUID();
    res.setHeader(REQUEST_ID_HEADER, requestId);

    runWithActorContext(
      actorContextFromRequest({
        ip: req.ip,
        userAgent: req.header('user-agent'),
        // Almost always undefined here: `requireAuth` is per-route and has not
        // run yet, so it calls `attachActorUserId` to name the person. The IP
        // and device — which only the transport knows — are captured regardless,
        // so an unauthenticated path still produces an attributable entry.
        userId: (req as { user?: { id?: string } }).user?.id,
        requestId,
      }),
      next,
    );
  };
}
