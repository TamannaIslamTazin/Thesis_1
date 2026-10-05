/**
 * SSI Healthcare Backend — the keystore vault (AUTH-AND-KEYSTORE-API.md §2-4).
 *
 * PUT   /api/keystore/envelope         authenticated; store or replace
 * POST  /api/keystore/envelope/fetch   { handle } -> { envelope } — unauthenticated
 *
 * FETCH IS DELIBERATELY UNAUTHENTICATED. Spec §6: on a new device, the
 * passphrase is the only factor available before any session exists — there
 * is no local key, and a fresh biometric proves a human is present, not which
 * one. Requiring a bearer token here would make the endpoint useless for the
 * exact flow it exists for.
 *
 * See `services/keystoreVault.ts` for what "opaque" means for the envelope,
 * why the row carries neither a userId nor a DID, and what the timing floor
 * on fetch does and does not hide. This file is the HTTP boundary: request
 * validation, rate limiting, and wiring the service's outcomes to responses.
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import { requireAuth, type AuthenticatedRequest } from '../middleware/auth.js';
import * as consentRepo from '../db/consentRepository.js';
import { logger } from '../utils/logger.js';
import { AuditEventType } from '../../prisma/generated/client/index.js';
import {
  assertE164Handle,
  passphraseEnvelopeShape,
  putEnvelope,
  fetchEnvelopeUniform,
  handleHmac,
} from '../services/keystoreVault.js';

const router = Router();

/**
 * Per-source-IP limiter. Generous relative to the handle limiter below,
 * because a shared NAT (a clinic waiting room, a family) is a real deployment
 * scenario and should not lock out everyone behind it after a handful of
 * legitimate recovery attempts.
 */
const keystoreIpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number.parseInt(process.env.KEYSTORE_IP_MAX ?? '1000', 10) || 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: { code: 'RATE_LIMITED', message: 'Too many keystore requests from this source. Try again later.' },
  },
});

/**
 * Per-handle limiter, keyed by the SAME HMAC the store uses — never the raw
 * phone number, so a rate-limiter's own in-memory keys are not themselves the
 * plaintext enrolment list §4 forbids at rest. Tighter than the IP limiter:
 * this is the control that actually bounds how many guesses one target
 * number can absorb, independent of how many source IPs an attacker rotates
 * through.
 */
const keystoreHandleLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number.parseInt(process.env.KEYSTORE_HANDLE_MAX ?? '200', 10) || 200,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    const handle = typeof req.body?.handle === 'string' ? req.body.handle : '';
    try {
      return handleHmac(handle);
    } catch {
      // Malformed input still needs a bucket; request validation downstream
      // refuses it on its own merits. This function must never throw.
      return 'unkeyable';
    }
  },
  message: {
    success: false,
    error: { code: 'RATE_LIMITED', message: 'Too many requests for this handle. Try again later.' },
  },
});

const putEnvelopeSchema = z.object({
  handle: z.string(),
  envelope: passphraseEnvelopeShape,
});

/**
 * PUT /api/keystore/envelope
 * Store or replace the caller's own recovery envelope under their phone
 * handle. "Their own": a slot already claimed by a different account is
 * refused (409), never merged — see `keystoreVault.ts`'s `putEnvelope`.
 */
router.put(
  '/envelope',
  keystoreIpLimiter,
  keystoreHandleLimiter,
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authReq = req as AuthenticatedRequest;
      const data = putEnvelopeSchema.parse(req.body);
      const handle = assertE164Handle(data.handle);

      const outcome = await putEnvelope({ handle, userId: authReq.user.id, envelope: data.envelope });

      if (outcome === 'conflict') {
        throw new AppError(
          ERROR_CODES.KEYSTORE_HANDLE_CONFLICT,
          'This handle is already associated with a different account\'s recovery envelope.',
          409,
        );
      }

      await consentRepo.createAuditLog({
        eventType: AuditEventType.WALLET_BACKED_UP,
        action: `Recovery envelope ${outcome} in keystore vault`,
        actorUserId: authReq.user.id,
        actorDid: authReq.user.did ?? undefined,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      logger.info('keystore_envelope_put', { userId: authReq.user.id, outcome });

      res.status(outcome === 'created' ? 201 : 200).json({ success: true, data: { stored: true } });
    } catch (error) {
      next(error);
    }
  },
);

const fetchEnvelopeSchema = z.object({
  handle: z.string(),
});

/**
 * POST /api/keystore/envelope/fetch
 * Uniform response shape and (padded) timing for an unknown handle — see the
 * module docblock and `keystoreVault.ts` for what this does and does not
 * hide. `envelope` is `null` when nothing is enrolled under this handle.
 */
router.post(
  '/envelope/fetch',
  keystoreIpLimiter,
  keystoreHandleLimiter,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = fetchEnvelopeSchema.parse(req.body);
      const handle = assertE164Handle(data.handle);
      const envelope = await fetchEnvelopeUniform(handle);
      res.status(200).json({ success: true, data: { envelope } });
    } catch (error) {
      next(error);
    }
  },
);

export { router as keystoreRouter };
