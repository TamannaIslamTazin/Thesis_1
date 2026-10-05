/**
 * SSI Healthcare Backend — professional authority routes.
 *
 * One endpoint: hand out the verifier-side nonce that `requireProfessional`
 * will later demand. The authorization decision itself is not an endpoint —
 * it happens inside the guard, on the request being authorized, which is the
 * whole point (see middleware/requireProfessional.ts).
 */

import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import {
  ERROR_CODES,
  PRACTICE_SCOPES,
  PROFESSIONAL_TRUST_ROOTS,
  PROFESSIONS,
  TRUST_ROOTS_ARE_PLACEHOLDERS,
  type ApiResponse,
} from '@ssi-healthcare/shared';
import { requireAuth, type AuthenticatedRequest } from '../middleware/auth.js';
import { AppError } from '../middleware/errorHandler.js';
import { config } from '../config/index.js';
import { createChallenge } from '../services/professionalChallenge.js';

export const professionalRouter: Router = Router();

const challengeSchema = z.object({
  profession: z.enum(PROFESSIONS).optional(),
  scope: z.array(z.enum(PRACTICE_SCOPES)).min(1),
});

/**
 * POST /api/professional/challenge
 *
 * Authenticated because a challenge is bound to the wallet that will answer it,
 * which lets a refusal be attributed. It is NOT authorized — proving authority
 * is what the challenge is for, so requiring it here would be circular.
 */
professionalRouter.post(
  '/challenge',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!config.verifierDid) {
        throw new AppError(
          ERROR_CODES.INTERNAL_ERROR,
          'This deployment has no VERIFIER_DID configured, so it cannot receive presentations',
          503,
        );
      }

      const requirement = challengeSchema.parse(req.body);
      const user = (req as AuthenticatedRequest).user;

      const challenge = await createChallenge({
        audience: config.verifierDid,
        holderDid: user.did ?? undefined,
        requirement,
      });

      const response: ApiResponse = {
        success: true,
        data: challenge,
        timestamp: new Date().toISOString(),
      };
      res.status(201).json(response);
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /api/professional/trust-roots
 *
 * The root store, as served. Public and read-only — there is deliberately no
 * write counterpart, because a trust root an attacker can POST into is not a
 * trust root (#214). Exposing it lets a wallet tell a holder who accredited a
 * professional, and lets a deployment check assert the placeholders are gone.
 */
professionalRouter.get('/trust-roots', (_req: Request, res: Response) => {
  const response: ApiResponse = {
    success: true,
    data: {
      placeholders: TRUST_ROOTS_ARE_PLACEHOLDERS,
      authorities: PROFESSIONAL_TRUST_ROOTS,
    },
    timestamp: new Date().toISOString(),
  };
  res.json(response);
});
