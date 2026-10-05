/**
 * SSI Healthcare Backend — the professional-authority guard.
 *
 * `requireAuth` answers "who is calling". This answers "may they do this",
 * and it answers it from a presentation verified DURING THIS REQUEST — not
 * from a session claim, not from a column, not from an earlier verification
 * cached anywhere.
 *
 * ---------------------------------------------------------------------------
 * WHY NOT A ROLE ON THE SESSION
 * ---------------------------------------------------------------------------
 * A session token that says `role: doctor` is a centralised assertion by this
 * server, which is the exact trust arrangement the project exists to remove.
 * Worse, it is a stale one: a licence revoked ten minutes ago still authorises
 * every request until the token expires. Verifying per request costs a ledger
 * read for the status list and one extra round trip for the challenge; the
 * alternative costs the thesis claim.
 *
 * ---------------------------------------------------------------------------
 * THE EXCHANGE
 * ---------------------------------------------------------------------------
 *   1. POST /api/professional/challenge   → { requestId, nonce, audience }
 *   2. wallet signs a vp+sd-jwt over that nonce, for that audience
 *   3. retry the real request with
 *        X-Presentation-Request-Id: <requestId>
 *        X-Professional-Presentation: <compact vp+sd-jwt>
 *
 * Headers rather than the body so one guard covers GET and POST identically; a
 * compact SD-JWT VP over a licence is well inside Node's 16 KB header budget.
 *
 * The challenge is single-use. That is a real cost — two round trips per
 * protected call — and it is paid deliberately: a challenge reusable inside its
 * TTL admits replay of a captured presentation for the length of that window.
 */

import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { ERROR_CODES, TRUST_ROOTS_ARE_PLACEHOLDERS } from '@ssi-healthcare/shared';
import { getAgent } from '../agent/index.js';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';
import { AppError } from './errorHandler.js';
import { verifySdJwtPresentation } from '../services/sdJwtVc.js';
import {
  authoriseProfessional,
  type ProfessionalIdentity,
  type ProfessionalRequirement,
} from '../services/professionalAuthority.js';
import { consumeChallenge, recordChallengeOutcome } from '../services/professionalChallenge.js';
import { DEPLOYMENT_TRUST_ROOTS } from '../services/professionalTrustRoots.js';

/** Header carrying the challenge this presentation answers. */
export const PRESENTATION_REQUEST_HEADER = 'x-presentation-request-id';
/** Header carrying the compact `vp+sd-jwt`. */
export const PRESENTATION_HEADER = 'x-professional-presentation';

/** A request whose caller proved professional authority for THIS request. */
export interface ProfessionalRequest extends Request {
  professional: ProfessionalIdentity;
}

function header(req: Request, name: string): string | undefined {
  const value = req.headers[name];
  const first = Array.isArray(value) ? value[0] : value;
  return typeof first === 'string' && first.length > 0 ? first : undefined;
}

/**
 * Require a verified professional licence covering `requirement`.
 *
 * Mount AFTER `requireAuth`/`requireWallet`: identity and authority are
 * separate questions and this one deliberately does not answer the first.
 */
export function requireProfessional(requirement: ProfessionalRequirement): RequestHandler {
  if (TRUST_ROOTS_ARE_PLACEHOLDERS) {
    // Once per mounted guard, at startup, where an operator will see it — not
    // per request, where it would drown the log it is meant to stand out in.
    logger.warn('Professional authority is pinned to PLACEHOLDER trust roots', {
      requirement,
      remedy: 'Replace PROFESSIONAL_TRUST_ROOTS in @ssi-healthcare/shared before any real enrolment',
    });
  }

  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      // The audience is ours and is configured. Refusing when it is unset is
      // not pedantry: verifying without an audience accepts a presentation the
      // holder made for somebody else.
      if (!config.verifierDid) {
        throw new AppError(
          ERROR_CODES.INTERNAL_ERROR,
          'This deployment has no VERIFIER_DID configured, so presentations cannot be bound to it',
          503,
        );
      }

      const requestId = header(req, PRESENTATION_REQUEST_HEADER);
      const vpToken = header(req, PRESENTATION_HEADER);

      if (!requestId || !vpToken) {
        throw new AppError(
          ERROR_CODES.PROFESSIONAL_PRESENTATION_REQUIRED,
          'This action requires a verified professional licence. Request a challenge from POST /api/professional/challenge and present your licence.',
          401,
          { required: requirement },
        );
      }

      const challenge = await consumeChallenge(requestId);
      if (!challenge.ok) {
        logger.warn('Professional presentation rejected before verification', {
          requestId,
          reason: challenge.reason,
          path: req.path,
        });
        throw new AppError(
          ERROR_CODES.PROFESSIONAL_PRESENTATION_REQUIRED,
          'Challenge is not open. Request a new one and present again.',
          401,
          { required: requirement },
        );
      }

      // THE ONE VERIFICATION PATH. Signatures, disclosure integrity, nonce,
      // audience and holder binding are all decided here, including the three
      // checks Credo 0.6 omits (CREDO-SECURITY-REPORT.md). Nothing below
      // re-derives any of them.
      const verified = await verifySdJwtPresentation(getAgent(), {
        presentation: vpToken,
        challenge: challenge.nonce,
        domain: challenge.audience,
      });

      if (!verified.isValid) {
        await recordChallengeOutcome(challenge.presentationId, {
          verified: false,
          reasons: verified.errors,
          checks: verified.checks,
        });
        logger.warn('Professional presentation failed the verification boundary', {
          requestId,
          path: req.path,
          checks: verified.checks,
          errors: verified.errors,
        });
        throw new AppError(
          ERROR_CODES.PROFESSIONAL_AUTHORITY_REFUSED,
          'Presentation could not be verified',
          403,
          { required: requirement },
        );
      }

      // Credo 0.6 admits exactly one credential per VC 2.0 presentation, so a
      // count other than one means the boundary's contract changed underneath
      // us. Refuse rather than picking one and hoping it is the licence.
      if (verified.credentials.length !== 1) {
        await recordChallengeOutcome(challenge.presentationId, {
          verified: false,
          reasons: [`Presentation carried ${verified.credentials.length} credentials, expected 1`],
          checks: verified.checks,
        });
        throw new AppError(
          ERROR_CODES.PROFESSIONAL_AUTHORITY_REFUSED,
          'Present exactly one professional licence',
          403,
          { required: requirement },
        );
      }

      const decision = await authoriseProfessional({
        presented: verified.credentials[0]!,
        requirement,
        // A compiled-in table chosen by network and NODE_ENV, never by the
        // request — see professionalTrustRoots.ts for why that distinction is
        // the whole safety argument.
        trustRoots: DEPLOYMENT_TRUST_ROOTS,
      });

      await recordChallengeOutcome(challenge.presentationId, {
        verified: decision.authorised,
        reasons: decision.reasons,
        checks: decision.checks,
      });

      if (!decision.authorised) {
        // The reasons ARE returned to the client. A professional refused for a
        // revoked licence and one refused for the wrong profession must be able
        // to tell which, or the only available response is to keep retrying.
        throw new AppError(
          ERROR_CODES.PROFESSIONAL_AUTHORITY_REFUSED,
          `Professional authority refused: ${decision.reasons.join('; ')}`,
          403,
          { required: requirement, checks: decision.checks },
        );
      }

      (req as ProfessionalRequest).professional = decision.professional!;

      logger.info('Professional authority accepted for request', {
        path: req.path,
        did: decision.professional!.did,
        profession: decision.professional!.profession,
        accreditedBy: decision.professional!.accreditedByName,
      });

      next();
    } catch (error) {
      next(error);
    }
  };
}

/** Type guard for handlers downstream of {@link requireProfessional}. */
export function hasProfessionalAuthority(req: Request): req is ProfessionalRequest {
  return 'professional' in req && (req as ProfessionalRequest).professional !== undefined;
}
