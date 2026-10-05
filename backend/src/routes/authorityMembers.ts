/**
 * L1 authority roster management (OFFICER-DOCUMENT-ACCESS.md §7).
 *
 * Round 3 seeded the four L1 institutions (migration
 * `20260905070559_seed_l1_authorities`) and added `InstitutionMember.role`
 * but created no members and no route that could create one — so nobody
 * could sign in to `routes/authority.ts` at all. This file is the means to
 * create and manage an officer that round asked for.
 *
 * Two different trust boundaries, because they answer two different
 * questions:
 *
 *   POST /bootstrap        "how does an institution get its FIRST admin,
 *                           when the roster starts empty and normal roster
 *                           management requires already being an admin?"
 *   the rest                "how does an existing ADMIN manage their own
 *                           institution's roster from here on?"
 *
 * ===========================================================================
 * WHY BOOTSTRAP NEEDS A SEPARATE SECRET, NOT JUST "ROSTER IS EMPTY"
 * ===========================================================================
 * "The roster is empty" alone is not a safe gate: any signed-up user could
 * discover that fact for the Ministry of Health institution (its id is
 * public — it is in every issuance request addressed to it) and claim ADMIN
 * of the national health-card authority before its real operator ever signs
 * in. An empty roster is necessary evidence that bootstrap is still open, but
 * it is not sufficient evidence that the CALLER is who the institution wants
 * running it. `AUTHORITY_BOOTSTRAP_SECRET` is the missing evidence: an
 * out-of-band value the institution's real operator is given, checked with
 * `timingSafeEqual` the same way session tokens are compared in the locker's
 * `didAuth.ts`. Losing the secret before first use means losing bootstrap for
 * that institution, which is recoverable (an operator with database access
 * can insert the first row directly); a bootstrap endpoint any signed-up user
 * can walk through is not.
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { timingSafeEqual, createHash } from 'node:crypto';
import { z } from 'zod';

import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import { requireAuth, type AuthenticatedRequest } from '../middleware/auth.js';
import { requireAuthorityMember, type AuthorityMemberRequest } from '../middleware/requireAuthorityMember.js';
import { requireAuthorityRole } from '../middleware/requireAuthorityRole.js';
import { db } from '../db/index.js';
import * as consentRepo from '../db/consentRepository.js';
import { logger } from '../utils/logger.js';
import { AuditEventType } from '../../prisma/generated/client/index.js';

export const authorityMembersRouter = Router();

const MEMBER_SELECT = { id: true, email: true, name: true, role: true, isActive: true, invitedAt: true, acceptedAt: true } as const;

function hashesEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a, 'utf8').digest();
  const hb = createHash('sha256').update(b, 'utf8').digest();
  return timingSafeEqual(ha, hb);
}

// ---------------------------------------------------------------------------
// POST /bootstrap — the one-time path to an institution's first ADMIN
// ---------------------------------------------------------------------------

const bootstrapSchema = z.object({
  institutionId: z.string().min(1),
});

/**
 * POST /api/authority/bootstrap
 *
 * Refuses closed on every axis:
 *   - no `AUTHORITY_BOOTSTRAP_SECRET` configured -> the feature does not
 *     exist (500, not a silent no-op that LOOKS like "wrong secret")
 *   - wrong or missing `X-Authority-Bootstrap-Secret` -> 403
 *   - caller has no email on file -> 403 (same reason `requireAuthorityMember`
 *     refuses this: email is the only column `InstitutionMember` shares with
 *     `User`)
 *   - institution unknown or inactive -> 404
 *   - institution already has an active member (of EITHER role) -> 409, and
 *     says so; this is what makes the endpoint single-use per institution
 *     rather than a standing back door
 *
 * The count-then-create is wrapped in one transaction so a race between two
 * simultaneous bootstrap calls cannot both observe zero and both insert —
 * Postgres serialises the transaction's own reads and writes against
 * concurrent access to the same rows.
 */
authorityMembersRouter.post(
  '/bootstrap',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const secret = process.env.AUTHORITY_BOOTSTRAP_SECRET;
      if (!secret) {
        throw new AppError(
          ERROR_CODES.INTERNAL_ERROR,
          'AUTHORITY_BOOTSTRAP_SECRET is not configured on this server; bootstrap is disabled.',
          500,
        );
      }
      const provided = req.get('X-Authority-Bootstrap-Secret');
      if (!provided || !hashesEqual(provided, secret)) {
        throw new AppError(ERROR_CODES.AUTH_FORBIDDEN, 'Bootstrap secret missing or incorrect.', 403);
      }

      const user = (req as AuthenticatedRequest).user;
      if (!user?.email) {
        throw new AppError(
          ERROR_CODES.AUTH_FORBIDDEN,
          'This account has no email on file, so it cannot become an InstitutionMember.',
          403,
        );
      }

      const { institutionId } = bootstrapSchema.parse(req.body ?? {});

      const created = await db.$transaction(async (tx) => {
        const institution = await tx.institution.findFirst({
          where: { id: institutionId, isActive: true, type: { in: ['MINISTRY', 'REGULATOR'] } },
        });
        if (!institution) {
          throw new AppError(
            ERROR_CODES.NOT_FOUND,
            `No active L1 institution '${institutionId}'.`,
            404,
          );
        }

        const activeCount = await tx.institutionMember.count({
          where: { institutionId, isActive: true },
        });
        if (activeCount > 0) {
          throw new AppError(
            ERROR_CODES.INSTITUTION_MEMBER_CONFLICT,
            `'${institution.name}' already has an active roster; ask an existing ADMIN to add you via POST /api/authority/members.`,
            409,
          );
        }

        return tx.institutionMember.create({
          data: {
            institutionId,
            email: user.email as string,
            name: `${user.firstName ?? ''} ${user.lastName ?? ''}`.trim() || (user.email as string),
            role: 'ADMIN',
            acceptedAt: new Date(),
          },
          select: MEMBER_SELECT,
        });
      });

      await consentRepo.createAuditLog({
        eventType: AuditEventType.INSTITUTION_MEMBER_BOOTSTRAPPED,
        action: `${user.email} bootstrapped as the first ADMIN of institution ${institutionId}`,
        actorDid: user.did ?? undefined,
        resourceType: 'institutionMember',
        resourceId: created.id,
        details: { institutionId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      logger.info('authority_bootstrapped', { institutionId, memberId: created.id });

      res.status(201).json({ success: true, data: created, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  },
);

// ---------------------------------------------------------------------------
// GET /me — "who am I as an authority member"
// ---------------------------------------------------------------------------

/**
 * GET /api/authority/me
 *
 * ISSUER-CONSOLE-BUILD-NOTES.md §1 named the gap this closes: round 4's
 * console had no endpoint to answer "who am I" and worked around it by
 * calling `GET /api/authority/members` and parsing a 403's MESSAGE TEXT to
 * distinguish "not on the roster" from "on the roster, not ADMIN" — fragile,
 * because a reworded message silently breaks the inference with no type
 * error to catch it. `requireAuthorityMember` already resolves and attaches
 * both pieces of state this needs; this route only has to serialise them.
 *
 * Deliberately open to BOTH roles (unlike `GET /members`, which is
 * ADMIN-only): "who am I" is not roster management, and an OFFICER asking it
 * about themselves is not a privilege question.
 */
authorityMembersRouter.get(
  '/me',
  requireAuth,
  requireAuthorityMember,
  (req: Request, res: Response) => {
    const { authorityMember, authorityInstitution } = req as AuthorityMemberRequest;
    res.json({
      success: true,
      data: {
        member: {
          id: authorityMember.id,
          email: authorityMember.email,
          name: authorityMember.name,
          role: authorityMember.role,
        },
        institution: {
          id: authorityInstitution.id,
          did: authorityInstitution.did,
          name: authorityInstitution.name,
          type: authorityInstitution.type,
        },
      },
      timestamp: new Date().toISOString(),
    });
  },
);

// ---------------------------------------------------------------------------
// GET /members — ADMIN-only roster read
// ---------------------------------------------------------------------------

authorityMembersRouter.get(
  '/members',
  requireAuth,
  requireAuthorityMember,
  requireAuthorityRole('ADMIN'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { authorityInstitution: institution } = req as AuthorityMemberRequest;
      const members = await db.institutionMember.findMany({
        where: { institutionId: institution.id },
        orderBy: { invitedAt: 'asc' },
        select: MEMBER_SELECT,
      });
      res.json({ success: true, data: { members }, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  },
);

// ---------------------------------------------------------------------------
// POST /members — ADMIN adds a colleague
// ---------------------------------------------------------------------------

const createMemberSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(200),
  role: z.enum(['OFFICER', 'ADMIN']).default('OFFICER'),
});

authorityMembersRouter.post(
  '/members',
  requireAuth,
  requireAuthorityMember,
  requireAuthorityRole('ADMIN'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { authorityInstitution: institution, authorityMember: actor } = req as AuthorityMemberRequest;
      const input = createMemberSchema.parse(req.body ?? {});

      const existing = await db.institutionMember.findUnique({
        where: { institutionId_email: { institutionId: institution.id, email: input.email } },
      });
      if (existing) {
        throw new AppError(
          ERROR_CODES.INSTITUTION_MEMBER_CONFLICT,
          `'${input.email}' is already on this institution's roster (${existing.isActive ? 'active' : 'inactive'}, ${existing.role}). Use PATCH to change it.`,
          409,
        );
      }

      const created = await db.institutionMember.create({
        data: { institutionId: institution.id, email: input.email, name: input.name, role: input.role, acceptedAt: null },
        select: MEMBER_SELECT,
      });

      await consentRepo.createAuditLog({
        eventType: AuditEventType.INSTITUTION_MEMBER_ADDED,
        action: `${actor.email} added ${input.email} as ${input.role}`,
        actorDid: institution.did,
        resourceType: 'institutionMember',
        resourceId: created.id,
        details: { institutionId: institution.id, email: input.email, role: input.role, addedByMemberId: actor.id },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      logger.info('authority_member_added', { institutionId: institution.id, memberId: created.id, role: input.role });

      res.status(201).json({ success: true, data: created, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  },
);

// ---------------------------------------------------------------------------
// PATCH /members/:id — ADMIN changes role or active status
// ---------------------------------------------------------------------------

const updateMemberSchema = z
  .object({
    role: z.enum(['OFFICER', 'ADMIN']).optional(),
    isActive: z.boolean().optional(),
  })
  .refine((v) => v.role !== undefined || v.isActive !== undefined, {
    message: 'at least one of role or isActive is required',
  });

authorityMembersRouter.patch(
  '/members/:id',
  requireAuth,
  requireAuthorityMember,
  requireAuthorityRole('ADMIN'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { authorityInstitution: institution, authorityMember: actor } = req as AuthorityMemberRequest;
      const id = String(req.params.id);
      const input = updateMemberSchema.parse(req.body ?? {});

      const target = await db.institutionMember.findFirst({
        where: { id, institutionId: institution.id },
      });
      if (!target) {
        throw new AppError(ERROR_CODES.NOT_FOUND, 'No such member on this institution.', 404);
      }

      const removingLastAdmin =
        target.role === 'ADMIN' &&
        target.isActive &&
        ((input.role !== undefined && input.role !== 'ADMIN') || input.isActive === false);

      if (removingLastAdmin) {
        const otherActiveAdmins = await db.institutionMember.count({
          where: { institutionId: institution.id, role: 'ADMIN', isActive: true, id: { not: id } },
        });
        if (otherActiveAdmins === 0) {
          // Failsafe-first: refuse a change that would leave the roster with
          // no one able to reverse it, rather than allow a lockout that then
          // needs direct database access to undo.
          throw new AppError(
            ERROR_CODES.INSTITUTION_MEMBER_CONFLICT,
            'Refusing: this would remove the last active ADMIN of this institution, with no route left to undo it.',
            409,
          );
        }
      }

      const updated = await db.institutionMember.update({
        where: { id },
        data: {
          ...(input.role !== undefined ? { role: input.role } : {}),
          ...(input.isActive !== undefined ? { isActive: input.isActive } : {}),
        },
        select: MEMBER_SELECT,
      });

      await consentRepo.createAuditLog({
        eventType: AuditEventType.INSTITUTION_MEMBER_UPDATED,
        action: `${actor.email} updated ${target.email}: ${JSON.stringify(input)}`,
        actorDid: institution.did,
        resourceType: 'institutionMember',
        resourceId: id,
        details: { institutionId: institution.id, change: input, updatedByMemberId: actor.id },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      logger.info('authority_member_updated', { institutionId: institution.id, memberId: id, change: input });

      res.json({ success: true, data: updated, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  },
);
