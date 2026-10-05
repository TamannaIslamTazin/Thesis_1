/**
 * Role gate for the L1 issuer dashboard (`routes/authority.ts`).
 *
 * L1 authorities — the ministry and the three professional councils — see
 * their own submission queue. L2 issuers (hospitals, clinics) must never
 * reach these routes (IDENTITY-VERIFICATION-API.md §5): this middleware is
 * the one place that boundary is enforced, by checking the caller's
 * `InstitutionMember` row is active AND belongs to an Institution of type
 * `MINISTRY` or `REGULATOR`.
 *
 * MEMBERSHIP IS MATCHED BY EMAIL, not by a foreign key from `User`.
 * `InstitutionMember` carries no `userId` column (round 4's schema-gap note:
 * "employment only" — see the model's own header) — it never has, this round
 * did not add one, and email is the only identifier the two tables share.
 * An account created through the DID-only signup path (spec §4) has no email
 * and therefore cannot hold an authority seat; that is refused explicitly
 * below rather than silently matching nothing.
 *
 * Must run AFTER `requireAuth` — it reads `(req as AuthenticatedRequest).user`
 * and does not itself check for a session.
 */

import type { Request, Response, NextFunction } from 'express';

import { AppError } from './errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import type { AuthenticatedRequest } from './auth.js';
import { db } from '../db/index.js';
import type { InstitutionMemberRole, InstitutionType } from '../../prisma/generated/client/index.js';

export interface AuthorityMemberRequest extends AuthenticatedRequest {
  authorityMember: {
    readonly id: string;
    readonly email: string;
    readonly name: string;
    readonly role: InstitutionMemberRole;
  };
  authorityInstitution: {
    readonly id: string;
    readonly did: string;
    readonly name: string;
    readonly type: InstitutionType;
  };
}

export async function requireAuthorityMember(
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const user = (req as AuthenticatedRequest).user;

    if (!user?.email) {
      throw new AppError(
        ERROR_CODES.AUTH_FORBIDDEN,
        'This account has no email on file, so it cannot be matched to an L1 issuing-authority staff roster.',
        403,
      );
    }

    const member = await db.institutionMember.findFirst({
      where: {
        email: user.email,
        isActive: true,
        institution: { isActive: true, type: { in: ['MINISTRY', 'REGULATOR'] } },
      },
      include: { institution: true },
    });

    if (!member) {
      throw new AppError(
        ERROR_CODES.AUTH_FORBIDDEN,
        'Not an active staff member of an L1 issuing authority (ministry or professional council).',
        403,
      );
    }

    if (!member.institution.did) {
      // Fails closed rather than letting a queue exist with nowhere to route
      // an approval's credential issuance — see routes/authority.ts's approve.
      throw new AppError(
        ERROR_CODES.INTERNAL_ERROR,
        `Institution '${member.institution.name}' has no DID configured and cannot act as an issuing authority.`,
        500,
      );
    }

    (req as AuthorityMemberRequest).authorityMember = {
      id: member.id,
      email: member.email,
      name: member.name,
      role: member.role,
    };
    (req as AuthorityMemberRequest).authorityInstitution = {
      id: member.institution.id,
      did: member.institution.did,
      name: member.institution.name,
      type: member.institution.type,
    };

    next();
  } catch (error) {
    next(error);
  }
}
