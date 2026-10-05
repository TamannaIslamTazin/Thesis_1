/**
 * Role gate layered on `requireAuthorityMember` (OFFICER-DOCUMENT-ACCESS.md
 * §7).
 *
 * Round 3 added `InstitutionMember.role` (`OFFICER` / `ADMIN`) but nothing
 * read it — every route in `routes/authority.ts` accepted any active member
 * regardless of role. This is the one place that gap closes for roster
 * management: an OFFICER who could create or re-role a colleague could create
 * a fresh ADMIN account under their own control, which collapses the two
 * roles back into one no matter what the schema says.
 *
 * Must run AFTER `requireAuthorityMember` — it reads
 * `(req as AuthorityMemberRequest).authorityMember`, which that middleware
 * attaches, and does not itself check membership or institution type.
 *
 * `routes/authority.ts`'s queue/approve/reject endpoints are UNCHANGED by
 * this file: OFFICER-DOCUMENT-ACCESS.md §7 and the schema's own comment on
 * `InstitutionMemberRole` describe queue review, approval and rejection as
 * work an OFFICER does, and say nothing that excludes an ADMIN from doing it
 * too — so those routes stay gated by `requireAuthorityMember` alone, open to
 * both roles. Only the roster-management routes this round adds
 * (`routes/authorityMembers.ts`) are additionally gated here.
 */

import type { Request, Response, NextFunction } from 'express';

import { AppError } from './errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import type { AuthorityMemberRequest } from './requireAuthorityMember.js';
import type { InstitutionMemberRole } from '../../prisma/generated/client/index.js';

export function requireAuthorityRole(...roles: readonly InstitutionMemberRole[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const { authorityMember } = req as AuthorityMemberRequest;

    if (!authorityMember) {
      // requireAuthorityMember did not run first, or did not attach. Fail
      // closed rather than treat an absent role as an implicit allow.
      next(
        new AppError(
          ERROR_CODES.AUTH_FORBIDDEN,
          'No authority membership on this request. requireAuthorityRole must run after requireAuthorityMember.',
          403,
        ),
      );
      return;
    }

    if (!roles.includes(authorityMember.role)) {
      next(
        new AppError(
          ERROR_CODES.AUTH_FORBIDDEN,
          `This action requires the role ${roles.join(' or ')}; '${authorityMember.email}' holds ${authorityMember.role}.`,
          403,
        ),
      );
      return;
    }

    next();
  };
}
