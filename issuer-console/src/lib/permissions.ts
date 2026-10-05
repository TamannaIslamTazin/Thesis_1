import type { AuthorityRole } from '@/lib/api';

/**
 * What each role may do, mirrored from the server-side gates this console
 * calls against:
 *
 *   - `requireAuthorityMember` (packages/backend/src/middleware/requireAuthorityMember.ts)
 *     admits any active OFFICER or ADMIN to queue/review/approve/reject.
 *   - `requireAuthorityRole('ADMIN')` (requireAuthorityRole.ts) additionally
 *     gates roster management.
 *
 * This is presentation only — hiding the "Roster" tab from an OFFICER saves
 * them a 403 they cannot act on. The server enforces the boundary
 * independently and refuses the request either way; this module must never
 * be the only thing standing between an OFFICER and a roster mutation.
 */
export interface AuthorityPermissions {
  readonly canReviewQueue: boolean;
  readonly canManageRoster: boolean;
  /**
   * Onboarding an L2 institution — ADMIN only, and STRICTER than reviewing the
   * queue for the same reason roster management is.
   *
   * Minting an institution is strictly more powerful than creating a member: an
   * OFFICER who could mint an arbitrary institution could invent an entity, have
   * it licensed, and append dispensing records against a pharmacy that never
   * existed. The server enforces this with `requireAuthorityRole('ADMIN')` on the
   * mint route; this flag only decides whether the link is worth showing.
   */
  readonly canOnboardInstitution: boolean;
}

export function permissionsForRole(role: AuthorityRole): AuthorityPermissions {
  return {
    canReviewQueue: role === 'OFFICER' || role === 'ADMIN',
    canManageRoster: role === 'ADMIN',
    canOnboardInstitution: role === 'ADMIN',
  };
}
