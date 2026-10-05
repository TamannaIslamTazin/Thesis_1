import { ApiError, getMe, type AuthorityMember, type AuthorityRole } from '@/lib/api';

export type AuthorityIdentity =
  | { readonly member: true; readonly role: AuthorityRole; readonly self: AuthorityMember | null }
  | { readonly member: false };

/**
 * Round 5 added `GET /api/authority/me`, closing the gap
 * ISSUER-CONSOLE-BUILD-NOTES.md §1 recorded: round 4 had no endpoint that
 * answered "who am I as an authority member" and worked around it by calling
 * `GET /api/authority/members` and matching a 403's MESSAGE TEXT to tell
 * "not on any roster" apart from "on the roster, not ADMIN" — fragile, since
 * a reworded message would silently break the inference with no type error.
 *
 * `GET /me` is open to both roles and returns the caller's own membership
 * directly, so this function is now a direct translation: 200 means a
 * member (with their real role attached), 403 means not a member, anything
 * else propagates.
 *
 * This is read for UI presentation only (which tabs to show). The server
 * re-checks every one of these gates independently on every request this
 * console makes — see `packages/backend/src/middleware/requireAuthorityRole.ts`
 * — so a wrong inference here costs a hidden tab, not a bypassed permission.
 */
export async function resolveAuthorityIdentity(_selfEmail: string | null): Promise<AuthorityIdentity> {
  try {
    const me = await getMe();
    return {
      member: true,
      role: me.member.role,
      self: { ...me.member, isActive: true, invitedAt: '', acceptedAt: '' },
    };
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return { member: false };
    }
    throw error;
  }
}
