/**
 * The counter's read of the 24-hour token rule (A1 stage 4b).
 *
 * ===========================================================================
 * WHAT THIS IS FOR
 * ===========================================================================
 * A queue token raised more than 24 hours ago and still open can no longer be
 * settled. The backend applies that rule when it READS the append (`tokenState`
 * in packages/backend/src/services/tokenSettlement.ts), so a settle attempt on
 * such a token is refused with 409 ALREADY_TERMINAL. The refusal is correct but
 * late: by then the operator has taken the money and pressed the button. This
 * module exists so the desk can say "this token has expired" BEFORE that.
 *
 * ===========================================================================
 * WHERE IT RUNS, AND WHAT IT IS NOT
 * ===========================================================================
 * It runs in the counter's SERVER routes (list and settle), never in the
 * browser. A browser clock is defeatable by changing the device's date, and a
 * device clock must never be the authority (steno #584,
 * __docs__/design/TOKEN-EXPIRY-CLOCK-OWNERSHIP.md).
 *
 * It is ALSO NOT THE ENFORCEMENT. The backend refuses the settle; this only
 * stops the counter walking into that refusal. The counter server and the
 * backend are different clocks in a real deployment, so the backend stays the
 * authority: if the two disagree, its 409 wins and the desk shows it.
 *
 * ===========================================================================
 * WHY THE CONSTANT IS DUPLICATED
 * ===========================================================================
 * This package is deliberately standalone (one container, no workspace package
 * at runtime), so it cannot import the backend's TOKEN_LIFETIME_MS. The rule is
 * duplicated here in one place, and the test pins the same boundary values the
 * backend's tests pin; a policy change moves both together.
 */

/** 24 hours, in milliseconds. The same policy as the backend's TOKEN_LIFETIME_MS. */
export const TOKEN_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** The moment this token dies, or null when createdAt cannot be read. */
export function tokenExpiresAt(createdAt: string): number | null {
  const created = Date.parse(createdAt);
  if (Number.isNaN(created)) return null;
  return created + TOKEN_LIFETIME_MS;
}

/**
 * True when the token is past its 24-hour window.
 *
 * Fail-closed on an unreadable timestamp: the backend's `tokenState` treats an
 * unparseable issued-at as expired, and two readers of the same rule must not
 * disagree. `now` is injected so the boundary can be tested at exactly 24 hours
 * rather than by sleeping; callers pass the server's clock.
 */
export function isTokenExpired(createdAt: string, now: number = Date.now()): boolean {
  const expiresAt = tokenExpiresAt(createdAt);
  if (expiresAt === null) return true;
  return now >= expiresAt;
}
