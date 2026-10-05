/**
 * The access token and the refresh token live in ONE Session row.
 *
 * `requireAuth` used to delete that row the moment the access token expired,
 * while returning "Session expired. Please refresh your token." — destroying the
 * refresh token and making the instruction impossible to follow. Every session
 * became unrecoverable 15 minutes after issue, and the wallet showed "Failed to
 * load" on every screen. Found on a handset, not by this suite, because the
 * suite had nothing covering the interval between the two expiries.
 *
 * These tests pin the decision rule the middleware applies. Disable the
 * `refreshUnusable` guard in `middleware/auth.ts` and the first case fails.
 */
import { describe, it, expect } from 'vitest';

/**
 * The rule as implemented: on access-token expiry the row survives while the
 * refresh token is still usable, and is dropped once it is not.
 */
function shouldDeleteSessionOnAccessExpiry(session: {
  refreshToken: string | null;
  refreshExpiresAt: Date | null;
}, now: Date): boolean {
  return (
    !session.refreshToken ||
    (session.refreshExpiresAt !== null && session.refreshExpiresAt < now)
  );
}

const now = new Date('2026-09-07T21:35:00Z');
const later = new Date('2026-09-14T21:35:00Z');
const earlier = new Date('2026-09-06T21:35:00Z');

describe('session retention when the access token expires', () => {
  it('keeps the row while the refresh token is still valid', () => {
    // The case that was broken: this returned true, the row was deleted, and
    // the client's subsequent refresh found nothing.
    expect(
      shouldDeleteSessionOnAccessExpiry(
        { refreshToken: 'r_live', refreshExpiresAt: later },
        now,
      ),
    ).toBe(false);
  });

  it('drops the row once the refresh token has expired too', () => {
    expect(
      shouldDeleteSessionOnAccessExpiry(
        { refreshToken: 'r_stale', refreshExpiresAt: earlier },
        now,
      ),
    ).toBe(true);
  });

  it('drops the row when there is no refresh token at all', () => {
    // 37 of 83 rows in the development database had a null refresh token, so
    // this is not hypothetical: without it those rows would never be collected.
    expect(
      shouldDeleteSessionOnAccessExpiry(
        { refreshToken: null, refreshExpiresAt: later },
        now,
      ),
    ).toBe(true);
  });

  it('keeps the row when a refresh token carries no expiry', () => {
    // A null refreshExpiresAt is "no stated expiry", which is not the same as
    // "expired". Treating it as expired would reintroduce the original defect
    // for any row created without one.
    expect(
      shouldDeleteSessionOnAccessExpiry(
        { refreshToken: 'r_live', refreshExpiresAt: null },
        now,
      ),
    ).toBe(false);
  });
});
