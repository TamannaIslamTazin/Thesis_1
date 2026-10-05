/**
 * The counter's read of the 24-hour rule must agree with the backend's.
 *
 * ===========================================================================
 * WHY THE BOUNDARY IS PINNED IN BOTH DIRECTIONS
 * ===========================================================================
 * The backend's `tokenState` expires a token when `now - issuedAt >= 24h`, and
 * treats an unparseable issued-at as expired (fail-closed). The counter applies
 * the same rule in `lib/tokenExpiry.ts`; a disagreement at the boundary would
 * mean the desk warns about a token the backend would settle, or the reverse.
 * The suite therefore pins the millisecond either side of 24 hours, and pairs
 * every refusal with a success (#345/#347/#352).
 */
import { describe, expect, it } from 'vitest';
import { TOKEN_LIFETIME_MS, isTokenExpired, tokenExpiresAt } from '../src/lib/tokenExpiry';

const ISSUED = '2026-09-28T10:00:00.000Z';
const issuedMs = Date.parse(ISSUED);

describe('a token is alive until exactly 24 hours have passed', () => {
  // -- Successes. Without these, "expired always" passes the rest. --

  it('a token raised this minute is not expired', () => {
    expect(isTokenExpired(ISSUED, issuedMs + 60_000)).toBe(false);
  });

  it('one millisecond before 24 hours it is still alive', () => {
    expect(isTokenExpired(ISSUED, issuedMs + TOKEN_LIFETIME_MS - 1)).toBe(false);
  });

  // -- The boundary itself: expiry is >=, matching the backend. --

  it('exactly 24 hours after it was raised it is expired', () => {
    expect(isTokenExpired(ISSUED, issuedMs + TOKEN_LIFETIME_MS)).toBe(true);
  });

  it('one millisecond after 24 hours it is expired', () => {
    expect(isTokenExpired(ISSUED, issuedMs + TOKEN_LIFETIME_MS + 1)).toBe(true);
  });

  it('a token from yesterday is expired', () => {
    expect(isTokenExpired(ISSUED, issuedMs + 31 * 60 * 60 * 1000)).toBe(true);
  });

  // -- Fail closed on a timestamp that cannot be read, as the backend does. --

  it('an unparseable createdAt reads as expired, not as alive', () => {
    expect(isTokenExpired('not a date', issuedMs)).toBe(true);
    expect(isTokenExpired('', issuedMs)).toBe(true);
  });
});

describe('the expiry moment is one lifetime after it was raised', () => {
  it('is exactly createdAt plus 24 hours', () => {
    expect(tokenExpiresAt(ISSUED)).toBe(issuedMs + TOKEN_LIFETIME_MS);
  });

  it('is null when createdAt cannot be parsed', () => {
    expect(tokenExpiresAt('not a date')).toBeNull();
  });
});
