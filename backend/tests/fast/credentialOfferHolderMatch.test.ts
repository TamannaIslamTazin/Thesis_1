/**
 * The offer-listing filter must NARROW on a missing identifier, never widen.
 *
 * Regression test for a real disclosure defect found on a handset 9 Sep 2026.
 * `GET /api/credentials/offers` built its holder filter as
 *
 *   OR: [ ...(user.did ? [{ holderDid: user.did }] : []), { holderEmail: user.email } ]
 *
 * The second clause was unguarded. That was harmless while every user had an
 * email — and became a wildcard the moment #398 removed email from citizen
 * signup, because Prisma renders `{ holderEmail: null }` as `holderEmail IS
 * NULL`. A doctor's wallet listed two other people's health-card offers.
 *
 * The property under test is the CLAUSE BUILDER, extracted here so it can be
 * checked without a database: given the identifiers a session actually has,
 * which match clauses are produced. Asserting on the clauses rather than on
 * query results is deliberate — the defect was that a clause EXISTED with a
 * null value, and a result-shaped assertion against a seeded database would
 * pass or fail depending on what happened to be seeded.
 */
import { describe, expect, it } from 'vitest';

/** Mirrors routes/credential.ts. Kept identical, deliberately duplicated. */
function holderMatchesFor(user: { did?: string | null; email?: string | null }) {
  return [
    ...(user.did ? [{ holderDid: user.did }] : []),
    ...(user.email ? [{ holderEmail: user.email }] : []),
  ];
}

describe('credential offer holder match', () => {
  it('a DID-only user matches on DID ALONE — no null email clause', () => {
    const clauses = holderMatchesFor({ did: 'did:cheqd:bdhealthtestnet:abc', email: null });
    expect(clauses).toEqual([{ holderDid: 'did:cheqd:bdhealthtestnet:abc' }]);
    // The defect stated directly: no clause may carry a null value, because
    // `field: null` is `field IS NULL` and selects rows belonging to others.
    for (const clause of clauses) {
      expect(Object.values(clause)).not.toContain(null);
      expect(Object.values(clause)).not.toContain(undefined);
    }
  });

  it('an email-only user still matches on email — the pairing that makes the above mean something', () => {
    // Without this, a builder that returned [] for EVERY input would satisfy
    // the assertions above perfectly while breaking the issuer console's
    // staff accounts, which are email-addressed by design (#398's exception).
    expect(holderMatchesFor({ did: null, email: 'officer@bmdc.bdhealthtrust.test' })).toEqual([
      { holderEmail: 'officer@bmdc.bdhealthtrust.test' },
    ]);
  });

  it('a user with both matches on either', () => {
    expect(holderMatchesFor({ did: 'did:x', email: 'a@b.test' })).toEqual([
      { holderDid: 'did:x' },
      { holderEmail: 'a@b.test' },
    ]);
  });

  it('a user with NEITHER produces no clauses, so the caller can answer empty', () => {
    // An empty OR must never reach the query. The route returns [] instead —
    // `OR: []` in Prisma matches NOTHING, but relying on that is relying on a
    // library detail for an authorization outcome.
    expect(holderMatchesFor({ did: null, email: null })).toEqual([]);
  });

  it('empty strings are treated as absent, not as a value to match', () => {
    // The offers observed leaking had holderEmail stored as '' in some rows
    // and NULL in others. A truthiness guard covers both; an `!= null` check
    // would not have.
    expect(holderMatchesFor({ did: '', email: '' })).toEqual([]);
  });
});
