/**
 * The enrolment token: what it protects, and what it deliberately does NOT do.
 *
 * ===========================================================================
 * THE SECURITY PROPERTY UNDER TEST
 * ===========================================================================
 * Possession of the QR must NOT mint anything. Redeeming it pairs the
 * institution's software to the officer's console session and stops there; the
 * officer then confirms what they saw on site, and only that mints.
 *
 * If a bitmap alone minted, the authorisation would come from whoever held the
 * screen, and the site visit — the one thing separating a real pharmacy from a
 * shell entity — would be decorative. So the tests below assert both halves:
 * a claimed token reports CLAIMED and nothing more, and completion requires the
 * SAME officer who created it.
 *
 * ===========================================================================
 * WHY THESE RUN AGAINST A FAKE STORE
 * ===========================================================================
 * The properties are about STATE TRANSITIONS and REFUSALS — unknown, expired,
 * spent, revoked, wrong officer — and a real database would add setup that
 * obscures them. The fake implements only the two operations the service uses,
 * so a call to anything else fails loudly rather than silently passing.
 *
 * EVERY REFUSAL IS PAIRED WITH A SUCCESS. A suite asserting only refusals passes
 * perfectly against code that refuses everything (#345, #347, #352).
 */
import { describe, expect, it, beforeEach, vi } from 'vitest';

const PENDING = 'PENDING';
const CLAIMED = 'CLAIMED';
const COMPLETED = 'COMPLETED';
const EXPIRED = 'EXPIRED';
const REVOKED = 'REVOKED';

interface Row {
  id: string;
  token: string;
  officerUserId: string;
  authorityId: string;
  status: string;
  expiresAt: Date;
  claimedBy: string | null;
  claimedAt: Date | null;
  institutionId: string | null;
}

const rows: Row[] = [];
let seq = 0;

function matchesWhere(row: Row, where: Record<string, unknown>): boolean {
  return Object.entries(where).every(([key, value]) => {
    if (key === 'id') return row.id === value;
    if (key === 'token') return row.token === value;
    if (key === 'officerUserId') return row.officerUserId === value;
    if (key === 'status') return row.status === value;
    return false;
  });
}

const fakeDb = {
  institutionEnrolment: {
    create: vi.fn(async ({ data }: { data: Partial<Row> }) => {
      const row = {
        id: `enr-${++seq}`,
        token: data.token!,
        officerUserId: data.officerUserId!,
        authorityId: data.authorityId!,
        status: data.status ?? PENDING,
        expiresAt: data.expiresAt!,
        claimedBy: null,
        claimedAt: null,
        institutionId: null,
      } as Row;
      rows.push(row);
      return row;
    }),
    findUnique: vi.fn(async ({ where }: { where: { token: string } }) => {
      if (where.token !== undefined) return rows.find((r) => r.token === where.token) ?? null;
      return rows.find((r) => matchesWhere(r, where)) ?? null;
    }),
    /** Prisma's updateMany returns a COUNT; the count is the atomicity proof. */
    updateMany: vi.fn(
      async ({ where, data }: { where: Record<string, unknown>; data: Partial<Row> }) => {
        const matched = rows.filter((r) => matchesWhere(r, where));
        for (const row of matched) Object.assign(row, data);
        return { count: matched.length };
      },
    ),
  },
};

vi.mock('../../src/db/index.js', () => ({ db: fakeDb }));
vi.mock('../../src/utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { createEnrolment, claimEnrolment, completeEnrolment, ENROLMENT_TTL_MS } = await import(
  '../../src/services/institutionEnrolment.js'
);

const OFFICER = 'officer-user-1';
const OTHER_OFFICER = 'officer-user-2';
const AUTHORITY = 'l1-pcb';

beforeEach(() => {
  rows.length = 0;
  seq = 0;
  vi.clearAllMocks();
});

describe('enrolment token — creation', () => {
  it('creates a PENDING token with a bounded life', async () => {
    const { token, expiresAt } = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    expect(token).toBeTruthy();
    expect(rows[0].status).toBe(PENDING);
    // The officer is standing there; a token is not a permanent credential.
    const ttl = expiresAt.getTime() - Date.now();
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(ENROLMENT_TTL_MS + 1000);
  });

  it('never reuses a token', async () => {
    const a = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    const b = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    expect(a.token).not.toBe(b.token);
  });
});

describe('enrolment token — claiming', () => {
  it('claims a pending token and reports it as CLAIMED, nothing more', async () => {
    const { token } = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    const claim = await claimEnrolment(token, 'hospital-software-1');
    expect(claim.ok).toBe(true);
    // THE PROPERTY: claiming produced no institution.
    expect(rows[0].status).toBe(CLAIMED);
    expect(rows[0].institutionId).toBeNull();
  });

  it('REFUSES an unknown token', async () => {
    const claim = await claimEnrolment('not-a-real-token', 'hospital-software-1');
    expect(claim).toEqual({ ok: false, reason: 'unknown token' });
  });

  it('REFUSES a second claim — two scanners must not both succeed', async () => {
    const { token } = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    const first = await claimEnrolment(token, 'software-A');
    const second = await claimEnrolment(token, 'software-B');
    expect(first.ok).toBe(true);
    expect(second).toEqual({ ok: false, reason: 'token already claimed' });
    // The first claimant is the one recorded; the second changed nothing.
    expect(rows[0].claimedBy).toBe('software-A');
  });

  it('REFUSES when the conditional update loses, EVEN IF the pre-check passed', async () => {
    // =====================================================================
    // THIS IS THE ATOMICITY TEST, and it exists because the test above cannot
    // reach it. A synchronous fake never interleaves, so the pre-check and the
    // conditional update can never disagree — meaning the two mutations that
    // remove `count !== 1` are BOTH undetectable through the ordinary path.
    //
    // The race is real regardless: between `findUnique` (sees PENDING) and
    // `updateMany` (claims it), another request can claim the same row. The
    // pre-check is a courtesy that produces a better message; the
    // conditional-update count is what actually enforces single use.
    //
    // So the guard is exercised by making the update report a loss, which is
    // exactly what it would report under contention.
    // =====================================================================
    const { token } = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    const row = rows.find((r) => r.token === token)!;

    // Simulate the loss: the row is PENDING for the read, then claimed by
    // someone else before this request's update lands.
    const original = fakeDb.institutionEnrolment.updateMany.getMockImplementation()!;
    fakeDb.institutionEnrolment.updateMany.mockImplementationOnce(async () => {
      row.status = CLAIMED;
      row.claimedBy = 'software-OTHER';
      return { count: 0 };
    });

    const claim = await claimEnrolment(token, 'software-A');
    expect(claim).toEqual({ ok: false, reason: 'token already claimed' });
    // The winner's claim stands; the loser changed nothing.
    expect(row.claimedBy).toBe('software-OTHER');

    fakeDb.institutionEnrolment.updateMany.mockImplementation(original);
  });

  it('REFUSES an expired token and records the expiry', async () => {
    const { token } = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    rows[0].expiresAt = new Date(Date.now() - 1000);
    const claim = await claimEnrolment(token, 'software-A');
    expect(claim).toEqual({ ok: false, reason: 'token expired' });
    expect(rows[0].status).toBe(EXPIRED);
  });

  it('REFUSES a revoked token', async () => {
    const { token } = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    rows[0].status = REVOKED;
    expect(await claimEnrolment(token, 'software-A')).toEqual({ ok: false, reason: 'token revoked' });
  });
});

describe('enrolment token — completion', () => {
  it('completes a claimed token for the SAME officer', async () => {
    const { token } = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    const claim = await claimEnrolment(token, 'software-A');
    if (!claim.ok) throw new Error('claim should have succeeded');

    await completeEnrolment({
      enrolmentId: claim.enrolmentId,
      institutionId: 'inst-1',
      officerUserId: OFFICER,
    });
    expect(rows[0].status).toBe(COMPLETED);
    expect(rows[0].institutionId).toBe('inst-1');
  });

  it('REFUSES completion by a DIFFERENT officer — a site visit is a person\'s act', async () => {
    const { token } = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    const claim = await claimEnrolment(token, 'software-A');
    if (!claim.ok) throw new Error('claim should have succeeded');

    // Another officer picking up an abandoned token would attribute someone
    // else's site visit to themselves, which is exactly what this record exists
    // to prevent.
    await expect(
      completeEnrolment({
        enrolmentId: claim.enrolmentId,
        institutionId: 'inst-1',
        officerUserId: OTHER_OFFICER,
      }),
    ).rejects.toThrow(/not claimed by this officer/i);

    expect(rows[0].status).toBe(CLAIMED);
    expect(rows[0].institutionId).toBeNull();
  });

  it('REFUSES completion of a token that was never claimed', async () => {
    const { token } = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    const row = rows.find((r) => r.token === token)!;
    await expect(
      completeEnrolment({ enrolmentId: row.id, institutionId: 'inst-1', officerUserId: OFFICER }),
    ).rejects.toThrow(/not claimed by this officer/i);
    expect(rows[0].status).toBe(PENDING);
  });

  it('REFUSES a second completion', async () => {
    const { token } = await createEnrolment({ officerUserId: OFFICER, authorityId: AUTHORITY });
    const claim = await claimEnrolment(token, 'software-A');
    if (!claim.ok) throw new Error('claim should have succeeded');

    await completeEnrolment({
      enrolmentId: claim.enrolmentId,
      institutionId: 'inst-1',
      officerUserId: OFFICER,
    });
    await expect(
      completeEnrolment({
        enrolmentId: claim.enrolmentId,
        institutionId: 'inst-2',
        officerUserId: OFFICER,
      }),
    ).rejects.toThrow(/not claimed by this officer/i);
    // The first institution stands.
    expect(rows[0].institutionId).toBe('inst-1');
  });
});
