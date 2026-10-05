/**
 * Enrolling an L2 institution: the officer's one-time QR.
 *
 * ===========================================================================
 * WHAT THIS IS FOR
 * ===========================================================================
 * An L1 officer stands inside a hospital or pharmacy and is satisfied it is real.
 * The institution's own software then needs to become THAT entity on the ledger —
 * and the software is on a counter PC nobody wants to configure, so it scans a QR
 * the officer shows it.
 *
 * ===========================================================================
 * THE TOKEN MINTS NOTHING. THE OFFICER DOES.
 * ===========================================================================
 * Redeeming the token PAIRS the institution's software to the officer's console
 * session and stops there. The officer then confirms what they actually saw on
 * site — name, address, licence number — and that confirmation is what mints the
 * DID.
 *
 * This is deliberate and it is the point of the feature. If possession of the QR
 * were sufficient, the authorisation would come from a bitmap, and the site visit
 * — the one thing that distinguishes a real pharmacy from a shell entity — would
 * be decorative. A token that has left the officer's screen is therefore a token
 * whose holder has proved attention, not authority.
 *
 * ===========================================================================
 * SINGLE USE, CLAIMED ATOMICALLY
 * ===========================================================================
 * Two phones must not both succeed. The claim is
 * `updateMany({ where: { id, status: 'PENDING' } })` and `count !== 1` is the
 * loss — the same shape as `consumeChallenge` and the console's single-use key
 * release. A read-then-write would let both scans pass a check neither could fail.
 */
import { randomBytes } from 'node:crypto';
import { db } from '../db/index.js';
import { logger } from '../utils/logger.js';

/** Short. The officer is standing there; a token left on screen overnight is a leak. */
export const ENROLMENT_TTL_MS = 10 * 60 * 1000;

export type EnrolmentRefusal =
  | { ok: false; reason: 'unknown token' }
  | { ok: false; reason: 'token expired' }
  | { ok: false; reason: 'token already claimed' }
  | { ok: false; reason: 'token revoked' };

export type EnrolmentClaim =
  | {
      ok: true;
      enrolmentId: string;
      officerMemberId: string;
      authorityId: string;
    }
  | EnrolmentRefusal;

/**
 * Create a token for an officer to display.
 *
 * `authorityId` is the L1 authority the officer acts for, and it is recorded on
 * the enrolment rather than derived later — the DID's trust anchor must be
 * whatever was true when the officer stood there, not whatever their roster row
 * says at mint time.
 */
export async function createEnrolment(params: {
  officerMemberId: string;
  authorityId: string;
  /** Human-readable hint shown on the officer's screen, e.g. "Stood at Mirpur, Dhaka". */
  note?: string;
}): Promise<{ enrolmentId: string; token: string; expiresAt: Date }> {
  const token = randomBytes(24).toString('base64url');
  const expiresAt = new Date(Date.now() + ENROLMENT_TTL_MS);

  const row = await db.institutionEnrolment.create({
    data: {
      token,
      officerMemberId: params.officerMemberId,
      authorityId: params.authorityId,
      status: 'PENDING',
      expiresAt,
    },
  });

  logger.info('institution_enrolment_created', {
    officerMemberId: params.officerMemberId,
    authorityId: params.authorityId,
    expiresAt: expiresAt.toISOString(),
    // The token is NOT logged. It is a bearer secret until claimed, and a log
    // line outlives the ten minutes it is valid for.
  });

  return { enrolmentId: row.id, token, expiresAt };
}

/**
 * Spend a token, atomically.
 *
 * Claiming does not create anything. It records that THIS software is the one
 * waiting, so the officer's console can show them what they are about to
 * confirm — and so a scan is visible as an event rather than assumed.
 */
export async function claimEnrolment(
  token: string,
  claimedBy: string,
  /** The software's own Ed25519 public key, multibase-encoded, when it has one. */
  claimantPublicKey?: string | null,
): Promise<EnrolmentClaim> {
  const row = await db.institutionEnrolment.findUnique({ where: { token } });
  if (!row) return { ok: false, reason: 'unknown token' };

  if (row.status === 'REVOKED') return { ok: false, reason: 'token revoked' };
  if (row.status !== 'PENDING') return { ok: false, reason: 'token already claimed' };

  if (row.expiresAt <= new Date()) {
    // Best-effort bookkeeping; the refusal does not depend on it landing.
    await db.institutionEnrolment
      .updateMany({ where: { id: row.id, status: 'PENDING' }, data: { status: 'EXPIRED' } })
      .catch(() => undefined);
    return { ok: false, reason: 'token expired' };
  }

  const claimed = await db.institutionEnrolment.updateMany({
    where: { id: row.id, status: 'PENDING' },
    data: {
      status: 'CLAIMED',
      claimedAt: new Date(),
      claimedBy,
      claimantPublicKey: claimantPublicKey?.trim() ?? null,
    },
  });

  if (claimed.count !== 1) return { ok: false, reason: 'token already claimed' };

  logger.info('institution_enrolment_claimed', {
    enrolmentId: row.id,
    officerMemberId: row.officerMemberId,
    authorityId: row.authorityId,
  });

  return {
    ok: true,
    enrolmentId: row.id,
    officerMemberId: row.officerMemberId,
    authorityId: row.authorityId,
  };
}

/**
 * Bind a created institution to its enrolment, closing the token out.
 *
 * Called ONLY after the officer confirms, so a COMPLETED enrolment means a person
 * looked at the details and said yes.
 */
export async function completeEnrolment(params: {
  enrolmentId: string;
  institutionId: string;
  officerMemberId: string;
}): Promise<void> {
  const done = await db.institutionEnrolment.updateMany({
    where: {
      id: params.enrolmentId,
      status: 'CLAIMED',
      // Only the officer who created it may complete it. A different officer
      // picking up an abandoned token would attribute someone else's site visit
      // to them, which is exactly the accountability this record exists for.
      officerMemberId: params.officerMemberId,
    },
    data: { status: 'COMPLETED', institutionId: params.institutionId },
  });

  if (done.count !== 1) {
    throw new Error(
      'The enrolment could not be completed: it is not claimed by this officer, or was already completed.',
    );
  }

  logger.info('institution_enrolment_completed', {
    enrolmentId: params.enrolmentId,
    institutionId: params.institutionId,
    officerMemberId: params.officerMemberId,
  });
}
