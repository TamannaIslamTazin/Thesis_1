/**
 * SSI Healthcare Backend - Emergency Access Service (Break-Glass)
 *
 * Implements Paradigm B from the thesis: break-glass emergency access
 * where a healthcare provider can access patient credentials in an emergency
 * without the patient's explicit real-time consent.
 *
 * - Time-limited access window (default: 60 minutes)
 * - Family notification on access
 * - Full audit trail
 * - Auto-expiration
 * - Database persistence REQUIRED (no in-memory fallback for healthcare data)
 */

import { randomUUID } from 'node:crypto';
import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import {
  ERROR_CODES,
  SYSTEM_DEFAULTS,
  EmergencyAccessStatus,
  type EmergencyAccessRecord,
} from '@ssi-healthcare/shared';
import { db } from '../db/index.js';
import { verifyRecoveryKeySignature } from '@ssi-healthcare/shared';
import { ed25519PublicKeyFromMultibase } from '@ssi-healthcare/sdk/ledger';
import {
  EmergencyAccessStatus as PrismaEmergencyStatus,
  AuditEventType as PrismaAuditEventType,
} from '../../prisma/generated/client/index.js';

// ---------------------------------------------------------------------------
// Status Mapping (Prisma <-> Shared)
// ---------------------------------------------------------------------------

function statusToShared(status: PrismaEmergencyStatus): EmergencyAccessStatus {
  switch (status) {
    case 'REQUESTED':
      return EmergencyAccessStatus.REQUESTED;
    case 'GRANTED':
      return EmergencyAccessStatus.GRANTED;
    case 'EXPIRED':
      return EmergencyAccessStatus.EXPIRED;
    case 'REVOKED':
      return EmergencyAccessStatus.REVOKED;
    default:
      return EmergencyAccessStatus.GRANTED;
  }
}

// ---------------------------------------------------------------------------
// Emergency Access Operations
// ---------------------------------------------------------------------------

/**
 * Request emergency break-glass access to a patient's credentials.
 * Database persistence is REQUIRED — emergency access without an audit trail
 * is unacceptable in a healthcare identity system.
 */
export async function requestEmergencyAccess(params: {
  providerDid: string;
  providerName: string;
  patientDid: string;
  reason: string;
  credentialIds: string[];
  familyContactDid?: string;
  providerRole?: string;
  providerInstitution?: string;
}): Promise<EmergencyAccessRecord> {
  const {
    providerDid,
    providerName,
    patientDid,
    reason,
    credentialIds,
    familyContactDid,
    providerRole = 'healthcare_provider',
    providerInstitution = 'unknown',
  } = params;

  // Validate provider DID is non-empty and starts with 'did:'
  if (!providerDid || !providerDid.startsWith('did:')) {
    throw new AppError(
      ERROR_CODES.VALIDATION_FAILED,
      'Valid provider DID is required for emergency access',
      400,
    );
  }

  // Validate reason is substantive
  if (!reason || reason.trim().length < 10) {
    throw new AppError(
      ERROR_CODES.VALIDATION_FAILED,
      'Emergency access requires a substantive reason (minimum 10 characters)',
      400,
    );
  }

  const now = new Date();
  const expiresAt = new Date(
    now.getTime() + SYSTEM_DEFAULTS.EMERGENCY_ACCESS_DURATION_MINUTES * 60 * 1000,
  );

  const dbRecord = await db.emergencyAccessRecord.create({
    data: {
      patientDid,
      requesterDid: providerDid,
      requesterName: providerName,
      requesterRole: providerRole,
      requesterInstitution: providerInstitution,
      reason,
      credentialsAccessed: credentialIds,
      accessLevel: 'LIMITED',
      status: 'GRANTED',
      grantedAt: now,
      expiresAt,
    },
  });

  const record: EmergencyAccessRecord = {
    id: dbRecord.id,
    patientDid: dbRecord.patientDid,
    providerDid: dbRecord.requesterDid,
    providerName: dbRecord.requesterName,
    reason: dbRecord.reason,
    status: EmergencyAccessStatus.GRANTED,
    credentialIdsAccessed: dbRecord.credentialsAccessed,
    requestedAt: dbRecord.grantedAt.toISOString(),
    grantedAt: dbRecord.grantedAt.toISOString(),
    expiresAt: dbRecord.expiresAt.toISOString(),
    familyContactDid,
    // NOT SET, and that is the correction.
    //
    // This was `familyContactDid ? now.toISOString() : undefined` — it stamped a
    // notification time whenever a contact DID was supplied, while NO
    // NOTIFICATION CODE EXISTS anywhere in this service. The record asserted a
    // safeguard had fired, and the audit entry below said `familyNotified: true`
    // to match. Fabricating evidence of a safeguard is worse than lacking one:
    // an unimplemented feature is discovered the first time someone looks for
    // it, whereas a false record is believed precisely when it matters, during
    // the review of an access the patient is disputing.
    //
    // Set this only from code that has actually delivered a notification.
    familyNotifiedAt: undefined,
  };

  // Audit trail
  await db.auditLog.create({
    data: {
      actorDid: providerDid,
      targetDid: patientDid,
      eventType: PrismaAuditEventType.EMERGENCY_ACCESS_ACTIVATED,
      action: `Emergency access requested: ${reason}`,
      details: {
        emergencyId: record.id,
        credentialIds,
        expiresAt: expiresAt.toISOString(),
        // What is TRUE: a contact was named. Not that anyone was told.
        familyContactNamed: !!familyContactDid,
        familyNotificationDelivered: false,
        familyNotificationChannel: 'NOT_IMPLEMENTED',
        grantModel: 'AUTO_GRANT_ON_SIGNED_REQUEST',
      },
    },
  });

  logger.warn('EMERGENCY ACCESS GRANTED', {
    emergencyId: record.id,
    providerDid,
    providerName,
    patientDid,
    reason,
    credentialCount: credentialIds.length,
    expiresAt: expiresAt.toISOString(),
    familyContactNamed: !!familyContactDid,
    familyNotificationDelivered: false,
  });

  return record;
}

// ---------------------------------------------------------------------------
// BREAK-GLASS BY SIGNATURE — a hospital needs a DID, not an account with us
// ---------------------------------------------------------------------------
//
// The session-authenticated route below works, but it cannot be how a hospital
// reaches this: `requireWallet` needs a user row and a session, which would make
// every provider in the country a registered user of the ministry's backend —
// the same centralisation the consent foreign key was removed for.
//
// The alternative was NOT available by the obvious path. An institutional DID
// carries exactly one `authentication` key and that slot must stay agent-held
// (see LEDGER_SIGNING_FRAGMENT): `@cheqd/sdk` computes its required signer set
// from `authentication` on both document versions, so a foreign-held slot whose
// key is lost blocks every future update. A hospital therefore cannot hold the
// authentication key, and DID *login* is closed to it.
//
// What a hospital CAN hold is an officer key in `assertionMethod`, which is the
// right relationship anyway: it is ASSERTING an emergency, not logging in. So
// the signature authenticates the request itself, exactly as it does for an
// OID4VP response — requiring a session on top would say the server's opinion of
// who you are matters more than your key.
//
// THE PAYLOAD IS MATERIALISED BY THE SERVER, never templated by the client.
// This is the locker's lesson (#401/#402): a "template" the client fills in is a
// canonicalisation contract in disguise, and the two sides drift. The server
// emits the exact bytes to sign; the client signs them unmodified or fails.

type BreakGlassPurpose = 'open' | 'read';

interface BreakGlassChallenge {
  readonly purpose: BreakGlassPurpose;
  readonly payload: string;
  readonly providerDid: string;
  readonly patientDid: string;
  readonly reason: string;
  readonly credentialIds: string[];
  readonly expiresAt: number;
}

/**
 * Single-use, short-lived, in memory.
 *
 * In memory is a deliberate limitation, not an oversight: a restart voids
 * outstanding challenges, which fails CLOSED — a provider retries and gets a new
 * one. Persisting them would add a replay surface to buy nothing.
 */
const breakGlassChallenges = new Map<string, BreakGlassChallenge>();
const BREAK_GLASS_CHALLENGE_TTL_MS = 120_000;

function sweepChallenges(now: number): void {
  for (const [id, c] of breakGlassChallenges) {
    if (c.expiresAt <= now) breakGlassChallenges.delete(id);
  }
}

/**
 * Mint the exact bytes a provider must sign to open break-glass access.
 *
 * The reason and the credential list are bound INTO the signed payload, so a
 * provider cannot obtain a signature for "checking a blood type" and spend it on
 * a different patient or a wider set of records. The nonce makes it single-use.
 */
export function createBreakGlassChallenge(params: {
  providerDid: string;
  patientDid: string;
  reason: string;
  credentialIds: string[];
  /**
   * `open` starts a grant; `read` spends an existing one.
   *
   * Bound into the signed bytes so a signature obtained to OPEN access cannot be
   * replayed to READ, or the reverse. Two acts, two audit entries, two
   * signatures — that separation is the whole reason a grant and a read remain
   * distinguishable afterwards.
   */
  purpose?: BreakGlassPurpose;
}): { challengeId: string; payload: string; expiresAt: string } {
  const now = Date.now();
  sweepChallenges(now);

  const challengeId = randomUUID();
  const nonce = randomUUID();
  // Line-oriented and fully materialised. Not JSON: JSON invites the client to
  // re-serialise, and key order is where that goes wrong silently.
  const purpose: BreakGlassPurpose = params.purpose ?? 'open';
  const payload = [
    `bdhealthtrust-break-glass-v1:${purpose}`,
    `provider:${params.providerDid}`,
    `patient:${params.patientDid}`,
    `reason:${params.reason}`,
    `credentials:${[...params.credentialIds].sort().join(',')}`,
    `nonce:${nonce}`,
    `challenge:${challengeId}`,
  ].join('\n');

  breakGlassChallenges.set(challengeId, {
    purpose,
    payload,
    providerDid: params.providerDid,
    patientDid: params.patientDid,
    reason: params.reason,
    credentialIds: params.credentialIds,
    expiresAt: now + BREAK_GLASS_CHALLENGE_TTL_MS,
  });

  return {
    challengeId,
    payload,
    expiresAt: new Date(now + BREAK_GLASS_CHALLENGE_TTL_MS).toISOString(),
  };
}

/**
 * Open break-glass access on a SIGNED request, with no session at all.
 *
 * Fails closed at every step, and a failure is audited: an unattributable
 * attempt to open someone's records is itself something the patient should be
 * able to see.
 */
type DidDocumentReader = (did: string) => Promise<{
  verificationMethod?: Array<{ id: string; publicKeyMultibase?: string }>;
  assertionMethod?: Array<string | { id: string }>;
} | null>;

/**
 * Spend a challenge: verify the signature and return what it committed to.
 *
 * Shared by both signed entry points so the checks cannot diverge. A second copy
 * of "may this key speak for this DID" is exactly the duplication that drifts
 * and then fails open on one path only.
 */
async function spendBreakGlassChallenge(params: {
  challengeId: string;
  verificationMethodId: string;
  signatureBase64Url: string;
  expectedPurpose: BreakGlassPurpose;
  resolveDidDocument: DidDocumentReader;
}): Promise<BreakGlassChallenge> {
  const now = Date.now();
  sweepChallenges(now);

  // SINGLE USE: removed before anything can fail, so a rejected signature
  // cannot be retried against the same nonce.
  const challenge = breakGlassChallenges.get(params.challengeId);
  breakGlassChallenges.delete(params.challengeId);

  if (!challenge || challenge.expiresAt <= now) {
    throw new AppError(
      ERROR_CODES.EMERGENCY_ACCESS_DENIED,
      'Break-glass challenge is unknown or expired. Request a new one.',
      400,
    );
  }
  if (challenge.purpose !== params.expectedPurpose) {
    throw new AppError(
      ERROR_CODES.EMERGENCY_ACCESS_DENIED,
      `This challenge was issued to ${challenge.purpose} access, not to ${params.expectedPurpose} it.`,
      400,
    );
  }

  // ATTRIBUTION BY VM ID PREFIX (#281), never by the controller field.
  const signerDid = params.verificationMethodId.split('#')[0];
  if (signerDid !== challenge.providerDid) {
    throw new AppError(
      ERROR_CODES.EMERGENCY_ACCESS_DENIED,
      `Signing key belongs to ${signerDid}, but the request names ${challenge.providerDid}.`,
      403,
    );
  }

  const document = await params.resolveDidDocument(challenge.providerDid);
  const method = document?.verificationMethod?.find((m) => m.id === params.verificationMethodId);
  const assertionIds = (document?.assertionMethod ?? []).map((a) =>
    typeof a === 'string' ? a : a.id,
  );

  // Published FOR ASSERTION. Merely existing in the document is not authority to
  // speak for it, and assertion is the correct relationship here: the hospital
  // is asserting an emergency, not logging in.
  if (!method?.publicKeyMultibase || !assertionIds.includes(params.verificationMethodId)) {
    throw new AppError(
      ERROR_CODES.EMERGENCY_ACCESS_DENIED,
      `${params.verificationMethodId} is not published for assertion by ${challenge.providerDid}.`,
      403,
    );
  }

  const signatureValid = verifyRecoveryKeySignature(
    ed25519PublicKeyFromMultibase(method.publicKeyMultibase),
    new TextEncoder().encode(challenge.payload),
    Buffer.from(params.signatureBase64Url, 'base64url'),
  );

  if (!signatureValid) {
    await db.auditLog.create({
      data: {
        actorDid: challenge.providerDid,
        targetDid: challenge.patientDid,
        eventType: PrismaAuditEventType.EMERGENCY_ACCESS_ACTIVATED,
        action: `Break-glass ${params.expectedPurpose} REFUSED — signature did not verify`,
        details: { refused: true, verificationMethodId: params.verificationMethodId },
      },
    });
    throw new AppError(
      ERROR_CODES.EMERGENCY_ACCESS_DENIED,
      'Break-glass signature did not verify against the provider DID document.',
      403,
    );
  }

  return challenge;
}

/** Open break-glass access on a SIGNED request, with no session at all. */
export async function requestEmergencyAccessBySignature(params: {
  challengeId: string;
  verificationMethodId: string;
  signatureBase64Url: string;
  providerName: string;
  resolveDidDocument: DidDocumentReader;
}): Promise<EmergencyAccessRecord> {
  const challenge = await spendBreakGlassChallenge({ ...params, expectedPurpose: 'open' });

  // Everything below comes from the CHALLENGE, never from the request body: the
  // signature covers those values, and re-reading them from the wire would let a
  // caller sign for one patient and open another.
  return requestEmergencyAccess({
    providerDid: challenge.providerDid,
    providerName: params.providerName,
    patientDid: challenge.patientDid,
    reason: challenge.reason,
    credentialIds: challenge.credentialIds,
  });
}

/** Read a patient's credentials on a SIGNED request, with no session. */
export async function readEmergencyCredentialsBySignature(params: {
  challengeId: string;
  verificationMethodId: string;
  signatureBase64Url: string;
  resolveDidDocument: DidDocumentReader;
}): Promise<{ credentials: unknown[]; emergencyId: string; expiresAt: string }> {
  const challenge = await spendBreakGlassChallenge({ ...params, expectedPurpose: 'read' });
  return readEmergencyCredentials({
    providerDid: challenge.providerDid,
    patientDid: challenge.patientDid,
  });
}

/**
 * Read a patient's credentials under an ACTIVE emergency grant.
 *
 * ===========================================================================
 * WHY THIS EXISTS: A GRANT THAT GRANTS NOTHING IS NOT A SAFEGUARD, IT IS A LOG
 * ===========================================================================
 * Until this function, `checkEmergencyAccess` was called by exactly one caller —
 * its own route — and no credential read path consulted an emergency record. So
 * break-glass created a row saying access had been granted while conferring no
 * access at all. That is dangerous in BOTH directions: a provider in a real
 * emergency gets nothing, and a reviewer reading the table believes data was
 * reached when it was not.
 *
 * ===========================================================================
 * THE GRANT MODEL IS AUTO-GRANT, AND THE SAFETY NET IS DETECTION
 * ===========================================================================
 * Access is granted on a signed provider request without patient approval,
 * deliberately: the patient may be unconscious, and that is the entire situation
 * break-glass exists for. Requiring approval fails closed exactly when failing
 * closed can kill someone. The compensating controls are therefore all about
 * making misuse VISIBLE and SHORT rather than impossible — expiry, one-tap
 * revocation, an audit entry per grant AND per read, and a patient-facing alarm.
 * This is #302 applied to a case where the damage of refusing exceeds the damage
 * of granting, and #293: detection latency is the load-bearing control.
 *
 * ===========================================================================
 * WHAT IS LOGGED, AND WHY PER-READ AND NOT JUST PER-GRANT
 * ===========================================================================
 * A grant records what a provider was ALLOWED to see. Only a read records what
 * they ACTUALLY saw. Those differ whenever a provider requests broadly and looks
 * narrowly, which is the common case, and the patient's question afterwards is
 * always the second one.
 *
 * EMERGENCY READS ARE FULL DISCLOSURE, unavoidably: there is no holder present
 * to choose a disclosure frame, so the whole credential is returned. That is
 * recorded plainly rather than being left to look like a selective disclosure.
 */
export async function readEmergencyCredentials(params: {
  providerDid: string;
  patientDid: string;
}): Promise<{ credentials: unknown[]; emergencyId: string; expiresAt: string }> {
  const { providerDid, patientDid } = params;

  // FAIL CLOSED. No active grant means no data, and the refusal is logged so a
  // probe for someone else's records is itself visible.
  const access = await checkEmergencyAccess(providerDid, patientDid);
  if (!access.isActive || !access.record) {
    await db.auditLog.create({
      data: {
        actorDid: providerDid,
        targetDid: patientDid,
        eventType: PrismaAuditEventType.EMERGENCY_ACCESS_ACTIVATED,
        action: 'Emergency credential read REFUSED — no active grant',
        details: { refused: true, reason: 'NO_ACTIVE_EMERGENCY_GRANT' },
      },
    });
    throw new AppError(
      ERROR_CODES.EMERGENCY_ACCESS_DENIED,
      'No active emergency access for this patient. Request break-glass access first.',
      403,
    );
  }

  // Only what the grant named. A provider cannot widen their reach after the
  // fact by asking for a different credential id than the one they justified.
  const credentials = await db.credential.findMany({
    where: {
      holderDid: patientDid,
      id: { in: access.record.credentialIdsAccessed },
    },
    select: {
      id: true,
      type: true,
      issuerDid: true,
      credentialData: true,
      credentialFormat: true,
      status: true,
      issuedAt: true,
    },
  });

  await db.auditLog.create({
    data: {
      actorDid: providerDid,
      targetDid: patientDid,
      eventType: PrismaAuditEventType.EMERGENCY_ACCESS_ACTIVATED,
      action: `Emergency READ of ${credentials.length} credential(s) by ${access.record.providerName}`,
      details: {
        emergencyId: access.record.id,
        credentialIdsRead: credentials.map((c) => c.id),
        disclosure: 'FULL',
        disclosureNote:
          'No holder is present to choose a disclosure frame, so emergency reads ' +
          'return the whole credential. Recorded so this is never mistaken for ' +
          'a selective disclosure the patient chose.',
      },
    },
  });

  logger.warn('EMERGENCY CREDENTIAL READ', {
    emergencyId: access.record.id,
    providerDid,
    patientDid,
    credentialCount: credentials.length,
  });

  return {
    credentials,
    emergencyId: access.record.id,
    expiresAt: access.record.expiresAt,
  };
}

/**
 * Revoke emergency access before it expires.
 *
 * @param emergencyId - ID of the emergency record
 * @param revokerDid - DID of the person revoking (patient or admin)
 */
export async function revokeEmergencyAccess(
  emergencyId: string,
  revokerDid: string,
): Promise<EmergencyAccessRecord> {
  const dbRecord = await db.emergencyAccessRecord.findUnique({
    where: { id: emergencyId },
  });

  if (!dbRecord) {
    throw new AppError(
      ERROR_CODES.EMERGENCY_ACCESS_DENIED,
      'Emergency access record not found',
      404,
    );
  }

  if (dbRecord.status !== 'GRANTED') {
    throw new AppError(
      ERROR_CODES.EMERGENCY_ACCESS_DENIED,
      `Cannot revoke: access is ${dbRecord.status}`,
      400,
    );
  }

  // Verify the revoker is authorized (must be the patient)
  if (dbRecord.patientDid !== revokerDid) {
    throw new AppError(
      ERROR_CODES.EMERGENCY_ACCESS_DENIED,
      'Only the patient can revoke emergency access',
      403,
    );
  }

  const updated = await db.emergencyAccessRecord.update({
    where: { id: emergencyId },
    data: {
      status: 'REVOKED',
      revokedAt: new Date(),
    },
  });

  const record: EmergencyAccessRecord = {
    id: updated.id,
    patientDid: updated.patientDid,
    providerDid: updated.requesterDid,
    providerName: updated.requesterName,
    reason: updated.reason,
    status: statusToShared(updated.status),
    credentialIdsAccessed: updated.credentialsAccessed,
    requestedAt: updated.grantedAt.toISOString(),
    grantedAt: updated.grantedAt.toISOString(),
    expiresAt: updated.expiresAt.toISOString(),
  };

  await db.auditLog.create({
    data: {
      actorDid: revokerDid,
      targetDid: record.providerDid,
      eventType: PrismaAuditEventType.EMERGENCY_ACCESS_DEACTIVATED,
      action: `Emergency access REVOKED for ${record.providerName}`,
      details: { emergencyId, action: 'revoke' },
    },
  });

  logger.info('Emergency access revoked', { emergencyId, revokerDid });
  return record;
}

/**
 * Check if emergency access is currently active for a provider-patient pair.
 */
export async function checkEmergencyAccess(
  providerDid: string,
  patientDid: string,
): Promise<{ isActive: boolean; record?: EmergencyAccessRecord }> {
  const now = new Date();

  // Find active record and auto-expire if needed
  const activeRecord = await db.emergencyAccessRecord.findFirst({
    where: {
      requesterDid: providerDid,
      patientDid,
      status: 'GRANTED',
    },
    orderBy: { grantedAt: 'desc' },
  });

  if (activeRecord) {
    if (activeRecord.expiresAt < now) {
      await db.emergencyAccessRecord.update({
        where: { id: activeRecord.id },
        data: { status: 'EXPIRED' },
      });
      return { isActive: false };
    }

    const record: EmergencyAccessRecord = {
      id: activeRecord.id,
      patientDid: activeRecord.patientDid,
      providerDid: activeRecord.requesterDid,
      providerName: activeRecord.requesterName,
      reason: activeRecord.reason,
      status: statusToShared(activeRecord.status),
      credentialIdsAccessed: activeRecord.credentialsAccessed,
      requestedAt: activeRecord.grantedAt.toISOString(),
      grantedAt: activeRecord.grantedAt.toISOString(),
      expiresAt: activeRecord.expiresAt.toISOString(),
    };

    return { isActive: true, record };
  }

  return { isActive: false };
}

/**
 * Query all emergency access records for a patient.
 */
export async function queryEmergencyRecords(
  patientDid: string,
): Promise<EmergencyAccessRecord[]> {
  const now = new Date();

  // Auto-expire any stale records
  await db.emergencyAccessRecord.updateMany({
    where: {
      patientDid,
      status: 'GRANTED',
      expiresAt: { lt: now },
    },
    data: { status: 'EXPIRED' },
  });

  const dbRecords = await db.emergencyAccessRecord.findMany({
    where: { patientDid },
    orderBy: { grantedAt: 'desc' },
  });

  return dbRecords.map((r) => ({
    id: r.id,
    patientDid: r.patientDid,
    providerDid: r.requesterDid,
    providerName: r.requesterName,
    reason: r.reason,
    status: statusToShared(r.status),
    credentialIdsAccessed: r.credentialsAccessed,
    requestedAt: r.grantedAt.toISOString(),
    grantedAt: r.grantedAt.toISOString(),
    expiresAt: r.expiresAt.toISOString(),
  }));
}
