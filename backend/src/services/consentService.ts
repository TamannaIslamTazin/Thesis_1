/**
 * SSI Healthcare Backend - Consent Service
 *
 * Manages patient consent records: granting, revoking, and querying
 * who accessed what credentials, when, and for what purpose.
 * All operations produce immutable audit log entries via Prisma.
 *
 * Database is REQUIRED — no in-memory fallback. Silent data loss
 * in a healthcare consent system is a HIPAA violation.
 */

import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import {
  ERROR_CODES,
  ConsentAction,
  type ConsentPurpose as SharedConsentPurpose,
  type ConsentRecord,
  type AuditLogEntry,
  AuditEventType,
} from '@ssi-healthcare/shared';
import { db } from '../db/index.js';
import {
  ConsentPurpose as PrismaConsentPurpose,
  AuditEventType as PrismaAuditEventType,
  type Consent as PrismaConsent,
} from '../../prisma/generated/client/index.js';

// ---------------------------------------------------------------------------
// Type mapping between shared types and Prisma types
// ---------------------------------------------------------------------------

const purposeToShared: Record<PrismaConsentPurpose, SharedConsentPurpose> = {
  [PrismaConsentPurpose.TREATMENT]: 'treatment' as SharedConsentPurpose,
  [PrismaConsentPurpose.INSURANCE_CLAIM]: 'insurance_claim' as SharedConsentPurpose,
  [PrismaConsentPurpose.RESEARCH]: 'research' as SharedConsentPurpose,
  [PrismaConsentPurpose.EMERGENCY]: 'emergency' as SharedConsentPurpose,
  [PrismaConsentPurpose.REFERRAL]: 'referral' as SharedConsentPurpose,
};

const purposeToPrisma: Record<string, PrismaConsentPurpose> = {
  treatment: PrismaConsentPurpose.TREATMENT,
  insurance_claim: PrismaConsentPurpose.INSURANCE_CLAIM,
  research: PrismaConsentPurpose.RESEARCH,
  emergency: PrismaConsentPurpose.EMERGENCY,
  referral: PrismaConsentPurpose.REFERRAL,
};

// ---------------------------------------------------------------------------
// Helper: Convert Prisma Consent to shared ConsentRecord
// ---------------------------------------------------------------------------

function prismaToConsentRecord(consent: PrismaConsent): ConsentRecord {
  return {
    id: consent.id,
    holderDid: consent.holderDid,
    verifierDid: consent.verifierDid,
    verifierName: consent.verifierName,
    credentialIds: consent.credentialIds,
    purpose: purposeToShared[consent.purpose],
    action: consent.isActive ? ConsentAction.GRANT : ConsentAction.REVOKE,
    timestamp: consent.grantedAt.toISOString(),
    expiresAt: consent.expiresAt?.toISOString(),
    isActive: consent.isActive,
  };
}

// ---------------------------------------------------------------------------
// Consent Operations
// ---------------------------------------------------------------------------

/**
 * Grant consent for a verifier to access specific credentials.
 */
export async function grantConsent(params: {
  holderDid: string;
  verifierDid: string;
  verifierName: string;
  credentialIds: string[];
  purpose: SharedConsentPurpose;
  durationDays?: number;
}): Promise<ConsentRecord> {
  const {
    holderDid,
    verifierDid,
    verifierName,
    credentialIds,
    purpose,
    durationDays,
  } = params;

  const now = new Date();
  const expiresAt = durationDays
    ? new Date(now.getTime() + durationDays * 24 * 60 * 60 * 1000)
    : undefined;

  const holderUser = await db.user.findUnique({
    where: { did: holderDid },
  });

  const consent = await db.consent.create({
    data: {
      holderDid,
      holderUserId: holderUser?.id,
      verifierDid,
      verifierName,
      credentialIds,
      credentialTypes: [],
      attributes: [],
      purpose: purposeToPrisma[purpose] || PrismaConsentPurpose.TREATMENT,
      grantedAt: now,
      expiresAt,
      isActive: true,
    },
  });

  await db.auditLog.create({
    data: {
      actorDid: holderDid,
      targetDid: verifierDid,
      eventType: PrismaAuditEventType.CONSENT_GRANTED,
      action: `Consent granted to ${verifierName} for ${purpose}`,
      details: { credentialIds, purpose, durationDays },
    },
  });

  logger.info('Consent granted', {
    consentId: consent.id,
    holderDid,
    verifierDid,
    purpose,
    credentialCount: credentialIds.length,
  });

  return prismaToConsentRecord(consent);
}

/**
 * Revoke an existing consent record.
 */
export async function revokeConsent(
  consentId: string,
  holderDid: string,
): Promise<ConsentRecord> {
  const consent = await db.consent.findUnique({
    where: { id: consentId },
  });

  if (!consent) {
    throw new AppError(ERROR_CODES.CONSENT_NOT_FOUND, 'Consent record not found', 404);
  }

  if (consent.holderDid !== holderDid) {
    throw new AppError(
      ERROR_CODES.AUTH_INSUFFICIENT_PERMISSIONS,
      'Only the holder can revoke their consent',
      403,
    );
  }

  if (!consent.isActive) {
    throw new AppError(
      ERROR_CODES.CONSENT_ALREADY_REVOKED,
      'Consent has already been revoked',
      400,
    );
  }

  const updatedConsent = await db.consent.update({
    where: { id: consentId },
    data: {
      isActive: false,
      revokedAt: new Date(),
    },
  });

  await db.auditLog.create({
    data: {
      actorDid: holderDid,
      targetDid: consent.verifierDid,
      eventType: PrismaAuditEventType.CONSENT_REVOKED,
      action: `Consent revoked for ${consent.verifierName}`,
      details: { consentId },
    },
  });

  logger.info('Consent revoked', { consentId, holderDid });

  return prismaToConsentRecord(updatedConsent);
}

/**
 * Query consent records for a given holder.
 */
export async function queryConsent(
  holderDid: string,
  activeOnly: boolean = true,
): Promise<ConsentRecord[]> {
  const now = new Date();

  const whereClause: Record<string, unknown> = { holderDid };

  if (activeOnly) {
    whereClause.isActive = true;
    whereClause.OR = [
      { expiresAt: null },
      { expiresAt: { gt: now } },
    ];
  }

  const consents = await db.consent.findMany({
    where: whereClause,
    orderBy: { grantedAt: 'desc' },
  });

  // Auto-expire consents past their expiration (batch update)
  const expiredIds = consents
    .filter(c => c.expiresAt && c.expiresAt < now && c.isActive)
    .map(c => c.id);

  if (expiredIds.length > 0) {
    await db.consent.updateMany({
      where: { id: { in: expiredIds } },
      data: { isActive: false },
    });
  }

  return consents
    .filter(c => !activeOnly || (c.isActive && (!c.expiresAt || c.expiresAt >= now)))
    .map(prismaToConsentRecord);
}

/**
 * Verify that a verifier has active consent to access specific credentials.
 */
export async function verifyConsent(
  holderDid: string,
  verifierDid: string,
  credentialId: string,
): Promise<{ hasConsent: boolean; consentRecord?: ConsentRecord }> {
  const now = new Date();

  const consent = await db.consent.findFirst({
    where: {
      holderDid,
      verifierDid,
      isActive: true,
      credentialIds: { has: credentialId },
      OR: [
        { expiresAt: null },
        { expiresAt: { gt: now } },
      ],
    },
  });

  if (consent) {
    await db.consentAccessLog.create({
      data: {
        consentId: consent.id,
        accessType: 'verify',
        attributes: [],
      },
    });

    await db.consent.update({
      where: { id: consent.id },
      data: {
        accessCount: { increment: 1 },
        lastAccessedAt: new Date(),
      },
    });

    return { hasConsent: true, consentRecord: prismaToConsentRecord(consent) };
  }

  return { hasConsent: false };
}

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

/**
 * Query the audit log for a given actor DID.
 */
export async function queryAuditLog(
  actorDid: string,
  limit: number = 50,
): Promise<AuditLogEntry[]> {
  const logs = await db.auditLog.findMany({
    where: {
      OR: [
        { actorDid },
        { targetDid: actorDid },
      ],
    },
    orderBy: { timestamp: 'desc' },
    take: limit,
  });

  return logs.map(log => ({
    id: log.id,
    eventType: mapPrismaAuditType(log.eventType),
    actorDid: log.actorDid || '',
    targetDid: log.targetDid || undefined,
    description: log.action,
    metadata: log.details as Record<string, unknown> | undefined,
    timestamp: log.timestamp.toISOString(),
    ipAddress: log.ipAddress || undefined,
  }));
}

/**
 * Map Prisma AuditEventType to shared AuditEventType
 */
function mapPrismaAuditType(prismaType: PrismaAuditEventType): AuditEventType {
  const mapping: Partial<Record<PrismaAuditEventType, AuditEventType>> = {
    [PrismaAuditEventType.CONSENT_GRANTED]: AuditEventType.CONSENT_GRANTED,
    [PrismaAuditEventType.CONSENT_REVOKED]: AuditEventType.CONSENT_REVOKED,
    [PrismaAuditEventType.DID_CREATED]: AuditEventType.DID_CREATED,
    [PrismaAuditEventType.CREDENTIAL_ISSUED]: AuditEventType.CREDENTIAL_ISSUED,
    [PrismaAuditEventType.CREDENTIAL_REVOKED]: AuditEventType.CREDENTIAL_REVOKED,
    [PrismaAuditEventType.PRESENTATION_VERIFIED]: AuditEventType.PRESENTATION_VERIFIED,
    [PrismaAuditEventType.EMERGENCY_ACCESS_ACTIVATED]: AuditEventType.EMERGENCY_ACCESS_GRANTED,
    [PrismaAuditEventType.USER_LOGIN]: AuditEventType.LOGIN_SUCCESS,
  };

  return mapping[prismaType] || (prismaType as unknown as AuditEventType);
}

/**
 * Get total counts by event type for a given DID (for dashboard).
 */
export async function getAuditSummary(
  did: string,
): Promise<Record<string, number>> {
  const logs = await db.auditLog.groupBy({
    by: ['eventType'],
    where: {
      OR: [
        { actorDid: did },
        { targetDid: did },
      ],
    },
    _count: true,
  });

  const summary: Record<string, number> = {};
  for (const log of logs) {
    summary[log.eventType] = log._count;
  }
  return summary;
}

/** Retention check: deactivate consents past their expiration date. */
export async function pruneExpiredConsents(): Promise<number> {
  const now = new Date();

  const result = await db.consent.updateMany({
    where: {
      isActive: true,
      expiresAt: { lt: now },
    },
    data: {
      isActive: false,
    },
  });

  if (result.count > 0) {
    logger.info('Pruned expired consents', { count: result.count });
  }

  return result.count;
}
