/**
 * SSI Healthcare - Consent Repository
 * 
 * Database operations for consent management and audit logging
 */

import { db } from './index.js';
import type { Prisma, ConsentPurpose, AuditEventType } from '../../prisma/generated/client/index.js';

export type ConsentCreateInput = Prisma.ConsentCreateInput;
export type ConsentUpdateInput = Prisma.ConsentUpdateInput;
export { AuditEventType } from '../../prisma/generated/client/index.js';

/**
 * Create a new consent record
 */
export async function createConsent(data: ConsentCreateInput) {
  return db.consent.create({
    data,
  });
}

/**
 * Find consent by ID
 */
export async function findConsentById(id: string) {
  return db.consent.findUnique({
    where: { id },
    include: {
      holder: {
        select: {
          id: true,
          displayName: true,
          email: true,
        },
      },
      accessLogs: {
        orderBy: { accessedAt: 'desc' },
        take: 10,
      },
    },
  });
}

/**
 * List consents given by a holder
 */
export async function listConsentsByHolder(
  holderDid: string,
  options: {
    activeOnly?: boolean;
    purpose?: ConsentPurpose;
    skip?: number;
    take?: number;
  } = {}
) {
  const { activeOnly = true, purpose, skip = 0, take = 50 } = options;
  
  return db.consent.findMany({
    where: {
      holderDid,
      ...(activeOnly && {
        isActive: true,
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: new Date() } },
        ],
      }),
      ...(purpose && { purpose }),
    },
    orderBy: { grantedAt: 'desc' },
    skip,
    take,
  });
}

/**
 * List consents received by a verifier
 */
export async function listConsentsByVerifier(
  verifierDid: string,
  options: {
    activeOnly?: boolean;
    skip?: number;
    take?: number;
  } = {}
) {
  const { activeOnly = true, skip = 0, take = 50 } = options;
  
  return db.consent.findMany({
    where: {
      verifierDid,
      ...(activeOnly && {
        isActive: true,
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: new Date() } },
        ],
      }),
    },
    orderBy: { grantedAt: 'desc' },
    skip,
    take,
    include: {
      holder: {
        select: {
          displayName: true,
        },
      },
    },
  });
}

/**
 * Verify if a verifier has active consent
 */
export async function verifyConsent(
  holderDid: string,
  verifierDid: string,
  credentialId: string
) {
  const consent = await db.consent.findFirst({
    where: {
      holderDid,
      verifierDid,
      isActive: true,
      credentialIds: { has: credentialId },
      OR: [
        { expiresAt: null },
        { expiresAt: { gt: new Date() } },
      ],
    },
  });
  
  return { hasConsent: !!consent, consent };
}

/**
 * Revoke a consent
 */
export async function revokeConsent(id: string, reason?: string) {
  return db.consent.update({
    where: { id },
    data: {
      isActive: false,
      revokedAt: new Date(),
      revokedReason: reason,
    },
  });
}

/**
 * Record consent access
 */
export async function recordConsentAccess(
  consentId: string,
  data: {
    accessType: string;
    attributes: string[];
    ipAddress?: string;
    userAgent?: string;
  }
) {
  // Create access log and increment access count in a transaction
  return db.$transaction([
    db.consentAccessLog.create({
      data: {
        consentId,
        ...data,
      },
    }),
    db.consent.update({
      where: { id: consentId },
      data: {
        accessCount: { increment: 1 },
        lastAccessedAt: new Date(),
      },
    }),
  ]);
}

/**
 * Get consent statistics for a holder
 */
export async function getConsentStats(holderDid: string) {
  const [active, revoked, expired, byPurpose] = await Promise.all([
    db.consent.count({
      where: {
        holderDid,
        isActive: true,
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: new Date() } },
        ],
      },
    }),
    db.consent.count({
      where: {
        holderDid,
        revokedAt: { not: null },
      },
    }),
    db.consent.count({
      where: {
        holderDid,
        expiresAt: { lt: new Date() },
        revokedAt: null,
      },
    }),
    db.consent.groupBy({
      by: ['purpose'],
      where: { holderDid, isActive: true },
      _count: true,
    }),
  ]);
  
  return {
    active,
    revoked,
    expired,
    total: active + revoked + expired,
    byPurpose: byPurpose.reduce((acc, item) => {
      acc[item.purpose] = item._count;
      return acc;
    }, {} as Record<ConsentPurpose, number>),
  };
}

/**
 * Mark expired consents
 */
export async function markExpiredConsents() {
  return db.consent.updateMany({
    where: {
      isActive: true,
      expiresAt: { lt: new Date() },
    },
    data: {
      isActive: false,
    },
  });
}

// Audit Log operations

interface CreateAuditLogParams {
  eventType: AuditEventType;
  action: string;
  actorUserId?: string;
  actorDid?: string;
  targetUserId?: string;
  targetDid?: string;
  resourceType?: string;
  resourceId?: string;
  details?: object;
  previousState?: object;
  newState?: object;
  ipAddress?: string;
  userAgent?: string;
  sessionId?: string;
}

/**
 * Create an audit log entry
 */
export async function createAuditLog(params: CreateAuditLogParams) {
  const {
    eventType,
    action,
    actorUserId,
    actorDid,
    targetUserId,
    targetDid,
    resourceType,
    resourceId,
    details,
    previousState,
    newState,
    ipAddress,
    userAgent,
    sessionId,
  } = params;
  
  return db.auditLog.create({
    data: {
      eventType,
      action,
      actorDid,
      targetDid,
      resourceType,
      resourceId,
      details: details as Prisma.InputJsonValue,
      previousState: previousState as Prisma.InputJsonValue,
      newState: newState as Prisma.InputJsonValue,
      ipAddress,
      userAgent,
      sessionId,
      ...(actorUserId && { actor: { connect: { id: actorUserId } } }),
      ...(targetUserId && { target: { connect: { id: targetUserId } } }),
    },
  });
}

/**
 * Find an audit log entry by matching details JSON fields.
 * Used for login code verification — matches codeHash and pendingToken.
 */
export async function findAuditLogByDetails(params: {
  actorUserId: string;
  details: Record<string, string>;
}) {
  // Find the most recent matching audit log entry
  const entries = await db.auditLog.findMany({
    where: {
      actorUserId: params.actorUserId,
      eventType: 'USER_LOGIN',
      action: { contains: 'pending verification' },
    },
    orderBy: { timestamp: 'desc' },
    take: 20,
  });

  // Check if any entry has matching details
  for (const entry of entries) {
    const details = entry.details as Record<string, unknown> | null;
    if (!details) continue;

    const allMatch = Object.entries(params.details).every(
      ([key, value]) => details[key] === value,
    );

    if (allMatch) {
      // Check expiry
      const expiresAt = details.expiresAt as string;
      if (expiresAt && new Date(expiresAt) < new Date()) continue;
      return entry;
    }
  }

  return null;
}

/**
 * Query audit logs for a user
 */
export async function queryAuditLogs(
  userId: string,
  options: {
    eventTypes?: AuditEventType[];
    startDate?: Date;
    endDate?: Date;
    skip?: number;
    take?: number;
  } = {}
) {
  const { eventTypes, startDate, endDate, skip = 0, take = 50 } = options;
  
  return db.auditLog.findMany({
    where: {
      OR: [
        { actorUserId: userId },
        { targetUserId: userId },
      ],
      ...(eventTypes && eventTypes.length > 0 && { eventType: { in: eventTypes } }),
      ...(startDate && { timestamp: { gte: startDate } }),
      ...(endDate && { timestamp: { lte: endDate } }),
    },
    orderBy: { timestamp: 'desc' },
    skip,
    take,
  });
}

/**
 * Get audit log summary for a user
 */
export async function getAuditSummary(userId: string) {
  const results = await db.auditLog.groupBy({
    by: ['eventType'],
    where: {
      OR: [
        { actorUserId: userId },
        { targetUserId: userId },
      ],
    },
    _count: true,
  });
  
  return results.reduce((acc, item) => {
    acc[item.eventType] = item._count;
    return acc;
  }, {} as Record<AuditEventType, number>);
}

/**
 * Get recent activity for a user
 */
/**
 * The holder's own activity feed.
 *
 * MATCHES ON THE DID AS WELL AS THE USER ROW, and the DID is the important one.
 * Events written by unauthenticated routes — every OID4VP presentation, which is
 * unauthenticated BY DESIGN because the signature is the authentication — have
 * no session to derive a user id from, so they carry `actorDid` and nothing
 * else. Keying this query on `actorUserId` alone hid all of them: measured
 * 9 Sep 2026, five PRESENTATION_VERIFIED rows existed for a holder whose wallet
 * showed only "Signed In". The one screen a holder would check to see who
 * received their data was the one screen that could not show it.
 */
export async function getRecentActivity(userId: string, limit = 10, did?: string | null) {
  return db.auditLog.findMany({
    where: {
      OR: [
        { actorUserId: userId },
        { targetUserId: userId },
        ...(did ? [{ actorDid: did }, { targetDid: did }] : []),
      ],
    },
    orderBy: { timestamp: 'desc' },
    take: limit,
    select: {
      id: true,
      eventType: true,
      action: true,
      timestamp: true,
      details: true,
    },
  });
}

/**
 * Clean up old audit logs (retention policy)
 */
export async function cleanupOldAuditLogs(retentionDays: number) {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
  
  return db.auditLog.deleteMany({
    where: {
      timestamp: { lt: cutoffDate },
    },
  });
}
