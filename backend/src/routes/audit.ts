/**
 * SSI Healthcare Backend - Audit Routes
 *
 * REST endpoints for querying user audit trail.
 * Protected: Requires authentication.
 *
 * GET /api/audit         - Get audit trail for authenticated user
 * GET /api/audit/:did    - Get audit trail for specific DID (admin only)
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { requireWallet, type AuthenticatedRequest } from '../middleware/auth.js';
import { db } from '../db/index.js';
import { logger } from '../utils/logger.js';
import type { ApiResponse } from '@ssi-healthcare/shared';
import { AuditEventType } from '../../prisma/generated/client/index.js';

export const auditRouter: Router = Router();

// -- Types --

interface AuditEvent {
  id: string;
  type: 'credential_issued' | 'credential_shared' | 'consent_granted' | 'consent_revoked' | 'verification_request' | 'login';
  title: string;
  description: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

// -- Validation Schemas --

const querySchema = z.object({
  did: z.string().startsWith('did:').optional(),
  type: z.enum([
    'credential_issued',
    'credential_shared',
    'consent_granted',
    'consent_revoked',
    'verification_request',
    'login',
  ]).optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  limit: z.coerce.number().min(1).max(100).default(50),
  offset: z.coerce.number().min(0).default(0),
});

// -- Helpers --

/**
 * Map database audit log event type to frontend-friendly type
 */
function mapEventType(eventType: string): AuditEvent['type'] {
  const mapping: Record<string, AuditEvent['type']> = {
    'CREDENTIAL_ISSUED': 'credential_issued',
    'CREDENTIAL_SHARED': 'credential_shared',
    'CONSENT_GRANTED': 'consent_granted',
    'CONSENT_REVOKED': 'consent_revoked',
    'CONSENT_CREATED': 'consent_granted',
    'CONSENT_UPDATED': 'consent_granted',
    'PRESENTATION_VERIFIED': 'verification_request',
    'PRESENTATION_CREATED': 'credential_shared',
    'USER_LOGIN': 'login',
    'USER_LOGOUT': 'login',
    'EMERGENCY_ACCESS_GRANTED': 'consent_granted',
    'EMERGENCY_ACCESS_REVOKED': 'consent_revoked',
  };
  return mapping[eventType] || 'login';
}

/**
 * Generate plain language title for audit event
 */
function generateTitle(eventType: string, details: Record<string, unknown>): string {
  switch (eventType) {
    case 'CREDENTIAL_ISSUED':
      return `${details.credentialType || 'Credential'} received`;
    case 'CREDENTIAL_SHARED':
      return `Shared ${details.credentialType || 'credential'} with ${details.verifierName || 'organization'}`;
    case 'CONSENT_GRANTED':
    case 'CONSENT_CREATED':
      return `Granted access to ${details.requesterName || 'an app'}`;
    case 'CONSENT_REVOKED':
      return `Revoked access from ${details.requesterName || 'an app'}`;
    case 'PRESENTATION_VERIFIED':
      return `${details.verifierName || 'Organization'} verified your credential`;
    case 'USER_LOGIN':
      return `Signed in to ${details.appName || 'SSI Wallet'}`;
    case 'EMERGENCY_ACCESS_GRANTED':
      return `Emergency access granted to ${details.providerName || 'provider'}`;
    case 'EMERGENCY_ACCESS_REVOKED':
      return `Emergency access revoked from ${details.providerName || 'provider'}`;
    default:
      return details.action as string || 'Activity recorded';
  }
}

/**
 * Generate description for audit event
 */
function generateDescription(eventType: string, details: Record<string, unknown>): string {
  switch (eventType) {
    case 'CREDENTIAL_ISSUED':
      return `A new ${details.credentialType || 'credential'} was issued by ${details.issuerName || 'an issuer'} and added to your wallet.`;
    case 'CREDENTIAL_SHARED':
      return `You shared ${details.fieldsCount || 'some'} fields from your ${details.credentialType || 'credential'} with ${details.verifierName || 'an organization'}.`;
    case 'CONSENT_GRANTED':
    case 'CONSENT_CREATED':
      return `You allowed ${details.requesterName || 'an app'} to access ${details.scopeDescription || 'your data'}.`;
    case 'CONSENT_REVOKED':
      return `You stopped ${details.requesterName || 'an app'} from accessing your data.`;
    case 'PRESENTATION_VERIFIED':
      return `${details.verifierName || 'An organization'} verified your ${details.credentialType || 'credential'}. ${details.purpose || ''}`;
    case 'USER_LOGIN':
      return `You signed in using ${details.method || 'your identity'}.`;
    case 'EMERGENCY_ACCESS_GRANTED':
      return `${details.providerName || 'A healthcare provider'} was granted emergency access to your records. Reason: ${details.reason || 'Emergency care'}`;
    case 'EMERGENCY_ACCESS_REVOKED':
      return `Emergency access for ${details.providerName || 'a provider'} has been revoked.`;
    default:
      return details.description as string || 'An activity was recorded in your audit trail.';
  }
}

// -- Routes --

/**
 * GET /api/audit
 * Get audit trail for the authenticated user
 */
auditRouter.get('/', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const params = querySchema.parse(req.query);
    
    // Use the authenticated user's DID
    const did = params.did || user.did;
    
    // Ensure user can only query their own data
    if (did !== user.did) {
      res.status(403).json({
        success: false,
        error: { code: 'FORBIDDEN', message: 'Cannot access audit trail for another user' },
      });
      return;
    }
    
    // Build query conditions
    const where: Record<string, unknown> = {
      OR: [
        { actorDid: did },
        { targetDid: did },
      ],
    };
    
    if (params.type) {
      // Map frontend type to database event types
      const typeMapping: Record<string, string[]> = {
        'credential_issued': ['CREDENTIAL_ISSUED'],
        'credential_shared': ['CREDENTIAL_SHARED', 'PRESENTATION_CREATED'],
        'consent_granted': ['CONSENT_GRANTED', 'CONSENT_CREATED'],
        'consent_revoked': ['CONSENT_REVOKED'],
        'verification_request': ['PRESENTATION_VERIFIED'],
        'login': ['USER_LOGIN', 'USER_LOGOUT'],
      };
      where.eventType = { in: typeMapping[params.type] || [params.type] };
    }
    
    if (params.startDate || params.endDate) {
      where.timestamp = {};
      if (params.startDate) (where.timestamp as Record<string, Date>).gte = new Date(params.startDate);
      if (params.endDate) (where.timestamp as Record<string, Date>).lte = new Date(params.endDate);
    }
    
    // Query audit logs
    const [logs, total] = await Promise.all([
      db.auditLog.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        take: params.limit,
        skip: params.offset,
      }),
      db.auditLog.count({ where }),
    ]);
    
    // Transform to frontend format
    const events: AuditEvent[] = logs.map((log) => {
      const details = (log.details as Record<string, unknown>) || {};
      return {
        id: log.id,
        type: mapEventType(log.eventType),
        title: generateTitle(log.eventType, details),
        description: generateDescription(log.eventType, details),
        timestamp: log.timestamp.toISOString(),
        metadata: {
          resourceType: log.resourceType,
          resourceId: log.resourceId,
          ipAddress: log.ipAddress,
          ...details,
        },
      };
    });
    
    logger.info('Audit trail queried', {
      did,
      resultCount: events.length,
      total,
    });
    
    const response: ApiResponse<{ events: AuditEvent[]; total: number; hasMore: boolean }> = {
      success: true,
      data: {
        events,
        total,
        hasMore: params.offset + events.length < total,
      },
      timestamp: new Date().toISOString(),
    };
    
    res.json(response);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/audit/stats
 * Get audit statistics for dashboard
 */
auditRouter.get('/stats', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const did = user.did;
    
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    
    // Get counts by type for the last 30 days
    const where = {
      OR: [
        { actorDid: did },
        { targetDid: did },
      ],
      timestamp: { gte: thirtyDaysAgo },
    };
    
    const [
      totalLast30Days,
      credentialIssued,
      credentialShared,
      verificationsReceived,
    ] = await Promise.all([
      db.auditLog.count({ where }),
      db.auditLog.count({ where: { ...where, eventType: AuditEventType.CREDENTIAL_ISSUED } }),
      db.auditLog.count({ where: { ...where, eventType: { in: [AuditEventType.CONSENT_ACCESSED, AuditEventType.PRESENTATION_SUBMITTED] } } }),
      db.auditLog.count({ where: { ...where, eventType: AuditEventType.PRESENTATION_VERIFIED } }),
    ]);
    
    // Get total all time
    const totalAllTime = await db.auditLog.count({
      where: {
        OR: [
          { actorDid: did },
          { targetDid: did },
        ],
      },
    });
    
    const response: ApiResponse<{
      totalAllTime: number;
      totalLast30Days: number;
      credentialsIssued: number;
      credentialsShared: number;
      verificationsReceived: number;
    }> = {
      success: true,
      data: {
        totalAllTime,
        totalLast30Days,
        credentialsIssued: credentialIssued,
        credentialsShared: credentialShared,
        verificationsReceived,
      },
      timestamp: new Date().toISOString(),
    };
    
    res.json(response);
  } catch (error) {
    next(error);
  }
});

export default auditRouter;
