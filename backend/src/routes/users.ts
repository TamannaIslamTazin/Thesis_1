/**
 * SSI Healthcare Backend - User Routes
 * 
 * User profile management and settings
 */

import { Router, Request, Response, NextFunction } from 'express';
import { createHash } from 'crypto';
import { z } from 'zod';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES, WalletCredentialCategorySchema } from '@ssi-healthcare/shared';
import {
  toWalletCredential,
  toWalletCredentialList,
  toWalletCredentialStats,
} from '../api/walletCredential.js';
import { requireAuth, type AuthenticatedRequest } from '../middleware/auth.js';
import { isIdentityVerified } from '../services/identityVerification.js';
import * as userRepo from '../db/userRepository.js';
import * as credentialRepo from '../db/credentialRepository.js';
import * as consentRepo from '../db/consentRepository.js';
import * as presentationRepo from '../db/presentationRepository.js';
import { AuditEventType } from '../../prisma/generated/client/index.js';
import { db } from '../db/index.js';

const router = Router();

/**
 * GET /api/users/me
 * Get full user profile (includes emergencyContacts, wallet status, etc.)
 */
router.get('/me', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const userId = authReq.user.id;
    
    const user = await db.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        displayName: true,
        did: true,
        walletSetup: true,
        totpEnabled: true,
        biometricEnabled: true,
        autoLockMinutes: true,
        createdAt: true,
        updatedAt: true,
        emergencyContacts: {
          select: {
            id: true,
            contactName: true,
            relationship: true,
            allowedCredentials: true,
          },
        },
      },
    });
    
    if (!user) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'User not found', 404);
    }

    // Derived from a credential, never a stored flag — see
    // services/identityVerification.ts. A user with no DID yet cannot hold
    // any credential, so this short-circuits rather than querying for one.
    const identityVerified = user.did ? await isIdentityVerified(user.did) : false;

    res.json({
      success: true,
      data: {
        ...user,
        identityVerified,
        emergencyContacts: user.emergencyContacts.map(ec => ({
          id: ec.id,
          name: ec.contactName,
          relationship: ec.relationship,
          canAccess: ec.allowedCredentials,
        })),
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/users/me/credentials
 * Get user's credentials as `WalletCredential` envelopes.
 *
 * The response body is the `WalletCredentialList` contract from
 * `@ssi-healthcare/shared` — never a raw Prisma row. See the `WalletCredential`
 * doc comment for why the envelope exists.
 */
router.get('/me/credentials', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { did: string | null } }).user;

    if (!user.did) {
      res.json({ success: true, data: { credentials: [], stats: null } });
      return;
    }

    // The category filter is PARSED, not cast. A cast would hand Prisma an
    // arbitrary string and turn a typo in a query string into a 500, and — the
    // worse failure — an unparseable value must not silently become
    // `undefined`, because Prisma elides `undefined` from a `where` clause
    // (previewFeatures is empty, so strictUndefinedChecks is off) and the
    // filter would vanish without a trace. Rejecting is the only safe answer.
    //
    // `status` is opt-in and unset by default, so the wallet receives revoked
    // and expired credentials and can render them as such — see the note on
    // listCredentialsByHolder(). A client that wants only usable credentials
    // asks for `?status=ACTIVE`.
    const querySchema = z.object({
      category: WalletCredentialCategorySchema.optional(),
      types: z.string().max(1024).optional(),
      status: z.enum(['PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED', 'SUSPENDED']).optional(),
    });
    const parsedQuery = querySchema.safeParse({
      category: typeof req.query.category === 'string' ? req.query.category.toUpperCase() : undefined,
      types: typeof req.query.types === 'string' ? req.query.types : undefined,
      status: typeof req.query.status === 'string' ? req.query.status.toUpperCase() : undefined,
    });

    if (!parsedQuery.success) {
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        'Invalid credential filter',
        400,
      );
    }

    const { category, status } = parsedQuery.data;
    const types = parsedQuery.data.types
      ?.split(',')
      .map(t => t.trim())
      .filter(Boolean);

    const [rows, stats] = await Promise.all([
      credentialRepo.listCredentialsByHolder(user.did, {
        // Only pass the keys that actually carry a value. Passing
        // `category: undefined` is indistinguishable from "no filter" to
        // Prisma, so the repository's `...(category && { category })` guard is
        // the thing keeping this honest — do not replace it with `?? undefined`.
        ...(category && { category }),
        ...(types && types.length > 0 && { types }),
        ...(status && { status }),
      }),
      credentialRepo.getCredentialStats(user.did),
    ]);

    res.json({
      success: true,
      data: {
        credentials: toWalletCredentialList(rows),
        stats: toWalletCredentialStats(stats),
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/users/me/credentials/:id
 * Get specific credential
 */
router.get('/me/credentials/:id', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { did: string | null } }).user;
    const credentialId = req.params.id as string;
    
    const credential = await credentialRepo.findCredentialById(credentialId);

    if (!credential) {
      throw new AppError(ERROR_CODES.CREDENTIAL_NOT_FOUND, 'Credential not found', 404);
    }

    if (credential.holderDid !== user.did) {
      throw new AppError(ERROR_CODES.AUTH_INSUFFICIENT_PERMISSIONS, 'Not authorized', 403);
    }

    const walletCredential = toWalletCredential(credential);

    // An unreadable `credentialData` is a storage defect, not a missing row.
    // The list endpoint drops such rows; here there is nothing to fall back to,
    // so fail loudly rather than return a half-built envelope.
    if (!walletCredential) {
      throw new AppError(
        ERROR_CODES.INTERNAL_ERROR,
        'Stored credential could not be decoded',
        500,
      );
    }

    res.json({
      success: true,
      data: walletCredential,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/users/me/consents
 * Get user's consent records
 */
router.get('/me/consents', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { did: string | null } }).user;
    
    if (!user.did) {
      res.json({ success: true, data: { consents: [], stats: null } });
      return;
    }
    
    const activeOnly = req.query.active !== 'false';
    
    const [rawConsents, stats] = await Promise.all([
      consentRepo.listConsentsByHolder(user.did, { activeOnly }),
      consentRepo.getConsentStats(user.did),
    ]);
    
    // Transform Prisma consents to frontend-expected shape
    const consents = rawConsents.map(c => {
      let status: 'active' | 'revoked' | 'expired' = 'active';
      if (c.revokedAt) status = 'revoked';
      else if (c.expiresAt && c.expiresAt < new Date()) status = 'expired';
      else if (!c.isActive) status = 'revoked';
      
      return {
        id: c.id,
        holderDid: c.holderDid,
        verifierDid: c.verifierDid,
        verifierName: c.verifierName,
        purpose: c.purposeDetail || c.purpose,
        scope: c.credentialTypes,
        allowedFields: c.attributes,
        status,
        grantedAt: c.grantedAt.toISOString(),
        expiresAt: c.expiresAt?.toISOString(),
        revokedAt: c.revokedAt?.toISOString(),
        accessCount: c.accessCount,
        lastAccessedAt: c.lastAccessedAt?.toISOString(),
        // Whether anything CONTINUES after this record, or it documents a
        // finished act. The wallet needs this to decide between offering
        // "Revoke" and explaining that there is nothing left to revoke.
        standingAccess: c.standingAccess,
      };
    });
    
    res.json({
      success: true,
      data: {
        consents,
        stats,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/users/me/consents/:id/revoke
 * Revoke a consent
 */
router.post('/me/consents/:id/revoke', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { id: string; did: string | null } }).user;
    const consentId = req.params.id as string;
    const { reason } = req.body as { reason?: string };
    
    const consent = await consentRepo.findConsentById(consentId);
    
    if (!consent) {
      throw new AppError(ERROR_CODES.CONSENT_NOT_FOUND, 'Consent not found', 404);
    }
    
    if (consent.holderDid !== user.did) {
      throw new AppError(ERROR_CODES.AUTH_INSUFFICIENT_PERMISSIONS, 'Not authorized', 403);
    }
    
    const revokedConsent = await consentRepo.revokeConsent(consentId, reason);
    
    await consentRepo.createAuditLog({
      eventType: AuditEventType.CONSENT_REVOKED,
      action: `Consent revoked for ${consent.verifierName}`,
      actorUserId: user.id,
      actorDid: user.did || undefined,
      details: { consentId, reason },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });
    
    res.json({
      success: true,
      data: revokedConsent,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/users/me/presentations
 * Get user's presentation history
 */
router.get('/me/presentations', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { did: string | null } }).user;
    
    if (!user.did) {
      res.json({ success: true, data: { presentations: [], stats: null } });
      return;
    }
    
    const [presentations, stats] = await Promise.all([
      presentationRepo.listPresentationsByHolder(user.did),
      presentationRepo.getPresentationStats(user.did),
    ]);
    
    res.json({
      success: true,
      data: {
        presentations,
        stats,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/users/me/activity
 * Get user's recent activity
 */
router.get('/me/activity', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { id: string; did?: string | null } }).user;
    const limitParse = z.coerce.number().int().min(1).max(200).default(20).safeParse(req.query.limit);
    const limit = limitParse.success ? limitParse.data : 20;

    // The DID matters as much as the user id: events from unauthenticated
    // routes carry only the DID. See getRecentActivity.
    const activity = await consentRepo.getRecentActivity(user.id, limit, user.did);
    
    res.json({
      success: true,
      data: activity,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/users/me/audit
 * FINDING-015: User-scoped audit log — only returns events for the authenticated user.
 * Frontend wallet/audit page must use this, not the admin /api/audit endpoint.
 */
router.get('/me/audit', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const schema = z.object({
      startDate: z.string().datetime().optional(),
      endDate: z.string().datetime().optional(),
      page: z.coerce.number().int().min(1).default(1),
      limit: z.coerce.number().int().min(1).max(100).default(20),
    });
    const { startDate, endDate, page, limit } = schema.parse(req.query);
    const skip = (page - 1) * limit;

    const where = {
      actorUserId: user.id,
      ...(startDate || endDate
        ? {
            timestamp: {
              ...(startDate ? { gte: new Date(startDate) } : {}),
              ...(endDate ? { lte: new Date(endDate) } : {}),
            },
          }
        : {}),
    };

    const [events, total] = await Promise.all([
      db.auditLog.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          eventType: true,
          details: true,
          ipAddress: true,
          userAgent: true,
          timestamp: true,
        },
      }),
      db.auditLog.count({ where }),
    ]);

    res.json({
      success: true,
      data: {
        events,
        total,
        hasMore: skip + events.length < total,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /api/users/me/profile
 * Update user profile
 */
router.put('/me/profile', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { id: string } }).user;
    
    const schema = z.object({
      firstName: z.string().optional(),
      lastName: z.string().optional(),
      displayName: z.string().optional(),
      phone: z.string().optional(),
      avatarUrl: z.string().url().optional(),
    });
    
    const data = schema.parse(req.body);
    
    const updatedUser = await userRepo.updateUser(user.id, data);
    
    res.json({
      success: true,
      data: {
        id: updatedUser.id,
        email: updatedUser.email,
        firstName: updatedUser.firstName,
        lastName: updatedUser.lastName,
        displayName: updatedUser.displayName,
        phone: updatedUser.phone,
        avatarUrl: updatedUser.avatarUrl,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /api/users/me/security
 * Update security settings
 */
router.put('/me/security', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { id: string } }).user;
    
    const schema = z.object({
      biometricEnabled: z.boolean().optional(),
      autoLockMinutes: z.number().min(1).max(60).optional(),
      totpEnabled: z.boolean().optional(),
    });
    
    const data = schema.parse(req.body);
    
    await userRepo.updateUser(user.id, data);
    
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/users/me/sessions
 * List active sessions
 */
router.get('/me/sessions', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const currentToken = req.headers.authorization?.slice(7) || '';

    // H-07+H-10: Fetch sessions with token hash for internal comparison only;
    // hash current token to match stored value; never return token hash in response
    const currentTokenHash = createHash('sha256').update(currentToken).digest('hex');

    const sessions = await db.session.findMany({
      where: {
        userId: user.id,
        expiresAt: { gt: new Date() },
      },
      orderBy: { lastActiveAt: 'desc' },
      select: {
        id: true,
        userAgent: true,
        deviceName: true,
        ipAddress: true,
        createdAt: true,
        lastActiveAt: true,
        expiresAt: true,
        token: true, // fetched only to determine isCurrent — never returned in response
      },
    });

    res.json({
      success: true,
      data: {
        sessions: sessions.map(s => ({
          id: s.id,
          userAgent: s.userAgent,
          // H-10: strip deviceName prefix if it's a pending_code slot
          deviceName: s.deviceName?.startsWith('pending_code:') ? null : s.deviceName,
          ipAddress: s.ipAddress,
          createdAt: s.createdAt.toISOString(),
          lastActiveAt: s.lastActiveAt.toISOString(),
          expiresAt: s.expiresAt.toISOString(),
          isCurrent: s.token === currentTokenHash, // H-07: compare hashes
          // H-10: token hash NOT returned
        })),
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/users/me/sessions
 * Logout all sessions except current
 */
router.delete('/me/sessions', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const rawToken = req.headers.authorization?.slice(7) || '';
    // Tokens are stored hashed in DB; must compare hashed value
    const currentTokenHash = createHash('sha256').update(rawToken).digest('hex');

    // Delete all sessions except the current one
    const result = await db.session.deleteMany({
      where: {
        userId: user.id,
        token: { not: currentTokenHash },
      },
    });

    res.json({
      success: true,
      data: { deletedCount: result.count },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /api/users/me/notifications
 * Update notification preferences
 */
router.put('/me/notifications', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;

    const schema = z.object({
      emailEnabled: z.boolean().optional(),
      pushEnabled: z.boolean().optional(),
      emailDigest: z.enum(['immediate', 'daily', 'weekly']).optional(),
      quietHoursEnabled: z.boolean().optional(),
      quietHoursStart: z.string().optional(),
      quietHoursEnd: z.string().optional(),
      eventPreferences: z.record(z.string(), z.boolean()).optional(),
    });

    const data = schema.parse(req.body);

    const prefs = await db.notificationPreference.upsert({
      where: { userId: user.id },
      update: {
        ...(data.emailEnabled !== undefined && { emailEnabled: data.emailEnabled }),
        ...(data.pushEnabled !== undefined && { pushEnabled: data.pushEnabled }),
        ...(data.emailDigest !== undefined && { emailDigest: data.emailDigest }),
        ...(data.quietHoursEnabled !== undefined && { quietHoursEnabled: data.quietHoursEnabled }),
        ...(data.quietHoursStart !== undefined && { quietHoursStart: data.quietHoursStart }),
        ...(data.quietHoursEnd !== undefined && { quietHoursEnd: data.quietHoursEnd }),
        ...(data.eventPreferences !== undefined && { eventPreferences: data.eventPreferences }),
      },
      create: {
        userId: user.id,
        emailEnabled: data.emailEnabled ?? true,
        pushEnabled: data.pushEnabled ?? true,
        emailDigest: data.emailDigest ?? 'immediate',
        quietHoursEnabled: data.quietHoursEnabled ?? false,
        quietHoursStart: data.quietHoursStart,
        quietHoursEnd: data.quietHoursEnd,
        eventPreferences: (data.eventPreferences ?? {}) as Record<string, boolean>,
      },
    });

    res.json({
      success: true,
      data: {
        emailEnabled: prefs.emailEnabled,
        pushEnabled: prefs.pushEnabled,
        emailDigest: prefs.emailDigest,
        quietHoursEnabled: prefs.quietHoursEnabled,
        eventPreferences: prefs.eventPreferences,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/users/me/notifications
 * Get current notification preferences
 */
router.get('/me/notifications', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;

    const prefs = await db.notificationPreference.findUnique({
      where: { userId: user.id },
    });

    res.json({
      success: true,
      data: prefs
        ? {
            emailEnabled: prefs.emailEnabled,
            pushEnabled: prefs.pushEnabled,
            emailDigest: prefs.emailDigest,
            quietHoursEnabled: prefs.quietHoursEnabled,
            quietHoursStart: prefs.quietHoursStart,
            quietHoursEnd: prefs.quietHoursEnd,
            eventPreferences: prefs.eventPreferences as Record<string, boolean>,
          }
        : {
            emailEnabled: true,
            pushEnabled: true,
            emailDigest: 'immediate',
            quietHoursEnabled: false,
            quietHoursStart: null,
            quietHoursEnd: null,
            eventPreferences: {
              credential_received: true,
              verification_request: true,
              consent_expiring: true,
              security_alert: true,
              marketing: false,
            },
          },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/users/me/emergency-contacts
 * Add an emergency contact
 */
router.post('/me/emergency-contacts', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;

    const schema = z.object({
      name: z.string().min(1).max(100),
      relationship: z.string().min(1).max(50),
      email: z.string().email().optional(),
      phone: z.string().optional(),
      allowedCredentials: z.array(z.string()).default([]),
    });

    const data = schema.parse(req.body);

    const contact = await db.emergencyContact.create({
      data: {
        userId: user.id,
        contactName: data.name,
        relationship: data.relationship,
        contactEmail: data.email,
        contactPhone: data.phone,
        allowedCredentials: data.allowedCredentials,
      },
    });

    res.status(201).json({
      success: true,
      data: {
        id: contact.id,
        name: contact.contactName,
        relationship: contact.relationship,
        email: contact.contactEmail,
        phone: contact.contactPhone,
        canAccess: contact.allowedCredentials,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /api/users/me/emergency-contacts/:id
 * Update an emergency contact
 */
router.put('/me/emergency-contacts/:id', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const contactId = req.params.id as string;

    const schema = z.object({
      name: z.string().min(1).max(100).optional(),
      relationship: z.string().min(1).max(50).optional(),
      email: z.string().email().nullable().optional(),
      phone: z.string().nullable().optional(),
      allowedCredentials: z.array(z.string()).optional(),
    });

    const data = schema.parse(req.body);

    // Verify ownership
    const existing = await db.emergencyContact.findFirst({ where: { id: contactId, userId: user.id } });
    if (!existing) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Emergency contact not found', 404);
    }

    const contact = await db.emergencyContact.update({
      where: { id: contactId },
      data: {
        ...(data.name !== undefined && { contactName: data.name }),
        ...(data.relationship !== undefined && { relationship: data.relationship }),
        ...(data.email !== undefined && { contactEmail: data.email }),
        ...(data.phone !== undefined && { contactPhone: data.phone }),
        ...(data.allowedCredentials !== undefined && { allowedCredentials: data.allowedCredentials }),
      },
    });

    res.json({
      success: true,
      data: {
        id: contact.id,
        name: contact.contactName,
        relationship: contact.relationship,
        email: contact.contactEmail,
        phone: contact.contactPhone,
        canAccess: contact.allowedCredentials,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/users/me/emergency-contacts/:id
 * Remove an emergency contact
 */
router.delete('/me/emergency-contacts/:id', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const contactId = req.params.id as string;

    const existing = await db.emergencyContact.findFirst({ where: { id: contactId, userId: user.id } });
    if (!existing) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Emergency contact not found', 404);
    }

    await db.emergencyContact.delete({ where: { id: contactId } });

    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/users/me
 * Delete the authenticated user's account and all associated data
 */
router.delete('/me', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;

    // Cascade delete: Prisma schema handles most relations, but log the event first
    await consentRepo.createAuditLog({
      eventType: AuditEventType.USER_LOGOUT,
      action: 'Account deletion requested',
      actorUserId: user.id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    await userRepo.deleteUser(user.id);

    res.json({ success: true, data: { message: 'Account deleted successfully' } });
  } catch (error) {
    next(error);
  }
});

export { router as usersRouter };
