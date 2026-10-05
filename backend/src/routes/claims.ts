/**
 * SSI Healthcare Backend - Insurance Claims Routes (H4)
 *
 * REST endpoints for insurance claim submission and tracking.
 * Protected: Requires authentication with wallet.
 *
 * POST /api/claims     - Submit a new insurance claim
 * GET  /api/claims     - List all claims for user
 * GET  /api/claims/:id - Get claim details
 * PUT  /api/claims/:id - Update claim (admin only)
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import { requireWallet, type AuthenticatedRequest } from '../middleware/auth.js';
import { db } from '../db/index.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import type { ApiResponse } from '@ssi-healthcare/shared';
import { AuditEventType, ClaimStatus, ClaimType } from '../../prisma/generated/client/index.js';

export const claimsRouter: Router = Router();

// -- Validation Schemas --

const submitClaimSchema = z.object({
  type: z.enum(['medical', 'prescription', 'dental', 'vision', 'mental_health', 'emergency']),
  amount: z.number().positive(),
  description: z.string().min(10).max(1000),
  providerName: z.string().min(1).max(200),
  serviceDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  credentialIds: z.array(z.string()).optional(),
});

const updateClaimSchema = z.object({
  status: z.enum(['pending', 'under_review', 'approved', 'denied', 'paid']),
  note: z.string().optional(),
});

// -- Helpers --

const claimTypeMap: Record<string, ClaimType> = {
  medical: ClaimType.MEDICAL,
  prescription: ClaimType.PRESCRIPTION,
  dental: ClaimType.DENTAL,
  vision: ClaimType.VISION,
  mental_health: ClaimType.MENTAL_HEALTH,
  emergency: ClaimType.EMERGENCY,
};

const claimStatusMap: Record<string, ClaimStatus> = {
  pending: ClaimStatus.PENDING,
  under_review: ClaimStatus.UNDER_REVIEW,
  approved: ClaimStatus.APPROVED,
  denied: ClaimStatus.DENIED,
  paid: ClaimStatus.PAID,
};

function generateClaimNumber(): string {
  const prefix = 'CLM';
  const date = new Date().toISOString().slice(2, 10).replace(/-/g, '');
  const random = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}-${date}-${random}`;
}

// -- Routes --

/**
 * POST /api/claims
 * Submit a new insurance claim
 */
claimsRouter.post('/', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const data = submitClaimSchema.parse(req.body);

    const claimNumber = generateClaimNumber();

    // Find user's insurance credential (if any)
    const insuranceCredential = await db.credential.findFirst({
      where: {
        holderDid: user.did!,
        type: { has: 'InsuranceCredential' },
        status: 'ACTIVE',
      },
    });

    const credentialIds = data.credentialIds || [];
    if (insuranceCredential) {
      credentialIds.push(insuranceCredential.id);
    }

    const now = new Date().toISOString();
    const initialHistory = [{ status: 'pending', timestamp: now, note: 'Claim submitted' }];

    // Persist claim to database
    const claim = await db.insuranceClaim.create({
      data: {
        claimNumber,
        holderDid: user.did!,
        type: claimTypeMap[data.type],
        amount: data.amount,
        description: data.description,
        providerName: data.providerName,
        serviceDate: new Date(data.serviceDate),
        credentialIds,
        statusHistory: initialHistory,
      },
    });

    // Audit log with correct event type
    await db.auditLog.create({
      data: {
        eventType: AuditEventType.CLAIM_SUBMITTED,
        action: `Insurance claim submitted: ${claimNumber}`,
        actorDid: user.did!,
        resourceType: 'claim',
        resourceId: claim.id,
        details: {
          claimNumber,
          type: data.type,
          amount: data.amount,
          providerName: data.providerName,
          credentialIds,
        },
        ipAddress: typeof req.ip === 'string' ? req.ip : undefined,
      },
    });

    logger.info('Insurance claim submitted', {
      claimId: claim.id,
      claimNumber,
      holderDid: user.did,
      amount: data.amount,
    });

    const response: ApiResponse<typeof claim> = {
      success: true,
      data: claim,
      timestamp: new Date().toISOString(),
    };

    res.status(201).json(response);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/claims
 * List all claims for the authenticated user
 */
claimsRouter.get('/', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const status = req.query.status as string | undefined;
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
    const offset = Math.max(Number(req.query.offset) || 0, 0);

    const where: Record<string, unknown> = { holderDid: user.did! };
    if (status && claimStatusMap[status]) {
      where.status = claimStatusMap[status];
    }

    const [claims, total] = await Promise.all([
      db.insuranceClaim.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: offset,
        take: limit,
      }),
      db.insuranceClaim.count({ where }),
    ]);

    const response: ApiResponse<{
      claims: typeof claims;
      total: number;
      hasMore: boolean;
    }> = {
      success: true,
      data: {
        claims,
        total,
        hasMore: offset + claims.length < total,
      },
      timestamp: new Date().toISOString(),
    };

    res.json(response);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/claims/:id
 * Get claim details
 */
claimsRouter.get('/:id', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const claimId = String(req.params.id);

    const claim = await db.insuranceClaim.findUnique({ where: { id: claimId } });

    if (!claim || claim.holderDid !== user.did) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Claim not found', 404);
    }

    const response: ApiResponse<typeof claim> = {
      success: true,
      data: claim,
      timestamp: new Date().toISOString(),
    };

    res.json(response);
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /api/claims/:id
 * Update claim status (admin/insurance company only)
 */
claimsRouter.put('/:id', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const claimId = String(req.params.id);
    const data = updateClaimSchema.parse(req.body);

    const claim = await db.insuranceClaim.findUnique({ where: { id: claimId } });

    if (!claim) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Claim not found', 404);
    }

    // Authorization: holders can only cancel their own claims.
    // Approval/denial/payment requires insurer roles (not yet implemented).
    if (claim.holderDid !== user.did) {
      throw new AppError(
        ERROR_CODES.AUTH_INSUFFICIENT_PERMISSIONS,
        'Not authorized to update this claim',
        403,
      );
    }

    // Holders cannot approve/deny/pay their own claims
    const insurerOnlyStatuses = ['approved', 'denied', 'paid'];
    if (insurerOnlyStatuses.includes(data.status)) {
      throw new AppError(
        ERROR_CODES.AUTH_INSUFFICIENT_PERMISSIONS,
        'Only insurers can approve, deny, or mark claims as paid',
        403,
      );
    }

    // Build updated status history
    const history = (claim.statusHistory as Array<{ status: string; timestamp: string; note?: string }>) || [];
    history.push({
      status: data.status,
      timestamp: new Date().toISOString(),
      note: data.note,
    });

    const updatedClaim = await db.insuranceClaim.update({
      where: { id: claimId },
      data: {
        status: claimStatusMap[data.status],
        statusHistory: history,
      },
    });

    // Choose correct audit event type based on status
    let eventType: AuditEventType = AuditEventType.CLAIM_UPDATED;
    if (data.status === 'approved') eventType = AuditEventType.CLAIM_APPROVED;
    if (data.status === 'denied') eventType = AuditEventType.CLAIM_DENIED;

    await db.auditLog.create({
      data: {
        eventType,
        action: `Claim status updated to ${data.status}`,
        actorDid: user.did!,
        targetDid: claim.holderDid,
        resourceType: 'claim',
        resourceId: claimId,
        details: {
          claimNumber: claim.claimNumber,
          newStatus: data.status,
          note: data.note,
        },
        ipAddress: typeof req.ip === 'string' ? req.ip : undefined,
      },
    });

    logger.info('Claim status updated', {
      claimId,
      claimNumber: claim.claimNumber,
      newStatus: data.status,
      updatedBy: user.did,
    });

    const response: ApiResponse<typeof updatedClaim> = {
      success: true,
      data: updatedClaim,
      timestamp: new Date().toISOString(),
    };

    res.json(response);
  } catch (error) {
    next(error);
  }
});

export default claimsRouter;
