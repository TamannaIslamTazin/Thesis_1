/**
 * SSI Healthcare Backend - Consent Routes
 *
 * REST endpoints for consent management.
 * All routes require authentication.
 *
 * POST   /api/consent/grant     - Grant consent (requires wallet)
 * POST   /api/consent/revoke    - Revoke consent (requires wallet + ownership)
 * GET    /api/consent/:holderDid - Query consent records (requires ownership)
 * POST   /api/consent/verify    - Verify consent for access (authenticated)
 * GET    /api/consent/audit/:did - Query audit log for a DID (requires ownership)
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import {
  grantConsent,
  revokeConsent,
  queryConsent,
  verifyConsent,
  queryAuditLog,
  getAuditSummary,
} from '../services/consentService.js';
import { ConsentPurpose, CuidSchema, type ApiResponse } from '@ssi-healthcare/shared';
import { 
  requireAuth, 
  requireWallet, 
  requireOwnership,
  type AuthenticatedRequest 
} from '../middleware/auth.js';

export const consentRouter: Router = Router();

// -- Validation schemas --

const grantConsentSchema = z.object({
  verifierDid: z.string().startsWith('did:'),
  verifierName: z.string().min(1),
  credentialIds: z.array(z.string()).min(1),
  purpose: z.nativeEnum(ConsentPurpose),
  durationDays: z.number().positive().optional(),
});

const revokeConsentSchema = z.object({
  // Consent.id is `@id @default(cuid())` (prisma/schema.prisma). This was
  // previously `z.string().uuid()`, which rejected every real consent ID and
  // made POST /api/consent/revoke return 400 unconditionally.
  consentId: CuidSchema,
});

const verifyConsentSchema = z.object({
  holderDid: z.string().startsWith('did:'),
  verifierDid: z.string().startsWith('did:'),
  credentialId: z.string().min(1),
});

// -- Routes --

/**
 * POST /api/consent/grant
 * Grant consent for a verifier to access specific credentials.
 * Requires authentication with a configured wallet.
 * The holderDid is automatically set from the authenticated user.
 */
consentRouter.post(
  '/grant',
  requireWallet,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const data = grantConsentSchema.parse(req.body);
      
      // Use authenticated user's DID as holderDid
      const record = await grantConsent({
        ...data,
        holderDid: user.did!,
      });

      const response: ApiResponse<typeof record> = {
        success: true,
        data: record,
        timestamp: new Date().toISOString(),
      };

      res.status(201).json(response);
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api/consent/revoke
 * Revoke an existing consent record.
 * Requires authentication with a configured wallet.
 * Only the consent holder can revoke their consent.
 */
consentRouter.post(
  '/revoke',
  requireWallet,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const { consentId } = revokeConsentSchema.parse(req.body);
      
      // Use authenticated user's DID to verify ownership
      const record = await revokeConsent(consentId, user.did!);

      const response: ApiResponse<typeof record> = {
        success: true,
        data: record,
        timestamp: new Date().toISOString(),
      };

      res.json(response);
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /api/consent/:holderDid
 * Query consent records for a holder.
 * Query param: ?activeOnly=true|false (default: true)
 * Requires authentication and ownership of the DID.
 */
consentRouter.get(
  '/:holderDid',
  requireWallet,
  requireOwnership('holderDid'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const holderDid = decodeURIComponent(req.params.holderDid as string);
      const activeOnly = req.query.activeOnly !== 'false';

      const records = await queryConsent(holderDid, activeOnly);

      const response: ApiResponse<typeof records> = {
        success: true,
        data: records,
        timestamp: new Date().toISOString(),
      };

      res.json(response);
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api/consent/verify
 * Check if a verifier has active consent to access a credential.
 * Requires authentication (for audit trail).
 */
consentRouter.post(
  '/verify',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { holderDid, verifierDid, credentialId } =
        verifyConsentSchema.parse(req.body);
      const result = await verifyConsent(holderDid, verifierDid, credentialId);

      const response: ApiResponse<typeof result> = {
        success: true,
        data: result,
        timestamp: new Date().toISOString(),
      };

      res.json(response);
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /api/consent/audit/:did
 * Query the audit log for a given DID.
 * Query param: ?limit=50
 * Requires authentication and ownership of the DID.
 */
consentRouter.get(
  '/audit/:did',
  requireWallet,
  requireOwnership('did'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const did = decodeURIComponent(req.params.did as string);
      const limitParse = z.coerce.number().int().min(1).max(200).default(50).safeParse(req.query.limit);
      const limit = limitParse.success ? limitParse.data : 50;

      const entries = await queryAuditLog(did, limit);
      const summary = await getAuditSummary(did);

      const response: ApiResponse<{ entries: typeof entries; summary: typeof summary }> =
        {
          success: true,
          data: { entries, summary },
          timestamp: new Date().toISOString(),
        };

      res.json(response);
    } catch (error) {
      next(error);
    }
  },
);
