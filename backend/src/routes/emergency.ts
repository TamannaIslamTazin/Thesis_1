/**
 * SSI Healthcare Backend - Emergency Access Routes
 *
 * REST endpoints for emergency break-glass access (Paradigm B).
 * All routes require authentication. Emergency requests create
 * comprehensive audit trails for HIPAA compliance.
 *
 * POST /api/emergency/request  - Request emergency access (provider auth)
 * POST /api/emergency/revoke   - Revoke emergency access (patient/family auth)
 * POST /api/emergency/check    - Check if emergency access is active (any auth)
 * GET  /api/emergency/:patientDid - Query emergency records (patient auth + ownership)
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { getAgent } from '../agent/index.js';
import { z } from 'zod';
import {
  requestEmergencyAccess,
  revokeEmergencyAccess,
  checkEmergencyAccess,
  queryEmergencyRecords,
  readEmergencyCredentials,
  createBreakGlassChallenge,
  requestEmergencyAccessBySignature,
  readEmergencyCredentialsBySignature,
} from '../services/emergencyService.js';
import { CuidSchema, type ApiResponse } from '@ssi-healthcare/shared';
import { 
  requireAuth, 
  requireWallet, 
  requireOwnership,
  type AuthenticatedRequest 
} from '../middleware/auth.js';

export const emergencyRouter: Router = Router();

// -- Validation schemas --

const requestAccessSchema = z.object({
  patientDid: z.string().startsWith('did:'),
  reason: z.string().min(10, 'Reason must be at least 10 characters'),
  credentialIds: z.array(z.string()).min(1),
  familyContactDid: z.string().startsWith('did:').optional(),
});

const revokeAccessSchema = z.object({
  // EmergencyAccessRecord.id is `@id @default(cuid())` (prisma/schema.prisma).
  // This was previously `z.string().uuid()`, which rejected every real record
  // ID and left break-glass revocation permanently non-functional.
  emergencyId: CuidSchema,
});

const checkAccessSchema = z.object({
  providerDid: z.string().startsWith('did:'),
  patientDid: z.string().startsWith('did:'),
});

/** The provider comes from the session, so only the patient is named here. */
const readCredentialsSchema = z.object({
  patientDid: z.string().startsWith('did:'),
});

const breakGlassChallengeSchema = z.object({
  providerDid: z.string().startsWith('did:'),
  patientDid: z.string().startsWith('did:'),
  reason: z.string().min(10, 'Reason must be at least 10 characters'),
  credentialIds: z.array(z.string()).min(1),
  purpose: z.enum(['open', 'read']).default('open'),
});

const breakGlassSubmitSchema = z.object({
  challengeId: z.string().min(1),
  verificationMethodId: z.string().includes('#'),
  signatureBase64Url: z.string().min(1),
  providerName: z.string().min(1),
});

const breakGlassReadSchema = z.object({
  challengeId: z.string().min(1),
  verificationMethodId: z.string().includes('#'),
  signatureBase64Url: z.string().min(1),
});

// -- Routes --

/**
 * POST /api/emergency/request
 * Request emergency break-glass access.
 * Requires authentication with wallet (provider must have DID).
 * Provider information is taken from authenticated user.
 */
emergencyRouter.post(
  '/request',
  requireWallet,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const data = requestAccessSchema.parse(req.body);
      
      // Use authenticated user's DID and name as provider
      const record = await requestEmergencyAccess({
        ...data,
        providerDid: user.did!,
        // `user.email` is optional since the auth/keystore round (a DID-only
        // signup path now exists); fall back to a fixed label rather than
        // `string | null` when this account has neither a name nor an email.
        providerName: user.firstName
          ? `${user.firstName} ${user.lastName || ''}`.trim()
          : user.email ?? 'Unnamed provider',
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
 * POST /api/emergency/revoke
 * Revoke emergency access.
 * Requires authentication with wallet.
 * Only the patient or designated family contact can revoke.
 */
emergencyRouter.post(
  '/revoke',
  requireWallet,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const { emergencyId } = revokeAccessSchema.parse(req.body);
      
      // Use authenticated user's DID as revoker
      const record = await revokeEmergencyAccess(emergencyId, user.did!);

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
 * POST /api/emergency/check
 * Check if emergency access is currently active.
 * Requires authentication for audit trail.
 */
emergencyRouter.post(
  '/check',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { providerDid, patientDid } = checkAccessSchema.parse(req.body);
      const result = await checkEmergencyAccess(providerDid, patientDid);

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
 * POST /api/emergency/challenge
 *
 * UNAUTHENTICATED BY DESIGN, like the OID4VP response route. A hospital proves
 * who it is with a signature over bytes this server chose; making it hold an
 * account here first would put every provider in the country in the ministry's
 * user table, which is the centralisation this system exists to remove.
 *
 * Returns the EXACT bytes to sign. Not a template — a template is a
 * canonicalisation contract in disguise, and the locker round (#401) is the
 * record of what that costs.
 */
emergencyRouter.post(
  '/challenge',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = breakGlassChallengeSchema.parse(req.body);
      const challenge = createBreakGlassChallenge(data);

      const response: ApiResponse<typeof challenge> = {
        success: true,
        data: challenge,
        timestamp: new Date().toISOString(),
      };
      res.json(response);
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api/emergency/break-glass
 *
 * Open emergency access with a signed request and no session. The provider,
 * patient, reason and credential list all come from the CHALLENGE, never from
 * this body — the signature covers those, and re-reading them from the wire
 * would let a caller sign for one patient and open another.
 */
emergencyRouter.post(
  '/break-glass',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = breakGlassSubmitSchema.parse(req.body);
      const agent = getAgent();

      const record = await requestEmergencyAccessBySignature({
        ...data,
        resolveDidDocument: async (did) =>
          (await agent.dids.resolveDidDocument(did)) as never,
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
 * POST /api/emergency/read-signed
 *
 * Spend an existing grant with a signature rather than a session. Separate from
 * opening it, and signed separately, so a grant and a read remain two acts with
 * two audit entries — a grant records what a provider was ALLOWED to see, and
 * only a read records what they actually saw.
 */
emergencyRouter.post(
  '/read-signed',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = breakGlassReadSchema.parse(req.body);
      const agent = getAgent();

      const result = await readEmergencyCredentialsBySignature({
        ...data,
        resolveDidDocument: async (did) =>
          (await agent.dids.resolveDidDocument(did)) as never,
      });

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
 * POST /api/emergency/read
 * Read a patient's credentials under an ACTIVE emergency grant.
 *
 * MOUNTED BEFORE `/:patientDid`, deliberately. Express matches in declaration
 * order and `/:patientDid` is a wildcard that would swallow `/read`, sending it
 * into the ownership guard with "read" as a DID — a 404 or a confusing 403 for
 * a route that exists.
 *
 * The provider is taken from the SESSION, never from the body: letting a caller
 * name the provider whose grant they are exercising would let anyone spend
 * anyone else's break-glass access.
 */
emergencyRouter.post(
  '/read',
  requireWallet,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const { patientDid } = readCredentialsSchema.parse(req.body);

      const result = await readEmergencyCredentials({
        providerDid: user.did!,
        patientDid,
      });

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
 * GET /api/emergency/:patientDid
 * Query all emergency access records for a patient.
 * Requires authentication and ownership of the patient DID.
 */
emergencyRouter.get(
  '/:patientDid',
  requireWallet,
  requireOwnership('patientDid'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const patientDid = decodeURIComponent(req.params.patientDid as string);
      const records = await queryEmergencyRecords(patientDid);

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
