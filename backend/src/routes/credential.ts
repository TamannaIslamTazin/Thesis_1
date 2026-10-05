/**
 * SSI Healthcare Backend - Credential Routes
 *
 * REST endpoints for Verifiable Credential operations following OID4VC.
 *
 * GET  /api/credentials/offers      - List credential offers for authenticated user
 * POST /api/credentials/accept-offer - Accept a credential offer
 * POST /api/credentials/reject-offer - Reject a credential offer
 * POST /api/credentials/offer        - Create a credential offer (requires wallet/issuer)
 * POST /api/credentials/verify       - Verify a presented credential
 * PATCH /api/credentials/:id/revoke  - Revoke a credential
 * DELETE /api/credentials/:id        - Delete a credential from wallet
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { randomBytes, randomUUID } from 'crypto';
import { z } from 'zod';
import {
  createCredentialOffer,
  issueCredentialWithCode,
  verifyCredential,
  revokeCredential,
} from '../services/credentialService.js';
import { 
  HealthcareCredentialCategory, 
  VerifiableCredentialSchema,
  DIDSchema,
  formatZodError,
  type ApiResponse,
} from '@ssi-healthcare/shared';
import { 
  requireAuth, 
  requireWallet,
  type AuthenticatedRequest 
} from '../middleware/auth.js';
import { db } from '../db/index.js';
import { logger } from '../utils/logger.js';

export const credentialRouter = Router();

// -- Validation schemas --

const credentialOfferSchema = z.object({
  subjectDid: DIDSchema,
  credentialType: z.string().min(1).max(256),
  category: z.nativeEnum(HealthcareCredentialCategory),
  claims: z.record(z.unknown()),
});

const verifyCredentialSchema = z.object({
  credential: VerifiableCredentialSchema,
  checkRevocation: z.boolean().default(true),
  checkExpiration: z.boolean().default(true),
});

// -- Routes --

/**
 * GET /api/credentials/offers
 * List pending credential offers for the authenticated user.
 * Matches by holder DID or holder email.
 */
credentialRouter.get(
  '/offers',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;

      // A NULL IDENTIFIER MUST NARROW TO NOTHING, NEVER MATCH EVERYTHING.
      //
      // This clause was `{ holderEmail: user.email }`, unguarded. When email
      // was mandatory that was a match on a value; once #398 removed email
      // from citizen signup, `user.email` became null for every wallet user
      // and Prisma renders `{ holderEmail: null }` as `holderEmail IS NULL` —
      // so the filter stopped selecting THIS holder's offers and started
      // selecting EVERY offer that had no email on it.
      //
      // Measured 9 Sep 2026: a doctor's wallet listed two health-card offers
      // belonging to two other people, naming their credential type and
      // issuer. `accept-offer` still refused them (its check short-circuits on
      // `user.email &&`, which is why nothing was mis-issued), so the damage
      // was confined to disclosure — but the listing is the surface a holder
      // actually reads.
      //
      // Generalise: a filter assembled from optional identity fields must be
      // built by COLLECTING the ones that are present, so an absent field
      // contributes no clause at all. An empty set of clauses then returns
      // nothing, which is the failsafe direction.
      const holderMatches = [
        ...(user.did ? [{ holderDid: user.did }] : []),
        ...(user.email ? [{ holderEmail: user.email }] : []),
      ];

      if (holderMatches.length === 0) {
        // Neither identifier is known, so nothing can be attributed to this
        // user. Answer empty rather than querying with no constraint.
        res.json({ success: true, data: [] });
        return;
      }

      const offers = await db.credentialOffer.findMany({
        where: {
          status: 'PENDING',
          expiresAt: { gt: new Date() },
          OR: holderMatches,
        },
        orderBy: { createdAt: 'desc' },
      });

      res.json({ success: true, data: offers });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api/credentials/accept-offer
 * Accept a credential offer and issue the credential.
 */
const acceptOfferSchema = z.object({
  offerId: z.string().min(1),
  pin: z.string().optional(),
});

credentialRouter.post(
  '/accept-offer',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const { offerId } = acceptOfferSchema.parse(req.body);

      const offer = await db.credentialOffer.findUnique({ where: { id: offerId } });
      if (!offer || offer.status !== 'PENDING') {
        res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Offer not found or already processed' } });
        return;
      }

      // Verify the offer belongs to this user
      const isHolder = (user.did && offer.holderDid === user.did) ||
                       (user.email && offer.holderEmail === user.email);
      if (!isHolder) {
        res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'This offer is not for you' } });
        return;
      }

      // SECURITY: this handler has never honoured the transaction PIN. The
      // schema above accepts `pin`, but it was never read, and issuance below
      // proceeds unconditionally — so a PIN-protected offer could be redeemed
      // here with no PIN at all, bypassing the gate entirely.
      //
      // The fix is to refuse, not to re-implement. `/oid4vci/token` already
      // does this properly (hashed comparison, attempt counting, exponential
      // lockout at oid4vci.ts:328-371); copying that logic here would recreate
      // the duplicated-surface-with-divergent-authorization class that the
      // deletion round removed. Callers holding a PIN-protected offer must use
      // the OID4VCI flow, which is also the standards-correct path.
      if (offer.pinRequired) {
        res.status(400).json({
          success: false,
          error: {
            code: 'PIN_REQUIRED',
            message:
              'This offer requires a transaction PIN. Redeem it via the OID4VCI flow (POST /oid4vci/token, then POST /oid4vci/credential).',
          },
        });
        return;
      }

      // If offer has pre-authorized code, issue the credential
      if (offer.preAuthorizedCode) {
        const credential = await issueCredentialWithCode(offer.preAuthorizedCode);
        res.json({ success: true, data: credential });
        return;
      }

      // Mark offer as accepted (credential will be issued separately)
      await db.credentialOffer.update({
        where: { id: offerId },
        data: { status: 'ACCEPTED', acceptedAt: new Date() },
      });

      res.json({ success: true, data: { message: 'Offer accepted' } });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api/credentials/reject-offer
 * Reject a credential offer.
 */
const rejectOfferSchema = z.object({
  offerId: z.string().min(1),
  reason: z.string().max(500).optional(),
});

credentialRouter.post(
  '/reject-offer',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const { offerId, reason } = rejectOfferSchema.parse(req.body);

      const offer = await db.credentialOffer.findUnique({ where: { id: offerId } });
      if (!offer || offer.status !== 'PENDING') {
        res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Offer not found or already processed' } });
        return;
      }

      const isHolder = (user.did && offer.holderDid === user.did) ||
                       (user.email && offer.holderEmail === user.email);
      if (!isHolder) {
        res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'This offer is not for you' } });
        return;
      }

      await db.credentialOffer.update({
        where: { id: offerId },
        data: { status: 'REJECTED' },
      });

      logger.info('Credential offer rejected', { offerId, userId: user.id, reason });
      res.json({ success: true, data: { message: 'Offer rejected' } });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api/credentials/resolve-offer
 * Resolve an OID4VCI pre-authorized code to get offer preview details.
 * Called by the holder wallet after scanning a credential-offer QR code.
 */
const resolveOfferSchema = z.object({
  preAuthorizedCode: z.string().min(1),
});

credentialRouter.post(
  '/resolve-offer',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const { preAuthorizedCode } = resolveOfferSchema.parse(req.body);

      const offer = await db.credentialOffer.findUnique({ where: { preAuthorizedCode } });

      if (!offer) {
        res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Credential offer not found for this code' } });
        return;
      }

      // SECURITY: this handler returns `previewData` — the full claims blob for
      // the credential (diagnoses, medications, results). Without this check it
      // was readable by ANY authenticated user who knew a `preAuthorizedCode`,
      // which is the exact leak round 1 stripped from the OID4VCI twin at
      // `oid4vci.ts` GET /offers/:id. The predicate mirrors /accept-offer above.
      const isHolder = (user.did && offer.holderDid === user.did) ||
                       (user.email && offer.holderEmail === user.email);
      if (!isHolder) {
        res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'This offer is not for you' } });
        return;
      }

      if (offer.status !== 'PENDING') {
        res.status(400).json({ success: false, error: { code: 'OFFER_ALREADY_USED', message: `Offer is ${offer.status.toLowerCase()}` } });
        return;
      }

      if (new Date() > offer.expiresAt) {
        await db.credentialOffer.update({ where: { id: offer.id }, data: { status: 'EXPIRED' } });
        res.status(400).json({ success: false, error: { code: 'OFFER_EXPIRED', message: 'Credential offer has expired' } });
        return;
      }

      res.json({
        success: true,
        data: {
          offerId: offer.id,
          credentialType: offer.credentialType,
          issuerDid: offer.issuerDid,
          issuerName: offer.issuerDid,
          previewData: offer.offerData,
          pinRequired: offer.pinRequired,
          expiresAt: offer.expiresAt.toISOString(),
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * DELETE /api/credentials/:id
 * Delete a credential from the user's wallet.
 */
credentialRouter.delete(
  '/:id',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const credentialId = String(req.params.id);

      const credential = await db.credential.findUnique({ where: { id: credentialId } });
      if (!credential) {
        res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Credential not found' } });
        return;
      }

      // Only the holder can delete from their wallet
      if (credential.holderDid !== user.did) {
        res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Not your credential' } });
        return;
      }

      await db.credential.delete({ where: { id: credentialId } });
      logger.info('Credential deleted', { credentialId, userId: user.id });

      res.json({ success: true, data: { message: 'Credential deleted' } });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api/credentials/offer
 * Create a credential offer with a pre-authorized code (OID4VCI flow).
 * Requires authentication with wallet (issuer must have a DID).
 * The issuer DID is automatically taken from authenticated user.
 */
credentialRouter.post(
  '/offer',
  requireWallet,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const data = credentialOfferSchema.parse(req.body);
      
      // Use authenticated user's DID as issuerDid
      const offer = await createCredentialOffer({
        ...data,
        issuerDid: user.did!,
      });

      const response: ApiResponse<typeof offer> = {
        success: true,
        data: offer,
        timestamp: new Date().toISOString(),
      };

      res.status(201).json(response);
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api/credentials/verify
 * Verify a Verifiable Credential's validity.
 * Validates the credential structure with Zod before verification.
 * Requires authentication for audit trail (the verifier).
 */
credentialRouter.post(
  '/verify',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Validate request body structure
      const parseResult = verifyCredentialSchema.safeParse(req.body);
      
      if (!parseResult.success) {
        const response: ApiResponse<null> = {
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid credential structure',
            details: { errors: formatZodError(parseResult.error) },
          },
          timestamp: new Date().toISOString(),
        };
        res.status(400).json(response);
        return;
      }
      
      const { credential, checkRevocation, checkExpiration } = parseResult.data;
      const result = await verifyCredential(credential, { checkRevocation, checkExpiration });

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
 * POST /api/credentials/:id/share
 * FINDING-013: Holder-initiated share — creates a verifiable presentation from the holder's
 * own credential and records it in the audit log for consent tracking (FINDING-034).
 */
const shareSchema = z.object({
  selectedAttributes: z.array(z.string()).optional(),
  recipientDid: z.string().optional(),
  requestId: z.string().optional(),
});

credentialRouter.post(
  '/:id/share',
  requireWallet,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const { selectedAttributes, recipientDid, requestId } = shareSchema.parse(req.body);

      const credId = String(req.params.id);
      // Verify credential belongs to this user (model is 'credential', not 'verifiableCredential')
      const credential = await db.credential.findFirst({
        where: { id: credId, holderUserId: user.id },
      });
      if (!credential) {
        res.status(404).json({ success: false, error: { code: 'CREDENTIAL_NOT_FOUND', message: 'Credential not found' } });
        return;
      }

      // Record share as a Presentation entry for audit/consent tracking (FINDING-034)
      const presentation = await db.presentation.create({
        data: {
          holderDid: user.did ?? undefined,
          verifierDid: recipientDid ?? 'self',
          // SECURITY: Math.random() is not a CSPRNG — its output is predictable
          // from observed values. A presentation nonce is replay-protection and
          // a requestId is a capability handle, so both must be unguessable.
          requestId: requestId ?? `share-${randomUUID()}`,
          nonce: randomBytes(32).toString('hex'),
          presentationType: selectedAttributes && selectedAttributes.length > 0 ? 'SELECTIVE' : 'FULL',
          requestedCredentials: { credentialId: credId },
          selectedDisclosure: selectedAttributes ? { attributes: selectedAttributes } : undefined,
          status: 'VERIFIED',
          presentedAt: new Date(),
          verifiedAt: new Date(),
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
          credentials: {
            create: {
              credentialId: credId,
              disclosedAttributes: selectedAttributes ?? [],
            },
          },
        },
      });

      // Audit log entry for FINDING-034 consent tracking
      await db.auditLog.create({
        data: {
          actorUserId: user.id,
          targetUserId: user.id,
          resourceType: 'credential',
          resourceId: credId,
          eventType: 'CREDENTIAL_SHARED' as never,
          action: `Shared credential ${credId}`,
          details: {
            presentationId: presentation.id,
            recipientDid,
            fieldsCount: selectedAttributes?.length,
            credentialType: credential.type,
          },
        },
      });

      const response: ApiResponse<{ presentationId: string }> = {
        success: true,
        data: { presentationId: presentation.id },
        timestamp: new Date().toISOString(),
      };

      res.json(response);
    } catch (error) {
      next(error);
    }
  },
);
const revokeSchema = z.object({
  reason: z.string().max(1000).optional(),
});

credentialRouter.patch(
  '/:id/revoke',
  requireWallet,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const { reason } = revokeSchema.parse(req.body);
      const result = await revokeCredential(String(req.params.id), user.did!, reason);

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
