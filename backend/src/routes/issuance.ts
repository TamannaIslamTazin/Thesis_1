/**
 * SSI Healthcare Backend — L1 identity/licence issuance, holder side
 * (IDENTITY-VERIFICATION-API.md §3-4).
 *
 * GET    /api/issuance/document-types   public; the one place the wallet's
 *                                        document-type dropdown reads from
 * POST   /api/issuance/requests         create a submission
 * GET    /api/issuance/requests         list my submissions
 * GET    /api/issuance/requests/:id     one submission
 * DELETE /api/issuance/requests/:id     withdraw, only while PENDING
 *
 * The server never receives the documents themselves — only locker object
 * references — and never receives the content key in the clear, only a
 * wrapped key it does not open (see `services/issuance.ts`). The authority
 * side (queue, single-use key release, approve/reject) is `routes/authority.ts`.
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';

import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES, DOCUMENT_TYPES, documentTypeById } from '@ssi-healthcare/shared';
import { requireWallet, type AuthenticatedRequest } from '../middleware/auth.js';
import { db } from '../db/index.js';
import * as consentRepo from '../db/consentRepository.js';
import { logger } from '../utils/logger.js';
import { AuditEventType, type Prisma } from '../../prisma/generated/client/index.js';
import {
  wrappedContentKeyShape,
  lockerCapabilityTokenShape,
  assertDocumentsSatisfyRequirements,
  assertWrappedKeyTargetsAuthority,
  assertCapabilityMatchesSubmission,
} from '../services/issuance.js';

export const issuanceRouter = Router();

// ---------------------------------------------------------------------------
// GET /document-types
// ---------------------------------------------------------------------------

/**
 * GET /api/issuance/document-types
 *
 * Public. Each type carries its issuing authority DID, the documents
 * required, and the credential type issued on approval. This is the ONLY
 * place the mapping lives — the wallet must never hardcode an authority.
 */
issuanceRouter.get('/document-types', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: { documentTypes: DOCUMENT_TYPES },
    timestamp: new Date().toISOString(),
  });
});

// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------

type IssuanceRequestWithDocuments = Prisma.IssuanceRequestGetPayload<{
  include: { documents: true };
}>;

/** Never includes `wrappedContentKey` — the holder submitted it and never needs it back. */
function toHolderView(request: IssuanceRequestWithDocuments) {
  return {
    id: request.id,
    documentType: request.documentTypeId,
    credentialType: request.credentialType,
    authorityDid: request.authorityDid,
    status: request.status,
    createdAt: request.createdAt,
    decidedAt: request.decidedAt,
    rejectionReason: request.rejectionReason,
    withdrawnAt: request.withdrawnAt,
    documents: request.documents.map((doc) => ({
      id: doc.id,
      lockerObjectId: doc.lockerObjectId,
      contentHash: doc.contentHash,
      mediaType: doc.mediaType,
    })),
  };
}

const submitDocumentSchema = z.object({
  lockerObjectId: z.string().min(1).max(256),
  contentHash: z.string().regex(/^[0-9a-f]{64}$/, 'contentHash must be the sha256 hex of the ciphertext'),
  mediaType: z.string().min(1).max(128),
});

const createIssuanceRequestSchema = z.object({
  /**
   * Client-generated. The locker capability's `sub` claim
   * (OFFICER-DOCUMENT-ACCESS.md §3) names the submission it belongs to, and
   * the wallet mints that capability BEFORE this row exists server-side —
   * there is no id to reference otherwise. Uniqueness is enforced by the
   * primary key; a collision (practically unreachable at this round's
   * entropy — 16 random bytes, same as the capability's own `jti`) is
   * refused with 409, never silently overwritten.
   */
  requestId: z.string().min(16).max(64),
  documentType: z.string().min(1),
  documents: z.array(submitDocumentSchema).min(1).max(10),
  wrappedContentKey: wrappedContentKeyShape,
  /** The holder's locker read capability (OFFICER-DOCUMENT-ACCESS.md §6a). */
  capability: lockerCapabilityTokenShape,
});

// ---------------------------------------------------------------------------
// POST /requests
// ---------------------------------------------------------------------------

/**
 * POST /api/issuance/requests
 *
 * Carries the document type and, per attached document, its locker object
 * id, content hash and media type — plus the content key wrapped to the
 * authority's public key. The server stores ciphertext references and a
 * wrapped key it cannot open; it never receives the documents.
 */
issuanceRouter.post('/requests', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const data = createIssuanceRequestSchema.parse(req.body);

    const documentType = documentTypeById(data.documentType);
    if (!documentType) {
      throw new AppError(ERROR_CODES.DOCUMENT_TYPE_UNKNOWN, `Unknown document type '${data.documentType}'.`, 400);
    }

    assertDocumentsSatisfyRequirements(documentType, data.documents);
    assertWrappedKeyTargetsAuthority(documentType, data.wrappedContentKey);
    assertCapabilityMatchesSubmission({
      documentType,
      holderDid: user.did!,
      requestId: data.requestId,
      documents: data.documents,
      capability: data.capability,
    });

    const authorityInstitution = await db.institution.findUnique({
      where: { did: documentType.issuingAuthorityDid },
    });
    if (!authorityInstitution || !authorityInstitution.isActive) {
      // The registry named an authority this deployment has not seeded (or
      // has deactivated). Fails closed rather than filing a submission with
      // nowhere for it to be reviewed — see the seed migration
      // (20260905070559_seed_l1_authorities) for how the four L1 rows are
      // meant to stay in step with this registry.
      logger.error('issuance_request_authority_unresolved', {
        documentType: documentType.id,
        issuingAuthorityDid: documentType.issuingAuthorityDid,
      });
      throw new AppError(
        ERROR_CODES.INTERNAL_ERROR,
        `The issuing authority for '${documentType.id}' is not configured on this deployment.`,
        503,
      );
    }

    let request;
    try {
      request = await db.issuanceRequest.create({
        data: {
          id: data.requestId,
          holderUserId: user.id,
          holderDid: user.did!,
          documentTypeId: documentType.id,
          credentialType: documentType.credentialType,
          authorityInstitutionId: authorityInstitution.id,
          authorityDid: documentType.issuingAuthorityDid,
          wrappedContentKey: data.wrappedContentKey as unknown as Prisma.InputJsonValue,
          lockerCapability: data.capability as unknown as Prisma.InputJsonValue,
          documents: {
            create: data.documents.map((doc) => ({
              lockerObjectId: doc.lockerObjectId,
              contentHash: doc.contentHash,
              mediaType: doc.mediaType,
            })),
          },
        },
        include: { documents: true },
      });
    } catch (error) {
      // Prisma P2002: unique constraint violation on the client-chosen id.
      if (error && typeof error === 'object' && 'code' in error && error.code === 'P2002') {
        throw new AppError(
          ERROR_CODES.ISSUANCE_REQUEST_ID_CONFLICT,
          `requestId '${data.requestId}' is already in use. Generate a fresh one and retry — ` +
            'nothing was persisted for this attempt.',
          409,
        );
      }
      throw error;
    }

    await consentRepo.createAuditLog({
      eventType: AuditEventType.ISSUANCE_REQUEST_SUBMITTED,
      action: `Issuance request submitted for ${documentType.label}`,
      actorUserId: user.id,
      actorDid: user.did ?? undefined,
      resourceType: 'issuanceRequest',
      resourceId: request.id,
      details: { documentType: documentType.id, authorityDid: documentType.issuingAuthorityDid },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    logger.info('issuance_request_submitted', { requestId: request.id, documentType: documentType.id });

    res.status(201).json({ success: true, data: toHolderView(request), timestamp: new Date().toISOString() });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// GET /requests
// ---------------------------------------------------------------------------

/** GET /api/issuance/requests — list my submissions and their status. */
issuanceRouter.get('/requests', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const requests = await db.issuanceRequest.findMany({
      where: { holderUserId: user.id },
      orderBy: { createdAt: 'desc' },
      include: { documents: true },
    });
    res.json({
      success: true,
      data: { requests: requests.map(toHolderView) },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// GET /requests/:id
// ---------------------------------------------------------------------------

/** GET /api/issuance/requests/:id — one submission. */
issuanceRouter.get('/requests/:id', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const id = String(req.params.id);

    const request = await db.issuanceRequest.findUnique({ where: { id }, include: { documents: true } });
    if (!request) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Issuance request not found.', 404);
    }
    if (request.holderUserId !== user.id) {
      throw new AppError(
        ERROR_CODES.AUTH_INSUFFICIENT_PERMISSIONS,
        'Not authorized to view this issuance request.',
        403,
      );
    }

    res.json({ success: true, data: toHolderView(request), timestamp: new Date().toISOString() });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// DELETE /requests/:id
// ---------------------------------------------------------------------------

/** DELETE /api/issuance/requests/:id — withdraw, only while PENDING. */
issuanceRouter.delete('/requests/:id', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const id = String(req.params.id);

    const request = await db.issuanceRequest.findUnique({ where: { id } });
    if (!request) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Issuance request not found.', 404);
    }
    if (request.holderUserId !== user.id) {
      throw new AppError(
        ERROR_CODES.AUTH_INSUFFICIENT_PERMISSIONS,
        'Not authorized to withdraw this issuance request.',
        403,
      );
    }

    // Compare-and-swap: only a request still PENDING moves, in one statement,
    // so a concurrent approve/reject cannot interleave between the read above
    // and this write.
    const outcome = await db.issuanceRequest.updateMany({
      where: { id, status: 'PENDING' },
      data: { status: 'WITHDRAWN', withdrawnAt: new Date() },
    });
    if (outcome.count !== 1) {
      throw new AppError(
        ERROR_CODES.ISSUANCE_REQUEST_NOT_PENDING,
        `Issuance request is ${request.status}, not PENDING; it cannot be withdrawn.`,
        400,
      );
    }

    await consentRepo.createAuditLog({
      eventType: AuditEventType.ISSUANCE_REQUEST_WITHDRAWN,
      action: 'Issuance request withdrawn by holder',
      actorUserId: user.id,
      actorDid: user.did ?? undefined,
      resourceType: 'issuanceRequest',
      resourceId: id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({ success: true, data: { id, status: 'WITHDRAWN' }, timestamp: new Date().toISOString() });
  } catch (error) {
    next(error);
  }
});
