/**
 * SSI Healthcare Backend — L1 issuer dashboard (IDENTITY-VERIFICATION-API.md §5).
 *
 * GET  /api/authority/queue                    PENDING submissions addressed
 *                                                to the caller's own authority
 * GET  /api/authority/requests/:id              detail; releases the wrapped
 *                                                content key on the first read
 * POST /api/authority/requests/:id/approve      issue the credential
 * POST /api/authority/requests/:id/reject       with a reason the holder sees
 *
 * Every route is gated by `requireAuthorityMember`, which is what keeps an L2
 * institution's staff (hospitals, clinics) out of this router entirely — see
 * that middleware for how membership is matched.
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';

import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES, documentTypeById, HEALTH_CARD_CREDENTIAL_TYPE } from '@ssi-healthcare/shared';
import { requireAuth } from '../middleware/auth.js';
import { requireAuthorityMember, type AuthorityMemberRequest } from '../middleware/requireAuthorityMember.js';
import { db } from '../db/index.js';
import * as consentRepo from '../db/consentRepository.js';
import { logger } from '../utils/logger.js';
import { AuditEventType, CredentialCategory, type Prisma } from '../../prisma/generated/client/index.js';
import { buildApprovalCredentialClaims } from '../services/issuance.js';

export const authorityRouter = Router();

const HOLDER_SELECT = { id: true, firstName: true, lastName: true, email: true } as const;

// ---------------------------------------------------------------------------
// GET /queue
// ---------------------------------------------------------------------------

/** GET /api/authority/queue — PENDING submissions addressed to my authority. */
authorityRouter.get(
  '/queue',
  requireAuth,
  requireAuthorityMember,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { authorityInstitution: institution } = req as AuthorityMemberRequest;

      const requests = await db.issuanceRequest.findMany({
        where: { authorityInstitutionId: institution.id, status: 'PENDING' },
        orderBy: { createdAt: 'asc' },
        include: {
          holder: { select: HOLDER_SELECT },
          documents: { select: { id: true, lockerObjectId: true, contentHash: true, mediaType: true } },
        },
      });

      res.json({
        success: true,
        data: {
          requests: requests.map((r) => ({
            id: r.id,
            documentType: r.documentTypeId,
            holderDid: r.holderDid,
            holder: r.holder,
            documents: r.documents,
            createdAt: r.createdAt,
            keyReleased: r.keyReleasedAt !== null,
          })),
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  },
);

// ---------------------------------------------------------------------------
// GET /requests/:id — single-use key release
// ---------------------------------------------------------------------------

/**
 * GET /api/authority/requests/:id
 *
 * SINGLE-USE KEY RELEASE, RECORDED BEFORE THE RESPONSE IS BUILT.
 *
 * `updateMany({ where: { ..., keyReleasedAt: null }, data: { keyReleasedAt: now, ... } })`
 * is the compare-and-swap: Postgres serialises concurrent UPDATEs against the
 * same row, so of any number of simultaneous requests for the same id, at
 * most one observes `count === 1`. That write COMMITS here, before this
 * handler has assembled a single byte of the JSON response — a crash between
 * this call and `res.json` below spends the key without ever handing it to
 * anyone, which is the fail-closed direction the brief asks for: a lost key
 * release is recoverable by re-approving through a fresh submission; a leaked
 * second release is not.
 */
authorityRouter.get(
  '/requests/:id',
  requireAuth,
  requireAuthorityMember,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { authorityInstitution: institution, authorityMember: member } = req as AuthorityMemberRequest;
      const id = String(req.params.id);

      const claim = await db.issuanceRequest.updateMany({
        where: { id, authorityInstitutionId: institution.id, keyReleasedAt: null },
        data: { keyReleasedAt: new Date(), keyReleasedToMemberId: member.id },
      });

      const request = await db.issuanceRequest.findFirst({
        where: { id, authorityInstitutionId: institution.id },
        include: {
          holder: { select: HOLDER_SELECT },
          documents: { select: { id: true, lockerObjectId: true, contentHash: true, mediaType: true } },
        },
      });

      if (!request) {
        throw new AppError(ERROR_CODES.NOT_FOUND, 'Issuance request not found.', 404);
      }

      const releasedJustNow = claim.count === 1;
      if (releasedJustNow) {
        await consentRepo.createAuditLog({
          eventType: AuditEventType.ISSUANCE_KEY_RELEASED,
          action: `Single-use content key released to ${member.email}`,
          actorDid: institution.did,
          resourceType: 'issuanceRequest',
          resourceId: id,
          details: { memberId: member.id },
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
        });
        logger.info('issuance_key_released', { requestId: id, memberId: member.id });
      }

      res.json({
        success: true,
        data: {
          id: request.id,
          documentType: request.documentTypeId,
          status: request.status,
          holderDid: request.holderDid,
          holder: request.holder,
          documents: request.documents,
          createdAt: request.createdAt,
          keyReleased: request.keyReleasedAt !== null,
          // Present ONLY on the read that just performed the release. Every
          // subsequent GET for this id — including a retry by this same
          // officer — gets `keyReleased: true` and no key.
          ...(releasedJustNow ? { wrappedContentKey: request.wrappedContentKey } : {}),
          // UNLIKE wrappedContentKey, returned on EVERY read (OFFICER-DOCUMENT-ACCESS.md
          // §4): the capability is time-bounded, not single-use, so an
          // officer re-opening the detail screen mid-review must still be
          // able to read the document without spending the key a second time.
          lockerCapability: request.lockerCapability,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  },
);

// ---------------------------------------------------------------------------
// POST /requests/:id/approve
// ---------------------------------------------------------------------------

const approveSchema = z.object({
  claims: z.record(z.unknown()).optional(),
});

/**
 * POST /api/authority/requests/:id/approve
 *
 * Issues through the existing CredentialOffer/OID4VCI mechanism — the same
 * row `POST /oid4vci/offers` creates — rather than a second issuance path.
 * `tx.credentialOffer.create` is used directly instead of the repository
 * helper because the approve claim (below) and the offer creation must
 * commit or roll back TOGETHER: `db.$transaction` is what makes that true.
 *
 * See `db.$transaction` below for why the approve claim, the offer creation
 * and linking the offer back onto the request happen inside one transaction:
 * CLAUDE.md #315 — a multi-phase procedure is only failsafe if each phase
 * re-establishes its own precondition rather than inheriting it from a prior
 * phase having run. Claiming the approval (status PENDING -> APPROVED) and
 * then failing to create the offer would leave a request stuck APPROVED with
 * nothing issued and no way to retry, because approve only proceeds from
 * PENDING. Wrapping both in one transaction makes a failure anywhere in it
 * leave the request exactly as it was — PENDING, retriable — instead of half
 * done.
 */
authorityRouter.post(
  '/requests/:id/approve',
  requireAuth,
  requireAuthorityMember,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { authorityInstitution: institution, authorityMember: member } = req as AuthorityMemberRequest;
      const id = String(req.params.id);
      const { claims } = approveSchema.parse(req.body ?? {});

      const request = await db.issuanceRequest.findFirst({
        where: { id, authorityInstitutionId: institution.id },
      });
      if (!request) {
        throw new AppError(ERROR_CODES.NOT_FOUND, 'Issuance request not found.', 404);
      }

      const documentType = documentTypeById(request.documentTypeId);
      if (!documentType) {
        throw new AppError(
          ERROR_CODES.INTERNAL_ERROR,
          `Document type '${request.documentTypeId}' is no longer configured.`,
          500,
        );
      }

      // Validated BEFORE any write, so a bad claims body fails without
      // touching the request's status.
      const credentialSubject = buildApprovalCredentialClaims(documentType, request.holderDid, claims);
      const category =
        documentType.credentialType === HEALTH_CARD_CREDENTIAL_TYPE
          ? CredentialCategory.IDENTITY
          : CredentialCategory.PROFESSIONAL;

      const offer = await db.$transaction(async (tx) => {
        const claimed = await tx.issuanceRequest.updateMany({
          where: { id, authorityInstitutionId: institution.id, status: 'PENDING' },
          data: { status: 'APPROVED', decidedAt: new Date(), decidedByMemberId: member.id },
        });
        if (claimed.count !== 1) {
          throw new AppError(
            ERROR_CODES.ISSUANCE_REQUEST_NOT_PENDING,
            'Issuance request is not PENDING; it has already been decided or withdrawn.',
            400,
          );
        }

        const created = await tx.credentialOffer.create({
          data: {
            issuerDid: institution.did,
            holderDid: request.holderDid,
            credentialType: documentType.credentialType,
            category,
            preAuthorizedCode: randomUUID(),
            pinRequired: false,
            offerData: credentialSubject as Prisma.InputJsonValue,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          },
        });

        await tx.issuanceRequest.update({
          where: { id },
          data: { issuedCredentialOfferId: created.id },
        });

        return created;
      });

      await consentRepo.createAuditLog({
        eventType: AuditEventType.ISSUANCE_REQUEST_APPROVED,
        action: `Issuance request approved by ${member.email}; credential offer created`,
        actorDid: institution.did,
        targetDid: request.holderDid,
        resourceType: 'issuanceRequest',
        resourceId: id,
        details: { offerId: offer.id, credentialType: documentType.credentialType, memberId: member.id },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      logger.info('issuance_request_approved', { requestId: id, offerId: offer.id, memberId: member.id });

      res.json({
        success: true,
        data: { id, status: 'APPROVED', offerId: offer.id },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  },
);

// ---------------------------------------------------------------------------
// POST /requests/:id/reject
// ---------------------------------------------------------------------------

const rejectSchema = z.object({
  reason: z.string().min(1).max(2000),
});

/** POST /api/authority/requests/:id/reject — with a reason the holder can see. */
authorityRouter.post(
  '/requests/:id/reject',
  requireAuth,
  requireAuthorityMember,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { authorityInstitution: institution, authorityMember: member } = req as AuthorityMemberRequest;
      const id = String(req.params.id);
      const { reason } = rejectSchema.parse(req.body);

      const claimed = await db.issuanceRequest.updateMany({
        where: { id, authorityInstitutionId: institution.id, status: 'PENDING' },
        data: { status: 'REJECTED', decidedAt: new Date(), decidedByMemberId: member.id, rejectionReason: reason },
      });

      if (claimed.count !== 1) {
        const exists = await db.issuanceRequest.findFirst({
          where: { id, authorityInstitutionId: institution.id },
          select: { status: true },
        });
        if (!exists) {
          throw new AppError(ERROR_CODES.NOT_FOUND, 'Issuance request not found.', 404);
        }
        throw new AppError(
          ERROR_CODES.ISSUANCE_REQUEST_NOT_PENDING,
          `Issuance request is ${exists.status}, not PENDING; it cannot be rejected.`,
          400,
        );
      }

      await consentRepo.createAuditLog({
        eventType: AuditEventType.ISSUANCE_REQUEST_REJECTED,
        action: `Issuance request rejected by ${member.email}`,
        actorDid: institution.did,
        resourceType: 'issuanceRequest',
        resourceId: id,
        details: { reason, memberId: member.id },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      logger.info('issuance_request_rejected', { requestId: id, memberId: member.id });

      res.json({ success: true, data: { id, status: 'REJECTED', reason }, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  },
);
