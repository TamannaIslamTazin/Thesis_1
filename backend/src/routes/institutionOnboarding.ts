/**
 * L2 institution onboarding (owner's instruction, 24 Sep 2026).
 *
 * ===========================================================================
 * WHY THIS IS A SEPARATE SURFACE, NOT A TAB IN THE ISSUANCE QUEUE
 * ===========================================================================
 * Every existing console surface shares one shape: a person submits a document,
 * an officer reviews it, a credential is issued to that person. Onboarding an
 * institution shares NONE of that — there is no document to fetch, no
 * single-use key to release, no holder wallet to deliver to. The subject is an
 * ENTITY, and what the officer judges is a PLACE.
 *
 * ===========================================================================
 * THE OFFICER AUTHORISES. THE QR ONLY PAIRS.
 * ===========================================================================
 * The enrolment token pairs the institution's software to the officer's session
 * and creates NOTHING. The officer then confirms what they saw on site, and that
 * confirmation mints. If possession of the QR were sufficient, the authorisation
 * would come from a bitmap and the site visit — the one thing separating a real
 * pharmacy from a shell entity — would be decorative.
 *
 * ===========================================================================
 * ADMIN ONLY, AND WHY THAT IS STRICTER THAN IT LOOKS
 * ===========================================================================
 * `requireAuthorityRole.ts` gates roster management to ADMIN because an OFFICER
 * who could create a colleague could create an ADMIN under their own control,
 * collapsing the two roles. Minting an institution is STRICTLY MORE POWERFUL
 * than creating a member: an OFFICER who could mint an arbitrary institution
 * could invent an entity, have it licensed, and append dispenses against a
 * pharmacy that never existed.
 *
 * ===========================================================================
 * THE CLAIM ENDPOINT IS NOT AUTHENTICATED, AND THAT IS THE DESIGN
 * ===========================================================================
 * The institution's software is not a signed-in user and has no session. Its
 * only credential is the token: secret, single-use, and valid for ten minutes.
 * That is the whole of its security, and it is why the token is never logged
 * (see institutionEnrolment.ts).
 */
import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';

import { AppError } from '../middleware/errorHandler.js';
import { requireAuth } from '../middleware/auth.js';
import { requireAuthorityMember, type AuthorityMemberRequest } from '../middleware/requireAuthorityMember.js';
import { requireAuthorityRole } from '../middleware/requireAuthorityRole.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import { logger } from '../utils/logger.js';
import {
  createEnrolment,
  claimEnrolment,
  completeEnrolment,
} from '../services/institutionEnrolment.js';
import { mintInstitutionDid } from '../services/institutionMinting.js';

export const institutionOnboardingRouter = Router();

const createSchema = z.object({
  /** Shown on the officer's screen, e.g. "Stood at Mirpur, Dhaka". Free text. */
  note: z.string().trim().max(500).optional(),
});

const completeSchema = z.object({
  name: z.string().trim().min(2).max(200),
  type: z.enum(['HOSPITAL', 'CLINIC', 'PHARMACY', 'LABORATORY']),
  /** What the officer read off the premises, recorded as the attestation. */
  address: z.string().trim().min(4).max(500),
  licenceNumber: z.string().trim().max(120).optional(),
  phone: z.string().trim().max(40).optional(),
  email: z.string().trim().email().max(200).optional(),
});

/**
 * POST /api/authority/enrolments — an ADMIN starts an onboarding.
 *
 * The authority recorded is the OFFICER'S OWN institution (`authorityInstitution`),
 * not a body chosen from a request body. The trust anchor must be whatever the
 * officer actually acts for, and taking it from their session rather than from
 * input is what makes it impossible to onboard an institution under an authority
 * the caller does not hold.
 */
institutionOnboardingRouter.post(
  '/enrolments',
  requireAuth,
  requireAuthorityMember,
  requireAuthorityRole('ADMIN'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const parsed = createSchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Invalid onboarding request', 400);
      }

      const { authorityMember, authorityInstitution } = req as AuthorityMemberRequest;
      const { enrolmentId, token, expiresAt } = await createEnrolment({
        officerMemberId: authorityMember.id,
        authorityId: authorityInstitution.id,
        note: parsed.data.note,
      });

      res.status(201).json({
        success: true,
        // `enrolmentId` is returned so the console can poll and complete without
        // a second lookup — the token itself is a bearer secret and should not be
        // the only handle the officer's own screen has on the enrolment.
        data: {
          enrolmentId,
          token,
          expiresAt: expiresAt.toISOString(),
          authorityId: authorityInstitution.id,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api/authority/enrolments/:token/claim — the institution's software claims
 * the token.
 *
 * NO AUTH, DELIBERATELY (see the file header). Refusals are generic: an unknown
 * token and an expired one both say little, because a detailed answer to an
 * unauthenticated caller is an oracle.
 */
institutionOnboardingRouter.post(
  '/enrolments/:token/claim',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = String(req.params.token ?? '').trim();
      if (token.length === 0) {
        throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'A token is required', 400);
      }

      // Identifies WHICH software is waiting, so the officer can see they are
      // confirming the machine in front of them. Not a trust signal, a label.
      const claimedBy =
        typeof req.body?.claimedBy === 'string' && req.body.claimedBy.trim().length > 0
          ? req.body.claimedBy.trim().slice(0, 200)
          : 'unknown device';

      // The software's own key, when it can generate one. Supplying it is what
      // makes the minted institution a 2-of-N that controls itself rather than a
      // 1-of-1 whose only key lives in this backend (see institutionMinting.ts).
      const claimantPublicKey =
        typeof req.body?.publicKeyMultibase === 'string'
          ? req.body.publicKeyMultibase.trim().slice(0, 200)
          : null;

      const claim = await claimEnrolment(token, claimedBy, claimantPublicKey);
      if (!claim.ok) {
        throw new AppError(ERROR_CODES.AUTH_FORBIDDEN, `This enrolment token is not usable: ${claim.reason}`, 403);
      }

      res.status(200).json({
        success: true,
        data: { enrolmentId: claim.enrolmentId, authorityId: claim.authorityId },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /api/authority/enrolments/:id — the officer polls for the scan.
 *
 * ADMIN-gated and scoped to the officer who created it: an enrolment's existence
 * names a real institution being onboarded, which is not something another
 * authority's officer should be able to enumerate.
 */
institutionOnboardingRouter.get(
  '/enrolments/:id',
  requireAuth,
  requireAuthorityMember,
  requireAuthorityRole('ADMIN'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { authorityMember } = req as AuthorityMemberRequest;
      const { db } = await import('../db/index.js');

      const row = await db.institutionEnrolment.findUnique({
        where: { id: String(req.params.id ?? '') },
        select: {
          id: true,
          status: true,
          claimedBy: true,
          claimedAt: true,
          expiresAt: true,
          officerMemberId: true,
          institutionId: true,
        },
      });

      // An enrolment belonging to another officer is reported as absent rather
      // than forbidden, so this cannot be used to discover that it exists.
      if (!row || row.officerMemberId !== authorityMember.id) {
        throw new AppError(ERROR_CODES.NOT_FOUND, 'Enrolment not found', 404);
      }

      res.status(200).json({
        success: true,
        data: {
          id: row.id,
          status: row.status,
          claimedBy: row.claimedBy,
          claimedAt: row.claimedAt?.toISOString() ?? null,
          expiresAt: row.expiresAt.toISOString(),
          institutionId: row.institutionId,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api/authority/enrolments/:id/complete — the officer confirms, and the
 * institution is created.
 *
 * MINTING IS NOT WIRED YET. This creates the Institution row and records the
 * officer's attestation; `provisionInstitutionalDid` (proven in #295) is the
 * next step and is deliberately not called half-built. Until it is, the row has
 * no `did`, which is visible and countable rather than a silent gap.
 */
institutionOnboardingRouter.post(
  '/enrolments/:id/complete',
  requireAuth,
  requireAuthorityMember,
  requireAuthorityRole('ADMIN'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const parsed = completeSchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        throw new AppError(
          ERROR_CODES.VALIDATION_FAILED,
          'Name, type, and the address you verified on site are required.',
          400,
        );
      }

      const { authorityMember, authorityInstitution } = req as AuthorityMemberRequest;
      const { db } = await import('../db/index.js');

      const enrolment = await db.institutionEnrolment.findUnique({
        where: { id: String(req.params.id ?? '') },
      });
      if (!enrolment || enrolment.officerMemberId !== authorityMember.id) {
        throw new AppError(ERROR_CODES.NOT_FOUND, 'Enrolment not found', 404);
      }
      if (enrolment.status !== 'CLAIMED') {
        throw new AppError(
          ERROR_CODES.VALIDATION_FAILED,
          `This enrolment is ${enrolment.status.toLowerCase()}; it must be claimed by the ` +
            "institution's software before it can be completed.",
          409,
        );
      }

      const details = parsed.data;

      const institution = await db.institution.create({
        data: {
          name: details.name,
          type: details.type,
          address: details.address,
          phone: details.phone ?? null,
          email: details.email ?? null,
          // MARKED VERIFIED BY THE ACT OF CONFIRMATION, with the officer and the
          // time recorded. This is the whole accountability of the feature: a
          // person attested that they stood there.
          isVerified: true,
          verifiedAt: new Date(),
          verificationDocs: {
            method: 'on-site visit',
            verifiedBy: authorityMember.email,
            verifiedByMemberId: authorityMember.id,
            authorityId: authorityInstitution.id,
            authorityName: authorityInstitution.name,
            licenceNumber: details.licenceNumber ?? null,
            note: 'Institution created through the issuer console onboarding flow.',
          },
        },
      });

      await completeEnrolment({
        enrolmentId: enrolment.id,
        institutionId: institution.id,
        officerMemberId: authorityMember.id,
      });

      // ===================================================================
      // MINT THE DID. NOTHING ABOVE THIS LINE IS IRREVERSIBLE — NOTHING BELOW
      // IT IS REVERSIBLE.
      // ===================================================================
      // An institutional DID's controller array cannot be repaired later (#286),
      // so the mint is the point of no return. It runs only after the officer's
      // confirmation has created the institution, which is what makes the
      // attestation real rather than implied.
      let minted: { did: string; verificationMethodCount: number; institutionHoldsKey: boolean };
      try {
        minted = await mintInstitutionDid({
          institutionId: institution.id,
          institutionName: institution.name,
          purpose:
            `L2 ${institution.type} onboarded by ${authorityInstitution.name} on an on-site ` +
            `visit; verified by ${authorityMember.email}`,
          claimantPublicKey: enrolment.claimantPublicKey,
        });
      } catch (mintError) {
        // The institution ROW stands and is verified; only the DID is missing.
        // Reported as a partial result rather than thrown, because throwing
        // would suggest the verification did not happen — and it did, and it is
        // recorded, and an operator can mint the DID afterwards.
        logger.error('l2_institution_did_mint_failed', {
          institutionId: institution.id,
          error: mintError instanceof Error ? mintError.message : String(mintError),
        });
        res.status(502).json({
          success: false,
          error: {
            code: ERROR_CODES.DID_CREATION_FAILED,
            message:
              'The institution was verified and recorded, but minting its DID failed. ' +
              'The verification stands; retry the mint rather than re-onboarding.',
          },
          data: { institutionId: institution.id, didMinted: false },
          timestamp: new Date().toISOString(),
        });
        return;
      }

      await db.institution.update({
        where: { id: institution.id },
        data: { did: minted.did },
      });

      logger.info('l2_institution_onboarded', {
        institutionId: institution.id,
        type: institution.type,
        authorityId: authorityInstitution.id,
        officerMemberId: authorityMember.id,
        did: minted.did,
        verificationMethodCount: minted.verificationMethodCount,
        // FALSE means the document is agent-held only: repairable in place
        // (#286), but a residual the caller must not have hidden from it.
        institutionHoldsKey: minted.institutionHoldsKey,
      });

      res.status(201).json({
        success: true,
        data: {
          institutionId: institution.id,
          name: institution.name,
          type: institution.type,
          isVerified: institution.isVerified,
          did: minted.did,
          didMinted: true,
          verificationMethodCount: minted.verificationMethodCount,
          institutionHoldsKey: minted.institutionHoldsKey,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  },
);
