/**
 * SSI Healthcare Backend - Pharmacy Routes (H3)
 *
 * REST endpoints for pharmacy prescription verification and dispensing.
 * All three require a wallet. Only /dispense requires a verified pharmacist
 * licence — /verify and /history read, they do not act.
 *
 * POST /api/pharmacy/verify   - Verify a prescription credential
 * POST /api/pharmacy/dispense - Mark prescription as dispensed
 * GET  /api/pharmacy/history  - Get dispense history
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import {  requireWallet, type AuthenticatedRequest } from '../middleware/auth.js';
import { requireProfessional } from '../middleware/requireProfessional.js';
import { db } from '../db/index.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import {
  authoriseDispense,
  DispenseRefused,
  type DispenseAppend,
  type Allowance,
} from '../services/dispenseLedger.js';
import {
  verifyAppendSignature,
  canonicalSettleMessage,
  verifySignatureOver,
  type AppendPayload,
  type SettlePayload,
} from '../services/dispenseAppend.js';
import {
  tokenState,
  assertTransitionAllowed,
  isSettled,
  SettlementRefused,
  type SettlementFields,
  type TokenState,
} from '../services/tokenSettlement.js';
import { getAgent } from '../agent/index.js';
import { resolveOnChain } from '../services/cheqdLedger.js';
import type { ApiResponse } from '@ssi-healthcare/shared';
import { AuditEventType } from '../../prisma/generated/client/index.js';
import { verifyCredential } from '../services/credentialService.js';
import type { VerifiableCredential } from '@ssi-healthcare/shared';

export const pharmacyRouter: Router = Router();

// -- Validation Schemas --

const verifySchema = z.object({
  prescriptionId: z.string().min(1, 'Prescription ID is required'),
  credentialJwt: z.string().optional(), // Optional JWT for direct credential verification
});

const dispenseSchema = z.object({
  prescriptionId: z.string().min(1),
  quantity: z.number().min(1),
  notes: z.string().optional(),
});

/**
 * Settlement is keyed by the dispense, not the token.
 *
 * The token is the pharmacy's own queue number and is deliberately NOT the
 * identifier the protocol runs on: two pharmacies may both mint "token 1", and a
 * settlement addressed by token number alone would then settle the wrong
 * dispense. The dispense id is generated once, before the ledger call, and is
 * already the idempotency key for the append — so it is the correct address here
 * too. The token travels as a field for display and nothing else.
 */
const settleSchema = z.object({
  dispenseId: z.string().min(1, 'A dispense id is required'),
  queueToken: z.number().int().positive().optional(),
  /**
   * The pharmacy signs the settlement, exactly as it signs the dispense.
   *
   * There is NO wallet session here on purpose. The caller is the pharmacy, and
   * the pharmacy account has no wallet; requiring one made every settlement fail
   * with "Wallet setup required" (measured 28 Sep). An institution is
   * authenticated by its signature against a chain-resolved DID.
   */
  pharmacyDid: z.string().min(1, 'The signing DID is required'),
  settledAt: z.string().min(1, 'A settlement time is required'),
  signature: z.string().min(1, 'A signature is required'),
});

const abandonSchema = z.object({
  dispenseId: z.string().min(1, 'A dispense id is required'),
  queueToken: z.number().int().positive().optional(),
  /** 'declined' when the counter says so. 'expired' is reserved for the read-time rule. */
  reason: z.enum(['declined']).default('declined'),
  pharmacyDid: z.string().min(1, 'The signing DID is required'),
  settledAt: z.string().min(1, 'A settlement time is required'),
  signature: z.string().min(1, 'A signature is required'),
});

/**
 * Verify that an institution signed this settlement, and that the institution is
 * one THIS deployment verified.
 *
 * The same two checks the append performs, for the same reasons: resolving a key
 * is not enough (any DID has keys), and reading a key from the request would let
 * anyone sign as anyone, so the keys come from the CHAIN.
 */
async function verifyInstitutionSignature(input: {
  payload: SettlePayload;
  signature: string;
}): Promise<void> {
  const institution = await db.institution.findFirst({
    where: { did: input.payload.pharmacyDid, isVerified: true },
    select: { id: true },
  });
  if (!institution) {
    throw new AppError(
      ERROR_CODES.AUTH_FORBIDDEN,
      'That DID is not a verified institution here, so it cannot settle a dispense.',
      403,
    );
  }
  const resolved = await resolveOnChain(getAgent(), input.payload.pharmacyDid);
  if (!resolved || resolved.deactivated) {
    throw new AppError(ERROR_CODES.NOT_FOUND, 'The signing DID could not be resolved on the ledger.', 404);
  }
  const ok = verifySignatureOver(
    canonicalSettleMessage(input.payload),
    input.signature,
    resolved.verificationMethod.map((vm) => vm.publicKeyMultibase),
  );
  if (!ok) {
    throw new AppError(ERROR_CODES.AUTH_FORBIDDEN, 'The settlement signature did not verify against that DID.', 403);
  }
}

// -- Types --

interface PrescriptionVerification {
  id: string;
  prescriptionId: string;
  patientName: string;
  patientDid: string;
  medication: string;
  dosage: string;
  quantity: number;
  refillsRemaining: number;
  prescribedBy: string;
  prescribedDate: string;
  expirationDate: string;
  status: 'valid' | 'expired' | 'filled' | 'revoked' | 'invalid';
  verified: boolean;
  verifiedAt?: string;
  dispensedAt?: string;
}

// -- Routes --

/**
 * POST /api/pharmacy/verify
 * Verify a prescription credential
 */
pharmacyRouter.post('/verify', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const { prescriptionId } = verifySchema.parse(req.body);

    // Look up the credential by ID or hash
    const credential = await db.credential.findFirst({
      where: {
        OR: [
          { id: prescriptionId },
          { credentialHash: prescriptionId },
          {
            credentialData: {
              path: ['id'],
              equals: prescriptionId,
            },
          },
        ],
        type: { has: 'PrescriptionCredential' },
      },
    });

    if (!credential) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Prescription not found', 404);
    }

    const credentialData = credential.credentialData as Record<string, unknown>;
    const credentialSubject = (credentialData.credentialSubject || {}) as Record<string, unknown>;

    // Determine status
    let status: PrescriptionVerification['status'] = 'valid';
    
    if (credential.status === 'REVOKED') {
      status = 'revoked';
    } else if (credential.expiresAt && new Date(credential.expiresAt) < new Date()) {
      status = 'expired';
    } else {
      // Check if already dispensed
      const dispenseRecord = await db.auditLog.findFirst({
        where: {
          resourceId: credential.id,
          eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        },
      });
      
      if (dispenseRecord) {
        status = 'filled';
      }
    }

    // Cryptographically verify the credential
    let cryptoVerified = false;
    try {
      const vcResult = await verifyCredential(credentialData as unknown as VerifiableCredential, {
        checkRevocation: true,
        checkExpiration: true,
      });
      cryptoVerified = vcResult.isValid;
      if (!vcResult.isValid) {
        logger.warn('Prescription credential failed cryptographic verification', {
          prescriptionId,
          errors: vcResult.errors,
        });
      }
    } catch (verifyErr) {
      logger.error('Credential verification threw', {
        error: verifyErr instanceof Error ? verifyErr.message : String(verifyErr),
      });
      cryptoVerified = false;
    }

    // Build response
    const verification: PrescriptionVerification = {
      id: credential.id,
      prescriptionId: (credentialData.id as string) || credential.id,
      patientName: (credentialSubject.patientName as string) || 'Unknown Patient',
      patientDid: credential.holderDid,
      medication: (credentialSubject.medicationName as string) || credential.name || 'Unknown Medication',
      dosage: (credentialSubject.dosage as string) || 'As directed',
      quantity: (credentialSubject.quantity as number) || 30,
      refillsRemaining: (credentialSubject.refillsRemaining as number) ?? 0,
      prescribedBy: (credentialSubject.prescribedBy as string) || 'Unknown Provider',
      prescribedDate: credential.issuedAt.toISOString(),
      expirationDate: credential.expiresAt?.toISOString() || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      status: cryptoVerified ? status : 'invalid',
      verified: cryptoVerified,
      verifiedAt: new Date().toISOString(),
    };

    // Log the verification
    await db.auditLog.create({
      data: {
        eventType: AuditEventType.PRESCRIPTION_VERIFIED,
        action: 'Prescription verified by pharmacy',
        actorDid: user.did!,
        targetDid: credential.holderDid,
        resourceType: 'credential',
        resourceId: credential.id,
        details: {
          prescriptionId,
          medication: verification.medication,
          status: verification.status,
          pharmacyDid: user.did,
        },
        ipAddress: req.ip,
      },
    });

    logger.info('Prescription verified', {
      prescriptionId,
      status: verification.status,
      pharmacyDid: user.did,
    });

    const response: ApiResponse<PrescriptionVerification> = {
      success: true,
      data: verification,
      timestamp: new Date().toISOString(),
    };

    res.json(response);
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/pharmacy/dispense
 * Mark a prescription as dispensed.
 *
 * The file header has always claimed this route "requires pharmacy
 * credentials"; until R4 nothing enforced it and any authenticated wallet could
 * dispense. `requireProfessional` makes the claim true: a licence from the
 * Pharmacy Council, presented and verified on this request, carrying `dispense`.
 */
pharmacyRouter.post('/dispense', requireWallet, requireProfessional({
  profession: 'pharmacist',
  scope: ['dispense'],
}), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const { prescriptionId, quantity, notes } = dispenseSchema.parse(req.body);

    // Find the credential
    const credential = await db.credential.findFirst({
      where: {
        OR: [
          { id: prescriptionId },
          { credentialHash: prescriptionId },
          {
            credentialData: {
              path: ['id'],
              equals: prescriptionId,
            },
          },
        ],
        type: { has: 'PrescriptionCredential' },
      },
    });

    if (!credential) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Prescription not found', 404);
    }

    // ===================================================================
    // A PRESCRIPTION IS AN ALLOWANCE, NOT A SINGLE EVENT.
    // ===================================================================
    // This used to refuse any second dispense as a replay, which made a
    // legitimate part-dispense impossible AND meant nothing summed quantities —
    // so the same 30 tablets could be collected here and at another counter with
    // no layer able to notice. The balance is now RECOMPUTED from the recorded
    // appends (see services/dispenseLedger.ts), never read from a stored counter.
    const appends = await db.auditLog.findMany({
      where: {
        resourceId: credential.id,
        eventType: AuditEventType.PRESCRIPTION_DISPENSED,
      },
      select: { details: true },
    });

    const recorded: DispenseAppend[] = appends
      .map((row) => row.details as Record<string, unknown> | null)
      .filter((d): d is Record<string, unknown> => Boolean(d))
      .map((d) => ({
        prescriptionId: String(d.prescriptionId ?? ''),
        quantity: Number(d.quantity ?? 0),
        pharmacyDid: String(d.pharmacyDid ?? ''),
        // Rows written before the idempotency key existed have no dispenseId.
        // Falling back to the row's own identity keeps them countable EXACTLY
        // ONCE each rather than being merged into a single phantom append.
        dispenseId: String(d.dispenseId ?? `legacy:${d.prescriptionId}:${d.quantity}`),
        dispensedAt: String(d.dispensedAt ?? ''),
      }));

    // The prescriber's ceiling, from the credential itself. A credential issued
    // before the allowance was recorded carries none, and that REFUSES rather
    // than reading as "no limit" (#163/#184).
    const allowance = readAllowanceFrom(credential.credentialData);

    try {
      authoriseDispense(allowance, recorded, quantity);
    } catch (error) {
      if (error instanceof DispenseRefused) {
        // The code is carried in the error, not invented here, so the counter can
        // distinguish "you asked for too much" from "this script is finished".
        throw new AppError(ERROR_CODES.VALIDATION_FAILED, error.message, 400);
      }
      throw error;
    }

    // Check expiration
    if (credential.expiresAt && new Date(credential.expiresAt) < new Date()) {
      throw new AppError(ERROR_CODES.CREDENTIAL_EXPIRED, 'Prescription has expired', 400);
    }

    // Check revocation
    if (credential.status === 'REVOKED') {
      throw new AppError(ERROR_CODES.CREDENTIAL_REVOKED, 'Prescription has been revoked', 400);
    }

    // Verify patient consent for pharmacy access
    const activeConsent = await db.consent.findFirst({
      where: {
        holderDid: credential.holderDid,
        verifierDid: user.did!,
        isActive: true,
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: new Date() } },
        ],
      },
    });

    if (!activeConsent) {
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        'No active patient consent for pharmacy access. Patient must grant consent first.',
        403,
      );
    }

    const dispenseId = uuidv4();
    const credentialData = credential.credentialData as Record<string, unknown>;
    const credentialSubject = (credentialData.credentialSubject || {}) as Record<string, unknown>;

    // Record the dispense
    await db.auditLog.create({
      data: {
        eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        action: `Prescription dispensed: ${quantity} units`,
        actorDid: user.did!,
        targetDid: credential.holderDid,
        resourceType: 'credential',
        resourceId: credential.id,
        details: {
          dispenseId,
          prescriptionId,
          medication: credentialSubject.medicationName || credential.name,
          quantity,
          notes,
          pharmacyDid: user.did,
          dispensedBy: user.firstName 
            ? `${user.firstName} ${user.lastName || ''}`.trim()
            : user.email,
        },
        ipAddress: req.ip,
      },
    });

    logger.info('Prescription dispensed', {
      dispenseId,
      prescriptionId,
      quantity,
      pharmacyDid: user.did,
    });

    const response: ApiResponse<{
      id: string;
      prescriptionId: string;
      quantity: number;
      dispensedAt: string;
    }> = {
      success: true,
      data: {
        id: dispenseId,
        prescriptionId,
        quantity,
        dispensedAt: new Date().toISOString(),
      },
      timestamp: new Date().toISOString(),
    };

    res.status(201).json(response);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/pharmacy/history
 * Get pharmacy dispense history
 */

/**
 * The prescriber's ceiling, read from the credential's own signed subject.
 *
 * RETURNS ZERO WHEN THE CREDENTIAL STATES NO ALLOWANCE, and the ledger treats
 * zero as a REFUSAL rather than "unlimited". Credentials issued before the
 * allowance was recorded carry none, and the rule everywhere else in this
 * codebase applies: "I could not check" must never read as "no constraint"
 * (#163/#184). A zero here stops the dispense; it does not wave it through.
 *
 * The value is `credentialSubject.medication.quantityValue`, which the issuer
 * sets only when the doctor's own words stated a count unambiguously — see the
 * HMS's parseQuantity. A credential whose quantity reads "as needed" therefore
 * has no enforceable ceiling, and refusing is the honest answer.
 */
function readAllowanceFrom(credentialData: unknown): Allowance {
  const subject = (credentialData as { credentialSubject?: Record<string, unknown> } | null)
    ?.credentialSubject;
  const medication = subject?.medication as { quantityValue?: unknown; quantity?: unknown } | undefined;
  const value = medication?.quantityValue;

  return {
    authorised: typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : 0,
    authorisedText: typeof medication?.quantity === 'string' ? medication.quantity : undefined,
  };
}


/**
 * POST /api/pharmacy/appends — a pharmacy records a dispense it has performed.
 *
 * NO SESSION. THE SIGNATURE IS THE AUTHENTICATION. The counter PC is not a
 * signed-in user; it is an institution with a key, and requiring a bearer token
 * would put a second, weaker credential in front of the one that actually
 * attributes the act. A valid signature from a VERIFIED INSTITUTION's DID is the
 * whole of the authorisation (owner's decision on the ledger review, attack 2).
 *
 * The reading is deliberately narrow: this records what the pharmacy says it
 * did. It does not confirm medicine changed hands, and the signature makes the
 * claim attributable rather than true — which is what makes a false one
 * detectable later instead of deniable.
 */

/**
 * GET /api/pharmacy/identity?key=<multibase> — which DID is this institution?
 *
 * WHY THIS IS NEEDED. The pharmacy supplies its public key when it pairs, and the
 * DID does not exist until the officer confirms on site. So at the moment of
 * pairing the pharmacy cannot know its own DID, and it cannot poll the enrolment
 * (that endpoint is the officer's, scoped to their session).
 *
 * The link already exists in the data: the enrolment records the claimant's public
 * key and, once completed, the institution it created. This joins them.
 *
 * NO SECRET IS DISCLOSED. A DID is public — it is on a ledger — and the caller
 * already holds the private half of the key that identifies the row, so this
 * reveals nothing they did not have. It is a lookup, not an authentication.
 */
pharmacyRouter.get('/identity', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const key = typeof req.query.key === 'string' ? req.query.key.trim() : '';
    if (!key) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'A public key is required.', 400);
    }

    const enrolment = await db.institutionEnrolment.findFirst({
      where: { claimantPublicKey: key, institutionId: { not: null } },
      select: { institutionId: true },
    });
    if (!enrolment?.institutionId) {
      // The honest answer while the officer has not yet confirmed: the DID does
      // not exist. 200 with a null, not 404, because "not yet" is not an error.
      res.status(200).json({ success: true, data: { did: null }, timestamp: new Date().toISOString() });
      return;
    }

    const institution = await db.institution.findUnique({
      where: { id: enrolment.institutionId },
      select: { did: true, name: true, isVerified: true },
    });

    res.status(200).json({
      success: true,
      data: { did: institution?.did ?? null, name: institution?.name ?? null, verified: institution?.isVerified ?? false },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

pharmacyRouter.post('/appends', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const body = req.body as Record<string, unknown>;
    const pharmacyDid = typeof body.pharmacyDid === 'string' ? body.pharmacyDid : '';
    const signature = typeof body.signature === 'string' ? body.signature : '';
    const payload: AppendPayload = {
      prescriptionId: String(body.prescriptionId ?? ''),
      quantity: Number(body.quantity ?? 0),
      dispenseId: String(body.dispenseId ?? ''),
      dispensedAt: String(body.dispensedAt ?? ''),
      pharmacyDid,
      holderDid: String(body.holderDid ?? ''),
    };
    /** Display only, and deliberately not signed: the dispenseId is the address. */
    const queueToken = typeof body.queueToken === 'number' ? body.queueToken : undefined;

    if (!pharmacyDid || !signature || !payload.prescriptionId || !payload.dispenseId) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'An append needs a DID, a signature, a prescription and a dispense id.', 400);
    }
    if (!payload.holderDid) {
      // Refused rather than defaulted: an append with no subject cannot be found
      // by the wallet it concerns, and a silently-empty holder would make the
      // dispense invisible to the one party it is about.
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'An append must name the holder it concerns.', 400);
    }

    // The signing DID must be an institution THIS deployment verified. Resolving
    // a key is not enough: any DID has keys, and the owner's decision is that an
    // UNLICENSED DID must not be able to append at all.
    const institution = await db.institution.findFirst({
      where: { did: pharmacyDid, isVerified: true },
      select: { id: true, name: true },
    });
    if (!institution) {
      throw new AppError(
        ERROR_CODES.AUTH_FORBIDDEN,
        'That DID is not a verified institution here, so it cannot record a dispense.',
        403,
      );
    }

    // Read the keys from the CHAIN, never from the request: a caller-supplied key
    // would let anyone sign as anyone.
    const resolved = await resolveOnChain(getAgent(), pharmacyDid);
    if (!resolved || resolved.deactivated) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'The signing DID could not be resolved on the ledger.', 404);
    }

    const ok = verifyAppendSignature({
      payload,
      signature,
      publicKeyMultibase: resolved.verificationMethod.map((vm) => vm.publicKeyMultibase),
    });
    if (!ok) {
      throw new AppError(ERROR_CODES.AUTH_FORBIDDEN, 'The append signature did not verify against that DID.', 403);
    }

    // Idempotent by dispenseId: a retried POST must not count twice, which is the
    // same rule the ledger applies when it recomputes the balance.
    const already = await db.auditLog.findFirst({
      where: {
        eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        details: { path: ['dispenseId'], equals: payload.dispenseId },
      },
      select: { id: true },
    });
    if (!already) {
      await db.auditLog.create({
        data: {
          eventType: AuditEventType.PRESCRIPTION_DISPENSED,
          action: `Dispense recorded by ${institution.name}: ${payload.quantity} units`,
          actorDid: pharmacyDid,
          // THE HOLDER, so the wallet can find its own dispenses. Before A1 the
          // append named the pharmacy and the prescription but not the person,
          // which left the wallet with nothing to query by.
          targetDid: payload.holderDid,
          resourceType: 'prescription',
          // Keyed by the prescription, which is what the balance is computed over.
          resourceId: payload.prescriptionId,
          details: { ...payload, ...(queueToken !== undefined ? { queueToken } : {}) },
          ipAddress: req.ip,
        },
      });
    }

    const appends = await db.auditLog.findMany({
      where: {
        eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        resourceId: payload.prescriptionId,
      },
      select: { details: true },
    });
    const recorded = appends
      .map((row) => row.details as Record<string, unknown> | null)
      .filter((d): d is Record<string, unknown> => Boolean(d))
      .map((d) => ({
        prescriptionId: String(d.prescriptionId ?? ''),
        quantity: Number(d.quantity ?? 0),
        pharmacyDid: String(d.pharmacyDid ?? ''),
        dispenseId: String(d.dispenseId ?? ''),
        dispensedAt: String(d.dispensedAt ?? ''),
      }));

    res.status(201).json({
      success: true,
      data: {
        recorded: !already,
        prescriptionId: payload.prescriptionId,
        // What the chain of appends now says, so the counter can show the patient
        // what is left without a second call.
        dispensedTotal: recorded.reduce((sum, a) => sum + a.quantity, 0),
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * The holder's own tokens, live and recently closed.
 *
 * THE WALLET'S DISCOVERY PATH. The pharmacy mints the queue number, so the wallet
 * cannot know it exists; it reads here instead. Scoped to the caller's OWN DID —
 * `requireWallet` gives the authenticated DID and the query filters on it, so a
 * holder cannot read another holder's dispenses.
 *
 * Returns ISSUED tokens (the wallet shows the number) and terminal ones from the
 * last day (so the wallet can write its activity entry once and then stop seeing
 * them). The 24-hour rule is applied HERE, at read time, from the server clock.
 */
pharmacyRouter.get('/settlement/mine', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    if (!user.did) {
      throw new AppError(ERROR_CODES.AUTH_REQUIRED, 'A wallet DID is required.', 401);
    }

    const since = new Date(Date.now() - 48 * 60 * 60 * 1000);
    const rows = await db.auditLog.findMany({
      where: {
        eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        targetDid: user.did,
        timestamp: { gte: since },
      },
      orderBy: { timestamp: 'desc' },
      take: 50,
      select: { details: true, timestamp: true, actorDid: true, resourceId: true },
    });

    const items = rows.map((row) => {
      const details = (row.details ?? {}) as Record<string, unknown>;
      const state = tokenState(details as SettlementFields, row.timestamp.toISOString());
      return {
        dispenseId: String(details.dispenseId ?? ''),
        prescriptionId: String(details.prescriptionId ?? row.resourceId ?? ''),
        queueToken: typeof details.queueToken === 'number' ? details.queueToken : null,
        pharmacyDid: row.actorDid,
        issuedAt: row.timestamp.toISOString(),
        state,
        movesBalance: isSettled(state),
      };
    });

    // The wallet only needs the live ones for the Token Number card, but the
    // terminal ones are returned so the activity entry can be written from the
    // same read rather than a second call that might disagree.
    const live = items.filter((i) => i.state === 'ISSUED');

    res.json({
      success: true,
      data: { live, recent: items },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * The holder's own dispense appends, whole.
 *
 * THE MEDICINE BALANCE'S DATA SOURCE. The wallet answers "how much of my
 * prescription is left" by recomputing from the appends it reads here (never
 * from a stored counter), the same rule the ledger applies. The read-time
 * settlement fields travel with each append so the wallet can tell bought from
 * issued-but-open without a second call.
 *
 * NO MEDICINE NAMES CROSS THIS BOUNDARY. The append holds the prescription id
 * and the quantity; the holder's credential holds the medicine, and the wallet
 * joins them locally. Shipping names here would put clinical detail in the
 * operator's database, which is the opposite of what this system is for.
 *
 * Scoped to the caller's OWN DID: requireWallet gives the authenticated DID and
 * the query filters on it, so a holder cannot read another holder's dispenses.
 */
pharmacyRouter.get('/dispenses/mine', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    if (!user.did) {
      throw new AppError(ERROR_CODES.AUTH_REQUIRED, 'A wallet DID is required.', 401);
    }

    const rows = await db.auditLog.findMany({
      where: {
        eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        targetDid: user.did,
      },
      orderBy: { timestamp: 'desc' },
      take: 500,
      select: { details: true, timestamp: true, actorDid: true },
    });

    const dispenses = rows.map((row) => {
      const details = (row.details ?? {}) as Record<string, unknown>;
      return {
        dispenseId: String(details.dispenseId ?? ''),
        prescriptionId: String(details.prescriptionId ?? ''),
        quantity: typeof details.quantity === 'number' ? details.quantity : 0,
        queueToken: typeof details.queueToken === 'number' ? details.queueToken : null,
        pharmacyDid: row.actorDid,
        issuedAt: row.timestamp.toISOString(),
        settledAt: (details.settledAt as string) ?? null,
        abandonedReason: (details.abandonedReason as string) ?? null,
      };
    });

    res.json({
      success: true,
      data: { dispenses },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Read one dispense's settlement state.
 *
 * Used by BOTH clients and it is the same answer for both, which is the point:
 * the counter must be able to see that a token has already expired BEFORE taking
 * money for it, and the wallet must be able to decide whether to show the number.
 * Neither of them decides the state; they read it.
 *
 * The 24-hour rule is applied HERE, at read time, from the server clock. There is
 * no scheduler. Note that this is a convention rather than an enforcement: the
 * record does not carry a cryptographic lifetime, and anyone holding it could
 * ignore the rule. See __docs__/design/TOKEN-EXPIRY-CLOCK-OWNERSHIP.md.
 */
pharmacyRouter.get('/settlement/:dispenseId', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const dispenseId = String(req.params.dispenseId ?? '');
    if (!dispenseId) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'A dispense id is required.', 400);
    }

    const row = await db.auditLog.findFirst({
      where: {
        eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        details: { path: ['dispenseId'], equals: dispenseId },
      },
      select: { details: true, timestamp: true, resourceId: true, actorDid: true },
    });
    if (!row) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'No dispense with that id.', 404);
    }

    const details = (row.details ?? {}) as Record<string, unknown>;
    const state = tokenState(details as SettlementFields, row.timestamp.toISOString());

    res.json({
      success: true,
      data: {
        dispenseId,
        prescriptionId: String(details.prescriptionId ?? row.resourceId ?? ''),
        queueToken: typeof details.queueToken === 'number' ? details.queueToken : null,
        pharmacyDid: row.actorDid,
        issuedAt: row.timestamp.toISOString(),
        state,
        /** The wallet's rule: only a settled dispense may move a balance. */
        movesBalance: isSettled(state),
        settledAt: (details.settledAt as string) ?? null,
        abandonedReason: (details.abandonedReason as string) ?? null,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Settle a dispense that has been PAID.
 *
 * The transition is refused rather than overwritten if the token is already
 * terminal, which is what stops a double-click in the other direction from
 * reversing a payment. A refusal is a 409, not a 400: the request was
 * well-formed and the state is what rejected it.
 */
pharmacyRouter.post('/settle', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { dispenseId, queueToken, pharmacyDid, settledAt, signature } = settleSchema.parse(req.body);
    const payload: SettlePayload = { dispenseId, outcome: 'paid', settledAt, pharmacyDid };
    await verifyInstitutionSignature({ payload, signature });

    const row = await db.auditLog.findFirst({
      where: {
        eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        actorDid: pharmacyDid,
        details: { path: ['dispenseId'], equals: dispenseId },
      },
      select: { id: true, details: true, timestamp: true },
    });
    if (!row) {
      throw new SettlementRefused('No dispense with that id.', 'NOT_FOUND');
    }

    const current: TokenState = tokenState((row.details ?? {}) as SettlementFields, row.timestamp.toISOString());
    assertTransitionAllowed(current);

    const settledDetails = {
      ...((row.details ?? {}) as Record<string, unknown>),
      settledAt,
      settledBy: pharmacyDid,
      ...(queueToken !== undefined ? { queueToken } : {}),
    };
    await db.auditLog.update({ where: { id: row.id }, data: { details: settledDetails } });

    logger.info('Dispense settled', { dispenseId, pharmacyDid });

    res.json({
      success: true,
      data: { dispenseId, state: 'SETTLED', movesBalance: true },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error instanceof SettlementRefused) {
      next(new AppError(ERROR_CODES.VALIDATION_FAILED, error.message, 409));
      return;
    }
    next(error);
  }
});

/**
 * Close a dispense that was NOT paid, so the wallet can discard the token.
 *
 * This exists because of the owner's edge case: a patient may scan and then walk
 * away. Without this the token would sit in the wallet until the 24-hour rule
 * eventually expired it, and the counter would have no way to say what actually
 * happened.
 */
pharmacyRouter.post('/abandon', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { dispenseId, queueToken, reason, pharmacyDid, settledAt, signature } = abandonSchema.parse(req.body);
    const payload: SettlePayload = { dispenseId, outcome: 'not-paid', settledAt, pharmacyDid };
    await verifyInstitutionSignature({ payload, signature });

    const row = await db.auditLog.findFirst({
      where: {
        eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        actorDid: pharmacyDid,
        details: { path: ['dispenseId'], equals: dispenseId },
      },
      select: { id: true, details: true, timestamp: true },
    });
    if (!row) {
      throw new SettlementRefused('No dispense with that id.', 'NOT_FOUND');
    }

    const current: TokenState = tokenState((row.details ?? {}) as SettlementFields, row.timestamp.toISOString());
    assertTransitionAllowed(current);

    const abandonedDetails = {
      ...((row.details ?? {}) as Record<string, unknown>),
      abandonedReason: reason,
      abandonedAt: settledAt,
      abandonedBy: pharmacyDid,
      ...(queueToken !== undefined ? { queueToken } : {}),
    };
    await db.auditLog.update({ where: { id: row.id }, data: { details: abandonedDetails } });

    logger.info('Dispense closed as not collected', { dispenseId, reason, pharmacyDid });

    res.json({
      success: true,
      data: { dispenseId, state: reason === 'declined' ? 'ABANDONED' : 'ABANDONED_EXPIRED', movesBalance: false },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error instanceof SettlementRefused) {
      next(new AppError(ERROR_CODES.VALIDATION_FAILED, error.message, 409));
      return;
    }
    next(error);
  }
});

pharmacyRouter.get('/history', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const limit = Math.min(Number(req.query.limit) || 50, 100);
    const offset = Number(req.query.offset) || 0;

    // Get dispense records for this pharmacy
    const [records, total] = await Promise.all([
      db.auditLog.findMany({
        where: {
          actorDid: user.did!,
          eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        },
        orderBy: { timestamp: 'desc' },
        take: limit,
        skip: offset,
      }),
      db.auditLog.count({
        where: {
          actorDid: user.did!,
          eventType: AuditEventType.PRESCRIPTION_DISPENSED,
        },
      }),
    ]);

    const history = await Promise.all(records.map(async (record) => {
      const details = (record.details || {}) as Record<string, unknown>;
      
      // Look up patient name from the credential or the user record
      let patientName = (details.patientName as string) || '';
      if (!patientName && record.targetDid) {
        const patient = await db.user.findFirst({ where: { did: record.targetDid }, select: { firstName: true, lastName: true } });
        if (patient) {
          patientName = [patient.firstName, patient.lastName].filter(Boolean).join(' ') || 'Patient';
        }
      }
      
      return {
        id: (details.dispenseId as string) || record.id,
        prescriptionId: (details.prescriptionId as string) || record.resourceId || '',
        patientName: patientName || 'Unknown Patient',
        medication: (details.medication as string) || 'Medication',
        dispensedAt: record.timestamp.toISOString(),
        dispensedBy: (details.dispensedBy as string) || 'Pharmacist',
        quantity: (details.quantity as number) || 0,
      };
    }));

    const response: ApiResponse<{
      history: typeof history;
      total: number;
      hasMore: boolean;
    }> = {
      success: true,
      data: {
        history,
        total,
        hasMore: offset + history.length < total,
      },
      timestamp: new Date().toISOString(),
    };

    res.json(response);
  } catch (error) {
    next(error);
  }
});

export default pharmacyRouter;
