/**
 * SSI Healthcare Backend - OID4VCI Routes
 * 
 * OpenID for Verifiable Credential Issuance (OID4VCI) endpoints.
 * Implements the Pre-Authorized Code Flow for frictionless credential issuance.
 * 
 * Reference: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import {
  W3cV2Credential,
  W3cV2CredentialSubject,
} from '@credo-ts/core';
import {
  allocateStatusIndex,
  buildStatusEntry,
  ensureStatusListPublished,
  toCredoV2CredentialStatus,
} from '../services/statusListService.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { requireWallet, type AuthenticatedRequest } from '../middleware/auth.js';
import { db } from '../db/index.js';
import * as credentialRepo from '../db/credentialRepository.js';
import {
  ERROR_CODES,
  VC_CONTEXTS,
  CREDENTIAL_FORMATS,
  SYSTEM_DEFAULTS,
  type VerifiableCredential,
  type IssuableCredentialFormat,
  isSsiError,
} from '@ssi-healthcare/shared';
import { AuditEventType, CredentialCategory, type Prisma } from '../../prisma/generated/client/index.js';
import { config } from '../config/index.js';
import { getAgent } from '../agent/index.js';
import {
  storedCredentialToW3cJson,
  credentialEnvelopeJwt,
  resolveHolderBinding,
  assertHolderBound,
} from '../services/jwtVc.js';
import { secureV2Credential } from '../services/securing.js';

/**
 * The OID4VCI format identifier describing a stored credential as it actually
 * is, rather than as the client happened to ask for it.
 *
 * A credential's data model is fixed at issuance and is readable from its
 * `@context`. Echoing the request's `format` back — which this endpoint used to
 * do — would label a VC 2.0 credential `jwt_vc_json` whenever an old client
 * asked for that, which is precisely the kind of mislabelling this migration
 * removed from the issuance path.
 */
function credentialFormatFor(credential: VerifiableCredential | null): string {
  const context = credential?.['@context'];
  const isV2 = Array.isArray(context) && context.includes(VC_CONTEXTS.W3C_CREDENTIALS_V2);
  return isV2 ? CREDENTIAL_FORMATS.VC_JWT : CREDENTIAL_FORMATS.JWT_VC_JSON;
}

export const oid4vciRouter = Router();

const JWT_SECRET = config.jwtSecret;
const ISSUER_BASE_URL = config.issuerBaseUrl;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BCRYPT_ROUNDS = 10;

async function hashPin(pin: string): Promise<string> {
  return bcrypt.hash(pin, BCRYPT_ROUNDS);
}

async function verifyPin(pin: string, hash: string): Promise<boolean> {
  return bcrypt.compare(pin, hash);
}

// ---------------------------------------------------------------------------
// Validation Schemas
// ---------------------------------------------------------------------------

const tokenRequestSchema = z.object({
  grant_type: z.literal('urn:ietf:params:oauth:grant-type:pre-authorized_code'),
  'pre-authorized_code': z.string().min(1),
  user_pin: z.string().optional(),
});

const credentialRequestSchema = z.object({
  // Two different kinds of value share this field, and the difference matters.
  //
  //   `vc+jwt` / `vc+sd-jwt`  are SECURING MECHANISMS this issuer honours. Ask
  //     for one and you get it; the response reports which was produced.
  //
  //   `jwt_vc_json` / `jwt_vc` / `ldp_vc` are VC 1.1 DATA MODEL identifiers
  //     this issuer no longer produces. They are still ACCEPTED rather than
  //     rejected, because a client built against the pre-migration metadata is
  //     asking for "a credential", not for a data model, and breaking it buys
  //     nothing. Such a request yields VC 2.0 `vc+jwt`, and the response's own
  //     `format` member says so plainly instead of echoing the request back.
  //
  // Selective disclosure is therefore OPT-IN ON THIS ROUTE, and silence means
  // `vc+jwt`. It has to be: an SD-JWT is larger, is not interchangeable with a
  // plain JWT to a consumer, and obliges the holder to choose a disclosure frame
  // before presenting. Defaulting every existing client into it would change the
  // artifact under clients that never asked, and this endpoint is spoken by
  // third-party wallets we do not ship.
  //
  // THE INTERNAL PATH DIFFERS, DELIBERATELY. `services/credentialService.ts`
  // (reached from POST /api/credentials/accept-offer, which is what OUR wallet
  // uses) now defaults to `vc+sd-jwt`, because there the client is ours and the
  // irreversibility argument wins: a `vc+jwt` credential can never be presented
  // selectively afterwards. See the note at its `issuedFormat`.
  //
  // This is the one place the two issuance paths are ALLOWED to differ, and it
  // is a difference in default rather than in behaviour — ask for a format here
  // and you get exactly it.
  format: z
    .enum([
      CREDENTIAL_FORMATS.VC_JWT,
      CREDENTIAL_FORMATS.SD_JWT_VC,
      CREDENTIAL_FORMATS.JWT_VC_JSON,
      'jwt_vc',
      CREDENTIAL_FORMATS.LDP_VC,
    ])
    .default(CREDENTIAL_FORMATS.VC_JWT),
  credential_definition: z.object({
    type: z.array(z.string()),
    credentialSubject: z.record(z.unknown()).optional(),
  }).optional(),
  proof: z.object({
    proof_type: z.literal('jwt'),
    jwt: z.string(),
  }).optional(),
});

const createOfferSchema = z.object({
  issuerDid: z.string().startsWith('did:'),
  issuerName: z.string().min(1),
  holderEmail: z.string().email().optional(),
  holderDid: z.string().startsWith('did:').optional(),
  credentialType: z.string().min(1),
  credentialSchemaId: z.string().optional(),
  claims: z.record(z.unknown()),
  expiresInMinutes: z.number().min(1).max(60 * 24 * 7).default(60),
  userPinRequired: z.boolean().default(false),
  userPin: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Issuer Metadata
// ---------------------------------------------------------------------------

/**
 * The credential types this issuer offers, independent of how they are secured.
 *
 * ONE ENTRY PER CREDENTIAL TYPE, not per type-and-format pair. Both securing
 * mechanisms carry the SAME data model with the same claims and the same
 * display — only the envelope differs — so listing each type twice by hand
 * would be five opportunities for the `vc+jwt` and `vc+sd-jwt` descriptions of
 * one credential to disagree about what that credential is. The two wire
 * projections below are derived from this.
 */
const CREDENTIAL_CATALOGUE = [
  {
    id: 'HealthRecordCredential',
    display: {
      name: 'Health Record',
      description: 'A verifiable health record credential',
      background_color: '#f0fdf4',
      text_color: '#166534',
    },
    credentialSubject: {
      givenName: { display: [{ name: 'Given Name', locale: 'en-US' }] },
      familyName: { display: [{ name: 'Family Name', locale: 'en-US' }] },
      dateOfBirth: { display: [{ name: 'Date of Birth', locale: 'en-US' }] },
      diagnosis: { display: [{ name: 'Diagnosis', locale: 'en-US' }] },
    },
  },
  {
    id: 'VaccinationCredential',
    display: {
      name: 'Vaccination Record',
      description: 'A verifiable vaccination record',
      background_color: '#eff6ff',
      text_color: '#1e40af',
    },
  },
  {
    id: 'PrescriptionCredential',
    display: {
      name: 'Prescription',
      description: 'A verifiable prescription',
      background_color: '#fef3c7',
      text_color: '#92400e',
    },
  },
  {
    id: 'LabResultCredential',
    display: {
      name: 'Lab Result',
      description: 'A verifiable lab test result',
      background_color: '#faf5ff',
      text_color: '#7c3aed',
    },
  },
  {
    id: 'InsuranceCredential',
    display: {
      name: 'Insurance Card',
      description: 'A verifiable insurance credential',
      background_color: '#fef2f2',
      text_color: '#b91c1c',
    },
  },
] as const satisfies ReadonlyArray<{
  id: string;
  display: { name: string; description: string; background_color: string; text_color: string };
  credentialSubject?: Record<string, unknown>;
}>;

/**
 * The securing mechanisms this issuer will actually produce on request.
 *
 * ADVERTISING IS A PROMISE, AND THIS ONE IS KEPT BY CONSTRUCTION. The same list
 * drives the metadata below AND the `format` enum the credential endpoint
 * accepts, so it is not possible to advertise a format the endpoint rejects.
 * That failure mode is worse than not advertising at all: a wallet that
 * discovers `vc+sd-jwt`, asks for it, and receives a 400 has been told the
 * feature exists and then denied it, with nothing to distinguish "not supported
 * here" from "your request was malformed".
 */
const ISSUABLE_FORMATS = [CREDENTIAL_FORMATS.VC_JWT, CREDENTIAL_FORMATS.SD_JWT_VC] as const;

/** Human-readable note explaining what choosing a format costs and buys. */
const FORMAT_NOTES: Record<(typeof ISSUABLE_FORMATS)[number], string> = {
  [CREDENTIAL_FORMATS.VC_JWT]:
    'Every claim is disclosed whenever this credential is presented.',
  [CREDENTIAL_FORMATS.SD_JWT_VC]:
    'The holder chooses which claims to disclose each time this credential is presented. '
    + 'Withheld claims are absent from the signed artifact, not merely hidden.',
};

/**
 * The configuration identifier for one type-and-format pair.
 *
 * The `vc+jwt` configuration keeps the bare type name it has always had, so
 * clients built against the pre-SD-JWT metadata keep resolving. The SD-JWT
 * variant gets a suffix rather than displacing it.
 */
function configurationId(typeId: string, format: (typeof ISSUABLE_FORMATS)[number]): string {
  return format === CREDENTIAL_FORMATS.SD_JWT_VC ? `${typeId}-sd-jwt` : typeId;
}

/**
 * OID4VCI issuer metadata. Exported because the spec requires this document to be
 * served from the domain root (`/.well-known/openid-credential-issuer`), while the
 * rest of the issuance surface stays namespaced under `/oid4vci`. index.ts mounts
 * this one handler at root rather than the whole router.
 *
 * TWO PROJECTIONS OF ONE CATALOGUE, and both are emitted deliberately.
 * `credential_configurations_supported` is the keyed map current OID4VCI
 * defines; `credentials_supported` is the array earlier drafts defined, which is
 * what this issuer has served until now and what `packages/web`'s client still
 * reads. Serving only the new shape would silently strip every credential from
 * a client that is still looking for the old one — a wallet would simply find
 * nothing on offer, with no error to explain why. They are generated from the
 * same source, so they cannot disagree.
 *
 * NOTE ON WHAT IS NOT ADVERTISED HERE: which individual claims of a given
 * credential are selectively disclosable. That is a property of the issued
 * credential, and the wallet reads it from the credential it actually holds
 * (see `enumerateDisclosableClaims` in the shared disclosure module). Restating
 * it in metadata would be a second source of truth for the one question where
 * being wrong means the holder believes they withheld something they did not.
 */
export function getIssuerMetadata(_req: Request, res: Response): void {
  const credentialsSupported = CREDENTIAL_CATALOGUE.flatMap((entry) =>
    ISSUABLE_FORMATS.map((format) => ({
      format,
      id: configurationId(entry.id, format),
      types: ['VerifiableCredential', entry.id],
      display: [
        {
          ...entry.display,
          locale: 'en-US',
          description: `${entry.display.description}. ${FORMAT_NOTES[format]}`,
        },
      ],
      ...('credentialSubject' in entry ? { credentialSubject: entry.credentialSubject } : {}),
    })),
  );

  const metadata = {
    credential_issuer: ISSUER_BASE_URL,
    credential_endpoint: `${ISSUER_BASE_URL}/oid4vci/credential`,
    token_endpoint: `${ISSUER_BASE_URL}/oid4vci/token`,
    deferred_credential_endpoint: `${ISSUER_BASE_URL}/oid4vci/deferred`,
    display: [
      {
        name: 'SSI Healthcare',
        locale: 'en-US',
        logo: {
          uri: `${ISSUER_BASE_URL}/logo.png`,
          alt_text: 'SSI Healthcare Logo',
        },
      },
    ],
    // Current OID4VCI: a map keyed by configuration id.
    credential_configurations_supported: Object.fromEntries(
      credentialsSupported.map(({ id, ...configuration }) => [
        id,
        { ...configuration, credential_definition: { type: configuration.types } },
      ]),
    ),
    // Earlier OID4VCI drafts: an array. Retained for existing clients.
    credentials_supported: credentialsSupported,
  };

  res.json(metadata);
}

oid4vciRouter.get('/.well-known/openid-credential-issuer', getIssuerMetadata);

// ---------------------------------------------------------------------------
// Create Credential Offer
// ---------------------------------------------------------------------------

oid4vciRouter.post('/offers', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const data = createOfferSchema.parse(req.body);
    
    const preAuthorizedCode = uuidv4();
    const expiresAt = new Date(Date.now() + data.expiresInMinutes * 60 * 1000);
    
    const categoryMap: Record<string, CredentialCategory> = {
      'HealthRecordCredential': CredentialCategory.GENERAL,
      'VaccinationCredential': CredentialCategory.VACCINATIONS,
      'PrescriptionCredential': CredentialCategory.PRESCRIPTIONS,
      'LabResultCredential': CredentialCategory.LAB_RESULTS,
      'InsuranceCredential': CredentialCategory.INSURANCE,
      'BloodWorkCredential': CredentialCategory.BLOOD_WORK,
      'ImagingCredential': CredentialCategory.IMAGING,
      'HealthCardCredential': CredentialCategory.IDENTITY,
      'ProfessionalLicenceCredential': CredentialCategory.PROFESSIONAL,
    };
    
    const category = categoryMap[data.credentialType] || CredentialCategory.GENERAL;
    
    // Hash PIN before storing
    const hashedPin = data.userPin ? await hashPin(data.userPin) : undefined;
    
    const offer = await credentialRepo.createCredentialOffer({
      issuerDid: user.did!,
      holderDid: data.holderDid,
      holderEmail: data.holderEmail,
      credentialType: data.credentialType,
      category,
      preAuthorizedCode,
      pinRequired: data.userPinRequired,
      pin: hashedPin,
      offerData: data.claims as Prisma.InputJsonValue,
      expiresAt,
    });
    
    const offerData = {
      credential_issuer: ISSUER_BASE_URL,
      credentials: [data.credentialType],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthorizedCode,
          user_pin_required: data.userPinRequired,
        },
      },
    };
    
    const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offerData))}`;
    const webOfferUri = `${ISSUER_BASE_URL}/oid4vci/offers/${offer.id}`;
    
    logger.info('Credential offer created', {
      offerId: offer.id,
      issuerDid: data.issuerDid,
      credentialType: data.credentialType,
    });
    
    res.status(201).json({
      success: true,
      data: {
        id: offer.id,
        offerUri,
        webOfferUri,
        preAuthorizedCode,
        expiresAt: expiresAt.toISOString(),
        credentialType: data.credentialType,
        issuerName: data.issuerName,
      },
    });
  } catch (error) {
    next(error);
  }
});

oid4vciRouter.get('/offers/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const offerId = req.params.id as string;
    
    const offer = await credentialRepo.findCredentialOfferById(offerId);
    
    if (!offer) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Offer not found', 404);
    }
    
    if (offer.status !== 'PENDING') {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, `Offer is ${offer.status}`, 400);
    }
    
    if (new Date() > offer.expiresAt) {
      await credentialRepo.updateCredentialOfferStatus(offerId, 'EXPIRED');
      throw new AppError(ERROR_CODES.CREDENTIAL_EXPIRED, 'Offer has expired', 400);
    }
    
    // SECURITY: this endpoint is deliberately unauthenticated so a wallet can
    // resolve an offer from a scanned QR code before it holds any token. It
    // therefore MUST NOT disclose protected health information.
    //
    // `offer.offerData` is the full claims blob for the credential about to be
    // issued (diagnoses, medications, results). It was previously returned here
    // as `previewData`, which made every claim readable by anyone who could
    // present an offer ID, with no token exchange and no audit trail.
    //
    // Only non-PHI offer metadata is returned. Claims are released by the token
    // endpoint (POST /oid4vci/token) followed by the credential endpoint, which
    // require the pre-authorized code and any configured PIN.
    res.json({
      success: true,
      data: {
        id: offer.id,
        credentialType: offer.credentialType,
        issuerDid: offer.issuerDid,
        pinRequired: offer.pinRequired,
        expiresAt: offer.expiresAt.toISOString(),
      },
    });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// Token Endpoint
// ---------------------------------------------------------------------------

oid4vciRouter.post('/token', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const body = req.body;
    const data = tokenRequestSchema.parse({
      grant_type: body.grant_type,
      'pre-authorized_code': body['pre-authorized_code'] || body.pre_authorized_code,
      user_pin: body.user_pin,
    });
    
    const offer = await db.credentialOffer.findUnique({
      where: { preAuthorizedCode: data['pre-authorized_code'] },
    });
    
    if (!offer) {
      logger.warn('Invalid pre-authorized code', { code: data['pre-authorized_code'].slice(0, 8) + '...' });
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Invalid pre-authorized code', 400);
    }
    
    if (offer.status !== 'PENDING') {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, `Offer is ${offer.status}`, 400);
    }
    
    if (new Date() > offer.expiresAt) {
      await credentialRepo.updateCredentialOfferStatus(offer.id, 'EXPIRED');
      throw new AppError(ERROR_CODES.CREDENTIAL_EXPIRED, 'Pre-authorized code has expired', 400);
    }
    
    // Verify PIN against hash with brute-force protection
    if (offer.pinRequired) {
      // Check if locked out
      if (offer.pinLockedUntil && new Date() < offer.pinLockedUntil) {
        const retryAfter = Math.ceil((offer.pinLockedUntil.getTime() - Date.now()) / 1000);
        throw new AppError(ERROR_CODES.RATE_LIMITED, `Too many PIN attempts. Retry after ${retryAfter} seconds`, 429);
      }
      
      if (!data.user_pin) {
        throw new AppError(ERROR_CODES.AUTH_FAILED, 'User PIN is required', 401);
      }
      
      if (offer.pin && !(await verifyPin(data.user_pin, offer.pin))) {
        const newAttempts = (offer.pinAttempts || 0) + 1;
        const MAX_PIN_ATTEMPTS = 5;
        
        // Lock after max attempts (exponential backoff: 30s, 60s, 120s...)
        const lockoutSeconds = newAttempts >= MAX_PIN_ATTEMPTS
          ? Math.min(30 * Math.pow(2, newAttempts - MAX_PIN_ATTEMPTS), 3600)
          : 0;
        
        await db.credentialOffer.update({
          where: { id: offer.id },
          data: {
            pinAttempts: newAttempts,
            ...(lockoutSeconds > 0 ? { pinLockedUntil: new Date(Date.now() + lockoutSeconds * 1000) } : {}),
          },
        });
        
        const remaining = Math.max(0, MAX_PIN_ATTEMPTS - newAttempts);
        if (remaining > 0) {
          throw new AppError(ERROR_CODES.AUTH_FAILED, `Invalid user PIN. ${remaining} attempts remaining`, 401);
        } else {
          throw new AppError(ERROR_CODES.RATE_LIMITED, `Too many PIN attempts. Locked for ${lockoutSeconds} seconds`, 429);
        }
      }
      
      // Reset attempts on successful PIN
      if (offer.pinAttempts > 0) {
        await db.credentialOffer.update({
          where: { id: offer.id },
          data: { pinAttempts: 0, pinLockedUntil: null },
        });
      }
    }
    
    const accessToken = jwt.sign(
      {
        offerId: offer.id,
        credentialType: offer.credentialType,
        issuerDid: offer.issuerDid,
        holderDid: offer.holderDid,
      },
      JWT_SECRET,
      { expiresIn: '15m' }
    );
    
    // Don't mark ACCEPTED yet — keep PENDING until credential is actually issued
    // This prevents the offer from being burned if the /credential endpoint fails
    logger.info('Token issued for credential offer', { offerId: offer.id });
    
    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      c_nonce: uuidv4(),
      c_nonce_expires_in: 86400,
    });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// Credential Endpoint
// ---------------------------------------------------------------------------

oid4vciRouter.post('/credential', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      throw new AppError(ERROR_CODES.AUTH_REQUIRED, 'Missing access token', 401);
    }
    
    const token = authHeader.slice(7);
    let payload: {
      offerId: string;
      credentialType: string;
      issuerDid: string;
      holderDid?: string;
    };
    
    try {
      payload = jwt.verify(token, JWT_SECRET) as typeof payload;
    } catch {
      throw new AppError(ERROR_CODES.AUTH_TOKEN_EXPIRED, 'Invalid or expired access token', 401);
    }
    
    const data = credentialRequestSchema.parse(req.body);
    
    const offer = await credentialRepo.findCredentialOfferById(payload.offerId);
    if (!offer) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Offer not found', 404);
    }
    
    // Verify holder proof if provided (holder binding)
    let holderDid = offer.holderDid || payload.holderDid;
    if (data.proof?.jwt) {
      try {
        const agent = getAgent();
        // First decode to extract issuer DID (header only, no trust yet)
        const unverifiedPayload = jwt.decode(data.proof.jwt) as { iss?: string; nonce?: string; iat?: number } | null;
        
        if (!unverifiedPayload?.iss?.startsWith('did:')) {
          throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Holder proof JWT must have a DID issuer (iss)', 400);
        }
        
        // Resolve the holder's DID to get their public key
        const didResult = await agent.dids.resolve(unverifiedPayload.iss);
        if (!didResult.didDocument) {
          throw new AppError(ERROR_CODES.VALIDATION_FAILED, `Cannot resolve holder DID: ${unverifiedPayload.iss}`, 400);
        }
        
        const verificationMethods = didResult.didDocument.verificationMethod ?? [];
        if (verificationMethods.length === 0) {
          throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Holder DID has no verification methods', 400);
        }
        
        // Extract the public key from the DID document for JWT verification
        const vm = verificationMethods[0];
        if ('publicKeyJwk' in vm && vm.publicKeyJwk) {
          // Use jose to import JWK and verify
          const jose = await import('jose');
          const publicKey = await jose.importJWK(vm.publicKeyJwk as Record<string, unknown>);
          const { payload: verifiedPayload } = await jose.jwtVerify(data.proof.jwt, publicKey, {
            clockTolerance: 60,
          });
          
          // Check proof is recent (within 5 minutes)
          if (verifiedPayload.iat) {
            const ageSeconds = Math.floor(Date.now() / 1000) - verifiedPayload.iat;
            if (ageSeconds > 300 || ageSeconds < -60) {
              throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Holder proof JWT is too old or has future timestamp', 400);
            }
          }
          
          holderDid = unverifiedPayload.iss;
          logger.info('Holder proof verified cryptographically via JWK', { holderDid });
        } else if ('publicKeyMultibase' in vm && vm.publicKeyMultibase) {
          // For did:key multibase-encoded Ed25519 public keys: decode multibase → raw bytes → verify JWT
          try {
            const multibaseKey = vm.publicKeyMultibase as string;
            
            // Multibase: 'z' prefix = base58btc encoding
            if (!multibaseKey.startsWith('z')) {
              throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Only base58btc multibase keys supported (z prefix)', 400);
            }
            
            // Decode base58btc → raw bytes (Ed25519 public key, 32 bytes)
            const { base58btc } = await import('multiformats/bases/base58');
            const keyBytes = base58btc.decode(multibaseKey);
            
            // Ed25519 public keys from did:key have a 2-byte multicodec prefix (0xed, 0x01)
            // Strip prefix if present
            const rawKey = keyBytes.length === 34 && keyBytes[0] === 0xed && keyBytes[1] === 0x01
              ? keyBytes.slice(2)
              : keyBytes;
            
            if (rawKey.length !== 32) {
              throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Invalid Ed25519 key length from multibase', 400);
            }
            
            // Import raw Ed25519 key and verify JWT using jose
            const jose = await import('jose');
            const publicKey = await (globalThis.crypto?.subtle ?? (await import('node:crypto')).webcrypto.subtle).importKey(
              'raw',
              rawKey,
              { name: 'Ed25519' },
              false,
              ['verify'],
            );
            
            const { payload: verifiedPayload } = await jose.jwtVerify(data.proof.jwt, publicKey, {
              clockTolerance: 60,
            });
            
            // Check proof is recent (within 5 minutes)
            if (verifiedPayload.iat) {
              const ageSeconds = Math.floor(Date.now() / 1000) - verifiedPayload.iat;
              if (ageSeconds > 300 || ageSeconds < -60) {
                throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Holder proof JWT is too old or has future timestamp', 400);
              }
            }
            
            holderDid = unverifiedPayload.iss;
            logger.info('Holder proof verified cryptographically via multibase/Ed25519', { holderDid });
          } catch (verifyErr) {
            if (isSsiError(verifyErr)) throw verifyErr;
            logger.warn('Multibase holder proof verification failed', {
              error: verifyErr instanceof Error ? verifyErr.message : String(verifyErr),
            });
            throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Holder proof JWT signature verification failed (Ed25519)', 400);
          }
        } else {
          // No usable key format — reject
          throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Holder DID has no supported key format (publicKeyJwk or publicKeyMultibase)', 400);
        }
      } catch (proofError) {
        if (isSsiError(proofError)) throw proofError;
        logger.warn('Holder proof verification failed', {
          error: proofError instanceof Error ? proofError.message : String(proofError),
        });
        throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Holder proof verification failed', 400);
      }
    }
    
    if (!holderDid) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Holder DID is required', 400);
    }
    
    const now = new Date();
    const expirationDate = new Date(now);
    expirationDate.setDate(expirationDate.getDate() + SYSTEM_DEFAULTS.CREDENTIAL_EXPIRY_DAYS);
    
    const credentialId = `urn:uuid:${uuidv4()}`;
    const credentialType = offer.credentialType;
    const types = ['VerifiableCredential', credentialType];

    // Revocation. This is the OID4VCI issuance path; the other one is
    // services/credentialService.ts issueCredential(), reached via
    // POST /api/credentials/accept-offer. Both must attach a status entry —
    // a credential issued through either route is indistinguishable to a
    // verifier, so a credential missing a status from one path would be an
    // unrevocable credential with no outward sign that it is one.
    const { list: statusList, index: statusIndex } = await allocateStatusIndex(offer.issuerDid);
    const publishedList = await ensureStatusListPublished(statusList);
    const statusEntry = buildStatusEntry(publishedList, statusIndex);


    // WHICH SECURING MECHANISM THE CLIENT ACTUALLY GETS.
    //
    // Only the two VC 2.0 identifiers select a mechanism. The three legacy VC
    // 1.1 identifiers name a data model this issuer no longer produces, so they
    // collapse to the default rather than being rejected — see the schema. The
    // result is reported back on the response's `format` member, so a client
    // that asked for something it did not get is told, rather than left to
    // assume its request was honoured.
    const issuedFormat: IssuableCredentialFormat =
      data.format === CREDENTIAL_FORMATS.SD_JWT_VC
        ? CREDENTIAL_FORMATS.SD_JWT_VC
        : CREDENTIAL_FORMATS.VC_JWT;

    // Sign credential using Credo-TS agent
    let signedCredential: Record<string, unknown>;
    // The compact envelope is the artifact an OID4VCI client expects, and under
    // VC 2.0 it is the only thing carrying a signature at all.
    let serializedJwt: string | null = null;

    try {
      const agent = getAgent();

      // VC DATA MODEL 2.0, secured with an enveloping JWT proof.
      //
      // The whole v2 stack is separate from v1 in Credo 0.6 and every piece
      // here has to match, or the mismatch is silent rather than loud:
      // `W3cV2Credential` (not `W3cCredential`), signed through
      // `agent.w3cV2Credentials` (not `agent.w3cCredentials`), with
      // `ClaimFormat.JwtW3cVc` (not `ClaimFormat.JwtVc`), and decoded by the
      // v2 branch of services/jwtVc.ts.
      //
      // Two shape changes come with the data model:
      //   - `issuanceDate`/`expirationDate` become `validFrom`/`validUntil`.
      //     `W3cV2Credential` has no `issuanceDate` member; passing one would
      //     be dropped rather than rejected.
      //   - `credentialSubject` takes the claims FLAT. v1's
      //     `W3cCredentialSubject` nested them under a `claims` key, which is
      //     Credo's in-memory model rather than the W3C one.
      //
      // The context array is v2-first, which is now correct rather than the
      // defect it was under v1: Credo's validator compares element zero against
      // the context URL for the class being built, and for `W3cV2Credential`
      // that is CREDENTIALS_CONTEXT_V2_URL.
      const w3cCredential = new W3cV2Credential({
        context: [VC_CONTEXTS.W3C_CREDENTIALS_V2, VC_CONTEXTS.SCHEMA_ORG],
        id: credentialId,
        type: types,
        issuer: offer.issuerDid,
        validFrom: now.toISOString(),
        validUntil: expirationDate.toISOString(),
        credentialSubject: new W3cV2CredentialSubject({
          id: holderDid,
          ...Object.fromEntries(Object.entries((offer.offerData as Record<string, unknown>) || {})),
        }),
        credentialStatus: toCredoV2CredentialStatus(statusEntry),
      });

      // Resolve issuer's verification method
      const didResult = await agent.dids.resolve(offer.issuerDid);
      const assertionMethods = didResult.didDocument?.assertionMethod ?? [];
      const verificationMethods = didResult.didDocument?.verificationMethod ?? [];
      const vmId =
        (typeof assertionMethods[0] === 'string'
          ? assertionMethods[0]
          : assertionMethods[0]?.id) ??
        verificationMethods[0]?.id;

      if (!vmId) {
        throw new Error(`No verification method found for ${offer.issuerDid}`);
      }

      // Bind the credential to the holder's key. Without this the credential is
      // a BEARER token — anyone holding the JWT can present it — and, in
      // Credo 0.6, it also cannot be put into a VC 2.0 presentation at all.
      // See resolveHolderBinding().
      const holderBinding = await resolveHolderBinding(agent, holderDid);
      // FAIL CLOSED. This used to warn and issue anyway, returning 200 with a
      // credential that can never be presented. See assertHolderBound().
      assertHolderBound(holderBinding, credentialId, holderDid);

      // THE SECURING STEP IS SHARED WITH services/credentialService.ts.
      // See services/securing.ts for why: a credential issued through either
      // route is indistinguishable to a verifier, so every rule about how one
      // is secured has to hold in both, and restating it at each call site is
      // how the two paths drifted apart before.
      //
      // This is also the point at which the metadata's promise is kept. The
      // format the client asked for is honoured here, so advertising
      // `vc+sd-jwt` and issuing `vc+jwt` anyway is not reachable.
      const secured = await secureV2Credential(agent, {
        credential: w3cCredential,
        format: issuedFormat,
        verificationMethod: vmId,
        holder: holderBinding.binding,
        subjectClaims: {
          id: holderDid,
          ...Object.fromEntries(Object.entries((offer.offerData as Record<string, unknown>) || {})),
        },
      });

      signedCredential = secured.json as unknown as Record<string, unknown>;
      serializedJwt = secured.envelope;

      logger.info('Credential signed via Credo-TS agent', {
        credentialId,
        format: secured.format,
        requestedFormat: data.format,
        dataModel: 'vc-2.0',
      });
    } catch (agentError) {
      // A deliberate, already-classified refusal (holder binding) must survive
      // this handler intact. Rewrapping it as a generic 500 would throw away
      // both the specific code and the retryable/permanent distinction that
      // assertHolderBound exists to communicate.
      if (isSsiError(agentError)) throw agentError;

      // Agent signing failed — NEVER issue unsigned credentials in a healthcare system
      logger.error('Credential signing failed — refusing to issue unsigned credential', {
        error: agentError instanceof Error ? agentError.message : String(agentError),
        credentialId,
        offerId: offer.id,
      });
      throw new AppError(
        ERROR_CODES.CREDENTIAL_ISSUANCE_FAILED,
        'Credential signing failed. Cannot issue unsigned credentials in a healthcare identity system.',
        500,
      );
    }
    
    const credentialHash = crypto.createHash('sha256')
      .update(JSON.stringify(signedCredential))
      .digest('hex');
    
    await db.credential.create({
      data: {
        holderDid,
        issuerDid: offer.issuerDid,
        type: types,
        category: offer.category,
        name: credentialType,
        description: `${credentialType} issued on ${now.toDateString()}`,
        credentialData: signedCredential as Prisma.InputJsonValue,
        // The enveloping proof. VC 2.0 keeps the securing mechanism out of the
        // credential, so this column — not `credentialData.proof` — is where
        // the signature lives. Read it back with `credentialEnvelopeJwt()`.
        credentialJwt: serializedJwt,
        // WHICH mechanism secures that envelope. Recorded rather than sniffed:
        // a compact SD-JWT still splits into three '.'-separated segments, so a
        // JWT decoder SUCCEEDS on one and returns the issuer-signed payload with
        // every disclosable claim replaced by a digest — a credential-shaped
        // husk with the patient data missing and nothing to say so.
        credentialFormat: issuedFormat,
        credentialHash,
        issuedAt: now,
        expiresAt: expirationDate,
        status: 'ACTIVE',
        statusListId: publishedList.id,
        statusListIndex: statusIndex,
      },
    });
    
    await credentialRepo.updateCredentialOfferStatus(offer.id, 'ACCEPTED');
    
    await db.auditLog.create({
      data: {
        eventType: AuditEventType.CREDENTIAL_ISSUED,
        action: `Credential ${credentialType} issued`,
        actorDid: offer.issuerDid,
        targetDid: holderDid,
        resourceType: 'credential',
        resourceId: credentialId,
        details: {
          credentialId,
          credentialType,
          offerId: offer.id,
        },
      },
    });
    
    logger.info('Credential issued', {
      credentialId,
      offerId: offer.id,
      credentialType,
      holderDid,
    });
    
    res.json({
      // Report what was issued, not what was requested. This endpoint always
      // produces VC 2.0, in one of two securing mechanisms, so a client that
      // asked for `jwt_vc_json` is told plainly that it received `vc+jwt`, and
      // one that asked for `vc+sd-jwt` can confirm it actually got it rather
      // than assuming from a 200.
      format: issuedFormat,
      // The `credential` member is the compact JWT string, not a JSON object.
      // For VC 2.0 this is not merely preferred: the enveloping JWT is the only
      // form carrying a signature at all, since the credential itself has no
      // embedded proof. Issuance above refuses to proceed without it.
      credential: serializedJwt,
      c_nonce: uuidv4(),
      c_nonce_expires_in: 86400,
    });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// Deferred Credential
// ---------------------------------------------------------------------------

oid4vciRouter.post('/deferred', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      throw new AppError(ERROR_CODES.AUTH_REQUIRED, 'Missing access token', 401);
    }

    const token = authHeader.slice(7);
    let payload: { offerId: string; credentialType: string; issuerDid: string; holderDid?: string };

    try {
      payload = jwt.verify(token, JWT_SECRET) as typeof payload;
    } catch {
      throw new AppError(ERROR_CODES.AUTH_TOKEN_EXPIRED, 'Invalid or expired access token', 401);
    }

    // Check if credential has been issued for this offer
    const offer = await credentialRepo.findCredentialOfferById(payload.offerId);
    if (!offer) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Offer not found', 404);
    }

    // The offer record is the server-side authority for this exchange. Confirm
    // the bearer token actually describes the offer it claims to, otherwise a
    // token minted for one offer could be replayed to read another.
    if (
      offer.issuerDid !== payload.issuerDid ||
      offer.credentialType !== payload.credentialType
    ) {
      logger.warn('Deferred credential token does not match its offer', {
        offerId: payload.offerId,
        tokenIssuerDid: payload.issuerDid,
        offerIssuerDid: offer.issuerDid,
      });
      throw new AppError(ERROR_CODES.AUTH_FAILED, 'Token does not match offer', 403);
    }

    // Resolve the holder from the offer, falling back to the token only when
    // the offer has not yet been bound to a holder.
    //
    // SECURITY: this predicate must never be `undefined`. Prisma elides
    // `undefined` values in a `where` clause (the generated client reports
    // "previewFeatures": [], so strictUndefinedChecks is off), which would drop
    // the ownership filter entirely and return the newest matching credential
    // belonging to ANY patient.
    const holderDid = offer.holderDid ?? payload.holderDid;
    if (!holderDid) {
      logger.warn('Deferred credential request has no resolvable holder', {
        offerId: payload.offerId,
      });
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        'Offer is not yet bound to a holder',
        400
      );
    }

    if (offer.holderDid && payload.holderDid && offer.holderDid !== payload.holderDid) {
      logger.warn('Deferred credential holder mismatch between token and offer', {
        offerId: payload.offerId,
      });
      throw new AppError(ERROR_CODES.AUTH_FAILED, 'Token does not match offer', 403);
    }

    const credential = await db.credential.findFirst({
      where: {
        issuerDid: payload.issuerDid,
        holderDid,
        type: { has: payload.credentialType },
      },
      orderBy: { issuedAt: 'desc' },
    });

    if (!credential) {
      // Credential not yet ready — ask client to retry
      res.status(202).json({
        acceptance_token: jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }),
        c_nonce: uuidv4(),
        c_nonce_expires_in: 86400,
        retry_after: 30,
      });
      return;
    }

    // Same rule as the immediate issuance response: emit the compact JWT.
    //
    // This used to read `storedCredential.proof.jwt`, which is `undefined` for
    // every VC 2.0 credential — v2 has no embedded proof — and would have
    // silently downgraded this response to unsigned JSON. `credentialEnvelopeJwt`
    // reads the `credentialJwt` column first and falls back to the legacy
    // VC 1.1 location, so it is correct for both data models.
    const storedCredential = storedCredentialToW3cJson(credential.credentialData);
    const storedJwt = credentialEnvelopeJwt(credential);

    res.json({
      format: credentialFormatFor(storedCredential),
      credential: storedJwt ?? storedCredential ?? credential.credentialData,
      c_nonce: uuidv4(),
      c_nonce_expires_in: 86400,
    });
  } catch (error) {
    next(error);
  }
});

export default oid4vciRouter;
