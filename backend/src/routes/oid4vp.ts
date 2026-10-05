/**
 * SSI Healthcare Backend - OID4VP Routes
 * 
 * OpenID for Verifiable Presentations (OID4VP) endpoints.
 * Implements the Authorization Request flow for frictionless verification.
 * 
 * Reference: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 * 
 * Endpoints:
 * - GET  /.well-known/openid-verifier           - Verifier metadata
 * - POST /oid4vp/authorization-request          - Create presentation request
 * - GET  /oid4vp/authorization-request/:id      - Retrieve presentation request
 * - POST /oid4vp/response                       - Submit presentation response
 * - GET  /oid4vp/sessions/:id                   - Get verification session status
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { requireAuth } from '../middleware/auth.js';
import { db } from '../db/index.js';
import * as presentationRepo from '../db/presentationRepository.js';
import {
  ERROR_CODES,
  VC_CONTEXTS,
  credentialValidUntil,
  credentialSubjectId,
  subjectClaimJsonPath,
  PRESENTATION_FORMATS,
  isSsiError,
} from '@ssi-healthcare/shared';
import {
  AuditEventType,
  PresentationStatus,
  PresentationType,
  ConsentPurpose as PrismaConsentPurpose,
  type Prisma,
} from '../../prisma/generated/client/index.js';

/**
 * The receipt carries the purpose category as a wire value; Prisma wants the
 * member. The two differ because each member carries an `@map`, and sending the
 * member name where the mapped value is expected is rejected as an invalid enum.
 */
const purposeToPrismaConsent: Record<string, PrismaConsentPurpose> = {
  treatment: PrismaConsentPurpose.TREATMENT,
  insurance_claim: PrismaConsentPurpose.INSURANCE_CLAIM,
  research: PrismaConsentPurpose.RESEARCH,
  emergency: PrismaConsentPurpose.EMERGENCY,
  referral: PrismaConsentPurpose.REFERRAL,
};
import { config } from '../config/index.js';
import { getAgent } from '../agent/index.js';
import { checkStatusOnLedger } from '../services/statusListService.js';
// Used only where Credo refuses on `vm.controller` attribution and the
// signature therefore still has to be checked by us — see the long note at
// that call site.
import { verifyRecoveryKeySignature, verifyConsentReceipt } from '@ssi-healthcare/shared';
import { ed25519PublicKeyFromMultibase } from '@ssi-healthcare/sdk/ledger';
import {
  decodeJwtHeader,
  extractPresentationCredentials,
  toV2VerifiableCredential,
  toV2VerifiablePresentation,
  // `toJsonLdVerifiablePresentation`, `envelopedCredentialToJwt` and
  // `jwtVcToW3cJson` are no longer imported here: the only code in this file
  // that used them was the JSON VP branch and its `toPresentedCredentials`
  // helper, both removed. See the removal note in the `/response` handler.
  // They remain exported from jwtVc.ts and are used by other callers.
  VP_JWT_TYP_V2,
  type PresentedCredential,
} from '../services/jwtVc.js';
import {
  verifySdJwtPresentation,
  toV2SdJwtVerifiablePresentation,
  toV2SdJwtVerifiableCredential,
  VP_SD_JWT_TYP,
} from '../services/sdJwtVc.js';

export const oid4vpRouter = Router();

/*
 * `toPresentedCredentials` was retired with the JSON VP branch (steno #192/#234)
 * and lived here commented out until 8 Sep 2026. It is now real code at
 * Backup/SSI_healthcare/packages/backend/src/routes/oid4vp.toPresentedCredentials.ts.bak,
 * with the two measured blockers to reviving it and the imports it needs back.
 */

const JWT_SECRET = config.jwtSecret;
const VERIFIER_BASE_URL = config.verifierBaseUrl;

// ---------------------------------------------------------------------------
// Validation Schemas
// ---------------------------------------------------------------------------

const authorizationRequestSchema = z.object({
  verifierDid: z.string().startsWith('did:'),
  verifierName: z.string().min(1),
  purpose: z.string().min(1),
  requestedCredentials: z.array(z.object({
    type: z.string().min(1),
    required: z.boolean().default(true),
    /**
     * THE CLAIMS THIS VERIFIER SAYS IT NEEDS, and how badly.
     *
     * This is the half of selective disclosure that lives with the verifier. A
     * holder can only disclose less if someone tells them what "enough" is;
     * absent that, the only safe choice is everything, and the disclosure sheet
     * becomes a list of toggles with no basis for setting any of them.
     *
     * `required: false` is a real commitment, not a hint — it says this verifier
     * will accept a presentation WITHOUT this claim. The wallet honours it by
     * leaving the claim unselected by default, so a verifier that marks
     * everything required gets everything, and one that marks a claim optional
     * genuinely gives the holder that privacy back.
     *
     * Paths are relative to `credentialSubject` (`hivStatus`,
     * `prescriber.name`, `medications[1]`) and are translated to Presentation
     * Exchange JSONPaths below. The verifier never writes JSONPath itself: the
     * `$.credentialSubject.` prefix is exactly the kind of detail that gets
     * mistyped once and silently matches nothing.
     */
    claims: z.array(z.object({
      path: z.string().min(1),
      required: z.boolean().default(true),
      purpose: z.string().optional(),
    })).optional(),
    constraints: z.object({
      fields: z.array(z.object({
        path: z.array(z.string()),
        filter: z.record(z.unknown()).optional(),
        optional: z.boolean().default(false),
      })).optional(),
    }).optional(),
  })),
  redirectUri: z.string().url().optional(),
  state: z.string().optional(),
  nonce: z.string().optional(),
  expiresInMinutes: z.number().min(1).max(60).default(15),
});

/**
 * The Ed25519 key a DID publishes for AUTHENTICATION, or null.
 *
 * Null means "this key may not authenticate as this DID" and every caller must
 * treat it as a refusal, never as "check skipped". The verification method must
 * both exist in `verificationMethod` AND be listed under `authentication`:
 * membership of the document alone is not authority to speak for it.
 *
 * Note what is deliberately NOT consulted — `vm.controller`. Attribution is by
 * the verification method's ID PREFIX, which is the rule the chain itself
 * applies (#281). For the recoverable patient shape the VM's controller is the
 * RECOVERY CONTROLLER, so comparing controllers rejects every legitimate
 * patient signature; that is exactly the Credo mismatch compensated for below.
 */
async function holderAuthenticationKey(did: string, vmId: string): Promise<Uint8Array | null> {
  const doc = await getAgent().dids.resolveDidDocument(did);
  const vm = doc.verificationMethod?.find((m) => m.id === vmId);
  const authIds = (doc.authentication ?? []).map((a) => (typeof a === 'string' ? a : a.id));
  if (!vm?.publicKeyMultibase || !authIds.includes(vmId)) return null;
  return ed25519PublicKeyFromMultibase(vm.publicKeyMultibase);
}

const presentationResponseSchema = z.object({
  vp_token: z.string().or(z.record(z.unknown())),
  presentation_submission: z.object({
    id: z.string(),
    definition_id: z.string(),
    descriptor_map: z.array(z.object({
      id: z.string(),
      format: z.string(),
      path: z.string(),
      path_nested: z.object({
        format: z.string(),
        path: z.string(),
      }).optional(),
    })),
  }),
  // REQUIRED. `state` carries the requestId that binds this response to its
  // authorization request. It was previously optional, and the handler fed it
  // straight into `where: { requestId: data.state }`. Prisma elides
  // `undefined` predicates, so an omitted state matched an arbitrary
  // presentation row which was then written to EXPIRED/REJECTED.
  state: z.string().min(1, 'state is required and identifies the request'),
  /**
   * The holder-signed consent receipt (steno #279), as a compact JWS.
   *
   * A SEPARATE PARAMETER, not a second credential inside the presentation.
   * That is the decision, and it is what keeps Credo's one-credential-per-VC-2.0
   * -presentation limit from ever applying and the sequential-presentation
   * mix-and-match surface from opening.
   *
   * Optional on the wire because a presentation is a complete act without one
   * and refusing here would break every existing verifier. What is NOT optional
   * is the consequence: no receipt means no consent row. Consent is recorded
   * only where the holder signed for it.
   */
  consent_receipt: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Verifier Metadata
// ---------------------------------------------------------------------------

/**
 * OID4VP verifier metadata. Exported because the spec requires this document to be
 * served from the domain root (`/.well-known/openid-verifier`), while the rest of
 * the presentation surface stays namespaced under `/oid4vp`. index.ts mounts this
 * one handler at root rather than the whole router.
 */
export function getVerifierMetadata(_req: Request, res: Response): void {
  const metadata = {
    verifier_endpoint: `${VERIFIER_BASE_URL}/oid4vp/authorization-request`,
    response_endpoint: `${VERIFIER_BASE_URL}/oid4vp/response`,
    presentation_definition_uri_supported: true,
    vp_formats_supported: {
      jwt_vp_json: {
        alg_values_supported: ['EdDSA', 'ES256', 'ES256K'],
      },
      // SELECTIVE DISCLOSURE, NEGOTIATED RATHER THAN ASSUMED.
      //
      // A wallet has no way to know a verifier will accept a partially
      // disclosed credential unless the verifier says so, and a holder who
      // cannot know that has no reason to disclose less. Advertising this is
      // what makes the disclosure sheet worth rendering at all.
      //
      // The credential and presentation formats are NOT independently
      // selectable: Credo 0.6 refuses a `vp+sd-jwt` carrying a `vc+jwt`
      // credential and vice versa, so a verifier accepting `vp+sd-jwt` is
      // accepting `vc+sd-jwt` credentials inside it.
      [PRESENTATION_FORMATS.VP_SD_JWT]: {
        alg_values_supported: ['EdDSA'],
        'sd-jwt_alg_values_supported': ['EdDSA'],
      },
      [PRESENTATION_FORMATS.VP_JWT]: {
        alg_values_supported: ['EdDSA'],
      },
      // `ldp_vp` IS DELIBERATELY ABSENT. It was advertised here with
      // `Ed25519Signature2020` / `JsonWebSignature2020` proof types, and the
      // route could not verify either — see the removal note in the `/response`
      // handler and steno #192. Advertising a format the verifier then refuses
      // is worse than not advertising it: a wallet has no way to discover the
      // refusal except by having a presentation rejected. Restore this entry
      // only together with real Data Integrity support.
    },
    client_id_schemes_supported: ['did', 'redirect_uri'],
    request_object_signing_alg_values_supported: ['EdDSA', 'ES256'],
    display: [
      {
        name: 'SSI Healthcare Verifier',
        locale: 'en-US',
        logo: {
          uri: `${VERIFIER_BASE_URL}/logo.png`,
          alt_text: 'SSI Healthcare Verifier Logo',
        },
      },
    ],
  };

  res.json(metadata);
}

oid4vpRouter.get('/.well-known/openid-verifier', getVerifierMetadata);

// ---------------------------------------------------------------------------
// Create Authorization Request
// ---------------------------------------------------------------------------

oid4vpRouter.post('/authorization-request', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = authorizationRequestSchema.parse(req.body);
    
    const requestId = uuidv4();
    const nonce = data.nonce || uuidv4();
    const state = data.state || uuidv4();
    const expiresAt = new Date(Date.now() + data.expiresInMinutes * 60 * 1000);
    
    const presentationDefinition = {
      id: requestId,
      name: data.purpose,
      purpose: data.purpose,
      input_descriptors: data.requestedCredentials.map((cred, index) => ({
        id: `descriptor_${index}`,
        name: cred.type,
        purpose: `Verify ${cred.type}`,
        constraints: {
          fields: [
            {
              // Constrains WHICH credential satisfies this descriptor. Not a
              // disclosure choice — `type` sits outside the issuer's disclosure
              // frame and is in every presentation regardless — and the wallet's
              // requirement reader skips it for exactly that reason.
              path: ['$.type'],
              filter: {
                type: 'array',
                contains: { const: cred.type },
              },
            },
            // The per-claim requirements, as standard PE fields. Emitted in the
            // format the wallet already has to understand rather than alongside
            // a second bespoke structure, so what the holder is shown and what
            // the verifier enforces cannot drift apart.
            //
            // NOTE THE POLARITY FLIP: this route speaks `required`, PE speaks
            // `optional`. Converted here, once.
            ...(cred.claims ?? []).map((claim) => ({
              path: [subjectClaimJsonPath(claim.path)],
              optional: !claim.required,
              ...(claim.purpose ? { purpose: claim.purpose } : {}),
            })),
            ...(cred.constraints?.fields || []),
          ],
        },
      })),
    };
    
    // Store entirely in DB — no in-memory Map needed
    const presentation = await db.presentation.create({
      data: {
        requestId,
        verifierDid: data.verifierDid,
        presentationType: PresentationType.SELECTIVE,
        status: PresentationStatus.REQUESTED,
        requestedCredentials: JSON.parse(JSON.stringify({
          types: data.requestedCredentials.map(c => c.type),
          purpose: data.purpose,
          verifierName: data.verifierName,
          definition: presentationDefinition,
        })) as Prisma.InputJsonValue,
        nonce,
        expiresAt,
      },
    });
    
    const authRequest = {
      response_type: 'vp_token',
      client_id: data.verifierDid,
      redirect_uri: data.redirectUri || `${VERIFIER_BASE_URL}/oid4vp/response`,
      response_mode: 'direct_post',
      presentation_definition: presentationDefinition,
      nonce,
      state,
    };
    
    const requestUri = `openid4vp://?request=${encodeURIComponent(JSON.stringify(authRequest))}`;
    const requestByReference = `openid4vp://?request_uri=${encodeURIComponent(`${VERIFIER_BASE_URL}/oid4vp/authorization-request/${requestId}`)}`;
    
    logger.info('Presentation request created', {
      requestId,
      verifierDid: data.verifierDid,
      credentialTypes: data.requestedCredentials.map(c => c.type),
    });
    
    res.status(201).json({
      success: true,
      data: {
        requestId,
        presentationId: presentation.id,
        requestUri,
        requestByReference,
        webUri: `${VERIFIER_BASE_URL}/verify?request=${requestId}`,
        expiresAt: expiresAt.toISOString(),
        presentationDefinition,
        nonce,
        state,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /oid4vp/authorization-request/:id
 */
oid4vpRouter.get('/authorization-request/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const requestId = req.params.id as string;
    
    const presentation = await db.presentation.findFirst({
      where: { 
        OR: [
          { id: requestId },
          { requestId },
          { nonce: requestId },
        ],
      },
    });
    
    if (!presentation) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Request not found', 404);
    }
    
    if (new Date() > presentation.expiresAt) {
      throw new AppError(ERROR_CODES.CREDENTIAL_EXPIRED, 'Request has expired', 400);
    }
    
    const requestedCredentials = presentation.requestedCredentials as { definition?: object; types?: string[]; purpose?: string; verifierName?: string } | null;
    const presentationDefinition = requestedCredentials?.definition || {
      id: presentation.requestId,
      input_descriptors: (requestedCredentials?.types || []).map((type, index) => ({
        id: `descriptor_${index}`,
        name: type,
        constraints: {
          fields: [{
            path: ['$.type'],
            filter: { type: 'array', contains: { const: type } },
          }],
        },
      })),
    };
    
    const authRequest = {
      response_type: 'vp_token',
      client_id: presentation.verifierDid,
      // WHO IS ASKING, in a form a holder can read.
      //
      // Without this the wallet has only a DID, and a DID is not a name — it
      // rendered "Unknown Organization" on the consent screen for a verifier
      // whose name we had all along, stored at request time and simply never
      // sent. `client_metadata.client_name` is the OID4VP-defined place for it.
      //
      // It is a CLAIM by the verifier about itself, not a verified fact, and
      // the wallet is expected to treat it that way.
      client_metadata: {
        client_name: requestedCredentials?.verifierName ?? undefined,
      },
      redirect_uri: `${VERIFIER_BASE_URL}/oid4vp/response`,
      response_mode: 'direct_post',
      presentation_definition: presentationDefinition,
      nonce: presentation.nonce,
      state: presentation.requestId,
    };
    
    if (req.headers.accept?.includes('application/jwt')) {
      const requestJwt = jwt.sign(authRequest, JWT_SECRET, { expiresIn: '15m' });
      res.type('application/jwt').send(requestJwt);
    } else {
      res.json(authRequest);
    }
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// Presentation Response
// ---------------------------------------------------------------------------

oid4vpRouter.post('/response', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = presentationResponseSchema.parse(req.body);

    // Defence in depth: the schema above already guarantees a non-empty state,
    // but this query MUST NOT run with an undefined predicate. Prisma would
    // elide it and findFirst would return an unrelated presentation, which the
    // code below then mutates.
    const requestId = data.state;
    if (!requestId) {
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        'state is required to identify the verification session',
        400
      );
    }

    const presentation = await db.presentation.findFirst({
      where: { requestId },
    });
    
    if (!presentation) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Verification session not found', 404);
    }
    
    if (presentation.status !== PresentationStatus.REQUESTED) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, `Request is ${presentation.status}`, 400);
    }
    
    if (new Date() > presentation.expiresAt) {
      await presentationRepo.updatePresentationStatus(presentation.id, PresentationStatus.EXPIRED);
      throw new AppError(ERROR_CODES.CREDENTIAL_EXPIRED, 'Request has expired', 400);
    }
    
    let vpToken: Record<string, unknown>;
    let holderDid: string | undefined;
    let disclosedFields: string[] = [];
    // The credentials actually carried by the presentation, each paired with the
    // envelope that secures it. Populated by `extractPresentationCredentials`
    // rather than by reading `vpToken.verifiableCredential`, which is undefined
    // for a VC 1.1 JWT VP and made the checks below iterate nothing at all.
    let presentedCredentials: PresentedCredential[] = [];
    // Which envelopes are SD-JWTs now travels ON each PresentedCredential as
    // `isSdJwt`, rather than in a parallel Set kept beside this list.
    //
    // The reason is unchanged and still load-bearing: a compact SD-JWT does not
    // fail a JWT decoder, it SUCCEEDS and returns the issuer-signed payload with
    // the disclosable claims replaced by digests, so the per-credential re-check
    // must be TOLD which reader to use. What changed is that a second collection
    // could drift from the first — the JWT-VP branch populated the list and left
    // the Set empty, so a narrowed SD-JWT arriving that way would have been read
    // with the JWT reader and verified against a husk.
    // Whether Credo verified the holder signature and the per-credential issuer
    // signatures. Anything that leaves this false must fail the presentation.
    let vpSignaturesVerified = false;
    
    if (typeof data.vp_token === 'string') {
      // JWT VP — verify using DID-based asymmetric verification via Credo-TS
      // SECURITY: Never use symmetric HMAC for VP verification — external wallets
      // sign with their own DID-bound keys, not our server secret.
      try {
        const agent = getAgent();

        // Route to the stack matching the presentation's data model. The `typ`
        // header is authoritative: Credo stamps `vp+jwt` on VC 2.0
        // presentations and `JWT` on VC 1.1 ones, and each stack rejects the
        // other's tokens outright.
        const vpHeader = decodeJwtHeader(data.vp_token);
        const vpTyp = typeof vpHeader?.typ === 'string' ? vpHeader.typ.toLowerCase() : null;
        const isSdJwtVp = vpTyp === VP_SD_JWT_TYP;
        const isV2Vp = vpTyp === VP_JWT_TYP_V2;

        if (isSdJwtVp) {
          // =================================================================
          // THE SELECTIVELY-DISCLOSED PATH, THROUGH THE HARDENED BOUNDARY.
          // =================================================================
          // This route previously had no SD-JWT branch at all, which meant a
          // `vp+sd-jwt` reaching it was handed to the JWT verifier. That does
          // not fail loudly: a compact SD-JWT still splits into three
          // '.'-separated segments, so the JWT reader SUCCEEDS and returns the
          // issuer-signed payload — every disclosable claim replaced by a
          // digest. The verifier would have received a credential-shaped husk
          // and no indication anything was wrong.
          //
          // `verifySdJwtPresentation` is used INSTEAD OF, not in addition to,
          // `agent.w3cV2Credentials.verifyPresentation`, because Credo's own
          // verdict is not an authorization decision here: it returns
          // `isValid: true` for replayed presentations, for stolen credentials,
          // and for presentations carrying disclosures the issuer never
          // committed to. The boundary runs Credo's checks internally and ANDs
          // them with the three it does not perform. See services/sdJwtVc.ts.
          const sdJwtResult = await verifySdJwtPresentation(agent, {
            presentation: data.vp_token,
            challenge: presentation.nonce ?? '',
            // The audience the holder signed for. OID4VP binds a presentation
            // to a verifier by `client_id`, which for this system is the
            // verifier's DID. Passing it makes an absent or mismatched `aud` a
            // FAILURE rather than a skipped check — a presentation naming no
            // audience is one the holder did not intend for us specifically.
            domain: presentation.verifierDid,
          });

          if (!sdJwtResult.isValid) {
            // Log the per-check verdict, not just the boolean. Which check
            // failed is the difference between a replay, a theft and a tampered
            // disclosure, and that distinction is unrecoverable after the fact
            // if only the outcome is recorded.
            logger.warn('SD-JWT presentation rejected at the verification boundary', {
              requestId,
              checks: sdJwtResult.checks,
              errors: sdJwtResult.errors,
            });
            throw new AppError(
              ERROR_CODES.VALIDATION_FAILED,
              `Presentation rejected: ${sdJwtResult.errors.join('; ')}`,
              400,
            );
          }

          const sdJwtPresentation = toV2SdJwtVerifiablePresentation(data.vp_token);
          vpToken = (sdJwtPresentation?.sdJwt.payload ?? {}) as Record<string, unknown>;
          holderDid = sdJwtPresentation?.resolvedPresentation.holderId;

          // Claims come from the boundary, which populates them ONLY on full
          // success and resolves them from `prettyClaims` — never from the raw
          // disclosure list, which can carry entries whose digests match
          // nothing.
          presentedCredentials = sdJwtResult.credentials.map((entry) => ({
            credential: entry.credential,
            envelopeJwt: entry.envelope,
            isSdJwt: true,
          }));
          vpSignaturesVerified = true;

          logger.info('SD-JWT presentation accepted', {
            requestId,
            holderDid,
            checks: sdJwtResult.checks,
            // What the verifier actually learned. This is the number that makes
            // selective disclosure auditable: a verifier receiving three claims
            // where the credential carries eight should be visible in the log.
            disclosedClaimCounts: sdJwtResult.credentials.map((entry) =>
              Object.keys(
                (entry.credential.credentialSubject ?? {}) as Record<string, unknown>,
              ).length,
            ),
          });
        } else {

        // The v2 API takes a class instance where v1 takes a compact string.
        // Passing a string typechecks (both option types are `unknown`) and
        // throws only at runtime — see `toV2VerifiablePresentation`.
        const v2Presentation = isV2Vp ? toV2VerifiablePresentation(data.vp_token) : null;
        if (isV2Vp && !v2Presentation) {
          throw new AppError(
            ERROR_CODES.VALIDATION_FAILED,
            'Presentation is not a readable VC 2.0 JWT presentation',
            400,
          );
        }

        const vpResult = isV2Vp
          ? await agent.w3cV2Credentials.verifyPresentation({
              presentation: v2Presentation!,
              challenge: presentation.nonce || '',
            })
          : await agent.w3cCredentials.verifyPresentation({
              presentation: data.vp_token,
              challenge: presentation.nonce || '',
              // MUST be false. Credo 0.6's VC 1.1 verifier defaults this to
              // TRUE and then hard-fails any credential that carries a
              // `credentialStatus` ("Verifying credential status is not
              // supported for JWT VCs") — so leaving it defaulted rejected
              // every presentation of every revocable credential we issue.
              // Revocation is checked below against the ledger instead, which
              // is stronger anyway. The v2 branch needs no such flag: its
              // verifier has no status handling to refuse on.
              verifyCredentialStatus: false,
            });
        // ===================================================================
        // CREDO ATTRIBUTES BY `controller`; THE CHAIN ATTRIBUTES BY VM ID.
        // ===================================================================
        // Credo 0.6's v2 JWT verifier decides "did the holder sign this?" by
        // comparing `verificationMethod.controller` to the holder DID — twice,
        // as `holderIsSigner` and again as `credentialSubjectAuthentication`.
        //
        // That assumption is FALSE for every recoverable patient DID this
        // system mints. Under S-1 §8.1 the patient's `#key-1` declares the
        // RECOVERY CONTROLLER as its controller, and that is not incidental:
        // steno #207 measured that a self-controlled VM makes the DID
        // permanently unrecoverable, and #208 measured that naming the patient
        // as its own controller is worse still. The shape is the reason
        // seedless recovery works at all.
        //
        // The chain does not read `controller` this way. `FindSignInfosBySigner`
        // attributes a signature by the DID PART OF THE SIGNING VM'S ID and
        // never by its controller field (#281) — so a key published at
        // `<holder>#key-1`, listed under the holder's own `authentication`, IS
        // the holder acting, whoever may rotate it.
        //
        // So those two checks are recomputed here on the chain's rule, exactly
        // as the four verifier holes in CREDO-SECURITY-REPORT.md are
        // compensated in our own code rather than by patching `node_modules`:
        // a patched dependency is invisible to every future reader.
        //
        // NOTHING IS WEAKENED. `dataModel` (nonce and audience) and
        // `presentationSignature` remain Credo's, and both must still pass. The
        // possession proof is unchanged — the signature must still verify under
        // a key published in the holder's own DID document.
        const CONTROLLER_ATTRIBUTION_CHECKS = new Set([
          'holderIsSigner',
          'credentialSubjectAuthentication',
        ]);
        const failedChecks = Object.entries(vpResult.validations ?? {}).filter(([, value]) => {
          const entry = value as { isValid?: boolean } | Array<{ isValid?: boolean }>;
          return Array.isArray(entry) ? entry.some((e) => !e?.isValid) : !entry?.isValid;
        });
        // The same disagreement also arrives as a THROWN error rather than a
        // failed check. `getVerificationMethodForJwt` runs before the per-check
        // results exist and refuses outright with "Verification method
        // controller '<X>' does not match the signer '<Y>'", so `validations`
        // holds only `dataModel` and the reason sits in `vpResult.error`.
        // Looking only at `validations` therefore missed the very case this
        // compensation exists for.
        const thrownReason =
          vpResult.error instanceof Error ? vpResult.error.message : String(vpResult.error ?? '');
        const attributionThrown = /verification method controller .* does not match the signer/i.test(
          thrownReason,
        );

        const onlyAttributionFailed =
          attributionThrown ||
          (failedChecks.length > 0 &&
            failedChecks.every(([name]) => CONTROLLER_ATTRIBUTION_CHECKS.has(name)));

        let acceptedByVmIdAttribution = false;
        if (!vpResult.isValid && onlyAttributionFailed) {
          const signingVm = decodeJwtHeader(data.vp_token as string)?.kid;
          const signerDid = typeof signingVm === 'string' ? signingVm.split('#')[0] : '';
          const claimedHolder = (
            v2Presentation as unknown as { resolvedPresentation?: { holderId?: string } } | null
          )?.resolvedPresentation?.holderId;

          // VERIFY THE SIGNATURE OURSELVES HERE. THIS IS NOT OPTIONAL.
          //
          // Credo refuses at `getVerificationMethodForJwt`, which runs BEFORE
          // `verifyJws`. So when it fails this way NO SIGNATURE CHECK HAS
          // HAPPENED, and accepting on attribution alone would admit a
          // presentation nobody proved possession of — a far worse hole than
          // the mismatch being compensated for. The key is taken from the
          // holder's own DID document, at the exact verification method the
          // header names, and must appear under `authentication`.
          let signatureIsValid = false;
          if (signerDid && signerDid === claimedHolder && typeof signingVm === 'string') {
            try {
              const holderDoc = await agent.dids.resolveDidDocument(signerDid);
              const vm = holderDoc.verificationMethod?.find((m) => m.id === signingVm);
              const authIds = (holderDoc.authentication ?? []).map((a) =>
                typeof a === 'string' ? a : a.id,
              );
              const publicKeyMultibase = vm?.publicKeyMultibase;

              if (vm && publicKeyMultibase && authIds.includes(signingVm)) {
                const [headerB64, payloadB64, signatureB64] = (data.vp_token as string).split('.');
                signatureIsValid = verifyRecoveryKeySignature(
                  ed25519PublicKeyFromMultibase(publicKeyMultibase),
                  new TextEncoder().encode(`${headerB64}.${payloadB64}`),
                  Buffer.from(signatureB64 ?? '', 'base64url'),
                );
              } else {
                logger.warn('VM-id attribution refused: key not usable for authentication', {
                  requestId,
                  signingVerificationMethod: signingVm,
                  foundVerificationMethod: Boolean(vm),
                  listedForAuthentication: authIds.includes(signingVm),
                });
              }
            } catch (resolveError) {
              logger.warn('VM-id attribution refused: could not resolve the holder DID', {
                requestId,
                holder: signerDid,
                error: resolveError instanceof Error ? resolveError.message : String(resolveError),
              });
            }
          }

          acceptedByVmIdAttribution =
            Boolean(signerDid) && signerDid === claimedHolder && signatureIsValid;
          if (acceptedByVmIdAttribution) {
            logger.info('Presentation accepted on VM-id attribution', {
              requestId,
              signingVerificationMethod: signingVm,
              holder: claimedHolder,
              recomputed: [...CONTROLLER_ATTRIBUTION_CHECKS],
              reason:
                'the signing key is published under the holder own DID; Credo compared ' +
                'vm.controller, which for the recoverable patient shape is the recovery controller',
            });
          }
        }

        if (!vpResult.isValid && !acceptedByVmIdAttribution) {
          // Log WHY. The message below is deliberately terse for the wire, but
          // discarding Credo's own reason left "VP signature verification
          // failed" as the only evidence for a dozen distinct causes — a wrong
          // kid, an unresolvable DID, a malformed context, a genuinely bad
          // signature. Diagnosing that from the outside is guesswork.
          logger.warn('VP verification failed', {
            requestId,
            failedChecks: failedChecks.map(([name]) => name),
            detail: JSON.stringify(vpResult, (_k, v) => (v instanceof Error ? v.message : v)).slice(0, 1200),
          });
          throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'VP signature verification failed', 400);
        }
        vpToken = jwt.decode(data.vp_token) as Record<string, unknown>;
        holderDid = vpToken?.iss as string;

        // Credo verified the holder's signature over the presentation AND, for
        // both stacks, the issuer signature on each credential inside it. What
        // it does not check is revocation, which is done per credential below.
        presentedCredentials = extractPresentationCredentials(data.vp_token);
        vpSignaturesVerified = true;
        }
      } catch (agentError) {
        if (isSsiError(agentError)) throw agentError;
        logger.error('VP verification failed — rejecting unverified presentation', {
          error: agentError instanceof Error ? agentError.message : String(agentError),
        });
        throw new AppError(
          ERROR_CODES.VALIDATION_FAILED,
          'Verifiable Presentation signature could not be verified. Presentation rejected.',
          400,
        );
      }
    } else {
      // =====================================================================
      // THE JSON (ldp_vp / Data Integrity) BRANCH WAS REMOVED. DO NOT RESTORE.
      // =====================================================================
      // Retired deliberately (steno #192, OpenDiscussion §P3) — this is not an
      // oversight and re-adding a verifier call here would not make it work.
      //
      // The branch that used to live here called
      // `agent.w3cCredentials.verifyPresentation` on a JSON-LD presentation.
      // Its runtime defect (a plain object where Credo dispatches on
      // `instanceof`) was genuinely fixed. It was removed anyway, because no
      // JSON VP can succeed for the DIDs this system issues, for two
      // INDEPENDENT reasons, both established by execution:
      //
      //   1. Our `did:cheqd` documents declare the `jws-2020` context, which is
      //      not in Credo 0.6's cached document-loader set. Loading the proof's
      //      context fails before any signature is checked.
      //   2. Those documents use `JsonWebKey2020` verification methods, while
      //      Credo's Data Integrity suites consume `Ed25519VerificationKey2018`.
      //      Even with the context loaded, no suite would match the key.
      //
      // OID4VP negotiates the JWT format for this verifier anyway (see
      // `vp_formats_supported` above — `ldp_vp` is no longer advertised), so
      // nothing we issue or accept travels this path.
      //
      // Reviving it means implementing Data Integrity proof support: a custom
      // document loader carrying `jws-2020`, plus a signature suite that
      // consumes `JsonWebKey2020`. That is a separate, larger piece of work —
      // a feature, not a bug fix. Until it exists, a JSON VP is UNSUPPORTED and
      // must be refused explicitly rather than half-checked.
      //
      // This throw is unconditional and outside any try/catch by design. There
      // is no fall-through: `vpToken`, `presentedCredentials` and
      // `vpSignaturesVerified` are never assigned on this path, so no later
      // code can report on an unverified presentation. Two bugs of exactly that
      // shape have already been found in this route (a JWT VP nested under `vp`
      // that made the per-credential loop iterate nothing and return
      // `verified: true` with an empty error list; and `vp+sd-jwt` falling
      // through to a JWT reader that SUCCEEDED and returned a digest-only
      // husk). Both looked like success. This one cannot.
      logger.warn('Rejected presentation in unsupported JSON/ldp_vp format', {
        requestId,
        presentationId: presentation.id,
        submissionFormats: data.presentation_submission.descriptor_map.map((d) => d.format),
      });
      throw new AppError(
        ERROR_CODES.PRESENTATION_INVALID,
        'Unsupported presentation format: this verifier accepts only JWT-secured ' +
          'presentations (vp+jwt, vp+sd-jwt, jwt_vp_json). JSON-LD / Data Integrity ' +
          'presentations (ldp_vp) are not supported and are not advertised in the ' +
          'verifier metadata. The presentation was rejected without being verified.',
        400,
        {
          reason: 'unsupported_presentation_format',
          receivedFormat: 'json',
          supportedFormats: [
            PRESENTATION_FORMATS.VP_JWT,
            PRESENTATION_FORMATS.VP_SD_JWT,
            'jwt_vp_json',
          ],
        },
      );
    }
    
    // Verify nonce binding — MANDATORY: the VP must be bound to this exact presentation request.
    // H-04: Both sides must have a nonce. If either is missing, reject — never skip the binding check.
    const vpNonce = vpToken?.nonce as string | undefined;
    if (!presentation.nonce || !vpNonce) {
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        'Nonce binding is required. Both presentation request and VP must include a nonce.',
        400,
      );
    }
    if (vpNonce !== presentation.nonce) {
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        'VP nonce does not match the presentation request nonce. Possible replay attack.',
        400,
      );
    }
    
    disclosedFields = data.presentation_submission.descriptor_map
      .map(d => d.path)
      .filter(Boolean);
    
    const verificationErrors: string[] = [];

    // Both branches above set this on success; neither can be reached without
    // it. Belt and braces: an unverified presentation must never fall through
    // to the per-credential checks and be reported on as if it were genuine.
    if (!vpSignaturesVerified) {
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        'Presentation signatures were not verified. Presentation rejected.',
        400,
      );
    }

    // A presentation carrying no credentials proves nothing. This used to be
    // the SILENT default rather than an error: `vpToken.verifiableCredential`
    // was undefined for every JWT VP, so this list was always empty and every
    // check below was skipped for every presentation, which then passed.
    if (presentedCredentials.length === 0) {
      verificationErrors.push('Presentation contains no readable credentials');
    }

    for (const { credential: vc, envelopeJwt, isSdJwt } of presentedCredentials) {
      const vcId = vc.id || 'unknown';

      // ===================================================================
      // WHOSE CREDENTIAL IS THIS? A SIGNATURE PROVES ISSUANCE, NOT OWNERSHIP.
      // ===================================================================
      // OID4VP lets a holder answer "give me a PrescriptionCredential" with ANY
      // one they hold. Nothing above compares the credential's SUBJECT to the
      // person presenting it, so a genuine, unrevoked, issuer-signed
      // prescription belonging to SOMEONE ELSE — a family member's, handed over
      // earlier — was dispensed against the presenter. Every cryptographic check
      // passed, because the credential really is valid; it is simply not theirs.
      //
      // The subject is the issuer's own statement of whose credential this is
      // (`credentialSubject.id`). The holder is who signed the presentation. For
      // a credential that names a subject, those must be the same party. This is
      // the same binding Credo 0.6 never enforces (#196 hole 2 — the credential's
      // own `cnf` reaches no comparison anywhere), applied where it decides
      // whether an action may proceed.
      //
      // FAIL CLOSED, and NOT silently: a credential whose subject cannot be read
      // is refused rather than waved through, because "I could not check" and
      // "it is fine" are the two answers this codebase has already confused once
      // (#163/#184: an unresolvable status list read as "not revoked").
      const subjectId = credentialSubjectId(vc);
      if (subjectId !== null && holderDid) {
        if (subjectId !== holderDid) {
          verificationErrors.push(
            `Credential ${vcId} was issued to ${subjectId} but was presented by ${holderDid}. ` +
              'A credential may only be presented by its own subject.',
          );
        }
      } else if (subjectId === null) {
        verificationErrors.push(
          `Credential ${vcId} names no subject, so it cannot be attributed to the presenter.`,
        );
      }

      // Validity window, read across both data models — VC 2.0 uses
      // validUntil, VC 1.1 uses expirationDate. Reading only the latter let
      // every expired VC 2.0 credential through.
      const validUntil = credentialValidUntil(vc);
      if (validUntil && new Date(validUntil) < new Date()) {
        verificationErrors.push(`Credential ${vcId} has expired`);
      }

      if (!vc.type?.includes('VerifiableCredential')) {
        verificationErrors.push(`Credential ${vcId} missing VerifiableCredential type`);
      }

      // Cryptographic verification.
      //
      // Credo already verified each embedded credential as part of verifying
      // the presentation, for both stacks. This re-check is deliberate and
      // cheap: it is what catches a credential that arrived by a path where
      // that guarantee does not hold, and it fails CLOSED. The previous version
      // swallowed every failure with a `catch {}` that logged a warning and
      // continued — a credential with a bad signature verified successfully as
      // long as the agent threw while checking it.
      if (!envelopeJwt) {
        verificationErrors.push(
          `Credential ${vcId} carries no verifiable proof — refusing to accept it`,
        );
      } else {
        try {
          const agent = getAgent();
          const isV2Credential = Array.isArray(vc['@context'])
            && vc['@context'].includes(VC_CONTEXTS.W3C_CREDENTIALS_V2);

          // WITHIN VC 2.0 THERE ARE TWO SECURING MECHANISMS, and the JWT reader
          // does not fail on an SD-JWT — it returns a husk. Route on the format
          // established at verification time, not on the artifact's shape.
          const isSdJwtCredential = isSdJwt;

          // Same class-instance requirement as the presentation above. Kept as
          // two separately-typed locals rather than one union: Credo's
          // `W3cV2VerifyCredentialOptions` is a union of two option objects and
          // a union-typed `credential` satisfies neither member.
          const v2SdJwtCredential =
            isV2Credential && isSdJwtCredential ? toV2SdJwtVerifiableCredential(envelopeJwt) : null;
          const v2JwtCredential =
            isV2Credential && !isSdJwtCredential ? toV2VerifiableCredential(envelopeJwt) : null;
          const v2Credential = v2SdJwtCredential ?? v2JwtCredential;

          if (isV2Credential && !v2Credential) {
            verificationErrors.push(
              `Credential ${vcId} is not a readable VC 2.0 ${isSdJwtCredential ? 'SD-JWT' : 'JWT'}`,
            );
            continue;
          }

          const vcResult = v2SdJwtCredential
            ? await agent.w3cV2Credentials.verifyCredential({ credential: v2SdJwtCredential })
            : v2JwtCredential
            ? await agent.w3cV2Credentials.verifyCredential({ credential: v2JwtCredential })
            : await agent.w3cCredentials.verifyCredential({
                credential: envelopeJwt,
                // See the note on the VP call above: `true` is an
                // unconditional refusal for status-bearing VC 1.1 JWT VCs.
                verifyCredentialStatus: false,
              });

          if (!vcResult.isValid) {
            verificationErrors.push(`Credential ${vcId} signature invalid`);
          }
        } catch (verifyError) {
          // Fail closed. "We could not check" is not "it is fine".
          logger.error('Credential crypto verification errored — rejecting credential', {
            vcId,
            error: verifyError instanceof Error ? verifyError.message : String(verifyError),
          });
          verificationErrors.push(
            `Credential ${vcId} signature could not be verified`,
          );
        }
      }

      // Revocation. OID4VP is the surface an actual third-party verifier
      // speaks, so it is the one that most needs this: a presentation of a
      // revoked credential was previously accepted here without comment,
      // because nothing on this path looked at revocation at all.
      //
      // The check reads the issuer's status list off the ledger rather than
      // this server's database, which is what makes it meaningful for a
      // verifier who is not us. Credentials with no `credentialStatus`
      // (issued before status lists, or by an external issuer) are skipped —
      // there is nothing to dereference and inventing a failure for them
      // would reject every legacy credential.
      const status = vc.credentialStatus as
        | { statusListIndex?: string; statusListCredential?: string }
        | undefined;

      if (status) {
        const statusResult = await checkStatusOnLedger(status);
        if (statusResult.checked && statusResult.revoked) {
          verificationErrors.push(`Credential ${vcId} has been revoked`);
        } else if (!statusResult.checked) {
          // "Could not check" is not "not revoked". Saying so would make
          // revocation trivially defeatable by making the list unreachable.
          verificationErrors.push(
            `Credential ${vcId} revocation status could not be checked: ${statusResult.error ?? 'unknown error'}`,
          );
        }
      }
    }
    
    const isValid = verificationErrors.length === 0;
    
    await db.presentation.update({
      where: { id: presentation.id },
      data: {
        holderDid: holderDid || undefined,
        status: isValid ? PresentationStatus.VERIFIED : PresentationStatus.REJECTED,
        verificationResult: JSON.parse(JSON.stringify({
          valid: isValid,
          vpToken,
          disclosedFields,
          errors: verificationErrors,
        })) as Prisma.InputJsonValue,
        selectedDisclosure: disclosedFields,
        // CAPTURED FROM THE VERIFIED VP, not looked up. The credential relation
        // is empty for anything the holder received directly from an issuer —
        // those live on the device and have no row here — so a verifier asking
        // for the claims was handed nothing while the holder had disclosed them.
        presentedClaims: JSON.parse(JSON.stringify(
          presentedCredentials.map(({ credential: vc }) => ({
            type: (vc as { type?: unknown }).type ?? [],
            claims: disclosedClaimsFrom(
              ((vc as { credentialSubject?: Record<string, unknown> }).credentialSubject ?? {}),
              disclosedFields,
            ),
          })),
        )) as Prisma.InputJsonValue,
        presentedAt: new Date(),
        verifiedAt: isValid ? new Date() : undefined,
      },
    });
    
    for (const { credential: vc } of presentedCredentials) {
      const vcId = vc.id;
      if (vcId) {
        const existingCredential = await db.credential.findFirst({
          where: { 
            OR: [
              { id: vcId },
              { credentialHash: vcId },
            ],
          },
        });
        
        if (existingCredential) {
          await db.presentationCredential.create({
            data: {
              presentationId: presentation.id,
              credentialId: existingCredential.id,
              disclosedAttributes: disclosedFields,
            },
          });
        }
      }
    }
    
    
    // -----------------------------------------------------------------
    // CONSENT — recorded from the holder's own signature, or not at all.
    // -----------------------------------------------------------------
    //
    // A consent row this server writes on its own authority says only that the
    // operator claims the patient agreed. That is the thing the design exists to
    // remove, and it is why #279 specified a receipt the HOLDER signs. So the
    // row below is created ONLY from a receipt that verifies against a key
    // published in the holder's own DID document.
    //
    // This also re-establishes its own precondition rather than inheriting one.
    // The earlier attempt called an authenticated `POST /api/consent/grant`
    // from the wallet AFTER the share, which assumed a live session, assumed the
    // verifier was a registered user, and failed silently on both. Here the
    // signature is the authentication — the same argument that makes this whole
    // route unauthenticated — so a holder whose session expired mid-exchange
    // still gets a consent record (#315).
    let consentRecorded = false;
    if (isValid && holderDid && data.consent_receipt) {
      try {
        const receiptKid = decodeJwtHeader(data.consent_receipt)?.kid;
        const receiptKey =
          typeof receiptKid === 'string' && receiptKid.split('#')[0] === holderDid
            ? await holderAuthenticationKey(holderDid, receiptKid)
            : null;

        if (!receiptKey) {
          logger.warn('Consent receipt refused: no authentication key for the signing method', {
            requestId,
            holderDid,
            receiptKid,
          });
        } else {
          const receipt = verifyConsentReceipt(data.consent_receipt, receiptKey, {
            holderDid,
            verifierDid: presentation.verifierDid,
            requestId: presentation.requestId,
            nonce: presentation.nonce,
            vpToken: data.vp_token as string,
          });

          if (!receipt.verified || !receipt.payload) {
            // LOUDLY, and with the named checks. "Consent could not be recorded"
            // is a materially different event from "the holder declined", and a
            // silent failure here is what left this table empty for a month.
            logger.error('Consent receipt REFUSED — no consent record written', {
              requestId,
              holderDid,
              checks: receipt.checks,
              errors: receipt.errors,
            });
          } else {
            const purposeEntry = receipt.payload.services[0]?.purposes[0];
            const category = purposeEntry?.purposeCategory ?? 'treatment';
            const holderUser = await db.user.findFirst({
              where: { did: holderDid },
              select: { id: true },
            });

            await db.consent.create({
              data: {
                holderDid,
                holderUserId: holderUser?.id ?? null,
                verifierDid: presentation.verifierDid,
                verifierName:
                  receipt.payload.piiControllers[0]?.piiController ?? presentation.verifierDid,
                credentialTypes: receipt.payload.presentation.credentialTypes,
                credentialIds: presentedCredentials
                  .map(({ credential }) => credential.id)
                  .filter((id): id is string => Boolean(id)),
                attributes: receipt.payload.presentation.disclosedClaims,
                purpose: (purposeToPrismaConsent[category] ?? PrismaConsentPurpose.TREATMENT),
                // The verifier's own words, kept verbatim beside the lossy enum.
                purposeText: purposeEntry?.purpose ?? null,
                purposeDetail: purposeEntry?.purpose ?? null,
                grantedAt: new Date(receipt.payload.iat * 1000),
                // NO EXPIRY, because there is nothing to expire.
                //
                // A presentation is a COMPLETED disclosure: the verifier already
                // holds the claims and no further access flows from this row.
                // Writing `now + 24h` here made the wallet mark a record red and
                // "Expiring" seconds after it was created, and an alarm that
                // always fires distinguishes nothing (#305/#308).
                expiresAt: null,
                standingAccess: false,
                isActive: true,
                // THE DISCLOSURE IS THE ACCESS. Leaving these at 0/null told the
                // holder their data had never been accessed, on a record that
                // exists precisely because it was.
                accessCount: 1,
                lastAccessedAt: new Date(receipt.payload.iat * 1000),
                presentationId: presentation.id,
                receiptJws: data.consent_receipt,
                receiptId: receipt.payload.jti,
                receiptVerifiedAt: new Date(),
              },
            });
            consentRecorded = true;

            logger.info('Consent recorded from a holder-signed receipt', {
              requestId,
              holderDid,
              verifierDid: presentation.verifierDid,
              receiptId: receipt.payload.jti,
              disclosedClaims: receipt.payload.presentation.disclosedClaims,
              purpose: purposeEntry?.purpose,
            });
          }
        }
      } catch (receiptError) {
        // Best-effort by necessity: the credential has already been disclosed,
        // so throwing would report a failure for something that did happen and
        // would still not un-send it. But it is logged as an ERROR, because a
        // disclosure with no record is precisely what the holder later cannot
        // audit.
        const duplicate =
          receiptError instanceof Error && receiptError.message.includes('Consent_receiptId_key');
        logger[duplicate ? 'warn' : 'error'](
          duplicate
            ? 'Consent receipt replayed — a record for this receipt already exists'
            : 'Consent record could not be written despite a verified presentation',
          {
            requestId,
            holderDid,
            error: receiptError instanceof Error ? receiptError.message : String(receiptError),
          },
        );
      }
    }

    if (isValid && holderDid && !consentRecorded) {
      // No receipt, or one that did not verify. Touch an existing standing
      // consent if there is one, but never CREATE a consent the holder did not
      // sign for.
      const existingConsent = await db.consent.findFirst({
        where: { holderDid, verifierDid: presentation.verifierDid, isActive: true },
      });
      if (existingConsent) {
        await db.consent.update({
          where: { id: existingConsent.id },
          data: { lastAccessedAt: new Date(), accessCount: { increment: 1 } },
        });
      }
    }
    
    await db.auditLog.create({
      data: {
        eventType: isValid ? AuditEventType.PRESENTATION_VERIFIED : AuditEventType.PRESENTATION_REJECTED,
        action: isValid
          ? `Shared with ${presentation.verifierDid.slice(0, 32)}…`
          : 'Presentation rejected',
        actorDid: holderDid,
        // Best-effort, and deliberately not required. This route is
        // UNAUTHENTICATED by design — the signature is the authentication — so
        // there is no session to read a user id from. The holder's own audit
        // query must therefore match on the DID, which is the identity here;
        // this is a convenience for queries that still key on user rows.
        actorUserId: holderDid
          ? (await db.user.findFirst({ where: { did: holderDid }, select: { id: true } }))?.id ?? null
          : null,
        targetDid: presentation.verifierDid,
        resourceType: 'presentation',
        resourceId: presentation.id,
        details: {
          credentialCount: presentedCredentials.length,
          disclosedFields,
          errors: verificationErrors,
        },
      },
    });
    
    logger.info('Presentation response processed', {
      presentationId: presentation.id,
      isValid,
      holderDid,
      errorCount: verificationErrors.length,
    });
    
    if (req.body.redirect_uri) {
      // Validate redirect_uri to prevent open redirect attacks
      try {
        const redirectUrl = new URL(req.body.redirect_uri);
        // Only allow HTTPS redirects (or localhost for development)
        const isLocalhost = redirectUrl.hostname === 'localhost' || redirectUrl.hostname === '127.0.0.1';
        if (redirectUrl.protocol !== 'https:' && !isLocalhost) {
          throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'redirect_uri must use HTTPS', 400);
        }
        redirectUrl.searchParams.set('state', data.state || '');
        redirectUrl.searchParams.set('verified', String(isValid));
        if (!isValid) {
          redirectUrl.searchParams.set('error', 'verification_failed');
          redirectUrl.searchParams.set('error_description', verificationErrors.join('; '));
        }
        res.redirect(redirectUrl.toString());
      } catch (urlError) {
        if (isSsiError(urlError)) throw urlError;
        throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Invalid redirect_uri', 400);
      }
    } else {
      res.json({
        success: true,
        data: {
          verified: isValid,
          presentationId: presentation.id,
          holderDid,
          disclosedFields,
          errors: verificationErrors.length > 0 ? verificationErrors : undefined,
        },
      });
    }
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// Session Status (DB-backed polling)
// ---------------------------------------------------------------------------


/**
 * Narrow a credential subject to the claims the holder actually disclosed.
 *
 * `disclosedAttributes` are JSON paths from the OID4VP descriptor map, e.g.
 * `$.credentialSubject.medication.name`. A path of `$` (or one that does not
 * begin at the subject) means the whole credential was presented.
 *
 * WHY THIS IS NOT JUST `subject`. Returning the full subject would hand a
 * verifier claims the holder never chose to share — and the disclosure sheet's
 * whole design is that minimal disclosure costs nothing and every extra claim
 * costs a deliberate tap. That intent has to be honoured where the data leaves
 * the backend, not only where it is displayed.
 */
function disclosedClaimsFrom(
  subject: Record<string, unknown>,
  paths: readonly string[],
): Record<string, unknown> {
  const whole = (p: string) => p === '$' || p === '$.credentialSubject' || p === '$';
  if (paths.length === 0 || paths.some(whole)) return subject;

  const out: Record<string, unknown> = {};
  for (const raw of paths) {
    const path = raw.replace(/^\$\.credentialSubject\.?/, '').replace(/^\$\.?/, '');
    if (path.length === 0) return subject;

    const parts = path.split('.').filter(Boolean);
    let src: unknown = subject;
    let dst: Record<string, unknown> = out;
    for (let i = 0; i < parts.length; i += 1) {
      if (src === null || typeof src !== 'object') break;
      const key = parts[i];
      const value = (src as Record<string, unknown>)[key];
      if (value === undefined) break;
      if (i === parts.length - 1) {
        dst[key] = value;
      } else {
        if (typeof value !== 'object' || value === null) break;
        if (typeof dst[key] !== 'object' || dst[key] === null) dst[key] = {};
        dst = dst[key] as Record<string, unknown>;
        src = value;
      }
    }
  }
  return out;
}

oid4vpRouter.get('/sessions/:id', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const requestId = req.params.id as string;
    
    const presentation = await db.presentation.findFirst({
      where: {
        OR: [
          { requestId },
          { nonce: requestId },
          { id: requestId },
        ],
      },
      include: {
        credentials: {
          include: {
            credential: { select: { type: true, credentialData: true } },
          },
        },
      },
    });
    
    if (!presentation) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Session not found', 404);
    }
    
    // Auto-expire if past deadline
    let status = presentation.status;
    if (status === PresentationStatus.REQUESTED && new Date() > presentation.expiresAt) {
      await presentationRepo.updatePresentationStatus(presentation.id, PresentationStatus.EXPIRED);
      status = PresentationStatus.EXPIRED;
    }
    
    res.json({
      success: true,
      data: {
        requestId: presentation.requestId,
        status,
        presentationId: presentation.id,
        holderDid: presentation.holderDid,
        verifiedAt: presentation.verifiedAt?.toISOString(),
        credentialCount: presentation.credentials.length,
        // =================================================================
        // THE CLAIMS THE VERIFIER ASKED FOR. THIS WAS NEVER SENT.
        // =================================================================
        // The response carried a COUNT and no credentials, so a verifier
        // reading `session.credentials?.[0]?.claims` — which is what the
        // pharmacy does — always received an empty object. Measured 24 Sep
        // 2026: a prescription verified, the pharmacy was handed `{}`, and it
        // refused with "carried no prescription to dispense" while the holder
        // had disclosed one. The counter could never have dispensed anything.
        //
        // NARROWED TO WHAT WAS DISCLOSED. `disclosedAttributes` holds the
        // descriptor-map paths, so returning the whole credentialSubject would
        // hand the verifier claims the holder did not share — the disclosure
        // sheet's default is minimal, and this is where that has to be honoured
        // rather than merely displayed. A path of `$` means the whole subject
        // was presented and everything in it was disclosed.
        credentials: (presentation.presentedClaims as
          | { type: unknown; claims: Record<string, unknown> }[]
          | null) ?? presentation.credentials.map((pc) => {
          const data = (pc.credential.credentialData ?? {}) as Record<string, unknown>;
          const subject = (data.credentialSubject ?? {}) as Record<string, unknown>;
          return {
            type: pc.credential.type,
            claims: disclosedClaimsFrom(subject, pc.disclosedAttributes),
          };
        }),
        expiresAt: presentation.expiresAt.toISOString(),
      },
    });
  } catch (error) {
    next(error);
  }
});

export default oid4vpRouter;
