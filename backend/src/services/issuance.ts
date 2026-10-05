/**
 * L1 identity/licence issuance — the wrapped-key envelope this server never
 * opens, and the credentialSubject an approval issues.
 *
 * See `routes/issuance.ts` (holder endpoints) and `routes/authority.ts` (L1
 * dashboard endpoints, role-gated by `middleware/requireAuthorityMember.ts`)
 * for the HTTP boundary. This module is the logic those two files share.
 */

import { z } from 'zod';

import {
  ERROR_CODES,
  DOCUMENT_TYPES,
  documentTypeById,
  type DocumentTypeDefinition,
  HEALTH_CARD_CREDENTIAL_TYPE,
  PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  trustRootForDid,
  narrowsScope,
  uncoveredScope,
  isPracticeScope,
  type PracticeScope,
  assertWellFormedLockerCapabilityClaims,
  type LockerCapabilityToken,
} from '@ssi-healthcare/shared';
import { AppError } from '../middleware/errorHandler.js';

export { DOCUMENT_TYPES, documentTypeById };

// ---------------------------------------------------------------------------
// The wrapped content key — validated shape, never opened
// ---------------------------------------------------------------------------

/**
 * The single-use wrapped content key for a submission
 * (IDENTITY-AND-ISSUANCE-SPEC.md §3.4: "one submission, one key").
 *
 * VALIDATED FOR SHAPE ONLY, exactly the boundary `keystoreVault.ts` draws
 * around the passphrase envelope: this server checks that the JSON is
 * well-formed and never derives a key from it or attempts to open it.
 *
 * The wrapping scheme is not fixed by this round — no wallet code exists yet
 * that wraps a key to an authority's DID-document public key (mobile,
 * deferred). `ciphertext`/`nonce`/`ephemeralPublicKey` are kept as generic
 * base64url-ish strings so this server does not need to change when that
 * scheme is chosen; `version` lets a future scheme change without stranding
 * rows already written, the same reasoning as `passphraseEnvelope.ts`'s KDF
 * parameters.
 */
export const wrappedContentKeyShape = z.object({
  version: z.literal(1),
  /** Verification method id the wallet claims it wrapped to. Checked
   * structurally against the document type's authority DID — see
   * `assertWrappedKeyTargetsAuthority`. */
  wrappedToVerificationMethodId: z.string().min(1),
  ephemeralPublicKey: z.string().min(1).optional(),
  nonce: z.string().min(1).optional(),
  /** HKDF salt for the wrap's derived AES key (round 5's ECIES scheme,
   * `@ssi-healthcare/shared`'s `crypto/contentKeyWrap.ts`). Optional at this
   * boundary for the same reason the other framing fields are: this server
   * validates shape only and never opens the envelope, so it does not get to
   * decide which fields a future scheme needs. */
  salt: z.string().min(1).optional(),
  ciphertext: z.string().min(1),
});

export type WrappedContentKey = z.infer<typeof wrappedContentKeyShape>;

/**
 * Structural check that a wrapped key's target verification method belongs
 * to the document type's issuing authority DID.
 *
 * NOT a substitute for resolving the authority's DID document and checking
 * the verification method is actually present there — this server does not
 * do that live resolution, because the pinned L1 authority DIDs
 * (`PROFESSIONAL_TRUST_ROOTS`, `MINISTRY_OF_HEALTH`) are testnet placeholders
 * that do not resolve to anything yet (see their module headers in
 * `@ssi-healthcare/shared`). Recorded here as a known limitation rather than
 * silently treated as full verification: this check only rules out a key
 * wrapped to a DID other than the one the submission is filed against.
 */
export function assertWrappedKeyTargetsAuthority(
  documentType: DocumentTypeDefinition,
  wrappedContentKey: WrappedContentKey,
): void {
  const expectedPrefix = `${documentType.issuingAuthorityDid}#`;
  if (!wrappedContentKey.wrappedToVerificationMethodId.startsWith(expectedPrefix)) {
    throw new AppError(
      ERROR_CODES.VALIDATION_FAILED,
      `The content key's wrappedToVerificationMethodId must belong to ${documentType.issuingAuthorityDid} ` +
        `(expected an id starting '${expectedPrefix}'). This is a structural check, not live DID resolution — ` +
        'see assertWrappedKeyTargetsAuthority in services/issuance.ts.',
      400,
    );
  }
}

// ---------------------------------------------------------------------------
// The locker capability — validated shape, never verified here
// ---------------------------------------------------------------------------

/**
 * Structural shape of a {@link LockerCapabilityToken} as it arrives over
 * HTTP. `claims` is re-checked with {@link assertWellFormedLockerCapabilityClaims}
 * below rather than duplicating that logic in zod, so the two cannot drift.
 */
export const lockerCapabilityTokenShape = z.object({
  claims: z.object({
    iss: z.string().min(1),
    aud: z.string().min(1),
    obj: z.array(z.string().min(1)).min(1),
    sub: z.string().min(1),
    jti: z.string().min(1),
    nbf: z.number(),
    exp: z.number(),
  }),
  signature: z.string().min(1),
  verificationMethodId: z.string().min(1),
});

/**
 * Checks a submitted locker capability (OFFICER-DOCUMENT-ACCESS.md §6a) is
 * internally consistent with the submission it travels alongside.
 *
 * DOES NOT VERIFY THE SIGNATURE. This server is not the capability's `aud` —
 * the locker is — so a signature check here would be checking the wrong
 * audience and would give a false sense that the capability was validated.
 * That check happens where it belongs: the locker, when the officer's
 * console actually presents it (`packages/locker/src/capability.ts`). What
 * belongs here is the same class of check `assertWrappedKeyTargetsAuthority`
 * already does for the wrapped key: does this artifact claim to be FOR this
 * submission, so a capability minted for one request cannot be attached to
 * another by mistake or by a malicious client.
 */
export function assertCapabilityMatchesSubmission(args: {
  readonly documentType: DocumentTypeDefinition;
  readonly holderDid: string;
  readonly requestId: string;
  readonly documents: readonly SubmittedDocument[];
  readonly capability: LockerCapabilityToken;
}): void {
  assertWellFormedLockerCapabilityClaims(args.capability.claims);
  const { claims } = args.capability;

  if (claims.iss !== args.holderDid) {
    throw new AppError(
      ERROR_CODES.ISSUANCE_CAPABILITY_INVALID,
      `The capability's iss ('${claims.iss}') is not the caller's own DID ('${args.holderDid}').`,
      400,
    );
  }
  if (claims.aud !== args.documentType.issuingAuthorityDid) {
    throw new AppError(
      ERROR_CODES.ISSUANCE_CAPABILITY_INVALID,
      `The capability's aud ('${claims.aud}') does not name the issuing authority for ` +
        `'${args.documentType.id}' ('${args.documentType.issuingAuthorityDid}').`,
      400,
    );
  }
  if (claims.sub !== args.requestId) {
    throw new AppError(
      ERROR_CODES.ISSUANCE_CAPABILITY_INVALID,
      `The capability's sub ('${claims.sub}') does not name this submission ('${args.requestId}').`,
      400,
    );
  }
  const covered = new Set(claims.obj);
  const uncoveredIds = args.documents
    .map((doc) => doc.lockerObjectId)
    .filter((id) => !covered.has(id));
  if (uncoveredIds.length > 0) {
    throw new AppError(
      ERROR_CODES.ISSUANCE_CAPABILITY_INVALID,
      `The capability does not cover every attached document's locker object id: ${uncoveredIds.join(', ')}.`,
      400,
    );
  }
}

// ---------------------------------------------------------------------------
// Attached documents — soft validation against the registry
// ---------------------------------------------------------------------------

export interface SubmittedDocument {
  readonly lockerObjectId: string;
  readonly contentHash: string;
  readonly mediaType: string;
}

/**
 * Checks a submission has at least as many documents as the document type
 * requires, and that every attached media type is one some slot accepts.
 *
 * DOES NOT check which required slot each attachment fills. The request body
 * (IDENTITY-VERIFICATION-API.md §4) carries only locker object id, content
 * hash and media type per document — no field says "this is the NID scan" —
 * so a submission with the right count and media types but the wrong actual
 * content is not caught here. That is left to the reviewing officer, who
 * looks at the documents; this check exists to fail closed on a submission
 * that is structurally incomplete before it ever reaches a queue.
 */
export function assertDocumentsSatisfyRequirements(
  documentType: DocumentTypeDefinition,
  documents: readonly SubmittedDocument[],
): void {
  if (documents.length < documentType.requiredDocuments.length) {
    throw new AppError(
      ERROR_CODES.VALIDATION_FAILED,
      `${documentType.label} requires at least ${documentType.requiredDocuments.length} document(s); ` +
        `${documents.length} attached.`,
      400,
    );
  }

  const accepted = new Set(documentType.requiredDocuments.flatMap((slot) => slot.acceptedMediaTypes));
  const rejected = documents.filter((doc) => !accepted.has(doc.mediaType));
  if (rejected.length > 0) {
    throw new AppError(
      ERROR_CODES.VALIDATION_FAILED,
      `Unsupported media type(s): ${rejected.map((d) => d.mediaType).join(', ')}. ` +
        `Accepted for ${documentType.label}: ${[...accepted].join(', ')}.`,
      400,
    );
  }
}

// ---------------------------------------------------------------------------
// Approval claims — what an approve() actually issues
// ---------------------------------------------------------------------------

const isoDateTime = z
  .string()
  .refine((value) => !Number.isNaN(Date.parse(value)), 'must be an ISO 8601 date-time');

const licenceApprovalClaimsSchema = z.object({
  licenceNumber: z.string().min(1),
  register: z.string().min(1),
  practiceScope: z.array(z.string()).min(1),
  licenceValidFrom: isoDateTime,
  licenceValidUntil: isoDateTime,
});

/**
 * Builds the `credentialSubject` an approval issues, and is where the two
 * credential types this round supports diverge.
 *
 * Fails closed (400/500 `AppError`) rather than issuing a credential with
 * missing or out-of-mandate claims — see the licence branch, which checks
 * `practiceScope` narrows the accrediting council's own `maxScope` using the
 * same `narrowsScope` predicate a verifier will later check the credential
 * against (`wasAuthorisedToAccredit`'s caller). A licence this function
 * built and a verifier's later re-check disagreeing about scope would be a
 * defect worth finding here, not after issuance.
 */
export function buildApprovalCredentialClaims(
  documentType: DocumentTypeDefinition,
  holderDid: string,
  rawClaims: unknown,
): Record<string, unknown> {
  if (documentType.credentialType === HEALTH_CARD_CREDENTIAL_TYPE) {
    // The officer attests a comparison already performed against a record the
    // ministry holds (IDENTITY-AND-ISSUANCE-SPEC.md §3.5). No claim here
    // duplicates the NID itself — see HealthCardCredentialSubject's header.
    return {
      id: holderDid,
      verifiedAt: new Date().toISOString(),
      verificationMethod: 'nid-record-comparison',
    };
  }

  if (documentType.credentialType === PROFESSIONAL_LICENCE_CREDENTIAL_TYPE) {
    // THE OFFICER VERIFIES THE DOCUMENT, NOT A FORM.
    //
    // These claims used to be REQUIRED, which meant approval was blocked until
    // someone re-typed everything already printed on the certificate the officer
    // had just read on screen. Deriving them automatically needs OCR — a good
    // idea, and deliberately not this version (owner, 9 Sep). Until then the
    // human eye is the validation, and demanding a structured payload as well
    // only guaranteed the approval could not happen.
    //
    // So every field is optional and the authority supplies the rest. What is
    // NOT invented is the registration number: a plausible-looking number
    // nobody read off the certificate would be a fabricated claim in a signed
    // credential, so an unsupplied one is recorded as UNTRANSCRIBED and the
    // consequence is left in place — the HMS appointment check compares this to
    // the number an admin recorded, and refuses when it cannot match. That is
    // the correct outcome for a licence nobody transcribed.
    const parsed = licenceApprovalClaimsSchema.partial().safeParse(rawClaims ?? {});
    if (!parsed.success) {
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        `Claims supplied for this ${documentType.label} are not usable.`,
        400,
        { issues: parsed.error.issues },
      );
    }

    const authority = trustRootForDid(documentType.issuingAuthorityDid);
    if (!authority) {
      // The registry named an authority DID that is not a pinned trust root.
      // A misconfiguration, not a caller error — fails closed rather than
      // issuing a licence with no recognised profession.
      throw new AppError(
        ERROR_CODES.INTERNAL_ERROR,
        `Document type '${documentType.id}' names an issuing authority DID that is not a pinned trust root.`,
        500,
      );
    }

    // Absent scope means "what this council may grant", which is the honest
    // reading: the officer approved a licence from this authority and named no
    // narrower limit. Supplying one still narrows, and still cannot widen.
    const requestedScope = parsed.data.practiceScope ?? [...authority.maxScope];
    if (!requestedScope.every(isPracticeScope)) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'practiceScope contains an unrecognised value.', 400);
    }
    const scope = requestedScope as PracticeScope[];

    if (!narrowsScope(authority.maxScope, scope)) {
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        `Requested practiceScope exceeds ${authority.shortName}'s mandate: ` +
          `${uncoveredScope(authority.maxScope, scope).join(', ')}.`,
        400,
      );
    }

    // A licence with no stated window is dated from today for five years — a
    // real window rather than an open-ended one, because an open-ended licence
    // is not a thing (see ProfessionalLicenceSubject). Both are still checked
    // when the officer supplies them.
    const validFrom = parsed.data.licenceValidFrom ?? new Date().toISOString();
    const validUntil =
      parsed.data.licenceValidUntil ??
      new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000).toISOString();
    if (Date.parse(validFrom) >= Date.parse(validUntil)) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'licenceValidFrom must be before licenceValidUntil.', 400);
    }

    // Each of the three pinned councils accredits exactly one profession
    // (accreditation/index.ts's PROFESSIONAL_TRUST_ROOTS) — there is no
    // per-request choice to make here.
    const profession = authority.professions[0];

    return {
      id: holderDid,
      profession,
      // Never invented. See the note above the schema parse.
      licenceNumber: parsed.data.licenceNumber ?? 'UNTRANSCRIBED',
      register: parsed.data.register ?? authority.name,
      practiceScope: scope,
      licenceValidFrom: validFrom,
      licenceValidUntil: validUntil,
    };
  }

  throw new AppError(
    ERROR_CODES.INTERNAL_ERROR,
    `No claim builder is registered for credential type '${documentType.credentialType}'.`,
    500,
  );
}
