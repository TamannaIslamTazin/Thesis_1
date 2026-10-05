/**
 * SSI Healthcare Backend - Credential Service
 *
 * Business logic for issuing and verifying W3C Verifiable Credentials.
 * Uses the Credo-TS agent for cryptographic signing and verification.
 * Implements OID4VCI Pre-Authorized Code Flow for frictionless issuance.
 */

import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import {
  W3cV2Credential,
  W3cV2CredentialSubject,
} from '@credo-ts/core';
import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { getAgent } from '../agent/index.js';
import {
  // `jwtVcToW3cJson` is not imported here right now: its only use in this file
  // was `storeExternalCredential`, which is commented out below pending the
  // third-party import work. Restore this import when that is revived.
  toV2VerifiableCredential,
  resolveHolderBinding,
  assertHolderBound,
  JWT_PROOF_TYPE,
} from './jwtVc.js';
import {
  allocateStatusIndex,
  buildStatusEntry,
  ensureStatusListPublished,
  publishStatusList,
  checkStatusOnLedger,
  toCredoV2CredentialStatus,
} from './statusListService.js';
import {
  ERROR_CODES,
  VC_CONTEXTS,
  CREDENTIAL_TYPES,
  CREDENTIAL_FORMATS,
  SYSTEM_DEFAULTS,
  credentialValidFrom,
  credentialValidUntil,
  type VerifiableCredential,
  type CredentialOffer,
  type HealthcareCredentialCategory,
  type IssuableCredentialFormat,
  type CredentialFormat,
  isSsiError,
} from '@ssi-healthcare/shared';
import {
  toV2SdJwtVerifiableCredential,
  credentialEnvelopeFormat,
  assertDisclosuresResolve,
} from './sdJwtVc.js';
import { secureV2Credential } from './securing.js';

// Prisma imports
import { db } from '../db/index.js';
import {
  AuditEventType as PrismaAuditEventType,
} from '../../prisma/generated/client/index.js';
import type {
  CredentialCategory,
  OfferStatus,
  CredentialStatus,
  Prisma,
} from '../../prisma/generated/client/index.js';

// Category mapping (shared enum -> Prisma enum)
const categoryMap: Record<string, CredentialCategory> = {
  blood_work: 'BLOOD_WORK',
  prescriptions: 'PRESCRIPTIONS',
  vaccinations: 'VACCINATIONS',
  imaging: 'IMAGING',
  lab_results: 'LAB_RESULTS',
  insurance: 'INSURANCE',
  general: 'GENERAL',
  mental_health: 'GENERAL',
  immunization: 'VACCINATIONS',
  emergency: 'GENERAL',
  // The Prisma PROFESSIONAL folder existed with nothing able to reach it; a
  // licence filed under GENERAL is a licence nobody can find.
  professional: 'PROFESSIONAL',
  // Same failure, worse consequence: without this line the Prisma IDENTITY
  // folder was unreachable and every ministry health card was stored as
  // GENERAL, so the holder's own identity credential appeared under "Other".
  identity: 'IDENTITY',
};

/** Database is always available (required by config) */

export interface CredentialData {
  issuerDid: string;
  subjectDid: string;
  credentialType: string;
  category: HealthcareCredentialCategory;
  claims: Record<string, unknown>;
  name?: string;
  description?: string;
  /**
   * Which securing mechanism to issue under. Defaults to `vc+jwt`.
   *
   * ADDITIVE, NOT A CUTOVER. `vc+sd-jwt` is the same VC 2.0 data model with the
   * same holder binding and the same revocation entry, secured so that claims
   * can be withheld at presentation time. Choosing it costs size and forces the
   * holder to pick a disclosure frame before presenting, so it is opt-in rather
   * than the default, and existing `vc+jwt` credentials are unaffected.
   */
  format?: IssuableCredentialFormat;
}

export interface IssuedCredential {
  credential: VerifiableCredential;
  offer?: CredentialOffer;
}

/**
 * Create a credential offer with a pre-authorized code.
 */
export async function createCredentialOffer(data: CredentialData): Promise<CredentialOffer> {
  const preAuthorizedCode = uuidv4();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  await db.credentialOffer.create({
    data: {
      issuerDid: data.issuerDid,
      holderDid: data.subjectDid,
      credentialType: data.credentialType,
      category: categoryMap[data.category] || 'GENERAL',
      preAuthorizedCode,
      offerData: data.claims as Prisma.InputJsonValue,
      expiresAt,
    },
  });

  logger.info('Credential offer created', {
    issuerDid: data.issuerDid,
    subjectDid: data.subjectDid,
    type: data.credentialType,
  });

  return {
    credentialIssuer: data.issuerDid,
    credentials: [data.credentialType],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': preAuthorizedCode,
        user_pin_required: false,
      },
    },
  };
}

/**
 * Issue a Verifiable Credential by exchanging a pre-authorized code.
 */
export async function issueCredentialWithCode(
  preAuthorizedCode: string,
): Promise<IssuedCredential> {
  const offer = await db.credentialOffer.findUnique({
    where: { preAuthorizedCode },
  });

  if (!offer) {
    throw new AppError(ERROR_CODES.CREDENTIAL_NOT_FOUND, 'Invalid pre-authorized code', 400);
  }

  if (offer.expiresAt < new Date()) {
    await db.credentialOffer.update({
      where: { id: offer.id },
      data: { status: 'EXPIRED' as OfferStatus },
    });
    throw new AppError(ERROR_CODES.CREDENTIAL_EXPIRED, 'Pre-authorized code has expired', 400);
  }

  const credentialData: CredentialData = {
    issuerDid: offer.issuerDid,
    subjectDid: offer.holderDid || '',
    credentialType: offer.credentialType,
    category: Object.entries(categoryMap).find(
      ([, v]) => v === offer.category
    )?.[0] as HealthcareCredentialCategory || 'general',
    claims: offer.offerData as Record<string, unknown>,
  };

  // ISSUE FIRST, THEN MARK ACCEPTED. The order matters and was the wrong way
  // round, which BURNED an offer on 9 Sep 2026: a status-list publish failed
  // 592 ms after the offer had already been stamped ACCEPTED, so the holder
  // was left with an offer that no longer existed to claim, no credential, and
  // a database row asserting they had received one. The failure was inside a
  // window this function itself opened.
  //
  // "Persist nothing on a partial failure" (#302). A throw from issueCredential
  // now leaves the offer exactly as it was — still PENDING, still claimable,
  // and the holder simply taps again once the cause is fixed. The reverse of
  // this trade is the unrecoverable one: nothing can re-open a spent offer,
  // because the pre-authorized code is single-use by design.
  //
  // NOT a transaction: issuance writes to the LEDGER, which no database
  // transaction can roll back. The remaining exposure is therefore a crash
  // between a successful issuance and this update — which leaves an offer that
  // can be redeemed twice, not one that cannot be redeemed at all. Duplicate
  // issuance of the same claims to the same holder is visible and revocable;
  // an unclaimable credential is neither.
  const issued = await issueCredential(credentialData);

  await db.credentialOffer.update({
    where: { id: offer.id },
    data: { status: 'ACCEPTED' as OfferStatus, acceptedAt: new Date() },
  });

  return issued;
}

/**
 * Resolve the issuer's first verification method for signing.
 * Uses the Credo-TS agent to resolve the DID document and find
 * an assertionMethod key.
 */
async function resolveIssuerVerificationMethod(issuerDid: string): Promise<string> {
  const agent = getAgent();
  const result = await agent.dids.resolve(issuerDid);

  if (!result.didDocument) {
    throw new AppError(
      ERROR_CODES.CREDENTIAL_ISSUANCE_FAILED,
      `Cannot resolve DID document for ${issuerDid}`,
      500,
    );
  }

  const assertionMethods = result.didDocument.assertionMethod ?? [];
  const verificationMethods = result.didDocument.verificationMethod ?? [];

  // Prefer assertionMethod, fall back to first verificationMethod
  const vmId =
    (typeof assertionMethods[0] === 'string'
      ? assertionMethods[0]
      : assertionMethods[0]?.id) ??
    verificationMethods[0]?.id;

  if (!vmId) {
    throw new AppError(
      ERROR_CODES.CREDENTIAL_ISSUANCE_FAILED,
      `No verification method found for ${issuerDid}`,
      500,
    );
  }

  return vmId;
}

/**
 * Issue a Verifiable Credential with cryptographic signing via Credo-TS.
 */
export async function issueCredential(data: CredentialData): Promise<IssuedCredential> {
  try {
    const now = new Date();
    const expirationDate = new Date(now);
    expirationDate.setDate(
      expirationDate.getDate() + SYSTEM_DEFAULTS.CREDENTIAL_EXPIRY_DAYS,
    );

    const credentialId = `urn:uuid:${uuidv4()}`;

    // Reserve this credential's bit in the issuer's revocation list, and make
    // sure that list actually exists on-ledger BEFORE signing a credential
    // that points at it. See ensureStatusListPublished() for why the order is
    // not arbitrary. Allocation is transactional, so two concurrent issuances
    // cannot be handed the same bit.
    const { list: statusList, index: statusIndex } = await allocateStatusIndex(data.issuerDid);
    const publishedList = await ensureStatusListPublished(statusList);
    const statusEntry = buildStatusEntry(publishedList, statusIndex);

    // Build W3C Credential using Credo-TS model.
    //
    // VC DATA MODEL 2.0 — see the long note at the equivalent line in
    // routes/oid4vci.ts. This is the second issuance path, reachable from
    // POST /api/credentials/accept-offer via issueCredentialWithCode(). Both
    // paths must produce the SAME data model: a credential issued through
    // either is indistinguishable to a verifier, so leaving one on v1 would
    // mean the format a holder gets depends on which button was pressed.
    const w3cCredential = new W3cV2Credential({
      context: [VC_CONTEXTS.W3C_CREDENTIALS_V2, VC_CONTEXTS.SCHEMA_ORG],
      id: credentialId,
      type: [CREDENTIAL_TYPES.BASE, data.credentialType],
      issuer: data.issuerDid,
      // v2 names the validity window validFrom/validUntil.
      validFrom: now.toISOString(),
      validUntil: expirationDate.toISOString(),
      // v2 takes subject claims flat; v1's `claims` key was Credo's in-memory
      // model rather than the W3C one.
      credentialSubject: new W3cV2CredentialSubject({
        id: data.subjectDid,
        ...data.claims,
      }),
      // Revocation. `statusListCredential` is a name+type DID URL that always
      // dereferences to the newest version of the list, so republishing the
      // list revokes credentials already sitting in wallets — no reissuance.
      credentialStatus: toCredoV2CredentialStatus(statusEntry),
    });

    let signedCredentialJson: VerifiableCredential;
    let serializedJwt: string | null = null;

    // Both securing mechanisms produce the same data model; only the envelope
    // differs. Recorded on the row so no consumer has to sniff it back out.
    //
    // SD-JWT IS THE DEFAULT, AND THAT DIRECTION IS THE WHOLE POINT.
    //
    // The disclosure frame is baked into the ISSUER's signature, so the choice
    // made here is irreversible: a `vc+jwt` credential can never be presented
    // selectively, no matter what the wallet's disclosure sheet offers, because
    // there are no disclosures to withhold. A `vc+sd-jwt` credential can always
    // be presented in full. Restriction at issuance is permanent; restriction at
    // presentation is the holder's to make every time (#194).
    //
    // So the safe option must be the DEFAULT rather than something a client
    // remembers to ask for. It was the other way round until 9 Sep 2026, and the
    // consequence was measured: a pharmacy that asked for one claim received
    // three, while the holder was shown "Share 1 item". A consent system that
    // discloses unconsented claims refutes itself.
    const issuedFormat: IssuableCredentialFormat = data.format ?? CREDENTIAL_FORMATS.SD_JWT_VC;

    try {
      const agent = getAgent();
      const verificationMethod = await resolveIssuerVerificationMethod(data.issuerDid);

      // Holder binding — see the note at the equivalent line in oid4vci.ts.
      // Both issuance paths must bind, or whether a credential is a bearer
      // token depends on which route issued it.
      //
      // ONE RESOLVER FOR BOTH SECURING MECHANISMS. SD-JWT's
      // `SdJwtVcHolderBinding` is the same `cnf` concept the JWT path already
      // binds, so it consumes this same result rather than resolving the holder
      // a second way. Two ways to decide who a credential is bound to is how
      // the two issuance paths drifted apart before.
      const holderBinding = await resolveHolderBinding(agent, data.subjectDid);
      // FAIL CLOSED, identically to the OID4VCI path. Whether a credential is
      // presentable must not depend on which route issued it.
      assertHolderBound(holderBinding, credentialId, data.subjectDid);

      // THE SECURING STEP IS SHARED WITH THE OID4VCI ROUTE, deliberately.
      // See services/securing.ts: these two issuance paths produce credentials
      // a verifier cannot tell apart, so every rule about how a credential is
      // secured has to hold in both, and restating it here is how they drifted
      // before.
      const secured = await secureV2Credential(agent, {
        credential: w3cCredential,
        format: issuedFormat,
        verificationMethod,
        holder: holderBinding.binding,
        subjectClaims: { id: data.subjectDid, ...data.claims },
      });

      signedCredentialJson = secured.json;
      serializedJwt = secured.envelope;

      logger.info('Credential signed via Credo-TS agent', {
        credentialId,
        issuer: data.issuerDid,
        format: issuedFormat,
        dataModel: 'vc-2.0',
      });
    } catch (agentError) {
      // Preserve an already-classified refusal (holder binding). Rewrapping it
      // as a generic 500 would discard the specific code and the
      // retryable-vs-permanent distinction the caller needs to act on.
      if (isSsiError(agentError)) throw agentError;

      // If agent signing fails, refuse to issue unsigned credential
      // Healthcare credentials MUST be cryptographically signed
      logger.error('Agent signing failed — refusing to issue unsigned credential', {
        error: agentError instanceof Error ? agentError.message : String(agentError),
        credentialId,
      });

      throw new AppError(
        ERROR_CODES.CREDENTIAL_ISSUANCE_FAILED,
        'Credential signing failed. Cannot issue unsigned credentials in a healthcare identity system.',
        500,
      );
    }

    // Persist to database — failures propagate (HIPAA requires audit trail)
    const credentialHash = crypto
        .createHash('sha256')
        .update(JSON.stringify(signedCredentialJson))
        .digest('hex');

    await db.credential.create({
      data: {
        holderDid: data.subjectDid,
        issuerDid: data.issuerDid,
        type: [CREDENTIAL_TYPES.BASE, data.credentialType],
        category: categoryMap[data.category] || 'GENERAL',
        name: data.name || data.credentialType,
        description: data.description,
        credentialData: JSON.parse(JSON.stringify(signedCredentialJson)) as Prisma.InputJsonValue,
        // The enveloping proof — see the column comment in schema.prisma.
        credentialJwt: serializedJwt,
        // Which mechanism that envelope uses. Written at issuance, where the
        // answer is known, rather than left to be inferred by every reader.
        credentialFormat: issuedFormat,
        credentialHash,
        issuedAt: now,
        expiresAt: expirationDate,
        status: 'ACTIVE' as CredentialStatus,
        // Persist the bit we reserved. Without this the credential carries a
        // status entry that nothing on our side can find again, so revocation
        // would have no way to know which bit to flip.
        statusListId: publishedList.id,
        statusListIndex: statusIndex,
      },
    });

    return { credential: signedCredentialJson };
  } catch (error) {
    if (isSsiError(error)) throw error;

    logger.error('Credential issuance error', { data, error });
    throw new AppError(
      ERROR_CODES.CREDENTIAL_ISSUANCE_FAILED,
      `Failed to issue credential: ${error instanceof Error ? error.message : 'Unknown error'}`,
      500,
    );
  }
}

export interface VerifyCredentialOptions {
  checkRevocation?: boolean;
  checkExpiration?: boolean;
  /**
   * The compact JWT that secures this credential, when the caller has it.
   *
   * REQUIRED IN PRACTICE FOR VC 2.0. A v2 credential's JSON carries no proof of
   * any kind — the signature lives in the enveloping JWT — so verifying the
   * JSON alone is not merely weaker, it is impossible. VC 1.1 credentials can
   * still be verified without this because they embed `proof.jwt`.
   *
   * When a v2 credential arrives with no envelope the signature check FAILS
   * rather than being skipped; treating "nothing to check" as "check passed"
   * is the fail-open pattern this codebase is trying to get rid of.
   */
  envelopeJwt?: string | null;
  /**
   * Which securing mechanism {@link envelopeJwt} uses, when the caller knows.
   *
   * Supply it from the stored `credentialFormat` wherever there is one. The
   * fallback is structural detection, which is correct but is exactly the
   * sniffing this column exists to avoid — a caller holding the recorded answer
   * should pass it rather than let it be re-derived.
   */
  envelopeFormat?: CredentialFormat | null;
}

/**
 * Verify a Verifiable Credential using Credo-TS agent for cryptographic
 * signature verification plus DB-backed revocation checks.
 */
export async function verifyCredential(
  credential: VerifiableCredential,
  options: VerifyCredentialOptions = {},
): Promise<{ isValid: boolean; errors: string[]; checks: Record<string, boolean> }> {
  const { checkRevocation = true, checkExpiration = true, envelopeJwt } = options;
  const errors: string[] = [];
  const checks: Record<string, boolean> = {
    structure: false,
    expiration: true,
    revocation: true,
    signature: false,
  };

  try {
    // Structural checks.
    //
    // The validity window is read through the shared helpers, which accept both
    // data models: VC 1.1 issuanceDate/expirationDate and VC 2.0
    // validFrom/validUntil. Reading `issuanceDate` directly — as this did
    // before the migration — reported "Missing issuance date" on every single
    // VC 2.0 credential, which does not carry that member.
    const validFrom = credentialValidFrom(credential);
    const validUntil = credentialValidUntil(credential);

    if (!credential.issuer) errors.push('Missing issuer');
    if (!credential.credentialSubject) errors.push('Missing credential subject');
    if (!validFrom) errors.push('Missing issuance date');
    if (!credential.type?.includes(CREDENTIAL_TYPES.BASE)) {
      errors.push('Missing VerifiableCredential base type');
    }

    checks.structure = !errors.some(e =>
      e.includes('Missing') || e.includes('base type')
    );

    // Expiration check
    if (checkExpiration && validUntil) {
      const expiry = new Date(validUntil);
      if (expiry < new Date()) {
        errors.push('Credential has expired');
        checks.expiration = false;
      }
    }

    // Cryptographic signature verification via Credo-TS.
    //
    // Credo needs the SIGNED artifact. For a JWT-VC that is the compact JWT
    // in `proof.jwt` — the surrounding W3C JSON is a rendering of it and
    // carries no signature of its own. This previously passed
    // `credential as unknown as string`, casting the JSON object to a string
    // it is not, which made Credo reject every credential with "Unsupported
    // credential type in options" and the catch below turn that into a 503.
    // The cast hid a type error rather than performing a conversion.
    // The envelope, if the caller supplied one, takes precedence: for VC 2.0 it
    // is the ONLY thing carrying a signature.
    const isV2 = Array.isArray(credential['@context'])
      && credential['@context'].includes(VC_CONTEXTS.W3C_CREDENTIALS_V2);

    const embeddedJwt =
      credential.proof?.type === JWT_PROOF_TYPE && typeof credential.proof.jwt === 'string'
        ? credential.proof.jwt
        : null;

    const signedArtifact: string | typeof credential = envelopeJwt ?? embeddedJwt ?? credential;

    if (isV2 && typeof signedArtifact !== 'string') {
      // Fail closed. A v2 credential with no envelope has no signature to
      // check anywhere, and reporting it "verified" on the strength of its
      // structural fields alone would be the fail-open pattern in a new format.
      checks.signature = false;
      errors.push(
        'Cryptographic signature verification failed: VC 2.0 credential supplied '
          + 'without its enveloping JWT, so no signature is available to verify',
      );
    } else {
      try {
        const agent = getAgent();

        // Route to the stack that matches the data model. The two are separate
        // in Credo 0.6 and each rejects the other's credentials, so picking the
        // wrong one fails every credential rather than falling back.
        // The v2 API needs a class instance, not a compact string — see
        // `toV2VerifiableCredential`. A string typechecks and throws at runtime.
        //
        // WITHIN v2 THERE ARE NOW TWO SECURING MECHANISMS, and the JWT reader
        // does NOT fail on an SD-JWT. A compact SD-JWT still splits into three
        // `.`-separated segments, so the JWT decoder succeeds and returns the
        // issuer-signed payload with every disclosable claim replaced by a
        // digest — a credential-shaped husk, verified as valid, with the
        // patient data missing and nothing to say so. Route on the recorded
        // format first, and only then on structure.
        const isSdJwt =
          isV2 && typeof signedArtifact === 'string'
            ? (options.envelopeFormat ?? credentialEnvelopeFormat({
                credentialJwt: signedArtifact,
                credentialFormat: null,
              })) === CREDENTIAL_FORMATS.SD_JWT_VC
            : false;

        // Kept as two separately-typed locals rather than one union. Credo's
        // `W3cV2VerifyCredentialOptions` is a union of two option objects, and
        // a union-typed `credential` satisfies neither member — the compiler is
        // right to refuse it, because the SD-JWT branch genuinely cannot accept
        // a JWT credential.
        const v2SdJwtCredential =
          isV2 && isSdJwt ? toV2SdJwtVerifiableCredential(signedArtifact as string) : null;
        const v2JwtCredential =
          isV2 && !isSdJwt ? toV2VerifiableCredential(signedArtifact as string) : null;
        const v2Credential = v2SdJwtCredential ?? v2JwtCredential;

        if (isV2 && !v2Credential) {
          checks.signature = false;
          errors.push(
            `Cryptographic signature verification failed: envelope is not a readable VC 2.0 ${
              isSdJwt ? 'SD-JWT' : 'JWT'
            }`,
          );
          return { isValid: false, errors, checks };
        }

        const verifyResult = v2SdJwtCredential
          ? await agent.w3cV2Credentials.verifyCredential({
              credential: v2SdJwtCredential,
            })
          : v2JwtCredential
          ? await agent.w3cV2Credentials.verifyCredential({
              credential: v2JwtCredential,
            })
          : await agent.w3cCredentials.verifyCredential({
              // Credo's own union is `W3cJsonLdVerifiableCredential | string`; a
              // Data Integrity credential still goes through as JSON.
              credential: signedArtifact as unknown as string,
              // NOT `true`. Credo 0.6 has no status implementation for VC 1.1
              // JWT VCs and hard-fails any credential that carries one. The
              // real check happens below against the ledger. See the header of
              // services/statusListService.ts.
              //
              // The v2 branch above takes no such option — `W3cV2CredentialService`
              // has no status handling at all, so there is nothing to disable
              // and nothing that can refuse a credential for carrying a status.
              verifyCredentialStatus: false,
            });

        // Credo drops a disclosure whose digest does not match and still
        // reports the credential valid, so an attacker can delete chosen claims
        // from an otherwise genuine credential without invalidating it. RFC 9807
        // §7.3 requires rejection. Applied here as well as at the presentation
        // boundary, because a credential can be verified without ever being
        // wrapped in a presentation.
        if (v2SdJwtCredential) {
          const disclosureErrors = assertDisclosuresResolve(v2SdJwtCredential.encoded);
          if (disclosureErrors.length > 0) {
            checks.signature = false;
            errors.push(...new Set(disclosureErrors));
            return { isValid: false, errors, checks };
          }
        }

        checks.signature = verifyResult.isValid;
        if (!verifyResult.isValid) {
          errors.push('Cryptographic signature verification failed');
          if (verifyResult.error) {
            errors.push(`Signature error: ${verifyResult.error.message ?? String(verifyResult.error)}`);
          }
        }
      } catch (agentError) {
        // H-15: Agent unavailability must not cause silent fail-open verification.
        // Propagate as 503 — callers must not treat unverified credentials as valid.
        const msg = agentError instanceof Error ? agentError.message : String(agentError);
        logger.error('Credential signature verification failed — agent unavailable or error', {
          error: msg,
        });
        throw new AppError(
          ERROR_CODES.CREDENTIAL_VERIFICATION_FAILED,
          `Credential signature verification unavailable: ${msg}`,
          503,
        );
      }
    }

    // Revocation check.
    //
    // The authoritative source is the status list ON THE LEDGER, not this
    // server's database, because that is the only source a third-party
    // verifier can also read. The database is consulted only as a fallback for
    // credentials that predate status lists (or came from an external issuer),
    // which have no `credentialStatus` to dereference.
    //
    // Note this is NOT Credo's `verifyCredentialStatus` — that flag is
    // hard-wired to fail any JWT VC carrying a status. See the header of
    // services/statusListService.ts.
    if (checkRevocation) {
      if (credential.credentialStatus) {
        const statusResult = await checkStatusOnLedger(credential.credentialStatus);

        if (statusResult.checked) {
          if (statusResult.revoked) {
            errors.push('Credential has been revoked');
            checks.revocation = false;
          }
        } else {
          // An unresolvable status list is not evidence of validity. A
          // verifier that treats "I could not check" as "not revoked" has no
          // revocation at all, so this is an error, not a warning.
          errors.push(`Revocation status could not be checked: ${statusResult.error ?? 'unknown error'}`);
          checks.revocation = false;
          logger.warn('Status list could not be dereferenced', {
            credentialId: credential.id,
            statusListCredential: statusResult.statusListCredential,
            error: statusResult.error,
          });
        }
      } else if (credential.id) {
        // Legacy path: no status entry, so fall back to the local record.
        try {
          const credentialHash = crypto
            .createHash('sha256')
            .update(JSON.stringify(credential))
            .digest('hex');

          const stored = await db.credential.findUnique({ where: { credentialHash } });

          if (stored?.status === 'REVOKED') {
            errors.push('Credential has been revoked');
            checks.revocation = false;
          }
        } catch {
          logger.warn('Local revocation check failed for credential without a status list');
        }
      }
    }

    const isValid = errors.length === 0;

    logger.info('Credential verification', {
      credentialId: credential.id,
      isValid,
      checks,
    });

    return { isValid, errors, checks };
  } catch (error) {
    logger.error('Credential verification error', { error });
    throw new AppError(
      ERROR_CODES.CREDENTIAL_VERIFICATION_FAILED,
      `Verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      500,
    );
  }
}

// ===========================================================================
// THIRD-PARTY CREDENTIAL IMPORT — COMMENTED OUT, PLANNED, NOT ABANDONED.
// ===========================================================================
//
// Owner's ruling (OpenDiscussion §P4, steno #193): importing a credential
// issued by an external OID4VCI issuer — a hospital or clinic that issued a
// JWT-VC directly to the holder's wallet — IS in scope for this system. It is
// deferred, not dropped. This code is parked here rather than deleted so the
// work already done on it is not redone from scratch.
//
// WHY IT IS PARKED RATHER THAN LIVE: `storeExternalCredential` has never had a
// route. `packages/web` POSTs to `/api/credentials/store-external`; no such
// handler exists in `routes/credential.ts`, so the affordance dead-ended on a
// 404 — and it did so at the LAST step, after the wallet had already completed
// the token and credential exchange with the third-party issuer and burned the
// pre-authorized code. The web affordance has been disabled to match; see
// `packages/web/src/lib/api/oid4vciClient.ts` and
// `packages/web/src/app/wallet/scan/page.tsx`.
//
// ---------------------------------------------------------------------------
// TWO LATENT DEFECTS ARE FIXED IN THE CODE BELOW. DO NOT REVIVE THE BUGS.
// ---------------------------------------------------------------------------
// Both were found in this function and corrected before it was parked. If this
// is ever restored from an older commit instead of from here, they come back:
//
//   1. THE STATUS TERNARY HAD `ACTIVE` IN BOTH BRANCHES. The expression read
//      `signatureVerified ? 'ACTIVE' : 'ACTIVE'`, so a credential whose
//      signature could NOT be verified against the issuer's JWKS was stored
//      indistinguishably from one that was — directly contradicting this
//      function's own docstring, which promised PENDING_VERIFICATION. A wallet
//      renders PENDING as not-yet-usable; ACTIVE it renders as trustworthy.
//      An unverified third-party credential displayed as trustworthy is the
//      whole threat model of external import. Now `'ACTIVE' : 'PENDING'`.
//
//   2. A MISSING ISSUANCE DATE WAS FABRICATED AS 1970-01-01. When the claim
//      was absent, `jwtVcToW3cJson` produced `new Date(0)` — the Unix epoch —
//      which is WORSE than null, because null renders as "unknown" while
//      1970-01-01 renders as data. A clinical credential that appears to have
//      been issued in 1970 is a silent falsehood in a patient record. Absent
//      now means absent.
//
// WHEN REVIVING, ALSO DECIDE THESE (they are open questions, not defects):
//   - Whether storing an unverified credential at all is acceptable, or whether
//     a failed JWKS fetch should refuse the import outright. The current code
//     stores as PENDING; failing closed is the more conservative choice and
//     needs an explicit ruling.
//   - `credentialIssuer` is caller-supplied and is used to build the JWKS URL.
//     A route mounting this MUST authenticate the holder and constrain or
//     allow-list that origin, or it is an SSRF vector: an attacker who can call
//     the route makes the backend fetch an arbitrary URL.
//   - The `issuerMatches` check below accepts `issuerFromCredential.includes(
//     expectedHost)` — a substring test, which `evil.com/?x=hospital.example`
//     satisfies. Tighten to a parsed-origin comparison before this goes live.
//
// ===========================================================================
//
// export interface StoredExternalCredential {
//   id: string;
//   type: string[];
//   issuerDid: string;
//   issuerName: string;
//   issuedAt: string;
//   expiresAt: string | null;
//   credentialData: Record<string, unknown>;
//   rawJwt: string;
// }
//
// /**
//  * Store a Verifiable Credential received from an **external** OID4VCI issuer
//  * (e.g. a hospital that issued a JWT-VC directly to the holder wallet).
//  *
//  * Verifies the JWT signature against the issuer's published JWKS before storing.
//  * Falls back to storing as PENDING_VERIFICATION if JWKS fetch fails.
//  */
// export async function storeExternalCredential(
//   holderUserId: string,
//   holderDid: string,
//   rawJwt: string,
//   credentialIssuer: string,
//   credentialType: string,
// ): Promise<StoredExternalCredential> {
//   // --- 1. Decode the JWT payload (base64url, no sig verification yet) ---
//   const parts = rawJwt.split('.');
//   if (parts.length !== 3) {
//     throw new AppError(ERROR_CODES.CREDENTIAL_ISSUANCE_FAILED, 'Invalid JWT format', 400);
//   }
//
//   const payloadB64 = parts[1];
//   let payload: Record<string, unknown>;
//   try {
//     const padded = payloadB64 + '='.repeat((4 - (payloadB64.length % 4)) % 4);
//     payload = JSON.parse(Buffer.from(padded, 'base64').toString('utf-8')) as Record<string, unknown>;
//   } catch {
//     throw new AppError(ERROR_CODES.CREDENTIAL_ISSUANCE_FAILED, 'Cannot decode JWT payload', 400);
//   }
//
//   // --- 2. Extract standard claims, ACROSS BOTH DATA MODELS ---
//   //
//   // This block used to read only VC 1.1 registered claims (`iss`, `sub`, `exp`).
//   // A VC 2.0 credential has NONE of them: the payload IS the credential, so the
//   // issuer is `issuer`, the subject is `credentialSubject.id`, and the validity
//   // window is `validFrom`/`validUntil`. The consequences were not cosmetic:
//   //
//   //   - `exp` absent  => `expiresAt` stored as NULL => an expired clinical
//   //     credential renders as NEVER-EXPIRING. That is the patient-safety bug.
//   //   - `iss` absent  => the JWKS check below asserted an issuer claim that is
//   //     not there, so signature verification could never succeed for v2.
//   //
//   // Decode once, through the module that knows both models, and read the
//   // credential rather than the JWT envelope's registered claims.
//   const decodedCredential = jwtVcToW3cJson(rawJwt);
//
//   const decodedIssuer = decodedCredential?.issuer;
//   const issuerFromCredential =
//     typeof decodedIssuer === 'string' ? decodedIssuer : decodedIssuer?.id;
//
//   // Precedence: what the credential says, then the v1 registered claim, then
//   // the caller's assertion. The credential is the most authoritative of the
//   // three because it is inside the signed payload for both models.
//   const iss = issuerFromCredential || (payload.iss as string) || credentialIssuer;
//   const sub =
//     (decodedCredential?.credentialSubject?.id as string) ||
//     (payload.sub as string) ||
//     holderDid;
//
//   const validFromIso = decodedCredential ? credentialValidFrom(decodedCredential) : undefined;
//   const validUntilIso = decodedCredential ? credentialValidUntil(decodedCredential) : undefined;
//
//   const iat = validFromIso
//     ? new Date(validFromIso)
//     : typeof payload.iat === 'number'
//       ? new Date(payload.iat * 1000)
//       : new Date();
//
//   const exp = validUntilIso
//     ? new Date(validUntilIso)
//     : typeof payload.exp === 'number'
//       ? new Date(payload.exp * 1000)
//       : null;
//
//   // A malformed date must not silently become "now" or "never". Reject rather
//   // than store a credential whose validity window is a guess.
//   if (Number.isNaN(iat.getTime()) || (exp && Number.isNaN(exp.getTime()))) {
//     throw new AppError(
//       ERROR_CODES.CREDENTIAL_SCHEMA_INVALID,
//       'Credential carries an unparseable validity window',
//       400,
//     );
//   }
//
//   // vc claim wraps the W3C credential in JWT-VC format
//   const vcClaim = (payload.vc as Record<string, unknown>) ?? payload;
//   const types: string[] = Array.isArray(vcClaim.type)
//     ? (vcClaim.type as string[])
//     : ['VerifiableCredential', credentialType];
//
//   const credentialSubject =
//     (vcClaim.credentialSubject as Record<string, unknown>) ?? {};
//
//   // --- 3. Attempt JWKS signature verification ---
//   let signatureVerified = false;
//   try {
//     const { createRemoteJWKSet, jwtVerify } = await import('jose');
//     const jwksUrl = new URL('/.well-known/jwks.json', credentialIssuer);
//     const JWKS = createRemoteJWKSet(jwksUrl);
//
//     // Only assert the `iss` REGISTERED CLAIM when the token actually has one.
//     // VC 2.0 has no `iss`, so passing `{ issuer }` made jose reject every v2
//     // credential for a missing claim — verification that could never succeed.
//     const hasRegisteredIss = typeof payload.iss === 'string' && payload.iss.length > 0;
//     await jwtVerify(rawJwt, JWKS, hasRegisteredIss ? { issuer: iss } : {});
//
//     // Dropping the `issuer` option must not drop the issuer BINDING, or a
//     // credential signed by one issuer could be stored as another's. For v2,
//     // bind explicitly: the issuer named inside the signed credential must be
//     // the issuer whose JWKS just validated the signature.
//     if (!hasRegisteredIss) {
//       const expectedHost = new URL(credentialIssuer).host;
//       const issuerMatches =
//         issuerFromCredential === credentialIssuer ||
//         (issuerFromCredential ? issuerFromCredential.includes(expectedHost) : false);
//       if (!issuerMatches) {
//         throw new Error(
//           `credential issuer '${issuerFromCredential ?? '(none)'}' does not match the JWKS origin '${credentialIssuer}'`,
//         );
//       }
//     }
//
//     signatureVerified = true;
//     logger.info('External credential JWT signature verified', {
//       iss,
//       types,
//       dataModel: hasRegisteredIss ? 'vc-1.1' : 'vc-2.0',
//     });
//   } catch (err) {
//     // Log but do not block storage — credential stored as unverified
//     logger.warn('External credential JWT signature could not be verified — storing as unverified', {
//       error: err instanceof Error ? err.message : String(err),
//       iss,
//     });
//   }
//
//   // --- 4. Build the W3C VC envelope for DB storage ---
//   //
//   // Decoding is delegated to `jwtVcToW3cJson`, which is the single place that
//   // knows the VC-JWT rules for BOTH data models. This function used to inline
//   // its own VC-JWT 1.1 decode (registered claims plus a `vc` wrapper), which an
//   // external issuer sending a VC 2.0 `vc+jwt` credential would have silently
//   // reduced to an empty husk — v2 has no `vc` claim and no `iss`/`sub`/`nbf`
//   // to read. Two copies of the decode rules is exactly how that drift happens.
//   const decoded = decodedCredential;
//
//   const credentialData: Record<string, unknown> = decoded
//     ? (decoded as unknown as Record<string, unknown>)
//     : {
//         // Last-resort reconstruction for a token that is not a decodable
//         // JWT-VC of either model. v1 by construction: a `vc` claim without
//         // `@context` is a 1.1 token. See jwtVc.ts.
//         '@context': (vcClaim['@context'] as unknown[]) ?? [VC_CONTEXTS.W3C_CREDENTIALS_V1],
//         id: (vcClaim.id as string) ?? `urn:jwt:${Date.now()}`,
//         type: types,
//         issuer: iss,
//         issuanceDate: iat.toISOString(),
//         ...(exp ? { expirationDate: exp.toISOString() } : {}),
//         credentialSubject: { id: sub, ...credentialSubject },
//         proof: { type: JWT_PROOF_TYPE, jwt: rawJwt },
//       };
//
//   const credentialHash = crypto
//     .createHash('sha256')
//     .update(rawJwt)
//     .digest('hex');
//
//   // Detect duplicate (same JWT)
//   const existing = await db.credential.findUnique({ where: { credentialHash } });
//   if (existing) {
//     return {
//       id: existing.id,
//       type: existing.type,
//       issuerDid: existing.issuerDid,
//       issuerName: iss,
//       issuedAt: existing.issuedAt.toISOString(),
//       expiresAt: existing.expiresAt?.toISOString() ?? null,
//       credentialData: credentialData,
//       rawJwt,
//     };
//   }
//
//   // Determine category from credential type
//   const lcType = credentialType.toLowerCase();
//   let category: CredentialCategory = 'GENERAL';
//   if (lcType.includes('prescription') || lcType.includes('medication')) category = 'PRESCRIPTIONS';
//   else if (lcType.includes('vital') || lcType.includes('blood')) category = 'BLOOD_WORK';
//   else if (lcType.includes('immuniz') || lcType.includes('vaccine')) category = 'VACCINATIONS';
//   else if (lcType.includes('imaging') || lcType.includes('xray') || lcType.includes('mri')) category = 'IMAGING';
//   else if (lcType.includes('lab') || lcType.includes('test')) category = 'LAB_RESULTS';
//
//   const stored = await db.credential.create({
//     data: {
//       holderUserId,
//       holderDid: sub,
//       issuerDid: iss,
//       type: types,
//       category,
//       name: credentialType,
//       description: `Issued by ${iss}${signatureVerified ? '' : ' (unverified signature)'}`,
//       credentialData: credentialData as Prisma.InputJsonValue,
//       // The enveloping proof. Set for both data models here: an external VC 2.0
//       // credential has nowhere else to keep its signature, and for a v1 one this
//       // simply duplicates `credentialData.proof.jwt` at the canonical location.
//       credentialJwt: rawJwt,
//       credentialHash,
//       issuedAt: iat,
//       expiresAt: exp,
//       // Honour what this function's contract already claimed. Both branches of
//       // this ternary used to be ACTIVE, so a credential whose signature could
//       // NOT be verified was stored indistinguishably from one that was — while
//       // the docstring said it would be held pending. PENDING is the status a
//       // wallet already renders as not-yet-usable.
//       status: (signatureVerified ? 'ACTIVE' : 'PENDING') as CredentialStatus,
//     },
//   });
//
//   await db.auditLog.create({
//     data: {
//       actorUserId: holderUserId,
//       eventType: PrismaAuditEventType.CREDENTIAL_ISSUED,
//       action: `Received external credential from ${iss}`,
//       details: {
//         credentialId: stored.id,
//         issuer: iss,
//         type: credentialType,
//         signatureVerified,
//         source: 'oid4vci-external',
//       },
//     },
//   }).catch(() => { /* non-fatal audit failure */ });
//
//   logger.info('External credential stored', {
//     credentialId: stored.id,
//     issuer: iss,
//     holderUserId,
//     signatureVerified,
//   });
//
//   return {
//     id: stored.id,
//     type: stored.type,
//     issuerDid: stored.issuerDid,
//     issuerName: iss,
//     issuedAt: stored.issuedAt.toISOString(),
//     expiresAt: stored.expiresAt?.toISOString() ?? null,
//     credentialData,
//     rawJwt,
//   };
// }

/**
 * Revoke a credential by its DB ID.
 * Only the issuer (DID that issued it) can revoke.
 */
export async function revokeCredential(
  credentialId: string,
  revokerDid: string,
  reason?: string,
): Promise<{ id: string; status: string; statusListPublished: boolean; publishError?: string }> {
  const credential = await db.credential.findUnique({
    where: { id: credentialId },
  });

  if (!credential) {
    throw new AppError(
      ERROR_CODES.CREDENTIAL_NOT_FOUND,
      'Credential not found',
      404,
    );
  }

  if (credential.issuerDid !== revokerDid) {
    throw new AppError(
      ERROR_CODES.AUTH_INSUFFICIENT_PERMISSIONS,
      'Only the issuer can revoke a credential',
      403,
    );
  }

  if (credential.status === 'REVOKED') {
    throw new AppError(
      ERROR_CODES.CREDENTIAL_ALREADY_REVOKED,
      'Credential is already revoked',
      400,
    );
  }

  const updated = await db.credential.update({
    where: { id: credentialId },
    data: {
      status: 'REVOKED' as CredentialStatus,
      revokedAt: new Date(),
      revocationReason: reason,
    },
  });

  // Flip the bit on-chain. The bitstring is regenerated from
  // `status = REVOKED` rows, so the write above IS the bit flip; publishing
  // pushes the new bitmap to the ledger as a fresh version of the same named
  // resource, which is what every already-issued credential dereferences to.
  //
  // A failure here is reported but does not roll back the local revocation.
  // The two are not equivalent and the asymmetry is deliberate: a credential
  // that is revoked locally but still shows clear on-chain is a system that
  // has not finished revoking, and the operator needs to see that. Rolling
  // back would instead leave a credential the issuer believes they revoked
  // still fully valid everywhere, which is the more dangerous of the two.
  let statusListPublished = false;
  let publishError: string | undefined;

  if (credential.statusListId) {
    const list = await db.credentialStatusList.findUnique({
      where: { id: credential.statusListId },
    });

    if (list) {
      try {
        const published = await publishStatusList(list);
        statusListPublished = true;
        logger.info('Revocation published to ledger', {
          credentialId,
          statusListIndex: credential.statusListIndex,
          resourceId: published.resourceId,
          version: published.version,
          revokedCount: published.revokedIndices.length,
        });
      } catch (error) {
        publishError = error instanceof Error ? error.message : String(error);
        logger.error('Credential revoked locally but status list publish FAILED — ' +
          'on-ledger status is now stale and must be republished', {
          credentialId,
          statusListId: list.id,
          error: publishError,
        });
      }
    }
  } else {
    logger.warn('Revoked credential has no status list entry — ' +
      'revocation is local only and no verifier can observe it', { credentialId });
  }

  await db.auditLog.create({
    data: {
      actorDid: revokerDid,
      targetDid: credential.holderDid,
      eventType: PrismaAuditEventType.CREDENTIAL_REVOKED,
      action: `Credential revoked: ${reason || 'No reason given'}`,
      details: {
        credentialId,
        reason,
        statusListIndex: credential.statusListIndex,
        statusListPublished,
        ...(publishError ? { publishError } : {}),
      },
    },
  });

  logger.info('Credential revoked', { credentialId, revokerDid, reason, statusListPublished });

  return { id: updated.id, status: updated.status, statusListPublished, publishError };
}

/**
 * Re-publish an issuer's revocation list.
 *
 * Exists because `revokeCredential` deliberately does not roll back when the
 * ledger write fails: something has to be able to reconcile afterwards, and
 * since the bitmap is derived from the database this is safe to run at any
 * time and any number of times.
 */
export async function republishStatusList(issuerDid: string) {
  const list = await db.credentialStatusList.findUnique({
    where: { issuerDid_purpose: { issuerDid, purpose: 'revocation' } },
  });

  if (!list) {
    throw new AppError(ERROR_CODES.CREDENTIAL_NOT_FOUND, `No revocation list for ${issuerDid}`, 404);
  }

  return publishStatusList(list);
}
