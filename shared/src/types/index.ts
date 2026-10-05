/**
 * SSI Healthcare System - Shared Type Definitions
 *
 * Core types for Decentralized Identifiers (DIDs), Verifiable Credentials (VCs),
 * Verifiable Presentations (VPs), and consent management used across all packages.
 */

import type { CredentialFormat } from '../constants/index.js';

// ---------------------------------------------------------------------------
// JSON Web Key (JWK) - defined here since DOM lib is not included
// ---------------------------------------------------------------------------

/** JSON Web Key as per RFC 7517. */
export interface JWK {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
  kid?: string;
  use?: string;
  alg?: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// DID Types
// ---------------------------------------------------------------------------

/** Supported DID methods in the system. */
export type DIDMethod = 'did:cheqd' | 'did:key' | 'did:web';

/** A resolved DID Document following W3C DID Core spec. */
export interface DIDDocument {
  '@context': string[];
  id: string;
  controller?: string | string[];
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  service?: ServiceEndpoint[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: JWK;
}

export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string | string[];
}

// ---------------------------------------------------------------------------
// Verifiable Credential Types
// ---------------------------------------------------------------------------

/** Credential status information for revocation checking. */
export interface CredentialStatus {
  id: string;
  type: string;
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: string;
  statusListCredential: string;
}

/**
 * A W3C Verifiable Credential, in either Data Model 1.1 or 2.0 shape.
 *
 * THE SYSTEM ISSUES VC 2.0. This type still models 1.1 because credentials
 * issued before the migration are still in holders' wallets and must keep
 * rendering and verifying — see the `W3cV2CredentialsModule` note in
 * `backend/src/agent/index.ts` for why v1 and v2 coexist rather than cut over.
 *
 * The two data models name the validity window differently, and this is the
 * single most common way a v2 credential silently reads as blank:
 *
 *   VC 1.1        VC 2.0
 *   --------      --------
 *   issuanceDate    ->  validFrom
 *   expirationDate  ->  validUntil
 *
 * Both pairs are optional here because exactly one pair is present on any given
 * credential. Never read `issuanceDate` directly — use `credentialValidFrom()`
 * / `credentialValidUntil()`, which fall back across both models.
 *
 * `proof` is 1.1-only. VC 2.0 secures credentials with an *enveloping* proof:
 * the compact JWT wraps the credential rather than being a property of it, so a
 * v2 credential has no `proof` member at all. The envelope travels beside the
 * credential — see {@link WalletCredential.credentialJwt}.
 */
export interface VerifiableCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string | { id: string; name?: string };
  /** VC 1.1 issuance instant. Absent on VC 2.0 credentials — see `validFrom`. */
  issuanceDate?: string;
  /** VC 1.1 expiry instant. Absent on VC 2.0 credentials — see `validUntil`. */
  expirationDate?: string;
  /** VC 2.0 start of the validity window. Absent on VC 1.1 credentials. */
  validFrom?: string;
  /** VC 2.0 end of the validity window. Absent on VC 1.1 credentials. */
  validUntil?: string;
  credentialSubject: CredentialSubject;
  credentialStatus?: CredentialStatus;
  /** VC 1.1 embedded proof. Never present on a VC 2.0 credential. */
  proof?: Proof;
}

/**
 * Start of a credential's validity window, whichever data model it uses.
 *
 * Prefers the v2 name. Returns `undefined` only if the credential carries
 * neither, which a conformant credential of either model cannot.
 */
export function credentialValidFrom(
  credential: Pick<VerifiableCredential, 'validFrom' | 'issuanceDate'>,
): string | undefined {
  return credential.validFrom ?? credential.issuanceDate;
}

/** End of a credential's validity window, whichever data model it uses. */
export function credentialValidUntil(
  credential: Pick<VerifiableCredential, 'validUntil' | 'expirationDate'>,
): string | undefined {
  return credential.validUntil ?? credential.expirationDate;
}

export interface CredentialSubject {
  id?: string;
  [key: string]: unknown;
}

/**
 * Whose credential this is, as the ISSUER stated it.
 *
 * `credentialSubject.id` is the only claim in a credential about its owner, and
 * it is the issuer's assertion rather than the holder's, which is what makes it
 * usable as an ownership check: a verifier can refuse a presentation whose
 * signer is not the subject the issuer named.
 *
 * Returns `null` when the credential names no subject. That is deliberately
 * distinguishable from the empty string: a caller enforcing ownership must
 * refuse `null` rather than treat it as "no constraint".
 */
export function credentialSubjectId(
  credential: Pick<VerifiableCredential, 'credentialSubject'> | { credentialSubject?: unknown },
): string | null {
  const subject = credential.credentialSubject;
  if (subject === null || typeof subject !== 'object') return null;
  const id = (subject as CredentialSubject).id;
  return typeof id === 'string' && id.length > 0 ? id : null;
}

/**
 * Proof on a credential or presentation.
 *
 * Two proof families occur in this system and they populate disjoint fields:
 *
 *  - **Data Integrity proofs** (`Ed25519Signature2020` and friends) carry
 *    `created` / `verificationMethod` / `proofPurpose` / `proofValue`.
 *  - **JWT proofs** (`JwtProof2020`) carry the compact JWT in `jwt` and
 *    nothing else. Every credential this system issues today is signed as
 *    `jwt_vc`, so this is the common case, not the exotic one.
 *
 * That is why every field except `type` is optional: declaring `proofValue`
 * required described a proof shape the system never actually produces, and
 * any schema built on that assumption rejects real credentials.
 */
export interface Proof {
  type: string;
  created?: string;
  verificationMethod?: string;
  proofPurpose?: string;
  /** Data Integrity signature (base58/base64 encoded). */
  proofValue?: string;
  /** Compact JWS, used by some Data Integrity suites. */
  jws?: string;
  /** Compact JWT serialization — the presentable artifact for a JWT-VC. */
  jwt?: string;
}

// ---------------------------------------------------------------------------
// Wallet Credential Envelope — the HTTP contract for a stored credential
// ---------------------------------------------------------------------------

/**
 * Lifecycle state of a stored credential.
 *
 * Mirrors the Prisma `CredentialStatus` enum exactly. This is the field that
 * conveys **revocation** to a wallet — a client that ignores it will happily
 * present a credential the issuer has already revoked, so it is required, not
 * optional.
 */
export type WalletCredentialStatus =
  | 'PENDING'
  | 'ACTIVE'
  | 'EXPIRED'
  | 'REVOKED'
  | 'SUSPENDED';

/**
 * Storage category of a stored credential.
 *
 * Mirrors the Prisma `CredentialCategory` enum exactly. Note this is NOT the
 * same vocabulary as {@link HealthcareCredentialCategory} (lowercase, thesis
 * folder taxonomy) — the two overlap but `IDENTITY` and `PROFESSIONAL` exist
 * only here, and `MENTAL_HEALTH`/`IMMUNIZATION`/`EMERGENCY` exist only there.
 * Clients that need folder colours must map between them explicitly.
 */
export type WalletCredentialCategory =
  | 'BLOOD_WORK'
  | 'PRESCRIPTIONS'
  | 'VACCINATIONS'
  | 'IMAGING'
  | 'LAB_RESULTS'
  | 'INSURANCE'
  | 'GENERAL'
  | 'IDENTITY'
  | 'PROFESSIONAL';

/**
 * The wire format of a credential held in a user's wallet.
 *
 * WHY THIS TYPE EXISTS
 * --------------------
 * `GET /api/users/me/credentials` used to return raw Prisma rows. That welded
 * the HTTP contract to the database schema: every client had to know that the
 * signed VC hides inside a column called `credentialData`, and a column rename
 * would have been a breaking API change. It also meant the SDK's `Credential`
 * type (a bare W3C VC) never matched what the server actually sent — the
 * mismatch was invisible because the SDK *casts* the response instead of
 * validating it, so `credential.issuer` was `undefined` at runtime while the
 * compiler insisted it was a string.
 *
 * The envelope separates the two things that were conflated:
 *   - `credential` — the signed W3C Verifiable Credential. Issuer-authored,
 *     cryptographically bound, and the only part that may be presented to a
 *     verifier.
 *   - everything else — wallet-local bookkeeping the VC has no room for
 *     (which row is it, has it been revoked, which folder does it live in,
 *     what did the user last do with it).
 *
 * FIELD SET
 * ---------
 * Every field below is a real column on the Prisma `Credential` model. Three
 * columns are deliberately NOT exposed: `holderUserId` (an internal FK — the
 * holder is already identified by `holderDid`), `schemaId` and `schemaVersion`
 * (internal FKs into `CredentialSchema` that no client reads). Adding a field
 * here is cheap; removing one is a breaking change, so the envelope starts
 * narrow.
 *
 * `id` is the wallet record id (a cuid) and is NOT the same as
 * `credential.id`, which is the issuer-assigned VC identifier. Endpoints that
 * take a credential id in the path take this one.
 */
export interface WalletCredential {
  /** Wallet record id (cuid). Distinct from `credential.id`. */
  id: string;
  /** DID of the wallet holding this credential. */
  holderDid: string;
  /** DID that issued it. Also present inside `credential.issuer`. */
  issuerDid: string;
  /** VC types, e.g. `["VerifiableCredential", "PrescriptionCredential"]`. */
  type: string[];
  /** Storage folder. */
  category: WalletCredentialCategory;
  /** Human-readable display name chosen at issuance. */
  name: string;
  /** Optional longer description shown in credential detail views. */
  description?: string;
  /** SHA-256 integrity hash of the stored credential. */
  credentialHash: string;
  /** Lifecycle state. Carries revocation — see {@link WalletCredentialStatus}. */
  status: WalletCredentialStatus;
  /** ISO 8601 timestamps. */
  issuedAt: string;
  expiresAt?: string;
  revokedAt?: string;
  revocationReason?: string;
  lastUsedAt?: string;
  /** How many times the holder has presented this credential. */
  useCount: number;
  createdAt: string;
  updatedAt: string;
  /**
   * The W3C Verifiable Credential itself, unwrapped from the `credentialData`
   * column. This is the *data model* only — on its own it carries no signature
   * and must never be sent to a verifier as proof of anything.
   */
  credential: VerifiableCredential;
  /**
   * The enveloping proof: the compact JWT that secures {@link credential}.
   *
   * THIS, NOT `credential`, IS WHAT GOES TO A VERIFIER. VC 2.0 separates the
   * data model from the securing mechanism, so the signature lives in this
   * envelope rather than in a `proof` property. For legacy VC 1.1 rows the same
   * string is also reachable at `credential.proof.jwt`; prefer this field,
   * which is populated for both models.
   *
   * Optional only because a credential secured by a Data Integrity (embedded)
   * proof has no envelope.
   *
   * The string is NOT always a compact JWT. When {@link credentialFormat} is
   * `vc+sd-jwt` it is a compact SD-JWT: an issuer-signed JWT followed by
   * tilde-separated disclosures. Read {@link credentialFormat} before parsing;
   * do not infer the format from the string.
   */
  credentialJwt?: string;
  /**
   * WHICH SECURING MECHANISM {@link credentialJwt} CARRIES.
   *
   * A JWT and an SD-JWT are not interchangeable to a consumer. Presenting an
   * SD-JWT requires choosing a presentation frame first; presenting a JWT does
   * not. Splitting a compact SD-JWT on `.` yields five segments rather than
   * three, so every naive JWT reader mis-parses it.
   *
   * THIS IS EXPLICIT RATHER THAN SNIFFED ON PURPOSE. The two are distinguishable
   * by structure — a `~` appears in one and not the other — but a consumer that
   * sniffs is a consumer that silently mis-handles the first artifact whose
   * shape it did not anticipate, and the failure surfaces at presentation time
   * in the holder's wallet rather than here. The issuer knows the answer at
   * issuance; it is recorded then, in the row and on the wire, and read back.
   *
   * Absent for pre-migration VC 1.1 rows, which have no enveloping proof and
   * whose signature lives at `credential.proof.jwt`. Absence therefore means
   * "legacy embedded proof", NOT "unknown" — treat it as VC 1.1 rather than
   * guessing.
   */
  credentialFormat?: CredentialFormat;
}

/** Response body of `GET /api/users/me/credentials`. */
export interface WalletCredentialList {
  credentials: WalletCredential[];
  stats: WalletCredentialStats | null;
}

/** Aggregate counts returned alongside a credential list. */
export interface WalletCredentialStats {
  total: number;
  active: number;
  expired: number;
  revoked: number;
  byCategory: Partial<Record<WalletCredentialCategory, number>>;
}

// ---------------------------------------------------------------------------
// Healthcare-Specific Credential Types
// ---------------------------------------------------------------------------

/** Categories of healthcare credentials displayed as skeuomorphic folders. */
export enum HealthcareCredentialCategory {
  BLOOD_WORK = 'blood_work',
  PRESCRIPTIONS = 'prescriptions',
  VACCINATIONS = 'vaccinations',
  IMAGING = 'imaging',
  LAB_RESULTS = 'lab_results',
  INSURANCE = 'insurance',
  GENERAL = 'general',
  MENTAL_HEALTH = 'mental_health',
  IMMUNIZATION = 'immunization',
  EMERGENCY = 'emergency',
  /** A professional licence. Maps to the Prisma PROFESSIONAL folder. */
  PROFESSIONAL = 'professional',
  /**
   * A health-card identity credential. Maps to the Prisma IDENTITY folder.
   *
   * THE MEMBER WAS MISSING and its absence was silent: three conversion tables
   * mapped the Prisma `IDENTITY` value onto `GENERAL` because there was nothing
   * else to map it to, so every ministry health card was filed under "Other"
   * — a folder no holder associates with their own identity. The wire
   * vocabulary (`WalletCredentialCategory`) and the Prisma enum both have it;
   * this was the only one that did not (measured 19 Sep 2026).
   */
  IDENTITY = 'identity',
}

/** Folder colors mapping for skeuomorphic UI (Paradigm A from thesis). */
export const CREDENTIAL_FOLDER_COLORS: Record<HealthcareCredentialCategory, string> = {
  [HealthcareCredentialCategory.BLOOD_WORK]: '#DC2626',
  [HealthcareCredentialCategory.PRESCRIPTIONS]: '#16A34A',
  [HealthcareCredentialCategory.VACCINATIONS]: '#2563EB',
  [HealthcareCredentialCategory.IMAGING]: '#9333EA',
  [HealthcareCredentialCategory.LAB_RESULTS]: '#CA8A04',
  [HealthcareCredentialCategory.INSURANCE]: '#0891B2',
  [HealthcareCredentialCategory.GENERAL]: '#6B7280',
  [HealthcareCredentialCategory.MENTAL_HEALTH]: '#7C3AED',
  [HealthcareCredentialCategory.IMMUNIZATION]: '#EA580C',
  [HealthcareCredentialCategory.EMERGENCY]: '#EF4444',
  [HealthcareCredentialCategory.PROFESSIONAL]: '#0F766E',
  [HealthcareCredentialCategory.IDENTITY]: '#0EA5E9',
};

/** A healthcare credential with domain-specific metadata. */
export interface HealthcareCredential {
  credential: VerifiableCredential;
  category: HealthcareCredentialCategory;
  displayName: string;
  issuedBy: string;
  issuedAt: string;
  expiresAt?: string;
  isRevoked: boolean;
}

// ---------------------------------------------------------------------------
// Verifiable Presentation Types
// ---------------------------------------------------------------------------

/** W3C Verifiable Presentation. */
export interface VerifiablePresentation {
  '@context': string[];
  type: string[];
  holder: string;
  verifiableCredential: VerifiableCredential[];
  proof?: Proof;
}

/** Fields the holder selects to disclose (selective disclosure). */
export interface DisclosureSelection {
  credentialId: string;
  selectedFields: string[];
}

// ---------------------------------------------------------------------------
// Consent Management Types
// ---------------------------------------------------------------------------

export enum ConsentAction {
  GRANT = 'grant',
  REVOKE = 'revoke',
  VIEW = 'view',
}

export enum ConsentPurpose {
  TREATMENT = 'treatment',
  INSURANCE_CLAIM = 'insurance_claim',
  RESEARCH = 'research',
  EMERGENCY = 'emergency',
  REFERRAL = 'referral',
}

/** A consent record representing who accessed what and when. */
export interface ConsentRecord {
  id: string;
  holderDid: string;
  verifierDid: string;
  verifierName: string;
  credentialIds: string[];
  purpose: ConsentPurpose;
  action: ConsentAction;
  timestamp: string;
  expiresAt?: string;
  isActive: boolean;
}

// ---------------------------------------------------------------------------
// Emergency Access Types (Break-Glass - Paradigm B)
// ---------------------------------------------------------------------------

export enum EmergencyAccessStatus {
  REQUESTED = 'requested',
  GRANTED = 'granted',
  EXPIRED = 'expired',
  REVOKED = 'revoked',
}

/** Emergency break-glass access record. */
export interface EmergencyAccessRecord {
  id: string;
  patientDid: string;
  providerDid: string;
  providerName: string;
  reason: string;
  status: EmergencyAccessStatus;
  credentialIdsAccessed: string[];
  requestedAt: string;
  grantedAt?: string;
  expiresAt: string;
  familyNotifiedAt?: string;
  familyContactDid?: string;
}

// ---------------------------------------------------------------------------
// API Types
// ---------------------------------------------------------------------------

/** Standard API response envelope. */
export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: ApiError;
  timestamp: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

/** OID4VCI Pre-Authorized Code offer. */
export interface CredentialOffer {
  credentialIssuer: string;
  credentials: string[];
  grants: {
    'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
      'pre-authorized_code': string;
      user_pin_required: boolean;
    };
  };
}

/** OID4VP Presentation request definition. */
export interface PresentationDefinition {
  id: string;
  name?: string;
  purpose?: string;
  inputDescriptors: InputDescriptor[];
}

export interface InputDescriptor {
  id: string;
  name?: string;
  purpose?: string;
  constraints: {
    fields: FieldConstraint[];
  };
}

export interface FieldConstraint {
  path: string[];
  filter?: {
    type: string;
    const?: string;
    enum?: string[];
  };
}

// ---------------------------------------------------------------------------
// Audit Log Types
// ---------------------------------------------------------------------------

export enum AuditEventType {
  DID_CREATED = 'did_created',
  DID_RESOLVED = 'did_resolved',
  CREDENTIAL_ISSUED = 'credential_issued',
  CREDENTIAL_REVOKED = 'credential_revoked',
  PRESENTATION_CREATED = 'presentation_created',
  PRESENTATION_VERIFIED = 'presentation_verified',
  CONSENT_GRANTED = 'consent_granted',
  CONSENT_REVOKED = 'consent_revoked',
  EMERGENCY_ACCESS_REQUESTED = 'emergency_access_requested',
  EMERGENCY_ACCESS_GRANTED = 'emergency_access_granted',
  EMERGENCY_ACCESS_DEACTIVATED = 'emergency_access_deactivated',
  KEY_EXPORTED = 'key_exported',
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILURE = 'login_failure',
}

/** Immutable audit log entry. */
export interface AuditLogEntry {
  id: string;
  eventType: AuditEventType;
  actorDid: string;
  targetDid?: string;
  description: string;
  metadata?: Record<string, unknown>;
  timestamp: string;
  ipAddress?: string;
}
