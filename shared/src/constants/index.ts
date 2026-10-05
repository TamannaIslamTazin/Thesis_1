/**
 * SSI Healthcare System - Shared Constants
 *
 * Credential schemas, DID method configurations, and system-wide constants.
 */

import { PROFESSIONAL_LICENCE_CREDENTIAL_TYPE } from '../accreditation/index.js';

// ---------------------------------------------------------------------------
// DID Method Configuration
// ---------------------------------------------------------------------------

/**
 * Sovereign network names for DID registration.
 *
 * These are OUR networks, not cheqd's. The DID *method* is still `did:cheqd`
 * — we run a fork of cheqd-node and the method spec is unchanged — but the
 * network segment names chains we operate, so nothing in this system resolves
 * to cheqd's public infrastructure.
 *
 * Constrained to `^[a-zA-Z0-9]*$` by the node's DidNamespaceRegexp, which is
 * why they are not hyphenated. Must stay in lockstep with `CheqdNetwork` in
 * @cheqd/sdk (held by a pnpm patch) and with `app_state.cheqd.did_namespace`
 * in the chain's genesis.json.
 */
export const CHEQD_NETWORKS = {
  /** Our sovereign production network. Endpoint not yet configured. */
  PRODUCTION: 'bdhealth',
  /** Our sovereign test network — chain `bd-health-trust-1`. */
  TEST: 'bdhealthtestnet',
} as const;

/**
 * Cheqd configuration for DID registration.
 *
 * `rpcUrl` previously pointed at `https://rpc.cheqd.network`, cheqd's public
 * test chain. It now points at the sovereign deployment. There is deliberately
 * no fallback to a public endpoint anywhere in the stack: @credo-ts/cheqd's
 * `DefaultRPCUrl` enum is deleted by patch, so a missing RPC URL fails loudly
 * rather than silently reaching a ledger we do not control.
 */
export const CHEQD_CONFIG = {
  network: CHEQD_NETWORKS.TEST,
  rpcUrl: 'http://localhost:26657',
  didMethod: `did:cheqd:${CHEQD_NETWORKS.TEST}` as const,
} as const;

// ---------------------------------------------------------------------------
// Credential Schema URIs
// ---------------------------------------------------------------------------

/** Standard JSON-LD contexts for Verifiable Credentials. */
export const VC_CONTEXTS = {
  W3C_CREDENTIALS_V2: 'https://www.w3.org/ns/credentials/v2',
  W3C_CREDENTIALS_V1: 'https://www.w3.org/2018/credentials/v1',
  SCHEMA_ORG: 'https://schema.org',
} as const;

/**
 * Credential format identifiers exchanged over OID4VCI / OID4VP.
 *
 * `VC_JWT` is what this system issues. It is the DIF Claim Format Registry
 * identifier for a VC 2.0 credential secured with an enveloping JWT proof, and
 * matches both Credo's `ClaimFormat.JwtW3cVc` and the `application/vc+jwt`
 * media type from W3C VC-JOSE-COSE.
 *
 * `JWT_VC_JSON` is VC Data Model 1.1 with a JWT proof — what the system issued
 * before the VC 2.0 migration. It is still ACCEPTED on request, because
 * credentials in that format are still in holders' wallets, but it is no longer
 * what gets produced. Do not conflate the two: they are different data models
 * with structurally incompatible JWT encodings, not two spellings of one thing.
 *
 * `SD_JWT_VC` is VC 2.0 secured with an enveloping SD-JWT proof — the SAME data
 * model as `VC_JWT`, secured differently so individual claims can be withheld
 * at presentation time. It is issued on request, not by default: an SD-JWT is
 * larger and is not interchangeable with a plain JWT to a consumer, so which
 * one a credential carries is recorded explicitly rather than sniffed from the
 * artifact. See `WalletCredential.credentialFormat`.
 */
export const CREDENTIAL_FORMATS = {
  /** VC 2.0, enveloping JWT proof. The default format this system issues. */
  VC_JWT: 'vc+jwt',
  /** VC 2.0, enveloping SD-JWT proof. Selective disclosure. */
  SD_JWT_VC: 'vc+sd-jwt',
  /** VC 1.1, embedded JwtProof2020. Legacy, still accepted. */
  JWT_VC_JSON: 'jwt_vc_json',
  /** VC 1.1, Data Integrity proof. Legacy, still accepted. */
  LDP_VC: 'ldp_vc',
} as const;

export type CredentialFormat =
  (typeof CREDENTIAL_FORMATS)[keyof typeof CREDENTIAL_FORMATS];

/**
 * The two VC 2.0 credential formats this system ISSUES.
 *
 * Narrower than {@link CredentialFormat}, which also names the two legacy VC
 * 1.1 formats that are accepted from elsewhere but never produced here. Use
 * this where a value must be one of the formats issuance can actually emit, so
 * that adding a third one is a compile error at every decision point rather
 * than a silent fallthrough.
 */
export type IssuableCredentialFormat =
  | typeof CREDENTIAL_FORMATS.VC_JWT
  | typeof CREDENTIAL_FORMATS.SD_JWT_VC;

/**
 * Presentation media types, the VP counterparts of {@link CREDENTIAL_FORMATS}.
 *
 * A presentation's format follows the credential it carries: Credo 0.6 refuses
 * a `vp+sd-jwt` containing a `vc+jwt` credential and vice versa, so these are
 * not independently selectable.
 */
export const PRESENTATION_FORMATS = {
  /** VC 2.0 presentation, enveloping JWT proof. */
  VP_JWT: 'vp+jwt',
  /** VC 2.0 presentation, enveloping SD-JWT proof. */
  VP_SD_JWT: 'vp+sd-jwt',
} as const;

export type PresentationFormat =
  (typeof PRESENTATION_FORMATS)[keyof typeof PRESENTATION_FORMATS];

/** Healthcare credential type URIs. */
export const CREDENTIAL_TYPES = {
  BASE: 'VerifiableCredential',
  HEALTH_RECORD: 'HealthRecordCredential',
  PRESCRIPTION: 'PrescriptionCredential',
  VACCINATION: 'VaccinationCredential',
  LAB_RESULT: 'LabResultCredential',
  INSURANCE: 'InsuranceCredential',
  BLOOD_WORK: 'BloodWorkCredential',
  IMAGING: 'ImagingCredential',
  MEMBER: 'MemberCredential',
  /**
   * Professional authority. Aliased from `accreditation/`, which owns the
   * definition — two spellings of one type name is how a verifier ends up
   * checking for a string no issuer ever writes.
   */
  PROFESSIONAL_LICENCE: PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  /** EBSI-style delegation from one authority to another. Not yet issued (#214). */
  ACCREDITATION: 'VerifiableAccreditation',
} as const;

// ---------------------------------------------------------------------------
// OID4VC Endpoints
// ---------------------------------------------------------------------------

export const OID4VC_PATHS = {
  /** OID4VCI: Token endpoint for exchanging pre-authorized codes. */
  TOKEN: '/oid4vci/token',
  /** OID4VCI: Credential issuance endpoint. */
  CREDENTIAL: '/oid4vci/credential',
  /** OID4VCI: Credential offer endpoint. */
  CREDENTIAL_OFFER: '/oid4vci/offer',
  /** OID4VP: Authorization request endpoint. */
  AUTHORIZATION: '/oid4vp/authorize',
  /** OID4VP: Presentation submission endpoint. */
  PRESENTATION: '/oid4vp/present',
} as const;

// ---------------------------------------------------------------------------
// Error Codes
// ---------------------------------------------------------------------------

export const ERROR_CODES = {
  // DID errors
  DID_CREATION_FAILED: 'DID_CREATION_FAILED',
  DID_RESOLUTION_FAILED: 'DID_RESOLUTION_FAILED',
  DID_NOT_FOUND: 'DID_NOT_FOUND',
  /** Deactivation is terminal on `x/did` — no signature can revive it (S-4 T1). */
  DID_DEACTIVATED: 'DID_DEACTIVATED',
  /**
   * The chain query service did not answer. Distinct from DID_NOT_FOUND: this
   * means "we do not know", not "no such DID" — see cheqdLedger.ts's
   * `isDefinitivelyNotFound` for why collapsing the two is a fail-open bug
   * dressed as an error message.
   */
  DID_RESOLVER_UNREACHABLE: 'DID_RESOLVER_UNREACHABLE',

  // Credential errors
  CREDENTIAL_ISSUANCE_FAILED: 'CREDENTIAL_ISSUANCE_FAILED',
  CREDENTIAL_VERIFICATION_FAILED: 'CREDENTIAL_VERIFICATION_FAILED',
  CREDENTIAL_REVOKED: 'CREDENTIAL_REVOKED',
  CREDENTIAL_EXPIRED: 'CREDENTIAL_EXPIRED',
  CREDENTIAL_NOT_FOUND: 'CREDENTIAL_NOT_FOUND',
  CREDENTIAL_ALREADY_REVOKED: 'CREDENTIAL_ALREADY_REVOKED',
  CREDENTIAL_SCHEMA_INVALID: 'CREDENTIAL_SCHEMA_INVALID',

  /**
   * Holder binding could not be established, so issuance was refused.
   *
   * A VC 2.0 credential without a `cnf` claim is a bearer token AND cannot be
   * put into a presentation at all in Credo 0.6 — it is permanently unusable.
   * Issuance therefore fails closed rather than returning 200 with an artifact
   * that is guaranteed to fail later. These two codes exist separately because
   * the correct client response differs:
   *
   *   ..._UNAVAILABLE  the resolver did not answer. Possibly transient — RETRY.
   *   ..._UNSUPPORTED  the DID resolved and has no bindable key. Retrying is
   *                    futile; the holder's DID document must change.
   */
  HOLDER_BINDING_UNAVAILABLE: 'HOLDER_BINDING_UNAVAILABLE',
  HOLDER_BINDING_UNSUPPORTED: 'HOLDER_BINDING_UNSUPPORTED',

  // Presentation errors
  PRESENTATION_INVALID: 'PRESENTATION_INVALID',
  PRESENTATION_VERIFICATION_FAILED: 'PRESENTATION_VERIFICATION_FAILED',

  // Consent errors
  CONSENT_NOT_FOUND: 'CONSENT_NOT_FOUND',
  CONSENT_EXPIRED: 'CONSENT_EXPIRED',
  CONSENT_ALREADY_REVOKED: 'CONSENT_ALREADY_REVOKED',

  // Emergency access errors
  EMERGENCY_ACCESS_DENIED: 'EMERGENCY_ACCESS_DENIED',
  EMERGENCY_ACCESS_EXPIRED: 'EMERGENCY_ACCESS_EXPIRED',

  // Auth errors
  AUTH_FAILED: 'AUTH_FAILED',
  AUTH_TOKEN_EXPIRED: 'AUTH_TOKEN_EXPIRED',
  AUTH_INSUFFICIENT_PERMISSIONS: 'AUTH_INSUFFICIENT_PERMISSIONS',
  AUTH_REQUIRED: 'AUTH_REQUIRED',

  // Security errors
  SECURITY_VIOLATION: 'SECURITY_VIOLATION',

  // Authorization errors
  AUTH_FORBIDDEN: 'AUTH_FORBIDDEN',
  WALLET_REQUIRED: 'WALLET_REQUIRED',

  /**
   * Professional authority was not proven for this request.
   *
   * Two codes, because the correct client response differs and collapsing them
   * would tell a refused professional to keep retrying:
   *
   *   ..._REQUIRED  no presentation accompanied the request. Get a challenge,
   *                 present the licence, retry — 401.
   *   ..._REFUSED   a presentation arrived and did not establish authority
   *                 (wrong profession, revoked licence, unaccredited issuer).
   *                 Retrying with the same credential cannot succeed — 403.
   */
  PROFESSIONAL_PRESENTATION_REQUIRED: 'PROFESSIONAL_PRESENTATION_REQUIRED',
  PROFESSIONAL_AUTHORITY_REFUSED: 'PROFESSIONAL_AUTHORITY_REFUSED',

  /**
   * A PUT to the keystore vault named a handle already claimed by a
   * different account's `ownerTag`. Refused rather than overwritten — see
   * `services/keystoreVault.ts` for why the handle alone cannot authorise a
   * replace.
   */
  KEYSTORE_HANDLE_CONFLICT: 'KEYSTORE_HANDLE_CONFLICT',

  /**
   * `POST /api/issuance/requests` named a document type absent from
   * `DOCUMENT_TYPES` — see `@ssi-healthcare/shared`'s `identity/documentTypes.ts`,
   * the one place the wallet's dropdown is supposed to read from.
   */
  DOCUMENT_TYPE_UNKNOWN: 'DOCUMENT_TYPE_UNKNOWN',

  /**
   * An action that only makes sense on a PENDING issuance request (withdraw,
   * approve, reject) was attempted against one already decided or withdrawn.
   */
  ISSUANCE_REQUEST_NOT_PENDING: 'ISSUANCE_REQUEST_NOT_PENDING',

  /**
   * An L1 authority roster write (OFFICER-DOCUMENT-ACCESS.md §7) collided
   * with the roster's own state: bootstrap attempted on an institution that
   * already has an active member, `POST /members` for an email already on
   * the roster, or a role/active change that would leave an institution with
   * no active ADMIN and no route left to undo it.
   */
  INSTITUTION_MEMBER_CONFLICT: 'INSTITUTION_MEMBER_CONFLICT',

  /**
   * `POST /api/issuance/requests` carried a locker capability
   * (OFFICER-DOCUMENT-ACCESS.md §6a) that is structurally malformed, or does
   * not match the submission it travels with: `iss` is not the caller's own
   * DID, `aud` is not the document type's issuing authority, `sub` is not
   * this submission's id, or `obj` does not cover every attached document's
   * locker object id. The server does not verify the SIGNATURE (it is not
   * `aud`, so it cannot) — only that the claims are self-consistent with the
   * request they were submitted alongside.
   */
  ISSUANCE_CAPABILITY_INVALID: 'ISSUANCE_CAPABILITY_INVALID',

  /**
   * `POST /api/issuance/requests` supplied a client-generated `requestId`
   * that collides with a row that already exists. The id is client-chosen
   * (round 5) so the locker capability's `sub` claim — minted before the
   * request exists server-side — can name the request it will belong to.
   * Practically unreachable at the entropy this round uses; refused rather
   * than silently overwritten if it ever happens.
   */
  ISSUANCE_REQUEST_ID_CONFLICT: 'ISSUANCE_REQUEST_ID_CONFLICT',

  /**
   * `POST /api/wallet/locker-session` or `POST /api/wallet/capability`
   * (round 5) could not complete. Both broker an operation this backend
   * performs on the caller's own behalf using the CLOUD-custodied key its
   * agent holds for `User.did` — see __docs__/frontend/WALLET-CUSTODY-NOTE.md
   * for why that broker exists at all. This code covers the broker's own
   * failure (agent has no key for this DID, the target locker refused the
   * resulting session, etc.), distinct from a caller error.
   */
  WALLET_CUSTODY_OPERATION_FAILED: 'WALLET_CUSTODY_OPERATION_FAILED',

  // General errors
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  NOT_FOUND: 'NOT_FOUND',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  RATE_LIMITED: 'RATE_LIMITED',
} as const;

// ---------------------------------------------------------------------------
// System Defaults
// ---------------------------------------------------------------------------

export const SYSTEM_DEFAULTS = {
  /** Default credential expiry in days. */
  CREDENTIAL_EXPIRY_DAYS: 365,
  /** Emergency access window in minutes. */
  EMERGENCY_ACCESS_DURATION_MINUTES: 60,
  /** Maximum selective disclosure fields per presentation. */
  MAX_DISCLOSURE_FIELDS: 50,
  /** Consent record retention in days. */
  CONSENT_RETENTION_DAYS: 730,
  /** Audit log retention in days. */
  AUDIT_LOG_RETENTION_DAYS: 1825,
  /** Rate limit: requests per minute per IP. */
  RATE_LIMIT_RPM: 60,
  /** Maximum credential size in bytes. */
  MAX_CREDENTIAL_SIZE_BYTES: 1_048_576,
} as const;
