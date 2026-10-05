/**
 * SSI Healthcare SDK
 *
 * Self-Sovereign Identity SDK for seamless SSI integration.
 * Provides an OAuth2-like experience for decentralized identity.
 *
 * @packageDocumentation
 */

// Core client
export { SSIClient } from './core/client';

// Types
export type {
  SSIClientConfig,
  StorageAdapter,
  Identity,
  PublicKey,
  CollectionStats,
  Credential,
  CredentialProof,
  CredentialStatus,
  Presentation,
  PresentationProof,
  CredentialOffer,
  PresentationRequest,
  RequestedCredential,
  CredentialPredicate,
  Consent,
  ConsentPurpose,
  AuthState,
  DisclosureSelection,
  VerificationResult,
  VerificationCheck,
  SSIEventType,
  SSIEventListener,
  SSIEvent,
  ApiResponse,
  PaginationParams,
  PaginatedResponse,
} from './types';

// Wallet credential contract — re-exported from @ssi-healthcare/shared, which
// is authoritative for it. Clients must import these from here (or from shared
// directly) rather than declaring their own copy; the local copies are what
// drifted from the server and produced runtime `undefined` dereferences.
export type {
  WalletCredential,
  WalletCredentialList,
  WalletCredentialStats,
  WalletCredentialStatus,
  WalletCredentialCategory,
  VerifiableCredential,
  CredentialSubject,
  Proof,
} from '@ssi-healthcare/shared';
export { WalletCredentialSchema } from '@ssi-healthcare/shared';

// Data-model-agnostic accessors for a credential's validity window.
//
// VC 1.1 names it issuanceDate/expirationDate and VC 2.0 names it
// validFrom/validUntil, and a wallet holding credentials from before and after
// the VC 2.0 migration sees both. Reading either name directly is how a
// credential silently renders as "Invalid Date" — always go through these.
export {
  credentialValidFrom,
  credentialValidUntil,
  CREDENTIAL_FORMATS,
  type CredentialFormat,
} from '@ssi-healthcare/shared';

// Selective disclosure — the HOLDER's half of the SD-JWT policy module.
//
// Re-exported rather than reimplemented, and this is load bearing. The wallet
// is the only place a human decides what to disclose, so the wallet is where a
// second, subtly different copy of this logic would do the most damage: a frame
// built by a divergent implementation does not fail loudly, it discloses the
// wrong thing. `packages/mobile` deliberately does not depend on
// `@ssi-healthcare/shared` directly (see the note in its types/credentials.ts),
// so this re-export is the supported route by which it reaches one
// implementation instead of writing its own.
//
// `buildDisclosureChoices` in particular carries the default that makes
// selective disclosure meaningful rather than decorative — see its docstring.
export {
  enumerateDisclosableClaims,
  buildPresentationFrame,
  presentationFrameForChoices,
  buildDisclosureChoices,
  volunteeredClaims,
  unsatisfiableRequirements,
  claimRequestsFromInputDescriptor,
  claimRequestsFromPresentationRequest,
  subjectClaimJsonPath,
  parseClaimPath,
  formatClaimPath,
  type DisclosableClaim,
  type DisclosureChoice,
  type ClaimRequirement,
  type VerifierClaimRequest,
  type SdJwtPresentationFrame,
} from '@ssi-healthcare/shared';

// Professional accreditation — the HOLDER's half.
//
// Re-exported by the same argument as the disclosure block above: the wallet
// does not depend on `@ssi-healthcare/shared` directly, and a second copy of
// "does this wallet hold a licence" written inside the app would be a copy that
// drifts. It would also be the wrong place for it — logic that cannot be
// imported without React Native present is logic no test reaches.
//
// READ `walletOffersVerifierMode`'s docstring BEFORE USING IT. It decides which
// SCREENS to show and is never an authorization decision: a wallet cannot
// establish its own authority, and R4's whole claim is that a licence is proved
// by presentation to a verifier, not asserted by the client.
export {
  professionalLicencesHeld,
  walletOffersVerifierMode,
  PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  PROFESSIONS,
  PRACTICE_SCOPES,
  type HeldCredential,
  type HeldProfessionalLicence,
  type Profession,
  type PracticeScope,
} from '@ssi-healthcare/shared';

// Authority names — resolved from the same pinned literals issuance routes on,
// so the name a holder is shown cannot drift from the authority the system
// trusts, and no network call is needed to put a name to a credential's issuer.
export { authorityDisplayName } from '@ssi-healthcare/shared';

// Local verification — the RELYING PARTY's half, and the only part of this SDK
// that establishes anything without trusting our servers.
//
// READ THE HEADER OF `verify/presentation.ts`. The short version: everything
// else in this package that has "verify" in its name asks our backend and
// returns the answer it gets, which is the same centralised trust OAuth2 has.
// `verifySdJwtPresentation` checks the issuer's signature, the holder's
// signature, the disclosure digests, the nonce, the audience and the `cnf`
// holder binding IN YOUR PROCESS, against key material YOU resolved. It is
// deliberately not a boolean and deliberately has no defaults for the inputs
// that make a replay check a replay check.
//
// Also available as `@ssi-healthcare/sdk/verify` for consumers who would rather
// not pull the crypto into a bundle that only needs the HTTP client.
export {
  verifySdJwtPresentation,
  DEFAULT_ALLOWED_ALGORITHMS,
  NOT_CHECKED,
  type VerifySdJwtPresentationOptions,
  type SdJwtPresentationVerification,
  type SdJwtPresentationChecks,
  type VerifiedSdJwtCredential,
  type ResolveVerificationKey,
  type VerificationJwk,
} from './verify';

// Vanilla JS API
export { createSSI, SSISignInButton, type VanillaSSI } from './vanilla';

// Webhook utilities
export {
  verifyWebhookSignature,
  createWebhookHandler,
  webhookMiddleware,
  WebhookEventSchema,
  ConsentGrantedDataSchema,
  ConsentRevokedDataSchema,
  type WebhookEventType,
  type WebhookEvent,
  type WebhookHandlers,
  type ConsentGrantedData,
  type ConsentRevokedData,
  type ConsentExpiredData,
  type CredentialReceivedData,
  type CredentialExpiredData,
  type CredentialRevokedData,
  type PresentationCreatedData,
  type PresentationVerifiedData,
  type EmergencyAccessRequestedData,
  type EmergencyAccessGrantedData,
} from './webhooks';

// Utility functions
export {
  base64UrlEncode,
  base64UrlDecode,
  base64UrlDecodeString,
  decodeJwtPayload,
  isJwtExpired,
  withRetry,
  sleep,
  didMethod,
  isValidDid,
  isObject,
  isNonEmptyString,
  type RetryOptions,
} from './utils';

// Issuer (OID4VCI) — for hospitals, clinics, labs acting as VC issuers
export { IssuerAgent } from './issuer/IssuerAgent';
export { createIssuerRouter, createIssuerWellKnown } from './issuer/express';
export type { IssuerRouterOptions } from './issuer/express';
export type {
  IssuerConfig,
  IssuerMetadata,
  OID4VCICredentialOffer,
  CredentialSupportedEntry,
  TokenRequest,
  TokenResponse,
  CredentialRequest,
  CredentialResponse,
  W3CCredential,
  HealthcareCredentialType,
} from './issuer/types';
export {
  PatientProfileSubjectSchema,
  VitalSignsSubjectSchema,
  PrescriptionSubjectSchema,
  AppointmentDiagnosisSubjectSchema,
  ImmunizationSubjectSchema,
  DischargeSummarySubjectSchema,
} from './issuer/schemas';
export type {
  PatientProfileSubject,
  VitalSignsSubject,
  PrescriptionSubject,
  AppointmentDiagnosisSubject,
  ImmunizationSubject,
  DischargeSummarySubject,
} from './issuer/schemas';

// Version
export const VERSION = '0.1.0';
