/**
 * OID4VCI (OpenID for Verifiable Credential Issuance) types for the SDK IssuerAgent.
 * Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 */

// ---------------------------------------------------------------------------
// Issuer Configuration
// ---------------------------------------------------------------------------

export interface IssuerConfig {
  /** DID of the issuer (e.g. did:key:z6Mk...) */
  issuerDid: string;
  /** Human-readable issuer name shown in wallet UIs */
  issuerName: string;
  /** Base URL for the issuer's OID4VCI endpoints (e.g. http://hospital.local:5000) */
  issuerUrl: string;
  /** Ed25519 private key as JWK */
  privateKeyJwk: JsonWebKey;
  /** Ed25519 public key as JWK */
  publicKeyJwk: JsonWebKey;
  /** Credential types this issuer supports */
  supportedCredentialTypes: HealthcareCredentialType[];
  /** Pre-auth code TTL in seconds (default: 300) */
  offerTtlSeconds?: number;
  /**
   * Resolve a holder DID to the absolute DID URL of a key the credential can be
   * bound to (the `cnf.kid` of the issued credential).
   *
   * WHY THIS IS A HOOK AND NOT A BUILT-IN RESOLVER.
   *
   * A VC 2.0 credential MUST carry a holder binding or it is both a bearer
   * token and — in Credo 0.6, the verifier this project targets — impossible to
   * present at all. So the issuer has to know the holder's key.
   *
   * The SDK resolves `did:key` itself, because that method encodes its key in
   * the identifier and needs no network. Every other method requires a
   * resolver, and an issuing library has no business choosing one for the
   * integrator: it would mean shipping a universal-resolver dependency, a
   * network policy, and a trust decision that belong to the deployment.
   *
   * Supply this to issue to `did:web`, `did:cheqd`, `did:ion` and friends.
   * Without it, issuance to those methods FAILS CLOSED rather than emitting an
   * unpresentable credential.
   *
   * Return `null` if the DID cannot be resolved or has no bindable key.
   */
  resolveHolderBinding?: (holderDid: string) => Promise<string | null> | string | null;
}

// ---------------------------------------------------------------------------
// Healthcare VC Types
// ---------------------------------------------------------------------------

export type HealthcareCredentialType =
  | 'PatientProfileCredential'
  | 'VitalSignsCredential'
  | 'PrescriptionCredential'
  | 'AppointmentDiagnosisCredential'
  | 'LabResultCredential'
  | 'ImmunizationCredential'
  | 'DischargeSummaryCredential';

// ---------------------------------------------------------------------------
// W3C Verifiable Credential structure
// ---------------------------------------------------------------------------

/**
 * A W3C Verifiable Credential in either data model.
 *
 * The validity window is named differently in each — VC 1.1 uses
 * `issuanceDate`/`expirationDate`, VC 2.0 uses `validFrom`/`validUntil` — so
 * both pairs are optional and exactly one is present on a given credential.
 * Read them with `credentialValidFrom()` / `credentialValidUntil()`.
 */
export interface W3CCredential {
  '@context': string[];
  type: string[];
  id?: string;
  issuer: string | { id: string; name?: string };
  /** VC 1.1 only. */
  issuanceDate?: string;
  /** VC 1.1 only. */
  expirationDate?: string;
  /** VC 2.0 only. */
  validFrom?: string;
  /** VC 2.0 only. */
  validUntil?: string;
  credentialSubject: Record<string, unknown> & { id?: string };
  credentialStatus?: {
    id: string;
    type: string;
  };
}

// ---------------------------------------------------------------------------
// OID4VCI: Issuer Metadata (/.well-known/openid-credential-issuer)
// ---------------------------------------------------------------------------

export interface CredentialDisplay {
  name: string;
  locale?: string;
  logo?: { url: string; alt_text?: string };
  background_color?: string;
  text_color?: string;
  description?: string;
}

export interface CredentialSupportedEntry {
  format: 'vc+jwt' | 'jwt_vc_json' | 'ldp_vc';
  id: string;
  types: string[];
  display?: CredentialDisplay[];
  cryptographic_binding_methods_supported?: string[];
  cryptographic_suites_supported?: string[];
}

export interface IssuerMetadata {
  credential_issuer: string;
  credential_endpoint: string;
  token_endpoint: string;
  credentials_supported: CredentialSupportedEntry[];
  display?: { name: string; locale?: string }[];
}

// ---------------------------------------------------------------------------
// OID4VCI: Credential Offer
// ---------------------------------------------------------------------------

export interface CredentialOfferGrants {
  'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
    'pre-authorized_code': string;
    user_pin_required: boolean;
  };
}

export interface OID4VCICredentialOffer {
  credential_issuer: string;
  credentials: string[];
  grants: CredentialOfferGrants;
}

// Stored internally alongside the offer
export interface PendingOffer {
  offerId: string;
  preAuthCode: string;
  credentialType: HealthcareCredentialType;
  credentialSubject: Record<string, unknown>;
  subjectDid?: string;
  expiresAt: number;
  used: boolean;
}

// Stored for issued access tokens
export interface IssuanceSession {
  accessToken: string;
  offerId: string;
  credentialType: HealthcareCredentialType;
  credentialSubject: Record<string, unknown>;
  subjectDid?: string;
  expiresAt: number;
  issued: boolean;
}

export interface TokenRequest {
  grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  'pre-authorized_code': string;
  user_pin?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  c_nonce?: string;
  c_nonce_expires_in?: number;
}

// ---------------------------------------------------------------------------
// OID4VCI: Credential endpoint
// ---------------------------------------------------------------------------

export interface ProofOfPossession {
  proof_type: 'jwt';
  jwt: string;
}

export interface CredentialRequest {
  /**
   * Legacy VC 1.1 identifiers are still accepted from older clients; the
   * issuer emits VC 2.0 regardless and says so in the response.
   */
  format: 'vc+jwt' | 'jwt_vc_json';
  types: string[];
  proof?: ProofOfPossession;
}

export interface CredentialResponse {
  /** Always the format actually issued, not the one requested. */
  format: 'vc+jwt';
  /** The compact JWT enveloping the VC 2.0 credential. */
  credential: string;
}

// Stored for issued access tokens
export interface IssuanceSession {
  accessToken: string;
  offerId: string;
  credentialType: HealthcareCredentialType;
  credentialSubject: Record<string, unknown>;
  subjectDid?: string;
  expiresAt: number;
  issued: boolean;
}
