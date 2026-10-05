/**
 * SSI Healthcare SDK - Core Types
 *
 * Type definitions for the SSI SDK, providing an OAuth2-like
 * experience for Self-Sovereign Identity operations.
 */

/** Configuration for initializing the SSI client */
export interface SSIClientConfig {
  /** Backend API endpoint */
  apiUrl: string;

  /** Application/Client ID for identification */
  clientId: string;

  /** Redirect URI after authentication */
  redirectUri?: string;

  /** Scopes requested (credential types) */
  scopes?: string[];

  /** Enable debug logging */
  debug?: boolean;

  /** Storage adapter for session data */
  storage?: StorageAdapter;

  /** Custom fetch implementation */
  fetch?: typeof fetch;

  /** Timeout in milliseconds for API requests */
  timeout?: number;

  /**
   * Refresh the session through the integrating app instead of from this client.
   *
   * A host app commonly has its own HTTP client against the same API, and the
   * backend keeps ONE access token per session. Two independent refreshers
   * therefore invalidate each other: whichever rotation the server applies
   * second is the only token it still accepts, and the other client's next
   * request 401s with a token that was valid a moment earlier (measured
   * 19 Sep 2026, steno #437). Supplying this hook makes the host's
   * single-flight refresher the ONLY refresher; the SDK adopts its result.
   *
   * Return null when the session cannot be renewed — the SDK treats that as a
   * failed refresh. Omit for a standalone client, which refreshes itself.
   */
  refreshAccessToken?: () => Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresIn?: number;
  } | null>;

  /**
   * JWT verification mode:
   * - 'strict': Verify JWT signatures (requires JWKS endpoint or public key)
   * - 'permissive': Only decode and validate structure (warns on issues)
   * @default 'permissive'
   */
  jwtVerification?: 'strict' | 'permissive';

  /**
   * JWKS URI for JWT signature verification (required if jwtVerification is 'strict')
   * Usually: {issuer}/.well-known/jwks.json
   */
  jwksUri?: string;

  /**
   * Validation mode for protocol messages:
   * - 'strict': Throw errors on validation failures
   * - 'permissive': Log warnings but continue (for interoperability)
   * @default 'permissive'
   */
  validationMode?: 'strict' | 'permissive';
}

/** Storage adapter interface for session persistence */
export interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

/** User/Wallet identity representation — matches backend User shape from /auth/me */
export interface Identity {
  /** Database user ID */
  id?: string;

  /** User's email */
  email?: string;

  /** First name */
  firstName?: string;

  /** Last name */
  lastName?: string;

  /** Display name */
  displayName?: string;

  /** Decentralized Identifier */
  did?: string;

  /** Wallet type (CLOUD, DEVICE, HARDWARE, HYBRID) */
  walletType?: string;

  /** Human-readable label */
  label?: string;

  /** Public keys associated with this identity */
  publicKeys?: PublicKey[];

  /** Whether TOTP is enabled */
  totpEnabled?: boolean;

  /** Whether biometric auth is enabled */
  biometricEnabled?: boolean;

  /** Auto-lock timeout in minutes */
  autoLockMinutes?: number;

  /** When the identity was created */
  createdAt?: string;

  /** When the identity was last updated */
  updatedAt?: string;
}

/** Stats returned alongside credential/consent/presentation lists */
export interface CollectionStats {
  total?: number;
  active?: number;
  expired?: number;
  revoked?: number;
  [key: string]: unknown;
}

/** Public key information */
export interface PublicKey {
  id: string;
  type: 'Ed25519' | 'X25519' | 'P-256' | 'P-384';
  controller: string;
  publicKeyMultibase: string;
}

/** Verifiable Credential */
export interface Credential {
  /** Unique credential ID */
  id: string;

  /** Credential type(s) */
  type: string[];

  /** Issuer DID or object */
  issuer: string | { id: string; name?: string };

  /**
   * When the credential was issued (VC Data Model 1.1 only).
   *
   * Absent on VC 2.0 credentials, which use {@link validFrom}. Use
   * `credentialValidFrom()` rather than reading either name directly.
   */
  issuanceDate?: string;

  /** When the credential expires (VC 1.1 only). See {@link validUntil}. */
  expirationDate?: string;

  /** Start of the validity window (VC 2.0). Absent on VC 1.1 credentials. */
  validFrom?: string;

  /** End of the validity window (VC 2.0). Absent on VC 1.1 credentials. */
  validUntil?: string;

  /** Credential subject/claims */
  credentialSubject: Record<string, unknown>;

  /** Cryptographic proof */
  proof?: CredentialProof;

  /** Credential status for revocation checks */
  credentialStatus?: CredentialStatus;
}

/** Cryptographic proof on a credential */
export interface CredentialProof {
  type: string;
  created: string;
  proofPurpose: string;
  verificationMethod: string;
  proofValue?: string;
  jws?: string;
}

/** Status method for revocation checking */
export interface CredentialStatus {
  id: string;
  type: string;
  revocationListIndex?: string;
  revocationListCredential?: string;
}

/** Presentation of credentials */
export interface Presentation {
  /** Context */
  '@context': string[];

  /** Presentation type */
  type: string[];

  /** Holder DID */
  holder?: string;

  /** Included credentials */
  verifiableCredential: Credential[];

  /** Cryptographic proof */
  proof?: PresentationProof;
}

/** Proof on a presentation */
export interface PresentationProof {
  type: string;
  created: string;
  proofPurpose: string;
  verificationMethod: string;
  challenge?: string;
  domain?: string;
  proofValue?: string;
  jws?: string;
}

/** OID4VCI Credential Offer */
export interface CredentialOffer {
  /** Unique offer ID (from backend database) */
  id: string;

  /** Credential issuer identifier */
  credential_issuer: string;

  /** Grant types available */
  grants?: {
    'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: {
      'pre-authorized_code': string;
      user_pin_required?: boolean;
    };
    authorization_code?: {
      issuer_state?: string;
    };
  };

  /** Credential configuration IDs */
  credential_configuration_ids: string[];
}

/** OID4VP Presentation Request */
export interface PresentationRequest {
  /** Request ID */
  id: string;

  /** Verifier DID/identifier */
  verifier: string;

  /** Purpose of the verification */
  purpose: string;

  /** Requested credential types */
  requestedCredentials: RequestedCredential[];

  /** Challenge nonce */
  nonce: string;

  /** Response destination */
  responseUri: string;

  /** Expiration timestamp */
  expiresAt?: string;
}

/** Individual credential request */
export interface RequestedCredential {
  /** Credential type requested */
  type: string;

  /** Specific attributes requested */
  attributes?: string[];

  /** Whether this credential is required */
  required: boolean;

  /** Predicates for ZKP proofs */
  predicates?: CredentialPredicate[];
}

/** Predicate for zero-knowledge proofs */
export interface CredentialPredicate {
  attribute: string;
  predicate: '>' | '<' | '>=' | '<=' | '==' | '!=';
  value: string | number;
}

/** Consent record for data sharing */
export interface Consent {
  /** Unique consent ID */
  id: string;

  /** Holder user ID */
  holderUserId?: string;

  /** Holder DID (data owner) */
  holderDid: string;

  /** Verifier DID (data recipient) */
  verifierDid: string;

  /** Verifier name for display */
  verifierName: string;

  /** Credential types shared */
  credentialTypes: string[];

  /** Specific credential IDs */
  credentialIds: string[];

  /** Specific attributes shared */
  attributes: string[];

  /** Purpose of sharing */
  purpose: ConsentPurpose;

  /** Additional purpose detail */
  purposeDetail?: string;

  /** When consent was granted */
  grantedAt: string;

  /** When consent expires */
  expiresAt?: string;

  /** Whether consent is active */
  isActive: boolean;

  /** When consent was revoked */
  revokedAt?: string;

  /** Reason for revocation */
  revokedReason?: string;
}

/** Consent purpose enum matching backend ConsentPurpose */
export type ConsentPurpose =
  | 'TREATMENT'
  | 'PAYMENT'
  | 'OPERATIONS'
  | 'RESEARCH'
  | 'EMERGENCY'
  | 'PUBLIC_HEALTH'
  | 'LEGAL'
  | 'INSURANCE'
  | 'OTHER';

/** Activity/audit log item */
export interface ActivityItem {
  id: string;
  type: string;
  action: string;
  timestamp: string;
  actorDid?: string;
  targetDid?: string;
  resourceType?: string;
  resourceId?: string;
  details?: Record<string, unknown>;
}

/** Authentication state */
export interface AuthState {
  /** Whether user is authenticated */
  isAuthenticated: boolean;

  /** User's identity if authenticated */
  identity?: Identity;

  /** Access token for API calls */
  accessToken?: string;

  /** Refresh token for session renewal */
  refreshToken?: string;

  /** Token expiration timestamp */
  expiresAt?: number;

  /** Whether authentication is in progress */
  isLoading: boolean;

  /** Any authentication error */
  error?: Error;
}

/** Selective disclosure selection */
export interface DisclosureSelection {
  /** Credential ID */
  credentialId: string;

  /** Selected attributes to disclose */
  attributes: string[];

  /** Predicates to prove */
  predicates?: CredentialPredicate[];
}

/** Verification result */
export interface VerificationResult {
  /** Whether verification succeeded */
  verified: boolean;

  /** Credential that was verified */
  credential?: Credential;

  /** Error message if failed */
  error?: string;

  /** Detailed checks performed */
  checks: VerificationCheck[];
}

/** Individual verification check */
export interface VerificationCheck {
  check: 'signature' | 'expiration' | 'revocation' | 'issuer' | 'schema';
  status: 'passed' | 'failed' | 'skipped';
  message?: string;
}

/** Event types emitted by the SDK */
export type SSIEventType =
  | 'auth:login'
  | 'auth:logout'
  | 'auth:stateChanged'
  | 'credential:received'
  | 'credential:deleted'
  | 'presentation:request'
  | 'presentation:shared'
  | 'consent:granted'
  | 'consent:revoked'
  | 'error';

/** Event payload */
export interface SSIEvent<T = unknown> {
  type: SSIEventType;
  timestamp: number;
  payload: T;
}

/** Event listener function */
export type SSIEventListener<T = unknown> = (event: SSIEvent<T>) => void;

/** API response wrapper */
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
}

/** Pagination parameters */
export interface PaginationParams {
  page?: number;
  limit?: number;
  cursor?: string;
}

/** Active session record returned by /users/me/sessions */
export interface SessionInfo {
  id: string;
  userAgent: string | null;
  deviceName: string | null;
  ipAddress: string | null;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

/** Paginated response */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  hasMore: boolean;
  nextCursor?: string;
}
