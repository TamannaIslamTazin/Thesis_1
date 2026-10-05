/**
 * SSI Healthcare Mobile - Domain Types
 *
 * TypeScript interfaces for all domain models.
 * These match the backend API responses and shared types.
 */

// -- Verifiable Credential Types --

/**
 * The W3C credential types come from `@ssi-healthcare/shared` (via the SDK),
 * which is authoritative for them. They are re-exported rather than redeclared:
 * the local copies used to insist `proof.created` and `proof.proofValue` were
 * required, which describes a Data Integrity proof. Every credential this
 * system issues is a JWT-VC whose proof is `{ type, jwt }`, so the local types
 * described a credential that never arrives.
 */
import type { VerifiableCredential } from '@ssi-healthcare/sdk';

export type {
  VerifiableCredential,
  CredentialSubject,
  Proof as CredentialProof,
} from '@ssi-healthcare/sdk';

/**
 * Issuer as shown in mobile UI. Local because `image` is a display concern the
 * wire contract does not carry.
 */
export interface Issuer {
  id: string;
  name?: string;
  image?: string;
}

export type CredentialCategory =
  | 'medical_record'
  | 'vaccination'
  | 'prescription'
  | 'lab_result'
  | 'insurance'
  | 'emergency'
  | 'identity'
  | 'other';

export type CredentialStatus = 'valid' | 'expired' | 'revoked' | 'pending';

export interface Credential {
  id: string;
  type: string;
  category: CredentialCategory;
  issuer: Issuer;
  issuanceDate: string;
  expirationDate?: string;
  status: CredentialStatus;
  verifiableCredential: VerifiableCredential;
  /**
   * The ENVELOPING PROOF — the compact JWT that secures this credential.
   *
   * This is the single most important field on a VC 2.0 credential and the
   * easiest one to lose, because losing it costs nothing at compile time and
   * everything at presentation time.
   *
   * VC 2.0 moved the securing mechanism OUT of the credential body: there is no
   * `proof` member, and `verifiableCredential` above is therefore the UNSIGNED
   * data model. It is fine to render — it is what the detail screen reads — but
   * it cannot be verified or presented by itself. The signature lives only
   * here, in the compact JWT the issuer returned.
   *
   * Optional because pre-migration VC 1.1 credentials carry their signature
   * inside `verifiableCredential.proof` instead and have no envelope. Those
   * still exist in the database, so a client must handle both.
   *
   * Anything that presents, verifies, or key-binds this credential must read
   * this field. Passing `verifiableCredential` to a verifier instead yields an
   * unsigned object that will be rejected — with an error that points at the
   * verifier rather than at the wallet that dropped the envelope.
   */
  credentialJwt?: string;
  metadata?: {
    displayName?: string;
    description?: string;
    backgroundColor?: string;
    textColor?: string;
    logo?: string;
  };
}

// -- Credential Field for Selective Disclosure --

export interface CredentialField {
  id: string;
  label: string;
  value: string;
  disclosed: boolean;
  required?: boolean;
  sensitive?: boolean;
}

// -- Credential Folder for Organization --

export interface CredentialFolder {
  id: string;
  name: string;
  category: CredentialCategory;
  icon: string;
  count: number;
  color: string;
  lastUpdated?: string;
}

// -- Consent Types --

export type ConsentStatus = 'active' | 'revoked' | 'expired' | 'pending';

export interface ConsentPurpose {
  id: string;
  name: string;
  description?: string;
}

export interface ConsentScope {
  id: string;
  name: string;
  description?: string;
  dataTypes: string[];
}

export interface Consent {
  id: string;
  requesterId: string;
  requesterName: string;
  requesterLogo?: string;
  purpose: ConsentPurpose;
  scope: ConsentScope;
  status: ConsentStatus;
  createdAt: string;
  expiresAt?: string;
  revokedAt?: string;
  accessCount?: number;
  /** False when this records a completed disclosure rather than ongoing access. */
  standingAccess?: boolean;
  lastAccessedAt?: string;
}

// -- Emergency Access Types --

export type EmergencyStatus = 'granted' | 'expired' | 'revoked' | 'pending';

export interface EmergencyContact {
  id: string;
  name: string;
  relationship: string;
  phone: string;
  email?: string;
  canAccessRecords: boolean;
}

export interface EmergencyAccessLog {
  id: string;
  accessorId: string;
  accessorName: string;
  accessorRole: string;
  timestamp: string;
  recordsAccessed: string[];
  location?: string;
  reason?: string;
}

export interface EmergencyRecord {
  id: string;
  providerName: string;
  reason: string;
  status: EmergencyStatus;
  requestedAt: string;
  expiresAt: string;
  familyNotified: boolean;
  credentialsAccessed?: string[];
}

export interface EmergencyProfile {
  id: string;
  userId: string;
  enabled: boolean;
  pin?: string;
  contacts: EmergencyContact[];
  records: EmergencyRecord[];
  accessLogs: EmergencyAccessLog[];
}

// -- User Types --

export interface UserProfile {
  id: string;
  did: string;
  email?: string;
  name?: string;
  avatar?: string;
  createdAt: string;
  biometricEnabled: boolean;
  notificationsEnabled: boolean;
}

// -- Activity Log Types --

export type ActivityKind =
  | 'credential_issued'
  | 'credential_shared'
  | 'credential_verified'
  | 'credential_revoked'
  | 'consent_granted'
  | 'consent_revoked'
  | 'verification_request'
  | 'emergency_access'
  | 'login'
  | 'logout'
  | 'backup_created'
  | 'recovery_completed'
  | 'other';

export interface ActivityItem {
  id: string;
  /**
   * ONE vocabulary for activity kinds, shared by the store that maps audit
   * events and the screen that renders them.
   *
   * There were two. `ActivityLogScreen` declared its own ten-value union and
   * keyed its icon/colour table on that, while the store mapped backend events
   * onto this six-value one — and the screen fetched the API directly with an
   * `as ActivityItem[]` cast, so nothing ever compared them. The overlap was
   * partial: the store emitted `verification_request` and `credential_shared`,
   * for which the table had no entry, and the screen read `config.color` off
   * `undefined`. Every presentation event crashed the audit log, which is the
   * screen a holder opens to find out who received their data.
   */
  type: ActivityKind;
  title: string;
  description: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

// -- API Response Types --

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

// -- Navigation Types --

// THE ONE HOME for navigation types. `App.tsx` used to declare its own copies
// of all three lists; they drifted (its CredentialStackParamList never gained
// `CredentialsByCategory`, so registering that screen failed to compile while
// the type next to it said the route existed), and a screen importing from
// `../../App` got a different shape than one importing from here. The navigator
// and its screens must read the same declaration or the compiler defends the
// wrong contract.
export type RootStackParamList = {
  Onboarding: undefined;
  Auth: undefined;
  NewDeviceRestore: undefined;
  MainTabs: undefined;
  /** `mode` is optional so the scanner can be opened as a plain scan. */
  Scanner: { mode?: 'receive' | 'share' } | undefined;
  ActivityLog: undefined;
  /** Emergency access, reached from the Consent screen (A2 follow-up). */
  EmergencyAccess: undefined;
  DocumentSubmission: undefined;
  SubmissionStatus: { focusRequestId?: string } | undefined;
  PassphraseSetup: undefined;
  EnrolmentRecovery: undefined;
};

export type RootTabParamList = {
  HomeTab: undefined;
  CredentialsTab: undefined;
  ScanTab: undefined;
  /** Present ONLY for a wallet holding a usable professional licence. */
  VerifyTab: undefined;
  ConsentTab: undefined;
  /** Medicine balances: the tab the Emergency tab used to occupy. */
  MedicineBalanceTab: undefined;
  SettingsTab: undefined;
};

export type CredentialStackParamList = {
  CredentialsList: undefined;
  CredentialDetail: { credentialId: string };
  CredentialsByCategory: { category: CredentialCategory };
};

// -- OID4VCI/OID4VP Types --

export interface CredentialOffer {
  credentialOfferId: string;
  issuer: string;
  credentialType: string;
  preAuthorizedCode?: string;
  expiresAt: string;
}

export interface PresentationRequest {
  requestId: string;
  verifier: string;
  verifierName: string;
  purpose: string;
  requestedFields: string[];
  expiresAt: string;
}

// -- Quick Action Types --

export interface QuickAction {
  id: string;
  icon: string;
  label: string;
  color: string;
  route?: keyof RootStackParamList | keyof RootTabParamList;
  action?: () => void;
}
