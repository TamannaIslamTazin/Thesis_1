import type { LockerCapabilityToken } from '@ssi-healthcare/shared';

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: { code: string; message: string; details?: Record<string, unknown> };
  timestamp: string;
}

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details?: Record<string, unknown>;

  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const SESSION_KEY = 'issuer_console_session';

export interface StoredSession {
  token: string;
  refreshToken: string;
  expiresAt: number;
}

export function getSession(): StoredSession | null {
  if (typeof window === 'undefined') return null;
  const raw = window.sessionStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as StoredSession;
  } catch {
    return null;
  }
}

export function setSession(session: StoredSession | null): void {
  if (typeof window === 'undefined') return;
  if (session) {
    window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  } else {
    window.sessionStorage.removeItem(SESSION_KEY);
  }
}

async function request<T>(path: string, init: RequestInit = {}, opts: { auth?: boolean } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');

  if (opts.auth !== false) {
    const session = getSession();
    if (!session) {
      throw new ApiError(401, 'AUTH_REQUIRED', 'Not signed in.');
    }
    headers.set('Authorization', `Bearer ${session.token}`);
  }

  const res = await fetch(path, { ...init, headers });
  const body = (await res.json().catch(() => null)) as ApiResponse<T> | null;

  if (!res.ok || !body || body.success !== true) {
    const code = body?.error?.code ?? 'UNKNOWN_ERROR';
    const message = body?.error?.message ?? `Request to ${path} failed with status ${res.status}.`;
    throw new ApiError(res.status, code, message, body?.error?.details);
  }

  return body.data as T;
}

// ---------------------------------------------------------------------------
// Auth: email + one-time code (packages/backend/src/routes/auth.ts)
// ---------------------------------------------------------------------------

export interface LoginResult {
  pendingToken: string;
  expiresIn: number;
  isNewUser: boolean;
}

export function login(email: string): Promise<LoginResult> {
  return request<LoginResult>('/api/auth/login', { method: 'POST', body: JSON.stringify({ email }) }, { auth: false });
}

export interface VerifyCodeResult {
  user: { id: string; email: string | null; firstName: string | null; lastName: string | null; did: string | null };
  token: string;
  refreshToken: string;
  expiresIn: number;
}

export function verifyCode(pendingToken: string, code: string): Promise<VerifyCodeResult> {
  return request<VerifyCodeResult>(
    '/api/auth/verify-code',
    { method: 'POST', body: JSON.stringify({ pendingToken, code }) },
    { auth: false },
  );
}

export interface CurrentUser {
  id: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
}

export function getCurrentUser(): Promise<CurrentUser> {
  return request<CurrentUser>('/api/auth/me', { method: 'GET' });
}

// ---------------------------------------------------------------------------
// Authority roster (packages/backend/src/routes/authorityMembers.ts)
// ---------------------------------------------------------------------------

export type AuthorityRole = 'OFFICER' | 'ADMIN';

export interface AuthorityMember {
  id: string;
  email: string;
  name: string;
  role: AuthorityRole;
  isActive: boolean;
  invitedAt: string;
  acceptedAt: string | null;
}

export function bootstrapAuthority(institutionId: string, bootstrapSecret: string): Promise<AuthorityMember> {
  return request<AuthorityMember>(
    '/api/authority/bootstrap',
    {
      method: 'POST',
      headers: { 'X-Authority-Bootstrap-Secret': bootstrapSecret },
      body: JSON.stringify({ institutionId }),
    },
  );
}

export function listMembers(): Promise<{ members: AuthorityMember[] }> {
  return request<{ members: AuthorityMember[] }>('/api/authority/members', { method: 'GET' });
}

export interface AuthorityMe {
  member: { id: string; email: string; name: string; role: AuthorityRole };
  institution: { id: string; did: string; name: string; type: string };
}

/** GET /api/authority/me — round 5. Replaces the message-parsing workaround
 * `authorityIdentity.ts` used to need (ISSUER-CONSOLE-BUILD-NOTES.md §1). */
export function getMe(): Promise<AuthorityMe> {
  return request<AuthorityMe>('/api/authority/me', { method: 'GET' });
}

export function addMember(input: { email: string; name: string; role: AuthorityRole }): Promise<AuthorityMember> {
  return request<AuthorityMember>('/api/authority/members', { method: 'POST', body: JSON.stringify(input) });
}

export function updateMember(
  id: string,
  input: { role?: AuthorityRole; isActive?: boolean },
): Promise<AuthorityMember> {
  return request<AuthorityMember>(`/api/authority/members/${id}`, { method: 'PATCH', body: JSON.stringify(input) });
}

// ---------------------------------------------------------------------------
// Queue and review (packages/backend/src/routes/authority.ts)
// ---------------------------------------------------------------------------

export interface QueueDocument {
  id: string;
  lockerObjectId: string;
  contentHash: string;
  mediaType: string;
}

export interface QueueEntry {
  id: string;
  documentType: string;
  holderDid: string;
  holder: { id: string; firstName: string | null; lastName: string | null; email: string | null };
  documents: QueueDocument[];
  createdAt: string;
  keyReleased: boolean;
}

export function getQueue(): Promise<{ requests: QueueEntry[] }> {
  return request<{ requests: QueueEntry[] }>('/api/authority/queue', { method: 'GET' });
}

/** The shape carried by wrappedContentKeyShape in services/issuance.ts. */
export interface WrappedContentKey {
  version: 1;
  wrappedToVerificationMethodId: string;
  ephemeralPublicKey?: string;
  nonce?: string;
  salt?: string;
  ciphertext: string;
}

export interface RequestDetail {
  id: string;
  documentType: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'WITHDRAWN';
  holderDid: string;
  holder: { id: string; firstName: string | null; lastName: string | null; email: string | null };
  documents: QueueDocument[];
  createdAt: string;
  keyReleased: boolean;
  /**
   * Present ONLY on the HTTP response that performed the release. This
   * client-side type says so; the component that reads it must not assume
   * the field survives a second call for the same id — see
   * src/lib/singleUseKey.ts.
   */
  wrappedContentKey?: WrappedContentKey;
  /**
   * The holder's locker read capability (OFFICER-DOCUMENT-ACCESS.md §6a,
   * round 5). Present on EVERY read, unlike `wrappedContentKey` — it is
   * time-bounded, not single-use, so an officer re-opening this page mid-
   * review must still be able to read the document.
   */
  lockerCapability: LockerCapabilityToken;
}

export function getRequestDetail(id: string): Promise<RequestDetail> {
  return request<RequestDetail>(`/api/authority/requests/${id}`, { method: 'GET' });
}

export function approveRequest(id: string, claims?: Record<string, unknown>): Promise<{ id: string; status: string; offerId: string }> {
  return request(`/api/authority/requests/${id}/approve`, { method: 'POST', body: JSON.stringify({ claims }) });
}

export function rejectRequest(id: string, reason: string): Promise<{ id: string; status: string; reason: string }> {
  return request(`/api/authority/requests/${id}/reject`, { method: 'POST', body: JSON.stringify({ reason }) });
}

// ===========================================================================
// L2 institution onboarding
// ===========================================================================
// The officer shows a QR; the institution's software scans it; the officer then
// confirms what they verified on site and the DID is minted. The QR PAIRS and
// authorises nothing — see packages/backend/src/routes/institutionOnboarding.ts.

export interface CreatedEnrolment {
  /** Used to poll and to complete. The token is a bearer secret; this is a handle. */
  enrolmentId: string;
  /** The secret that goes in the QR. Single-use, ten minutes. */
  token: string;
  expiresAt: string;
  authorityId: string;
}

export interface EnrolmentStatus {
  id: string;
  status: 'PENDING' | 'CLAIMED' | 'COMPLETED' | 'EXPIRED' | 'REVOKED';
  /** The software that scanned it, so the officer can see WHICH machine. */
  claimedBy: string | null;
  claimedAt: string | null;
  expiresAt: string;
  institutionId: string | null;
}

export interface InstitutionDetails {
  name: string;
  type: 'HOSPITAL' | 'CLINIC' | 'PHARMACY' | 'LABORATORY';
  /** What the officer read off the premises. Recorded as the attestation. */
  address: string;
  licenceNumber?: string;
  phone?: string;
  email?: string;
}

export interface MintedInstitution {
  institutionId: string;
  name: string;
  type: string;
  isVerified: boolean;
  did: string | null;
  didMinted: boolean;
  verificationMethodCount?: number;
  /**
   * False when the document is agent-held only. Repairable in place (#286), but
   * a residual the officer must be told about rather than have hidden.
   */
  institutionHoldsKey?: boolean;
}

export function createEnrolment(note?: string): Promise<CreatedEnrolment> {
  return request<CreatedEnrolment>('/api/authority/enrolments', {
    method: 'POST',
    body: JSON.stringify({ note }),
  });
}

export function getEnrolment(id: string): Promise<EnrolmentStatus> {
  return request<EnrolmentStatus>(`/api/authority/enrolments/${id}`, { method: 'GET' });
}

export function completeEnrolment(id: string, details: InstitutionDetails): Promise<MintedInstitution> {
  return request<MintedInstitution>(`/api/authority/enrolments/${id}/complete`, {
    method: 'POST',
    body: JSON.stringify(details),
  });
}
