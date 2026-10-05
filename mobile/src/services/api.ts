/**
 * SSI Healthcare Mobile - API Service
 *
 * HTTP client for communicating with the backend.
 * All API calls route through this service.
 */

import Constants from 'expo-constants';
import { secureStorage, STORAGE_KEYS } from './secureStorage';

/**
 * Candidate API hosts, tried in order until one answers.
 *
 * WHY A LIST. The single `apiUrl` was `http://10.0.2.2:3001/api`, which is the
 * Android EMULATOR's alias for the host machine. On a physical handset it
 * resolves to nothing, so every request failed and the UI bounced straight back
 * to the login screen with no visible error — the app looked broken when it was
 * merely unreachable.
 *
 * The wallet has to work on two networks that cannot both be hardcoded: the
 * ordinary LAN during development, and the closed ESP32 network used for
 * self-contained testing. Rather than rebuilding the app to switch, it probes.
 */
const apiCandidates = (): string[] => {
  const extra = Constants.expoConfig?.extra ?? {};
  const configured: string[] = [
    ...(Array.isArray(extra.apiUrls) ? extra.apiUrls : []),
    ...(extra.apiUrl ? [extra.apiUrl] : []),
  ];

  if (__DEV__) {
    const Platform = require('react-native').Platform;
    // Emulator-only aliases go LAST: harmless there, useless on a real device,
    // and listing them first is what produced the silent failure above.
    configured.push(
      Platform.OS === 'android' ? 'http://10.0.2.2:3001/api' : 'http://localhost:3001/api',
    );
  }

  return [...new Set(configured)];
};

const CANDIDATES = apiCandidates();

/** First candidate, used until a probe proves a different one reachable. */
let API_BASE = CANDIDATES[0] ?? 'http://localhost:3001/api';

/**
 * Probe the candidates and adopt the first that answers.
 *
 * Deliberately does NOT throw when none answer: an unreachable backend is an
 * expected state on a closed network, and the caller's own request will fail
 * with a real error. Throwing here would replace a specific failure with a
 * generic one at startup.
 */
export async function resolveApiBase(timeoutMs = 2500): Promise<string> {
  // THE HOLDER'S OWN SERVER ADDRESS COMES FIRST.
  //
  // Everything else in this list is baked into app.json at build time, which
  // means a build handed to someone on a different network can reach nothing
  // and has no way to be told otherwise short of rebuilding. One address, set
  // in Settings, overrides the lot: the backend and both lockers run on the
  // same host in every deployment we have, so a host is all that is needed.
  let candidates = CANDIDATES;
  try {
    const host = await secureStorage.get(STORAGE_KEYS.SERVER_HOST);
    if (host && host.trim().length > 0) {
      candidates = [`http://${host.trim()}:3001/api`, ...CANDIDATES];
    }
  } catch {
    // A storage fault must not make the backend unreachable.
  }

  for (const base of candidates) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(`${base}/health`, { signal: controller.signal });
      clearTimeout(timer);
      if (res.ok) {
        API_BASE = base;
        console.log(`[api] backend reachable at ${base}`);
        return base;
      }
      console.log(`[api] ${base} answered ${res.status}, trying next`);
    } catch (error) {
      // Try the next candidate. A failure here is information, not an error --
      // but it is logged, because an unreachable backend was previously
      // indistinguishable from a working one that returned nothing.
      console.log(`[api] ${base} unreachable (${(error as Error)?.message ?? 'no response'})`);
    }
  }
  console.warn(
    `[api] no candidate answered; staying on ${API_BASE}. Tried: ${CANDIDATES.join(', ')}`,
  );
  return API_BASE;
}

/** Every candidate, so a diagnostics screen can show what was tried. */
export const API_CANDIDATES = CANDIDATES;

// Export API_BASE for SDK client configuration
export { API_BASE };

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: { code: string; message: string };
  timestamp: string;
}

interface TokenStorage {
  getAccessToken(): Promise<string | null>;
  setAccessToken(token: string): Promise<void>;
  getRefreshToken(): Promise<string | null>;
  setRefreshToken(token: string): Promise<void>;
  clearTokens(): Promise<void>;
}

// Secure token storage using the shared SecureStorageService
const tokenStorage: TokenStorage = {
  async getAccessToken() {
    return secureStorage.get(STORAGE_KEYS.ACCESS_TOKEN);
  },
  async setAccessToken(token: string) {
    await secureStorage.set(STORAGE_KEYS.ACCESS_TOKEN, token);
  },
  async getRefreshToken() {
    return secureStorage.get(STORAGE_KEYS.REFRESH_TOKEN);
  },
  async setRefreshToken(token: string) {
    await secureStorage.set(STORAGE_KEYS.REFRESH_TOKEN, token);
  },
  async clearTokens() {
    await secureStorage.clearTokens();
  },
};

class ApiService {
  /** Set only when a caller pins a URL (tests). Otherwise the live probe result wins. */
  private readonly pinnedBaseUrl?: string;
  private tokenStorage: TokenStorage;

  /**
   * Called once when a 401 could not be refreshed. The auth context registers
   * it so the navigator can return to sign-in; without it the wallet knows the
   * session is dead and shows that fact on every screen instead of acting on it.
   */
  private sessionExpiredHandler?: () => void;

  // Read through a getter, never captured. The previous `this.baseUrl = API_BASE`
  // in the constructor froze the URL at module-load time, so `resolveApiBase()`
  // could reassign API_BASE and the singleton would keep using the stale host.
  private get baseUrl(): string {
    return this.pinnedBaseUrl ?? API_BASE;
  }

  constructor(baseUrl?: string, storage: TokenStorage = tokenStorage) {
    this.pinnedBaseUrl = baseUrl;
    this.tokenStorage = storage;
  }

  /**
   * Set the access token for authenticated requests
   */
  async setAuthToken(token: string): Promise<void> {
    await this.tokenStorage.setAccessToken(token);
  }

  /**
   * Set the refresh token
   */
  async setRefreshToken(token: string): Promise<void> {
    await this.tokenStorage.setRefreshToken(token);
  }

  /**
   * Clear all authentication tokens
   */
  async clearAuth(): Promise<void> {
    await this.tokenStorage.clearTokens();
  }

  /**
   * Check if user has stored auth token
   */
  async hasAuthToken(): Promise<boolean> {
    const token = await this.tokenStorage.getAccessToken();
    return !!token;
  }

  /**
   * Renew the session through this service's single-flight refresher.
   *
   * Exposed for the SDK, whose own refresh is delegated here so the APP HAS
   * EXACTLY ONE REFRESHER. The backend keeps one access token per session, so
   * two refreshers — this service and the SDK — invalidate each other's
   * rotations and the loser's next request 401s with a token that was valid a
   * moment earlier (measured 19 Sep 2026, steno #437). Returns the tokens now
   * in storage, or null when renewal failed.
   */
  async refreshTokens(): Promise<{ accessToken: string; refreshToken?: string } | null> {
    const refreshed = await this.tryRefreshToken();
    if (!refreshed) return null;

    const accessToken = await this.tokenStorage.getAccessToken();
    if (!accessToken) return null;

    const refreshToken = await this.tokenStorage.getRefreshToken();
    return { accessToken, refreshToken: refreshToken ?? undefined };
  }

  private async request<T>(path: string, options?: RequestInit & { requireAuth?: boolean }): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...options?.headers,
    };

    // Add auth header if we have a token or if auth is required
    const token = await this.tokenStorage.getAccessToken();
    if (token) {
      (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
    } else if (options?.requireAuth) {
      throw new Error('Authentication required but no token available');
    }

    const response = await fetch(url, {
      ...options,
      headers,
    });

    // Handle 401 Unauthorized - token may be expired
    if (response.status === 401) {
      // Try to refresh token
      const refreshed = await this.tryRefreshToken();
      if (refreshed) {
        // Retry the request with new token
        const newToken = await this.tokenStorage.getAccessToken();
        (headers as Record<string, string>)['Authorization'] = `Bearer ${newToken}`;
        const retryResponse = await fetch(url, { ...options, headers });
        const retryData: ApiResponse<T> = await retryResponse.json();
        if (!retryData.success || !retryData.data) {
          throw new Error(retryData.error?.message || 'API request failed');
        }
        return retryData.data;
      }
      // Refresh failed, so the session is unrecoverable. Previously this threw
      // and stopped, leaving the stored tokens in place and the auth context
      // still reporting a signed-in user: the wallet stayed inside the tab
      // shell and rendered "Session expired" on every screen, with no route
      // back to sign-in. Clearing the tokens and telling the context is what
      // turns a dead end into a login prompt.
      await this.clearAuth();
      this.sessionExpiredHandler?.();
      throw new Error('Session expired. Please sign in again.');
    }

    const data: ApiResponse<T> = await response.json();

    if (!data.success || !data.data) {
      throw new Error(data.error?.message || 'API request failed');
    }

    return data.data;
  }

  /**
   * At most one refresh in flight, shared by every caller waiting on it.
   *
   * `/auth/refresh` ROTATES the refresh token. The wallet issues several
   * requests on load, so when a session lapses they all 401 at once and each
   * used to start its own refresh: the first succeeded and invalidated the token
   * the other three were holding, which then failed and — once a failed refresh
   * began signing the user out — logged them out of a session that had just been
   * renewed. Four refresh calls, one success, three spurious logouts.
   */
  private refreshInFlight?: Promise<boolean>;

  private async tryRefreshToken(): Promise<boolean> {
    if (this.refreshInFlight) return this.refreshInFlight;
    this.refreshInFlight = this.performRefresh().finally(() => {
      this.refreshInFlight = undefined;
    });
    return this.refreshInFlight;
  }

  private async performRefresh(): Promise<boolean> {
    const refreshToken = await this.tokenStorage.getRefreshToken();
    if (!refreshToken) return false;

    try {
      const response = await fetch(`${this.baseUrl}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      });

      if (!response.ok) return false;

      const data = await response.json();
      if (data.success && data.data?.token) {
        await this.tokenStorage.setAccessToken(data.data.token);
        if (data.data.refreshToken) {
          await this.tokenStorage.setRefreshToken(data.data.refreshToken);
        }
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  // -- Authentication Operations --

  /**
   * Step 1: Request OTP login code.
   * Backend returns { pendingToken, expiresIn, _devCode? }
   */
  /**
   * Step 2: Verify the OTP code with the pending token.
   * Backend returns { user, token, refreshToken, expiresIn }
   */
  /**
   * Register a new user.
   * Backend returns { user, token, refreshToken, expiresIn } immediately (no OTP).
   */
  /**
   * Create an account. No email: identity is the patient DID, minted at
   * enrolment with a key this handset holds.
   */
  async register(firstName?: string, lastName?: string) {
    const result = await this.request<{ user: unknown; token: string; refreshToken: string; expiresIn: number }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ firstName, lastName }),
    });
    await this.setAuthToken(result.token);
    await this.setRefreshToken(result.refreshToken);
    return result;
  }

  /** Registered by the auth context; see `sessionExpiredHandler`. */
  setSessionExpiredHandler(handler: (() => void) | undefined): void {
    this.sessionExpiredHandler = handler;
  }

  async logout() {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      await this.clearAuth();
    }
  }

  async getCurrentUser() {
    return this.request('/auth/me', { requireAuth: true });
  }

  /**
   * Provision the user's wallet: mints a DID and binds it to the user record.
   *
   * This is the ONLY endpoint that sets `User.did`. `POST /dids` (see
   * `createDID` below) mints a standalone DID and leaves `User.did` null, so a
   * user provisioned that way still has no holder identifier — and
   * `GET /users/me/credentials` short-circuits to an empty list for any user
   * whose `did` is null. That is why every credential screen looked like an
   * empty wallet rather than a broken one.
   *
   * `walletType: 'CLOUD'` is the honest description of today's custody: the
   * backend Credo agent generates and holds the key. Do not pass 'DEVICE'
   * until the device actually holds a signing key.
   */
  /**
   * Mint the patient DID.
   *
   * `devicePublicKeyMultibase` is what makes the resulting identity the
   * holder's: with it the DID's `#key-1` is a key this handset generated and
   * the private half never leaves it, so the wallet can authenticate by signing
   * a challenge. Without it the backend generates the key and the account can
   * only sign in through the legacy email path.
   *
   * Idempotent server-side: a user who already has a DID gets it back
   * unchanged, and the key is NOT retrofitted. Supply it on first provisioning
   * or not at all. See __docs__/REMOVING-EMAIL-FROM-AUTH.md.
   */
  async setupWallet(
    walletType: 'CLOUD' | 'DEVICE' | 'HARDWARE' | 'HYBRID' = 'CLOUD',
    devicePublicKeyMultibase?: string,
  ) {
    return this.request<{ did: string; walletType: string }>('/auth/wallet/setup', {
      method: 'POST',
      body: JSON.stringify({ walletType, devicePublicKeyMultibase }),
      requireAuth: true,
    });
  }

  // -- DID challenge-response login (AUTH-AND-KEYSTORE-API.md §1) --

  /**
   * Ask for a nonce to sign. Single-use, 120s, bound to this deployment.
   *
   * `payloadTemplate` is the fully materialised canonical payload, not a
   * template with holes: the wallet signs those exact bytes. The server echoes
   * it precisely so a wallet cannot guess the canonical form wrong.
   */
  async requestDidChallenge(did: string) {
    return this.request<{
      nonce: string;
      expiresAt: string;
      audience: string;
      payloadTemplate: string;
    }>('/auth/challenge', {
      method: 'POST',
      body: JSON.stringify({ did }),
    });
  }

  /**
   * Complete login with a signature over the canonical payload.
   *
   * Returns the same session shape as the email path, so `requireAuth`,
   * `/refresh` and `/logout` are unchanged downstream.
   */
  async didLogin(did: string, nonce: string, signature: string) {
    const result = await this.request<{
      user: unknown;
      token: string;
      refreshToken: string;
      expiresIn: number;
    }>('/auth/did-login', {
      method: 'POST',
      body: JSON.stringify({ did, nonce, signature }),
    });
    await this.setAuthToken(result.token);
    await this.setRefreshToken(result.refreshToken);
    return result;
  }

  // -- DID Operations --

  /**
   * Mint a standalone, local `did:key`.
   *
   * `'cheqd'` USED TO BE ACCEPTED HERE AND NO LONGER IS. `POST /dids` cannot
   * mint an on-ledger identity: a did:cheqd's controller set and its
   * verification-method controller are fixed at creation and can never be
   * repaired, and there is no correct value the server could infer from a
   * request that only says "make me a cheqd DID". Guessing produces an identity
   * that is permanently unrecoverable if the device key is lost — see
   * `S1-DID-CONTROLLER-SEMANTICS.md` and `backend/src/services/cheqdDid.ts`.
   *
   * Narrowed rather than left as-is so this client stops advertising a
   * capability the server refuses: the request would be rejected by the route's
   * schema, and a type that promises otherwise just moves the discovery to
   * runtime.
   */
  async createDID(method: 'key' = 'key') {
    return this.request('/dids', {
      method: 'POST',
      body: JSON.stringify({ method }),
      requireAuth: true,
    });
  }

  async resolveDID(did: string) {
    return this.request(`/dids/${encodeURIComponent(did)}`);
  }

  // -- Credential Operations --

  async createCredentialOffer(params: {
    issuerDid: string;
    subjectDid: string;
    credentialType: string;
    category: string;
    claims: Record<string, unknown>;
  }) {
    return this.request('/credentials/offer', {
      method: 'POST',
      body: JSON.stringify(params),
      requireAuth: true,
    });
  }

  async issueCredentialWithCode(preAuthorizedCode: string) {
    return this.request('/credentials/issue', {
      method: 'POST',
      body: JSON.stringify({ preAuthorizedCode }),
      requireAuth: true,
    });
  }

  async verifyCredential(credential: unknown) {
    return this.request('/credentials/verify', {
      method: 'POST',
      body: JSON.stringify(credential),
      requireAuth: true,
    });
  }

  async getCredentials() {
    return this.request<{ credentials: unknown[]; stats: Record<string, unknown> | null }>('/users/me/credentials', { requireAuth: true });
  }

  async getCredential(credentialId: string) {
    return this.request<unknown>(`/users/me/credentials/${credentialId}`, { requireAuth: true });
  }

  // -- Dispense tokens (A1) --

  /**
   * The holder's own dispense tokens.
   *
   * The pharmacy mints the queue number, so the wallet cannot know it exists and
   * reads it here. `live` are the ISSUED ones the Home card shows; `recent`
   * includes terminal ones so the activity entry can be written from the same
   * read. The state is decided by the BACKEND, from the server clock — the wallet
   * never decides expiry, because a device clock can be changed.
   */
  async getMyTokens() {
    return this.request<{
      live: Array<{
        dispenseId: string;
        prescriptionId: string;
        queueToken: number | null;
        pharmacyDid: string;
        issuedAt: string;
        state: 'ISSUED' | 'SETTLED' | 'ABANDONED' | 'ABANDONED_EXPIRED';
        movesBalance: boolean;
      }>;
      recent: Array<{
        dispenseId: string;
        prescriptionId: string;
        queueToken: number | null;
        pharmacyDid: string;
        issuedAt: string;
        state: 'ISSUED' | 'SETTLED' | 'ABANDONED' | 'ABANDONED_EXPIRED';
        movesBalance: boolean;
      }>;
    }>('/pharmacy/settlement/mine', { requireAuth: true });
  }

  /**
   * The holder's own dispense appends, for the medicine balance screen.
   *
   * Read from the APPENDS themselves, never from a stored balance, so what the
   * wallet shows and what the ledger authorises cannot drift. No medicine names
   * are returned: the wallet joins these to its own credentials by prescription
   * locally, so clinical detail never reaches the operator's database.
   */
  async getMyDispenses() {
    return this.request<{
      dispenses: Array<{
        dispenseId: string;
        prescriptionId: string;
        quantity: number;
        queueToken: number | null;
        pharmacyDid: string;
        issuedAt: string;
        /** Set when the counter settled it; the dispense is then a fact. */
        settledAt: string | null;
        /** Set when the counter closed it as not collected. */
        abandonedReason: string | null;
      }>;
    }>('/pharmacy/dispenses/mine', { requireAuth: true });
  }

  // -- Consent Operations --

  async listConsents() {
    return this.request<{ consents: unknown[]; stats: Record<string, unknown> }>('/users/me/consents', { requireAuth: true });
  }

  async grantConsent(params: {
    verifierDid: string;
    verifierName: string;
    credentialIds: string[];
    purpose: string;
    durationDays?: number;
  }) {
    return this.request('/consent/grant', {
      method: 'POST',
      body: JSON.stringify(params),
      requireAuth: true,
    });
  }

  async revokeConsent(consentId: string) {
    return this.request('/consent/revoke', {
      method: 'POST',
      body: JSON.stringify({ consentId }),
      requireAuth: true,
    });
  }

  async queryConsent(holderDid: string) {
    return this.request(`/consent/${encodeURIComponent(holderDid)}`, { requireAuth: true });
  }

  // -- Activity Operations --

  async getActivity(params?: { page?: number; limit?: number }) {
    const query = params ? `?page=${params.page || 1}&limit=${params.limit || 20}` : '';
    return this.request<unknown[]>(`/users/me/activity${query}`, { requireAuth: true });
  }

  // -- Verification Operations --

  async createPresentationRequest(params: {
    definition: {
      id: string;
      inputDescriptors: Array<{
        id: string;
        constraints: { fields: Array<{ path: string[] }> };
      }>;
    };
  }) {
    return this.request('/verification/request', {
      method: 'POST',
      body: JSON.stringify(params),
      requireAuth: true,
    });
  }

  async submitPresentation(params: {
    requestId: string;
    credentials: unknown[];
  }) {
    return this.request('/verification/submit', {
      method: 'POST',
      body: JSON.stringify(params),
      requireAuth: true,
    });
  }

  // -- Emergency Operations --

  async requestEmergencyAccess(params: {
    patientDid: string;
    reason: string;
    credentialIds: string[];
    familyContactDid?: string;
  }) {
    return this.request('/emergency/request', {
      method: 'POST',
      body: JSON.stringify(params),
      requireAuth: true,
    });
  }

  async revokeEmergencyAccess(emergencyId: string) {
    return this.request('/emergency/revoke', {
      method: 'POST',
      body: JSON.stringify({ emergencyId }),
      requireAuth: true,
    });
  }

  async queryEmergencyRecords(patientDid: string) {
    return this.request(`/emergency/${encodeURIComponent(patientDid)}`, { requireAuth: true });
  }

  // -- User Profile & Settings Operations --

  async getProfile() {
    return this.request<{
      id: string;
      email: string;
      firstName: string | null;
      lastName: string | null;
      displayName: string | null;
      phone: string | null;
      did: string | null;
      walletSetup: boolean;
      biometricEnabled: boolean;
      autoLockMinutes: number;
      totpEnabled: boolean;
      /**
       * Computed server-side from holding a valid, unrevoked health-card
       * credential (services/identityVerification.ts) — never a stored flag.
       * This is the ONLY source the verified badge may read; see round 5's
       * brief ("wire it to that and nothing else").
       */
      identityVerified: boolean;
    }>('/users/me', { requireAuth: true });
  }

  async updateProfile(data: {
    firstName?: string;
    lastName?: string;
    displayName?: string;
    phone?: string;
  }) {
    return this.request('/users/me/profile', {
      method: 'PUT',
      body: JSON.stringify(data),
      requireAuth: true,
    });
  }

  async updateSecurity(data: {
    biometricEnabled?: boolean;
    autoLockMinutes?: number;
  }) {
    return this.request('/users/me/security', {
      method: 'PUT',
      body: JSON.stringify(data),
      requireAuth: true,
    });
  }

  async updateNotifications(data: {
    emailEnabled?: boolean;
    pushEnabled?: boolean;
    eventPreferences?: Record<string, boolean>;
  }) {
    return this.request('/users/me/notifications', {
      method: 'PUT',
      body: JSON.stringify(data),
      requireAuth: true,
    });
  }

  async getNotificationPreferences() {
    return this.request<{
      emailEnabled: boolean;
      pushEnabled: boolean;
      eventPreferences: Record<string, boolean>;
    }>('/users/me/notifications', { requireAuth: true });
  }

  // -- Identity issuance (round 5) --

  /**
   * The ONE place a document type — and the authority it routes to — comes
   * from. Never hardcode an authority in a screen; read it from here.
   */
  async getDocumentTypes() {
    return this.request<{
      documentTypes: Array<{
        id: string;
        label: string;
        issuingAuthorityDid: string;
        issuingAuthorityName: string;
        credentialType: string;
        requiredDocuments: Array<{ id: string; label: string; acceptedMediaTypes: string[] }>;
        placeholder: boolean;
        contentKeyPublicKey: string;
      }>;
    }>('/issuance/document-types');
  }

  async submitIssuanceRequest(body: {
    requestId: string;
    documentType: string;
    documents: Array<{ lockerObjectId: string; contentHash: string; mediaType: string }>;
    wrappedContentKey: unknown;
    capability: unknown;
  }) {
    return this.request<IssuanceRequestSummary>('/issuance/requests', {
      method: 'POST',
      body: JSON.stringify(body),
      requireAuth: true,
    });
  }

  async listIssuanceRequests() {
    return this.request<{ requests: IssuanceRequestSummary[] }>('/issuance/requests', { requireAuth: true });
  }

  async getIssuanceRequest(id: string) {
    return this.request<IssuanceRequestSummary>(`/issuance/requests/${encodeURIComponent(id)}`, {
      requireAuth: true,
    });
  }

  /**
   * Credential offers waiting to be claimed.
   *
   * An authority approving a submission does not push a credential onto the
   * handset — it creates an OFFER, and the holder decides whether to accept it.
   * Without this call the wallet had no way to learn an offer existed: the
   * submission screen said "Approved" and the credential sat unclaimed forever,
   * reachable only by an HTTP call made outside the app. Receiving a credential
   * is the holder's own act, so it needs a surface in the holder's own wallet.
   */
  async listCredentialOffers() {
    return this.request<CredentialOfferSummary[]>('/credentials/offers', { requireAuth: true });
  }

  /**
   * Claim one. The backend re-checks that the offer is PENDING and addressed to
   * this holder's DID, so a stale list cannot redeem someone else's offer.
   * PIN-protected offers are REFUSED here by design (see routes/credential.ts)
   * and must go through the OID4VCI flow — this path does not re-implement the
   * PIN check, it declines to be the second place that has one.
   */
  async acceptCredentialOffer(offerId: string) {
    return this.request<{ credential?: unknown; id?: string }>('/credentials/accept-offer', {
      method: 'POST',
      body: JSON.stringify({ offerId }),
      requireAuth: true,
    });
  }

  async withdrawIssuanceRequest(id: string) {
    return this.request<{ id: string; status: string }>(`/issuance/requests/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      requireAuth: true,
    });
  }

  // -- Keystore vault (recovery envelope, AUTH-AND-KEYSTORE-API.md §2) --

  async putKeystoreEnvelope(handle: string, envelope: unknown) {
    return this.request<{ stored: boolean }>('/keystore/envelope', {
      method: 'PUT',
      body: JSON.stringify({ handle, envelope }),
      requireAuth: true,
    });
  }

  /**
   * Deliberately unauthenticated (see routes/keystore.ts) — a new device has
   * no session yet. `envelope` is `null` when nothing is enrolled under this
   * handle; the caller must not treat that as an error.
   */
  async fetchKeystoreEnvelope(handle: string) {
    return this.request<{ envelope: unknown | null }>('/keystore/envelope/fetch', {
      method: 'POST',
      body: JSON.stringify({ handle }),
    });
  }

  // -- Wallet custody broker (round 5 — see WALLET-CUSTODY-NOTE.md) --

  /**
   * Completes DID challenge-response against a locker on the caller's own
   * behalf (this wallet is CLOUD-custodied today; see the note). Returns a
   * bearer token the wallet then uses to talk to the locker DIRECTLY —
   * ciphertext never transits this backend.
   */
  async walletLockerSession(lockerBaseUrl: string) {
    return this.request<{ token: string; expiresAt: string; lockerBaseUrl: string }>('/wallet/locker-session', {
      method: 'POST',
      body: JSON.stringify({ lockerBaseUrl }),
      requireAuth: true,
    });
  }

  /** Mints a locker capability naming the caller's own DID as issuer. */
  async walletMintCapability(body: {
    documentType: string;
    objectIds: string[];
    issuanceRequestId: string;
    validitySeconds?: number;
  }) {
    return this.request<unknown>('/wallet/capability', {
      method: 'POST',
      body: JSON.stringify(body),
      requireAuth: true,
    });
  }

  // -- Health Check --

  async healthCheck() {
    return this.request('/health');
  }
}

export interface IssuanceRequestSummary {
  id: string;
  documentType: string;
  credentialType: string;
  authorityDid: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'WITHDRAWN';
  createdAt: string;
  decidedAt: string | null;
  rejectionReason: string | null;
  withdrawnAt: string | null;
  documents: Array<{ id: string; lockerObjectId: string; contentHash: string; mediaType: string }>;
}

export interface CredentialOfferSummary {
  id: string;
  issuerDid: string;
  credentialType: string;
  category: string;
  pinRequired: boolean;
  createdAt: string;
  expiresAt: string;
}

export const apiService = new ApiService();
