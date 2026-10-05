/**
 * SSI Healthcare Mobile - SDK Client Service
 *
 * Wraps the SSI Healthcare SDK with React Native secure storage
 * and provides a configured client instance for the mobile app.
 *
 * This replaces direct API calls in stores with SDK method calls,
 * providing a single source of truth for SSI operations.
 */

import {
  SSIClient,
  decodeJwtPayload,
  type StorageAdapter,
  type SSIClientConfig,
} from '@ssi-healthcare/sdk';
import { secureStorage, STORAGE_KEYS } from './secureStorage';
import { API_BASE, apiService } from './api';

/**
 * Create a storage adapter that uses React Native SecureStore
 */
const createSecureStorageAdapter = (): StorageAdapter => ({
  get: async (key: string) => {
    return secureStorage.get(key);
  },
  set: async (key: string, value: string) => {
    await secureStorage.set(key, value);
  },
  remove: async (key: string) => {
    await secureStorage.delete(key);
  },
});

/**
 * SDK configuration for mobile client
 * 
 * Validation modes:
 * - Development (__DEV__): permissive mode for faster iteration
 * - Production (!__DEV__): strict mode for security
 */
const SDK_CONFIG: SSIClientConfig = {
  apiUrl: API_BASE,
  clientId: 'ssi-healthcare-mobile',
  redirectUri: 'ssi-healthcare://callback',
  scopes: ['profile', 'credentials', 'consent'],
  debug: __DEV__,
  storage: createSecureStorageAdapter(),
  timeout: 30000,
  // Use strict validation in production, permissive in development
  jwtVerification: __DEV__ ? 'permissive' : 'strict',
  validationMode: __DEV__ ? 'permissive' : 'strict',
  // THE APP HAS ONE REFRESHER. Delegating to apiService keeps the SDK from
  // POSTing /auth/refresh beside it; the backend's single access token per
  // session makes two concurrent refreshers invalidate each other (steno #437).
  refreshAccessToken: () => apiService.refreshTokens(),
};

/**
 * Base URL of the OID4VCI endpoints.
 *
 * `API_BASE` ends in `/api`, but the OID4VCI router is mounted at the server
 * root (`app.use('/oid4vci', ...)`) because the OpenID specs place the issuer
 * endpoints alongside `/.well-known/openid-credential-issuer`.
 */
const OID4VCI_BASE = `${API_BASE.replace(/\/api\/?$/, '')}/oid4vci`;

/** The backend issues 900s access tokens (`expiresIn: 900` on login/refresh). */
const DEFAULT_ACCESS_TOKEN_SECONDS = 900;

/** Thrown when a scanned offer requires a transaction PIN the caller did not supply. */
export class CredentialOfferPinRequiredError extends Error {
  constructor() {
    super('This credential is protected by a PIN from the issuer. Enter the PIN to continue.');
    this.name = 'CredentialOfferPinRequiredError';
  }
}

/**
 * Extract the pre-authorized code and PIN requirement from a scanned offer URI.
 *
 * Accepts both the current OID4VCI shape (`credential_configuration_ids`) and
 * the legacy shape (`credentials`) — this project's own issuer emits the legacy
 * shape at `oid4vci.ts` `POST /offers`, so a parser that only accepts the
 * current one rejects every offer the system produces.
 */
export function parseCredentialOfferUri(uri: string): {
  preAuthorizedCode: string;
  pinRequired: boolean;
  credentialIssuer?: string;
} {
  let offerJson: string | null = null;

  if (uri.startsWith('openid-credential-offer://')) {
    // `new URL()` on a custom scheme is unreliable across RN engines; read the
    // query directly.
    const queryStart = uri.indexOf('?');
    const params = new URLSearchParams(queryStart >= 0 ? uri.slice(queryStart + 1) : '');
    offerJson = params.get('credential_offer');

    if (!offerJson && params.get('credential_offer_uri')) {
      throw new Error('This offer must be fetched from a URL, which this wallet does not support yet');
    }
  } else {
    offerJson = uri;
  }

  if (!offerJson) {
    throw new Error('This QR code does not contain a credential offer');
  }

  let parsed: {
    credential_issuer?: string;
    grants?: Record<string, { 'pre-authorized_code'?: string; user_pin_required?: boolean; tx_code?: unknown }>;
  };
  try {
    parsed = JSON.parse(offerJson);
  } catch {
    throw new Error('This QR code does not contain a readable credential offer');
  }

  const preAuthGrant = parsed.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
  const preAuthorizedCode = preAuthGrant?.['pre-authorized_code'];

  if (!preAuthorizedCode) {
    throw new Error('This offer does not use the pre-authorized code flow, which this wallet requires');
  }

  return {
    preAuthorizedCode,
    pinRequired: preAuthGrant?.user_pin_required === true || preAuthGrant?.tx_code !== undefined,
    credentialIssuer: typeof parsed.credential_issuer === 'string' ? parsed.credential_issuer : undefined,
  };
}

/** Read a human-usable message out of a failed issuer response. */
async function extractErrorMessage(response: Response, fallback: string): Promise<string> {
  try {
    const body = (await response.json()) as {
      error?: { message?: string } | string;
      message?: string;
      error_description?: string;
    };
    if (typeof body.error === 'object' && body.error?.message) return body.error.message;
    if (typeof body.error === 'string') return body.error_description ?? body.error;
    if (body.message) return body.message;
  } catch {
    // Non-JSON error body — fall through.
  }
  return fallback;
}

/**
 * Singleton SDK client instance
 */
let ssiClientInstance: SSIClient | null = null;

/**
 * Get or create the SSI client instance
 */
export function getSSIClient(): SSIClient {
  if (!ssiClientInstance) {
    ssiClientInstance = new SSIClient(SDK_CONFIG);
  }
  return ssiClientInstance;
}

/**
 * Reset the SDK client (for logout/testing)
 */
export function resetSSIClient(): void {
  ssiClientInstance = null;
}

/**
 * SSI Client Service - Convenience wrapper for common SDK operations
 *
 * This service provides:
 * - Typed methods matching mobile app needs
 * - Error handling with user-friendly messages
 * - Integration with secure storage
 */
class SSIClientService {
  private get client(): SSIClient {
    return getSSIClient();
  }

  /**
   * Wait for the SDK client's own async construction to finish reading its
   * persisted auth state.
   *
   * `SSIClient`'s constructor fires `initializeAuthState()` but does not
   * await it (see `packages/sdk/src/core/client.ts`); it reads the stored
   * token via an async storage call and only then flips `isLoading` to
   * `false`, emitting `auth:stateChanged` when it does. `getSSIClient()`
   * constructs that client lazily, on whichever call reaches it first — which
   * in this app is always `HomeScreen`'s mount-time `fetchCredentials()` /
   * `fetchConsents()`. Without this wait, `requireAuth()` inside the SDK runs
   * against the constructor's synchronous default (`isAuthenticated: false`)
   * before the storage read resolves, so the very first credential/consent
   * fetch after login or app relaunch always fails with "Authentication
   * required" — and a manual retry then succeeds, because by then
   * initialization has finished. This was the cause of the "Failed to Load"
   * flash on cold start.
   *
   * Bounded by a short timeout rather than awaited indefinitely: a stuck
   * native storage read should surface as the SDK's own clear
   * "Authentication required" error, not hang the screen.
   */
  /**
   * Adopt the access token that is CURRENTLY in storage.
   *
   * `apiService` refreshes the 15-minute access token on its own and writes the
   * new one to `STORAGE_KEYS.ACCESS_TOKEN`. Nothing told the SDK, so it went on
   * holding the copy handed to it at login, decided that copy had expired, and
   * refused before issuing a request — no HTTP call ever left the device, which
   * is why the backend log showed `/api/users/me` succeeding and
   * `/api/credentials` absent entirely while the screen said only "Failed to
   * fetch credentials" (measured 8 Sep 2026).
   *
   * Reading it per call rather than being pushed to keeps the two in step
   * whichever path refreshed it — login, biometric unlock, or a background
   * refresh — instead of requiring every one of them to remember.
   */
  private async syncTokenFromStorage(): Promise<void> {
    const stored = await secureStorage.get(STORAGE_KEYS.ACCESS_TOKEN);
    if (!stored) return;
    // Compare against the PERSISTED auth state, never the client's in-memory
    // one. While the SDK is still reading its state, `accessToken` is undefined,
    // so comparing to it reported a difference every time — and since
    // `setAuthToken` resets the singleton, each call discarded the half-loaded
    // client and started another. The state never finished loading and every
    // request failed "Authentication required" without one leaving the device.
    const persisted = await secureStorage.getObject<{
      accessToken?: string;
      expiresAt?: number;
    }>(STORAGE_KEYS.AUTH_STATE);
    // Matching tokens are not enough: a state persisted WITHOUT a usable
    // `expiresAt` is read by the SDK as already expired and cleared on every
    // load, so skipping the rewrite here would leave it permanently locked out.
    const persistedIsUsable =
      typeof persisted?.expiresAt === 'number' && Date.now() < persisted.expiresAt;
    if (persisted?.accessToken === stored && persistedIsUsable) return;

    // AN EXPIRED TOKEN MUST NOT BE LAUNDERED INTO A LIVE ONE.
    //
    // `setAuthToken` has to stamp an expiry, and without one it uses the
    // backend's standard 15 minutes. Passing an already-expired token through
    // here therefore produced a state that CLAIMED to be valid for a quarter of
    // an hour, so the SDK skipped its refresh and every request 401'd — the
    // cold start that showed 0 Credentials while the server held four (steno
    // #437). An expired token is left alone; the SDK's own 401 path renews it.
    const payload = decodeJwtPayload(stored);
    const expiresAtMs = typeof payload?.exp === 'number' ? payload.exp * 1000 : null;
    if (expiresAtMs !== null && expiresAtMs <= Date.now()) return;

    const refreshToken = await secureStorage.get(STORAGE_KEYS.REFRESH_TOKEN);
    await this.setAuthToken(
      stored,
      refreshToken ?? undefined,
      expiresAtMs !== null ? Math.max(1, Math.floor((expiresAtMs - Date.now()) / 1000)) : undefined,
    );
  }

  /**
   * Run an authenticated SDK call, recovering from the cold-start race.
   *
   * On a cold start the first call can reach the SDK before the access token is
   * readable from secure storage — AuthContext is still restoring the session —
   * so the SDK correctly reports "Authentication required" and the screen shows
   * "Failed to Load". Reloading the app then fixes it, which is the tell: the
   * token was fine, it just was not there YET.
   *
   * So: if the call is refused for authentication AND a token is in storage
   * after all, adopt it and try exactly once more. The retry is conditional on
   * the token existing, so a genuinely signed-out wallet still fails fast
   * instead of retrying its way to the same answer.
   */
  private async withAuthRetry<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // The SDK now reports the server's own wording on a failed call — e.g.
      // "Invalid or expired session" — because the credential and consent
      // fetches no longer turn a failure into an empty list. Matching only the
      // literal "authentication required" skipped this recovery for exactly
      // the failure it exists to recover from (steno #437).
      if (!/authentication required|invalid or expired session|token expired/i.test(message)) {
        throw error;
      }

      const token = await secureStorage.get(STORAGE_KEYS.ACCESS_TOKEN);
      if (!token) throw error;

      // Same rule as `syncTokenFromStorage`: never stamp a live expiry on a
      // token that has already expired, because the retry cannot succeed and
      // the fake state hides that from the next reader.
      const payload = decodeJwtPayload(token);
      if (typeof payload?.exp === 'number' && payload.exp * 1000 <= Date.now()) throw error;

      const refreshToken = await secureStorage.get(STORAGE_KEYS.REFRESH_TOKEN);
      await this.setAuthToken(token, refreshToken ?? undefined);
      await this.waitUntilReady();
      return await run();
    }
  }

  private async waitUntilReady(): Promise<void> {
    await this.syncTokenFromStorage();
    if (!this.client.getAuthState().isLoading) return;

    await new Promise<void>((resolve) => {
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(finish, 3000);
      const unsubscribe = this.client.on('auth:stateChanged', () => {
        unsubscribe();
        finish();
      });
    });
  }

  // ============================================================
  // Authentication
  // ============================================================

  /**
   * Check if user is currently authenticated
   */
  isAuthenticated(): boolean {
    return this.client.isAuthenticated();
  }

  /**
   * Get current auth state
   */
  getAuthState() {
    return this.client.getAuthState();
  }

  /**
   * Sync an external auth token into the SDK client.
   * Called after login via apiService so the SDK can make authenticated requests.
   */
  async setAuthToken(accessToken: string, refreshToken?: string, expiresIn?: number): Promise<void> {
    // Store the full auth state with accessToken so the SDK picks it up on init
    const authState = {
      isAuthenticated: true,
      isLoading: false,
      accessToken,
      refreshToken,
      // NEVER leave this undefined. The SDK reads `Date.now() < parsed.expiresAt`
      // and an absent value is FALSY, so a state with no expiry is treated as
      // ALREADY EXPIRED and cleared on load — the client then reports
      // `isAuthenticated: false` and refuses every call before it reaches the
      // network. Callers that do not know the remaining lifetime get the
      // backend's standard access-token window; the server remains the real
      // authority, and a 401 still drives a refresh.
      expiresAt: Date.now() + (expiresIn ?? DEFAULT_ACCESS_TOKEN_SECONDS) * 1000,
    };
    await secureStorage.setObject(STORAGE_KEYS.AUTH_STATE, authState);
    
    // Reset the singleton so the next getSSIClient() re-reads from storage
    resetSSIClient();
  }

  /**
   * Logout - clear all auth state
   */
  async logout(): Promise<void> {
    await this.client.logout();
    await secureStorage.clearTokens();
    resetSSIClient();
  }

  /**
   * Permanently delete the authenticated user's account and all
   * server-held data (credentials, consents, sessions). Calls
   * `DELETE /api/users/me` and, on success, clears local SDK auth state —
   * see `SSIClient.deleteAccount()` in `@ssi-healthcare/sdk`.
   */
  async deleteAccount(): Promise<void> {
    await this.waitUntilReady();
    await this.client.deleteAccount();
    resetSSIClient();
  }

  // ============================================================
  // Credentials
  // ============================================================

  /**
   * Get all credentials for the current user
   */
  async getCredentials() {
    await this.waitUntilReady();
    try {
      const response = await this.withAuthRetry(() => this.client.getCredentials());
      return response.credentials;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to fetch credentials';
      throw new Error(message);
    }
  }

  /**
   * Get a specific credential by ID
   */
  async getCredential(id: string) {
    await this.waitUntilReady();
    try {
      return await this.withAuthRetry(() => this.client.getCredential(id));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to fetch credential';
      throw new Error(message);
    }
  }

  /**
   * Accept a credential offer scanned from a QR code, via OID4VCI.
   *
   * WHY THIS TALKS TO /oid4vci AND NOT /api/credentials
   * ---------------------------------------------------
   * The previous implementation posted `{ offerId: <the raw
   * "openid-credential-offer://..." URI> }` to `POST /credentials/accept-offer`.
   * That handler does `findUnique({ where: { id: offerId } })` expecting a cuid,
   * so the call could only ever 404 — QR acceptance has never worked on mobile.
   *
   * The obvious repair, copying the web client's
   * `resolve-offer` -> `accept-offer` pair, was rejected:
   * `POST /credentials/resolve-offer` returns `previewData` (the full claims
   * blob — diagnoses, medications, results) **together with** `pinRequired`, so
   * it hands over the protected data in the same response that announces the
   * data is PIN-protected. `POST /credentials/accept-offer` then ignores the
   * `pin` field entirely. Pointing a second client at that pair would have
   * spread a known weakness rather than removed one.
   *
   * The OID4VCI endpoints enforce the gate properly: `/oid4vci/token` verifies
   * the PIN (with hashing, attempt counting and lockout) before issuing an
   * access token, and only `/oid4vci/credential` — which requires that token —
   * releases claims. It is also the standards-defined flow, which matters for a
   * wallet that is meant to interoperate with issuers this project does not own.
   *
   * The PIN requirement is read from the offer itself (`user_pin_required` /
   * `tx_code`), exactly as OID4VCI intends, so the wallet learns a PIN is
   * needed without any server round-trip and without disclosing anything.
   */
  async acceptCredentialOffer(
    offer: Parameters<SSIClient['acceptCredentialOffer']>[0] | { uri: string; pin?: string },
  ) {
    if ('uri' in offer) {
      return this.acceptOfferUri(offer.uri, offer.pin);
    }

    await this.waitUntilReady();
    try {
      return await this.client.acceptCredentialOffer(offer);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to accept credential';
      throw new Error(message);
    }
  }

  /**
   * Run the OID4VCI pre-authorized code flow for a scanned offer URI.
   */
  private async acceptOfferUri(uri: string, pin?: string) {
    const { preAuthorizedCode, pinRequired, credentialIssuer } = parseCredentialOfferUri(uri);

    if (pinRequired && !pin) {
      throw new CredentialOfferPinRequiredError();
    }

    /*
     * REDEEM AT THE ISSUER THE OFFER NAMES, NOT AT A FIXED BACKEND.
     *
     * This posted every pre-authorized code to the national backend's
     * `/oid4vci`, so an offer minted by a hospital issuer was refused with
     * "Invalid pre-authorized code" — the code was never the backend's to
     * redeem. OID4VCI already says where to go: ask the offer's issuer for its
     * metadata and use the endpoints IT declares.
     */
    let tokenUrl = `${OID4VCI_BASE}/token`;
    let credentialUrl = `${OID4VCI_BASE}/credential`;
    if (credentialIssuer) {
      try {
        const meta = await fetch(`${credentialIssuer}/.well-known/openid-credential-issuer`);
        if (meta.ok) {
          const m = (await meta.json()) as { token_endpoint?: string; credential_endpoint?: string };
          if (m.token_endpoint) tokenUrl = m.token_endpoint;
          if (m.credential_endpoint) credentialUrl = m.credential_endpoint;
        }
      } catch {
        // Falls through to the configured base; an unreachable issuer then
        // fails loudly at the token call with its own error.
      }
    }

    const tokenResponse = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': preAuthorizedCode,
        ...(pin ? { user_pin: pin } : {}),
      }),
    });

    if (!tokenResponse.ok) {
      throw new Error(await extractErrorMessage(tokenResponse, 'Could not redeem this credential offer'));
    }

    const { access_token: accessToken } = (await tokenResponse.json()) as { access_token?: string };
    if (!accessToken) {
      throw new Error('Issuer did not return an access token');
    }

    const credentialResponse = await fetch(credentialUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      // VC 2.0 with an enveloping JWT proof — what the issuer advertises and
      // issues. The issuer still accepts the legacy `jwt_vc_json` identifier
      // but answers with `vc+jwt` either way, so asking for the old one only
      // made the request describe something we were not receiving.
      body: JSON.stringify({ format: 'vc+jwt' }),
    });

    if (!credentialResponse.ok) {
      throw new Error(await extractErrorMessage(credentialResponse, 'Issuer could not issue the credential'));
    }

    // The issuance endpoint persists the credential to the holder's wallet, so
    // the caller's next `fetchCredentials()` will see it. The compact JWT is
    // returned here for callers that want to display it immediately.
    return (await credentialResponse.json()) as { format: string; credential: unknown };
  }

  /**
   * Delete a credential
   */
  async deleteCredential(id: string): Promise<void> {
    await this.waitUntilReady();
    try {
      await this.client.deleteCredential(id);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to delete credential';
      throw new Error(message);
    }
  }

  /**
   * Verify a credential
   */
  async verifyCredential(credential: Parameters<SSIClient['verifyCredential']>[0]) {
    try {
      return await this.client.verifyCredential(credential);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to verify credential';
      throw new Error(message);
    }
  }

  // ============================================================
  // Presentations (OID4VP)
  // ============================================================

  /**
   * Parse a presentation request from QR code or deep link
   */
  async parsePresentationRequest(data: string) {
    try {
      return await this.client.parsePresentationRequestAsync(data);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Invalid presentation request';
      throw new Error(message);
    }
  }

  /**
   * Get credentials that match a presentation request
   */
  async getMatchingCredentials(request: Parameters<SSIClient['getMatchingCredentials']>[0]) {
    await this.waitUntilReady();
    try {
      return await this.client.getMatchingCredentials(request);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to find matching credentials';
      throw new Error(message);
    }
  }

  /**
   * Present credentials in response to a verification request
   */
  async presentCredentials(
    request: Parameters<SSIClient['presentCredentials']>[0],
    selection: Parameters<SSIClient['presentCredentials']>[1]
  ) {
    await this.waitUntilReady();
    try {
      return await this.client.presentCredentials(request, selection);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to present credentials';
      throw new Error(message);
    }
  }

  // ============================================================
  // Consent Management
  // ============================================================

  /**
   * Get all consents (active or revoked)
   */
  async getConsents(active?: boolean) {
    await this.waitUntilReady();
    try {
      const response = await this.withAuthRetry(() => this.client.getConsents({ active }));
      return response.consents;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to fetch consents';
      throw new Error(message);
    }
  }

  /**
   * Revoke a consent
   */
  async revokeConsent(consentId: string): Promise<void> {
    await this.waitUntilReady();
    try {
      await this.client.revokeConsent(consentId);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to revoke consent';
      throw new Error(message);
    }
  }
}

// Export singleton instance
export const ssiClient = new SSIClientService();
