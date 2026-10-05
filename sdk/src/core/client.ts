/**
 * SSI Healthcare SDK - Core Client
 *
 * Main client for interacting with SSI services. Provides an
 * OAuth2-like API for frictionless identity operations.
 */

import {
  CredentialOfferSchema,
  PresentationRequestPayloadSchema,
  WalletCredentialSchema,
  validateSafe,
  formatZodError,
} from '@ssi-healthcare/shared';
import type { WalletCredential, WalletCredentialStats } from '@ssi-healthcare/shared';
import { decodeJwtPayload as decodeJwt } from '../utils';
import type {
  SSIClientConfig,
  StorageAdapter,
  Identity,
  Credential,
  Presentation,
  CredentialOffer,
  PresentationRequest,
  Consent,
  ConsentPurpose,
  AuthState,
  CollectionStats,
  DisclosureSelection,
  VerificationResult,
  ApiResponse,
  PaginationParams,
  ActivityItem,
  SSIEventType,
  SSIEventListener,
  SSIEvent,
  SessionInfo,
} from '../types';

/** JWKS Key with optional kid (Key ID) - extends Web Crypto JsonWebKey */
interface JwksKey extends JsonWebKey {
  kid?: string;
  use?: string;
}

/** Default storage using localStorage (browser) or in-memory (Node) */
const createDefaultStorage = (): StorageAdapter => {
  if (typeof localStorage !== 'undefined') {
    return {
      get: async (key) => localStorage.getItem(key),
      set: async (key, value) => localStorage.setItem(key, value),
      remove: async (key) => localStorage.removeItem(key),
    };
  }

  // In-memory fallback for Node.js
  const store = new Map<string, string>();
  return {
    get: async (key) => store.get(key) ?? null,
    set: async (key, value) => { store.set(key, value); },
    remove: async (key) => { store.delete(key); },
  };
};

/** Storage keys */
const STORAGE_KEYS = {
  AUTH_STATE: 'ssi_auth_state',
  IDENTITY: 'ssi_identity',
  ACCESS_TOKEN: 'ssi_access_token',
  REFRESH_TOKEN: 'ssi_refresh_token',
} as const;

/**
 * SSI Client - Main entry point for SSI operations
 *
 * @example
 * ```typescript
 * const ssi = new SSIClient({
 *   apiUrl: 'https://api.ssi-healthcare.com',
 *   clientId: 'your-app-id',
 *   redirectUri: 'https://yourapp.com/callback',
 * });
 *
 * // Authenticate user
 * await ssi.authenticate();
 *
 * // Get credentials
 * const credentials = await ssi.getCredentials();
 *
 * // Share credential
 * await ssi.presentCredential(request, selection);
 * ```
 */
/** Config with every default resolved, except the optional refresh delegate. */
type ResolvedClientConfig = Required<Omit<SSIClientConfig, 'refreshAccessToken'>> & {
  refreshAccessToken: SSIClientConfig['refreshAccessToken'] | undefined;
};

export class SSIClient {
  private config: ResolvedClientConfig;
  private storage: StorageAdapter;
  private eventListeners: Map<SSIEventType, Set<SSIEventListener>>;
  private authState: AuthState;
  private jwksCache: Map<string, { key: JsonWebKey; kid: string }>;
  private jwksCacheExpiry: number;

  constructor(config: SSIClientConfig) {
    this.config = {
      apiUrl: config.apiUrl,
      clientId: config.clientId,
      redirectUri: config.redirectUri ?? '',
      scopes: config.scopes ?? ['profile', 'credentials'],
      debug: config.debug ?? false,
      storage: config.storage ?? createDefaultStorage(),
      fetch: config.fetch ?? globalThis.fetch.bind(globalThis),
      timeout: config.timeout ?? 30000,
      jwtVerification: config.jwtVerification ?? 'strict',
      jwksUri: config.jwksUri ?? '',
      validationMode: config.validationMode ?? 'strict',
      refreshAccessToken: config.refreshAccessToken,
    };

    this.storage = this.config.storage;
    this.eventListeners = new Map();
    this.jwksCache = new Map();
    this.jwksCacheExpiry = 0;
    this.authState = {
      isAuthenticated: false,
      isLoading: true,
    };

    // Initialize auth state from storage
    this.initializeAuthState();
  }

  // ============================================================
  // Authentication
  // ============================================================

  /**
   * Initialize authentication state from storage
   */
  private async initializeAuthState(): Promise<void> {
    try {
      const storedAuth = await this.storage.get(STORAGE_KEYS.AUTH_STATE);
      if (storedAuth) {
        const parsed = JSON.parse(storedAuth);
        
        // Basic structure validation
        if (typeof parsed !== 'object' || parsed === null) {
          this.log('warn', 'Invalid stored auth state structure, clearing');
          await this.clearAuthState();
          return;
        }
        
        if (typeof parsed.isAuthenticated !== 'boolean') {
          this.log('warn', 'Invalid auth state: missing isAuthenticated, clearing');
          await this.clearAuthState();
          return;
        }
        
        if (parsed.expiresAt && Date.now() < parsed.expiresAt) {
          this.authState = { ...parsed, isLoading: false };
        } else {
          // Token expired — try to refresh before clearing
          const refreshToken = await this.storage.get('ssi_refresh_token');
          if (refreshToken) {
            try {
              await this.refreshToken();
              return; // refreshToken sets state + emits
            } catch {
              this.log('warn', 'Token refresh failed during init, clearing');
            }
          }
          await this.clearAuthState();
        }
      } else {
        this.authState.isLoading = false;
      }
    } catch (error) {
      this.log('error', 'Failed to initialize auth state', error);
      await this.clearAuthState();
    } finally {
      this.authState.isLoading = false;
      // Notify subscribers that initialization is complete
      this.emit('auth:stateChanged', { state: this.getAuthState() });
    }
  }

  /**
   * Get current authentication state
   */
  getAuthState(): AuthState {
    return { ...this.authState };
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return this.authState.isAuthenticated && !this.isTokenExpired();
  }

  /**
   * Check if the current token is expired
   */
  private isTokenExpired(): boolean {
    if (!this.authState.expiresAt) return false;
    return Date.now() >= this.authState.expiresAt;
  }

  /**
   * Authenticate user via magic link or OAuth
   *
   * For email: sends a 6-digit code to the email, then call verifyCode() 
   * For OAuth providers: requires an idToken from the provider
   */
  async authenticate(options?: {
    method?: 'popup' | 'redirect';
    provider?: 'google' | 'apple' | 'microsoft' | 'email';
    email?: string;
    idToken?: string;
  }): Promise<AuthState> {
    const provider = options?.provider ?? 'email';

    this.authState.isLoading = true;
    this.authState.error = undefined;

    try {
      if (provider === 'email') {
        if (!options?.email) {
          throw new Error('Email is required for email authentication');
        }
        
        // Request magic link code
        const response = await this.request<{
          pendingToken: string;
          expiresIn: number;
          _devCode?: string;
        }>('/auth/login', {
          method: 'POST',
          body: JSON.stringify({ email: options.email }),
        });

        if (!response.success) {
          throw new Error(response.error?.message ?? 'Login request failed');
        }

        // Store pendingToken for verify-code step
        if (response.data?.pendingToken) {
          await this.storage.set('ssi_pending_token', response.data.pendingToken);
        }
        await this.storage.set('ssi_pending_email', options.email);
        
        this.authState.isLoading = false;
        
        // In dev mode, the code is returned in the response
        if (response.data?._devCode) {
          this.log('debug', 'Dev mode: code returned in response');
        }
        
        return this.authState;
      } else {
        // OAuth flow — requires idToken from provider
        if (!options?.idToken) {
          throw new Error(`idToken is required for ${provider} authentication`);
        }

        const response = await this.request<{
          token: string;
          refreshToken: string;
          expiresIn: number;
          user: Identity;
        }>('/auth/oauth', {
          method: 'POST',
          body: JSON.stringify({
            provider,
            idToken: options.idToken,
          }),
        });

        if (!response.success || !response.data) {
          throw new Error(response.error?.message ?? 'OAuth authentication failed');
        }

        // Store refresh token for session renewal
        if (response.data.refreshToken) {
          await this.storage.set('ssi_refresh_token', response.data.refreshToken);
        }

        // Use server-provided expiry (seconds) instead of hardcoded 24h
        const expiresInMs = (response.data.expiresIn ?? 900) * 1000;
        await this.setAuthState({
          isAuthenticated: true,
          identity: response.data.user,
          accessToken: response.data.token,
          expiresAt: Date.now() + expiresInMs,
          isLoading: false,
        });

        this.emit('auth:login', { identity: this.authState.identity });
        return this.authState;
      }
    } catch (error) {
      this.authState.error = error instanceof Error ? error : new Error('Authentication failed');
      this.authState.isLoading = false;
      this.emit('error', { error: this.authState.error });
      throw this.authState.error;
    }
  }

  /**
   * Verify the 6-digit magic link code sent to email.
   * Call this after authenticate({ provider: 'email', email }) 
   */
  async verifyCode(code: string): Promise<AuthState> {
    const pendingToken = await this.storage.get('ssi_pending_token');
    if (!pendingToken) {
      throw new Error('No pending authentication. Call authenticate() first.');
    }

    const response = await this.request<{
      token: string;
      refreshToken: string;
      user: Identity;
      expiresIn: number;
    }>('/auth/verify-code', {
      method: 'POST',
      body: JSON.stringify({ pendingToken, code }),
    });

    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? 'Code verification failed');
    }

    await this.storage.remove('ssi_pending_token');
    await this.storage.remove('ssi_pending_email');

    await this.setAuthState({
      isAuthenticated: true,
      identity: response.data.user,
      accessToken: response.data.token,
      refreshToken: response.data.refreshToken,
      expiresAt: Date.now() + (response.data.expiresIn ?? 86400) * 1000,
      isLoading: false,
    });

    this.emit('auth:login', { identity: this.authState.identity });
    return this.authState;
  }

  /**
   * Register a new user
   */
  async register(options: {
    email: string;
    firstName?: string;
    lastName?: string;
  }): Promise<AuthState> {
    const response = await this.request<{
      token: string;
      refreshToken: string;
      user: Identity;
      expiresIn: number;
    }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(options),
    });

    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? 'Registration failed');
    }

    await this.setAuthState({
      isAuthenticated: true,
      identity: response.data.user,
      accessToken: response.data.token,
      refreshToken: response.data.refreshToken,
      expiresAt: Date.now() + (response.data.expiresIn ?? 86400) * 1000,
      isLoading: false,
    });

    this.emit('auth:login', { identity: this.authState.identity });
    return this.authState;
  }

  /**
   * Handle OAuth callback (legacy — use authenticate with idToken instead)
   */
  async handleCallback(params?: URLSearchParams): Promise<AuthState> {
    const searchParams = params ?? (typeof window !== 'undefined' 
      ? new URLSearchParams(window.location.search)
      : new URLSearchParams());

    const code = searchParams.get('code');
    const error = searchParams.get('error');

    if (error) {
      throw new Error(searchParams.get('error_description') ?? error);
    }

    if (!code) {
      throw new Error('Missing authorization code');
    }

    // Use verify-code for magic link flow
    return this.verifyCode(code);
  }

  /**
   * Log out the current user
   */
  async logout(): Promise<void> {
    const identity = this.authState.identity;
    
    // Call backend logout to invalidate the session
    if (this.authState.accessToken) {
      try {
        await this.request('/auth/logout', { method: 'POST' });
      } catch {
        // Best-effort — clear local state regardless
        this.log('warn', 'Backend logout failed, clearing local state');
      }
    }
    
    await this.clearAuthState();
    this.emit('auth:logout', { identity });
  }

  // ============================================================
  // User Profile & Sessions
  // ============================================================

  /**
   * Get current authenticated user profile.
   * Persists the identity via setAuthState() and emits auth:login to sync React hooks.
   */
  async getMe(): Promise<Identity | null> {
    this.requireAuth();
    const response = await this.request<Identity>('/auth/me');
    if (response.success && response.data) {
      await this.setAuthState({
        ...this.authState,
        identity: response.data,
      });
    }
    return response.data ?? null;
  }

  /**
   * Refresh the session token.
   *
   * AT MOST ONE REFRESH IN FLIGHT, shared by every caller waiting on it.
   *
   * `/auth/refresh` ROTATES the refresh token, so concurrent refreshes are not
   * merely wasteful — they are destructive. The first succeeds and invalidates
   * the token the others are holding; each of those then fails, and the 401
   * handler below responds to a failed refresh by calling `clearAuthState()`.
   * One expired token therefore produced several spurious logouts.
   *
   * Measured on a handset 9 Sep 2026: FIFTEEN `/auth/refresh` calls in two
   * seconds, which exhausted the backend's 100-request/15-minute auth limiter
   * (#271) and left every subsequent call failing with TOO_MANY_AUTH_ATTEMPTS —
   * so the storm broke recovery at exactly the moment recovery was needed. The
   * holder saw "You don't have credentials that match this request", which
   * names neither the cause nor even the right subsystem.
   *
   * `apiService` in the wallet already carries this exact fix, with this exact
   * reasoning, for this exact endpoint. The SDK is the second HTTP client
   * against the same API and never received it — cross-package contract drift,
   * one of the three structural root causes in the August audit.
   */
  private refreshInFlight?: Promise<void>;

  async refreshToken(): Promise<void> {
    if (this.refreshInFlight) return this.refreshInFlight;
    this.refreshInFlight = this.performRefresh().finally(() => {
      this.refreshInFlight = undefined;
    });
    return this.refreshInFlight;
  }

  private async performRefresh(): Promise<void> {
    // ONE REFRESHER PER APP, when the integrator supplies one. Both of this
    // wallet's HTTP clients share a single access token server-side, so two
    // refreshers invalidate each other's rotations (steno #437); delegating
    // makes the host's single-flight the only place a refresh can happen.
    if (this.config.refreshAccessToken) {
      const fresh = await this.config.refreshAccessToken();
      if (!fresh?.accessToken) {
        throw new Error('Token refresh failed. Please login again.');
      }
      this.authState.accessToken = fresh.accessToken;
      if (fresh.refreshToken) this.authState.refreshToken = fresh.refreshToken;
      this.authState.expiresAt = Date.now() + (fresh.expiresIn ?? 900) * 1000;
      await this.setAuthState(this.authState);
      return;
    }

    // Check authState first, then storage fallback
    let rt = this.authState.refreshToken;
    if (!rt) {
      rt = await this.storage.get('ssi_refresh_token') ?? undefined;
    }
    if (!rt) {
      throw new Error('No refresh token available. Please login again.');
    }

    const response = await this.request<{
      token: string;
      refreshToken: string;
      expiresIn: number;
    }>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: rt }),
    });

    // A refresh that returns no token MUST reject. Silently resolving left the
    // 401 branch above believing a refresh had happened, retrying against the
    // same dead token, and — before the endpoint guard — leaving callers with
    // no error to act on at all. Rejecting is what lets `request()` clear the
    // auth state and what makes `initializeAuthState` fall through to its own
    // "refresh failed during init, clearing" path.
    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? 'Token refresh failed. Please login again.');
    }

    this.authState.accessToken = response.data.token;
    this.authState.refreshToken = response.data.refreshToken;
    this.authState.expiresAt = Date.now() + response.data.expiresIn * 1000;
    await this.storage.set('ssi_refresh_token', response.data.refreshToken);
    await this.setAuthState(this.authState);
  }

  /**
   * Setup the user's SSI wallet
   */
  async setupWallet(walletType: 'CLOUD' | 'DEVICE' | 'HARDWARE' | 'HYBRID'): Promise<{ did: string; walletType: string }> {
    this.requireAuth();

    const response = await this.request<{ did: string; walletType: string }>('/auth/wallet/setup', {
      method: 'POST',
      body: JSON.stringify({ walletType }),
    });

    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? 'Wallet setup failed');
    }

    // Update identity with new DID
    if (this.authState.identity) {
      this.authState.identity.did = response.data.did;
      await this.setAuthState(this.authState);
    }

    return response.data;
  }

  /**
   * Update user profile
   */
  async updateProfile(data: {
    firstName?: string;
    lastName?: string;
    displayName?: string;
  }): Promise<Identity> {
    this.requireAuth();

    const response = await this.request<Identity>('/users/me/profile', {
      method: 'PUT',
      body: JSON.stringify(data),
    });

    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? 'Profile update failed');
    }

    this.authState.identity = response.data;
    await this.setAuthState(this.authState);
    return response.data;
  }

  /**
   * Get user activity log
   */
  async getActivity(params?: PaginationParams): Promise<ActivityItem[]> {
    this.requireAuth();

    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', params.page.toString());
    if (params?.limit) queryParams.set('limit', params.limit.toString());

    const response = await this.request<{ events: ActivityItem[] } | ActivityItem[]>(
      `/audit?${queryParams.toString()}`
    );

    // Handle both array and { events: [] } response shapes
    const data = response.data;
    if (Array.isArray(data)) return data;
    if (data && 'events' in data) return data.events;
    return [];
  }

  /**
   * Get user's presentations
   */
  async getPresentations(params?: PaginationParams): Promise<{ presentations: Presentation[]; stats: CollectionStats }> {
    this.requireAuth();

    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', params.page.toString());
    if (params?.limit) queryParams.set('limit', params.limit.toString());

    const response = await this.request<{ presentations: Presentation[]; stats: CollectionStats }>(
      `/users/me/presentations?${queryParams.toString()}`
    );

    return response.data ?? { presentations: [], stats: {} };
  }

  /**
   * Get active sessions
   */
  async getSessions(): Promise<{ sessions: SessionInfo[] }> {
    this.requireAuth();
    const response = await this.request<{ sessions: SessionInfo[] }>('/users/me/sessions');
    return response.data ?? { sessions: [] };
  }

  /**
   * Delete all other sessions (keep current)
   */
  async deleteOtherSessions(): Promise<void> {
    this.requireAuth();
    await this.request('/users/me/sessions', { method: 'DELETE' });
  }

  /**
   * Update security settings (biometric, autoLock, TOTP)
   */
  async updateSecurity(data: {
    biometricEnabled?: boolean;
    autoLockMinutes?: number;
    totpEnabled?: boolean;
  }): Promise<void> {
    this.requireAuth();
    const response = await this.request('/users/me/security', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
    if (!response.success) {
      throw new Error(response.error?.message ?? 'Security update failed');
    }
  }

  /**
   * Get notification preferences
   */
  async getNotifications(): Promise<Record<string, unknown>> {
    this.requireAuth();
    const response = await this.request<Record<string, unknown>>('/users/me/notifications');
    return response.data ?? {};
  }

  /**
   * Update notification preferences
   */
  async updateNotifications(data: {
    emailEnabled?: boolean;
    pushEnabled?: boolean;
    emailDigest?: boolean;
    quietHoursEnabled?: boolean;
    quietHoursStart?: string;
    quietHoursEnd?: string;
    eventPreferences?: Record<string, boolean>;
  }): Promise<void> {
    this.requireAuth();
    const response = await this.request('/users/me/notifications', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
    if (!response.success) {
      throw new Error(response.error?.message ?? 'Notification update failed');
    }
  }

  /**
   * Permanently delete the authenticated user's account and all associated data
   */
  async deleteAccount(): Promise<void> {
    this.requireAuth();
    const response = await this.request('/users/me', { method: 'DELETE' });
    if (!response.success) {
      throw new Error(response.error?.message ?? 'Account deletion failed');
    }
    await this.logout();
  }

  /**
   * Setup TOTP 2FA — returns QR code data URL and otpauth URL
   */
  async setupTotp(): Promise<{ qrCodeDataUrl: string; otpauthUrl: string }> {
    this.requireAuth();
    const response = await this.request<{ qrCodeDataUrl: string; otpauthUrl: string }>(
      '/auth/totp/setup',
      { method: 'POST' },
    );
    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? 'TOTP setup failed');
    }
    return response.data;
  }

  /**
   * Verify TOTP code and enable 2FA
   */
  async verifyTotp(code: string): Promise<void> {
    this.requireAuth();
    const response = await this.request('/auth/totp/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
    if (!response.success) {
      throw new Error(response.error?.message ?? 'TOTP verification failed');
    }
  }

  /**
   * Disable TOTP 2FA (requires a valid TOTP code for confirmation)
   */
  async disableTotp(code: string): Promise<void> {
    this.requireAuth();
    const response = await this.request('/auth/totp/disable', {
      method: 'DELETE',
      body: JSON.stringify({ code }),
    });
    if (!response.success) {
      throw new Error(response.error?.message ?? 'TOTP disable failed');
    }
  }

  // ============================================================
  // Credentials
  // ============================================================

  /**
   * Validate one wallet credential envelope received from the server.
   *
   * `this.request<T>()` applies a generic — an *assertion*, not a check. A cast
   * on a `fetch` result proves nothing at runtime, and that is exactly how a
   * response with no `issuer` field satisfied the compiler while the mobile
   * wallet dereferenced `undefined.id` on the first credential it rendered.
   *
   * Behaviour follows the same convention as `parseCredentialOffer`: throw in
   * `strict` mode, warn and pass through in `permissive`.
   */
  private validateWalletCredential(candidate: unknown): WalletCredential | null {
    const result = validateSafe(WalletCredentialSchema, candidate);

    if (!result.success) {
      const errorMsg = formatZodError(result.error);
      if (this.config.validationMode === 'strict') {
        throw new Error(`Credential validation failed: ${errorMsg}`);
      }
      this.log('warn', 'Credential validation warning', errorMsg);
    }

    return candidate as WalletCredential;
  }

  /**
   * Get all credentials in the wallet.
   *
   * Returns `WalletCredential` envelopes — wallet metadata (including `status`,
   * which carries revocation) plus the signed W3C VC under `credential`.
   */
  async getCredentials(params?: PaginationParams): Promise<{ credentials: WalletCredential[]; stats: WalletCredentialStats | null }> {
    this.requireAuth();

    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', params.page.toString());
    if (params?.limit) queryParams.set('limit', params.limit.toString());

    const response = await this.request<{ credentials: unknown[]; stats: WalletCredentialStats | null }>(
      `/users/me/credentials?${queryParams.toString()}`
    );

    // A failed request is not an empty wallet. Returning [] here rendered an
    // unreachable backend, an expired session and a genuinely empty wallet
    // identically — measured 19 Sep 2026, the dashboard showed 0 Credentials
    // while the server held four (steno #437). The caller must see the failure.
    if (!response.success) {
      throw new Error(response.error?.message ?? 'Failed to fetch credentials');
    }

    const rawCredentials = response.data?.credentials ?? [];
    const credentials = rawCredentials
      .map((candidate) => this.validateWalletCredential(candidate))
      .filter((credential): credential is WalletCredential => credential !== null);

    return { credentials, stats: response.data?.stats ?? null };
  }

  /**
   * Get a specific credential by ID
   */
  async getCredential(id: string): Promise<WalletCredential | null> {
    this.requireAuth();

    const response = await this.request<unknown>(`/users/me/credentials/${id}`);
    if (!response.success) {
      throw new Error(response.error?.message ?? 'Failed to fetch credential');
    }
    if (!response.data) return null;

    return this.validateWalletCredential(response.data);
  }

  /**
   * Accept a credential offer by exchanging its pre-authorized code
   */
  async acceptCredentialOffer(offer: CredentialOffer): Promise<Credential> {
    this.requireAuth();

    const response = await this.request<Credential>('/credentials/accept-offer', {
      method: 'POST',
      body: JSON.stringify({ offerId: offer.id }),
    });

    if (!response.data) {
      throw new Error(response.error?.message ?? 'Failed to accept credential');
    }

    this.emit('credential:received', { credential: response.data });
    return response.data;
  }

  /**
   * Parse a credential offer from URL or QR code data with Zod validation
   */
  parseCredentialOffer(data: string): CredentialOffer {
    try {
      let parsed: unknown;
      
      // Handle openid-credential-offer:// URI
      if (data.startsWith('openid-credential-offer://')) {
        const url = new URL(data);
        const offerParam = url.searchParams.get('credential_offer');
        if (offerParam) {
          parsed = JSON.parse(decodeURIComponent(offerParam));
        } else {
          const offerUri = url.searchParams.get('credential_offer_uri');
          if (offerUri) {
            throw new Error('credential_offer_uri requires async resolution');
          }
          throw new Error('Missing credential_offer parameter');
        }
      } else {
        // Try parsing as JSON directly
        parsed = JSON.parse(data);
      }

      // Validate with Zod schema
      const result = validateSafe(CredentialOfferSchema, parsed);
      if (!result.success) {
        const errorMsg = formatZodError(result.error);
        if (this.config.validationMode === 'strict') {
          throw new Error(`Credential offer validation failed: ${errorMsg}`);
        }
        this.log('warn', 'Credential offer validation warning', errorMsg);
      }

      // Return the parsed data cast to CredentialOffer
      // The SDK's CredentialOffer type is compatible with the validated schema
      return parsed as CredentialOffer;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Invalid credential offer format');
    }
  }

  /**
   * Delete a credential from the user's wallet.
   * Calls backend DELETE /api/credentials/:id — only the holder can delete.
   */
  async deleteCredential(id: string): Promise<void> {
    this.requireAuth();

    const response = await this.request<{ message: string }>(`/credentials/${id}`, {
      method: 'DELETE',
    });

    if (!response.success) {
      throw new Error(response.error?.message ?? 'Failed to delete credential');
    }

    this.emit('credential:deleted', { credentialId: id });
  }

  // ============================================================
  // Presentations
  // ============================================================

  /**
   * Parse a presentation request from URL or QR code with Zod validation.
   * NOTE: This is synchronous and does NOT verify JWT signatures.
   * Use parsePresentationRequestAsync for full signature verification.
   */
  parsePresentationRequest(data: string): PresentationRequest {
    try {
      let parsed: unknown;
      
      // Handle openid-vp:// URI
      if (data.startsWith('openid-vp://') || data.startsWith('openid4vp://')) {
        const url = new URL(data.replace(/^openid4?-vp:/, 'https:'));
        const requestParam = url.searchParams.get('request');
        if (requestParam) {
          // JWT-encoded request - decode and validate
          const payload = decodeJwt(requestParam);
          if (!payload) throw new Error('Invalid JWT format');
          
          // Validate JWT payload structure
          const payloadResult = validateSafe(PresentationRequestPayloadSchema, payload);
          if (!payloadResult.success) {
            const errorMsg = formatZodError(payloadResult.error);
            if (this.config.validationMode === 'strict') {
              throw new Error(`JWT payload validation failed: ${errorMsg}`);
            }
            this.log('warn', 'JWT payload validation failed, using raw payload', errorMsg);
          }
          
          parsed = payload;
        } else {
          const requestUri = url.searchParams.get('request_uri');
          if (requestUri) {
            throw new Error('request_uri requires async resolution - use parsePresentationRequestAsync');
          }
          throw new Error('Missing request parameter');
        }
      } else {
        parsed = JSON.parse(data);
      }

      // Basic structure validation for PresentationRequest
      if (!parsed || typeof parsed !== 'object') {
        throw new Error('Invalid presentation request structure');
      }

      return parsed as PresentationRequest;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Invalid presentation request format');
    }
  }

  /**
   * Parse a presentation request with full JWT signature verification.
   * Use this method when strict security is required.
   */
  async parsePresentationRequestAsync(data: string): Promise<PresentationRequest> {
    let parsed: unknown;
    
    // Handle openid-vp:// URI
    if (data.startsWith('openid-vp://') || data.startsWith('openid4vp://')) {
      const url = new URL(data.replace(/^openid4?-vp:/, 'https:'));
      const requestParam = url.searchParams.get('request');
      
      if (requestParam) {
        // JWT-encoded request - verify and decode
        const result = await this.verifyAndDecodeJwt(requestParam);
        
        if (!result.valid) {
          throw new Error(`JWT verification failed: ${result.error}`);
        }
        
        // Validate JWT payload structure
        const payloadResult = validateSafe(PresentationRequestPayloadSchema, result.payload);
        if (!payloadResult.success) {
          throw new Error(`JWT payload validation failed: ${formatZodError(payloadResult.error)}`);
        }
        
        parsed = result.payload;
      } else {
        const requestUri = url.searchParams.get('request_uri');
        if (requestUri) {
          // Fetch the request from the URI
          const response = await this.config.fetch(requestUri, {
            method: 'GET',
            headers: { Accept: 'application/jwt, application/json' },
          });
          
          if (!response.ok) {
            throw new Error(`Failed to fetch request from URI: ${response.status}`);
          }
          
          const contentType = response.headers.get('content-type') || '';
          const body = await response.text();
          
          if (contentType.includes('jwt') || body.split('.').length === 3) {
            // JWT response - verify and decode
            const result = await this.verifyAndDecodeJwt(body);
            if (!result.valid) {
              throw new Error(`JWT verification failed: ${result.error}`);
            }
            parsed = result.payload;
          } else {
            // JSON response
            parsed = JSON.parse(body);
          }
        } else {
          throw new Error('Missing request or request_uri parameter');
        }
      }
    } else {
      parsed = JSON.parse(data);
    }

    // Validate structure
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid presentation request structure');
    }

    return parsed as PresentationRequest;
  }

  /**
   * Create and submit a verifiable presentation
   */
  async presentCredentials(
    request: PresentationRequest,
    selections: DisclosureSelection[]
  ): Promise<void> {
    this.requireAuth();

    // Backend expects { requestId, credentials } — map selections to credential array
    const credentials = selections.map(s => ({
      id: s.credentialId,
      disclosedAttributes: s.attributes ?? [],
    }));

    const response = await this.request('/verification/submit', {
      method: 'POST',
      body: JSON.stringify({
        requestId: request.id,
        credentials,
      }),
    });

    if (!response.success) {
      throw new Error(response.error?.message ?? 'Failed to submit presentation');
    }

    this.emit('presentation:shared', {
      request,
      selections,
    });
  }

  /**
   * Get matching credentials for a presentation request
   */
  async getMatchingCredentials(
    request: PresentationRequest
  ): Promise<{ credential: WalletCredential; matchedAttributes: string[] }[]> {
    this.requireAuth();

    const requestTypes = request.requestedCredentials?.map(c => c.type).filter(Boolean) ?? [];

    // FINDING-028: push type filter to the server instead of fetching everything and filtering client-side
    const queryParams = new URLSearchParams();
    if (requestTypes.length > 0) {
      queryParams.set('types', requestTypes.join(','));
    }

    const response = await this.request<{ credentials: unknown[] }>(
      `/users/me/credentials?${queryParams.toString()}`,
      { method: 'GET' },
    );

    // A FAILED LOOKUP IS NOT AN EMPTY WALLET. `request` returns
    // `{ success: false, error }` rather than throwing, so `response.data?
    // .credentials ?? []` turned an expired session, a rate limit or a network
    // fault into "you hold no credentials" — and the only caller renders that
    // as "You don't have credentials that match this request". Measured on a
    // handset 9 Sep 2026 against a wallet that was, at that moment, displaying
    // the very credential the verifier had asked for.
    //
    // Throwing is the failsafe direction here: the caller already handles a
    // thrown error by telling the holder the check could not be made, which is
    // true and actionable, whereas the empty list is neither.
    if (!response.success) {
      throw new Error(
        `Could not read your credentials (${response.error?.code ?? 'UNKNOWN'}): ` +
          `${response.error?.message ?? 'no detail'}`,
      );
    }

    const allCredentials = (response.data?.credentials ?? [])
      .map((candidate) => this.validateWalletCredential(candidate))
      .filter((credential): credential is WalletCredential => credential !== null);

    return allCredentials
      .filter(cred => {
        if (requestTypes.length === 0) return true;
        const credTypes = Array.isArray(cred.type) ? cred.type : [cred.type];
        return requestTypes.some((rt: string) => credTypes.includes(rt));
      })
      .map(cred => ({
        credential: cred,
        // The disclosable attributes are the issuer's claims about the holder,
        // which live on the VC — not on the wallet envelope around it. Reading
        // `cred.credentialSubject` (a field the envelope does not have) yielded
        // `[]` for every credential, so the OID4VP share sheet offered nothing
        // to disclose. `id` is the subject's DID, not a disclosable claim.
        matchedAttributes: Object.keys(cred.credential.credentialSubject ?? {})
          .filter((key) => key !== 'id'),
      }));
  }

  // ============================================================
  // Consents
  // ============================================================

  /**
   * Get all consents for the current user
   */
  async getConsents(params?: PaginationParams & { active?: boolean }): Promise<{ consents: Consent[]; stats: CollectionStats }> {
    this.requireAuth();

    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.set('page', params.page.toString());
    if (params?.limit) queryParams.set('limit', params.limit.toString());
    if (params?.active !== undefined) queryParams.set('active', String(params.active));

    const response = await this.request<{ consents: Consent[]; stats: CollectionStats }>(
      `/users/me/consents?${queryParams.toString()}`
    );

    if (!response.success) {
      throw new Error(response.error?.message ?? 'Failed to fetch consents');
    }

    return response.data ?? { consents: [], stats: {} };
  }

  /**
   * Grant consent for a verifier to access specific credentials
   */
  async grantConsent(params: {
    verifierDid: string;
    verifierName: string;
    credentialIds: string[];
    purpose: ConsentPurpose;
    durationDays?: number;
  }): Promise<Consent> {
    this.requireAuth();

    const response = await this.request<Consent>('/consent/grant', {
      method: 'POST',
      body: JSON.stringify(params),
    });

    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? 'Failed to grant consent');
    }

    this.emit('consent:granted', { consent: response.data });
    return response.data;
  }

  /**
   * Verify if a consent exists for a specific holder-verifier-credential combination
   */
  async verifyConsent(params: {
    holderDid: string;
    verifierDid: string;
    credentialId: string;
  }): Promise<{ valid: boolean; consent?: Consent }> {
    this.requireAuth();

    const response = await this.request<{ valid: boolean; consent?: Consent }>('/consent/verify', {
      method: 'POST',
      body: JSON.stringify(params),
    });

    return response.data ?? { valid: false };
  }

  /**
   * Revoke a consent
   */
  async revokeConsent(consentId: string, reason?: string): Promise<void> {
    this.requireAuth();

    await this.request(`/users/me/consents/${consentId}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ reason: reason ?? 'User revoked consent' }),
    });
    this.emit('consent:revoked', { consentId });
  }

  // ============================================================
  // Verification
  // ============================================================
  //
  // ⚠ NEITHER METHOD BELOW VERIFIES ANYTHING LOCALLY.
  //
  // Both POST to the BDHealthTrust backend and return the boolean it sends
  // back. Whatever the field is called, the property being asserted is "our
  // server said so" — the caller has checked no signature, no digest, no nonce
  // and no holder binding, and cannot tell a valid presentation from an
  // invalid one if the server is wrong, compromised, or simply someone else's.
  // For a first-party integration that is a reasonable trade. For a
  // third-party relying party it is the centralised trust OAuth2 already has,
  // and the reason this SDK now ships a real verifier:
  //
  //     import { verifySdJwtPresentation } from '@ssi-healthcare/sdk/verify';
  //
  // Prefer it for any authorization decision. Use these two only to reconcile
  // with our records, or where the answer is advisory.
  //
  // Note also that `/verification/verify` is NOT MOUNTED on the backend as of
  // 21 Aug 2026 — the router that served it was retired to `Backup/` with a DO
  // NOT RESTORE header, because it ran a verifier that never checked the
  // presentation signature at all. `verifyPresentation` therefore fails rather
  // than returning a wrong answer, which is the better of the two failures.

  /**
   * Ask the BDHealthTrust backend whether it considers a credential valid.
   *
   * NOT a local check. See the block comment above this method.
   */
  async verifyCredential(credential: Credential): Promise<VerificationResult> {
    const response = await this.request<VerificationResult>('/credentials/verify', {
      method: 'POST',
      body: JSON.stringify({ credential }),
    });

    return response.data ?? {
      verified: false,
      error: 'Verification failed',
      checks: [],
    };
  }

  /**
   * Ask the BDHealthTrust backend whether it considers a presentation valid.
   *
   * NOT a local check, and currently calls an unmounted route. See the block
   * comment above `verifyCredential`, and use `verifySdJwtPresentation` from
   * `@ssi-healthcare/sdk/verify` instead.
   */
  async verifyPresentation(
    presentation: Presentation,
    options?: { challenge?: string; domain?: string }
  ): Promise<VerificationResult> {
    const response = await this.request<VerificationResult>('/verification/verify', {
      method: 'POST',
      body: JSON.stringify({ presentation, ...options }),
    });

    return response.data ?? {
      verified: false,
      error: 'Verification failed',
      checks: [],
    };
  }

  // ============================================================
  // Events
  // ============================================================

  /**
   * Subscribe to SDK events
   */
  on<T = unknown>(event: SSIEventType, listener: SSIEventListener<T>): () => void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, new Set());
    }
    this.eventListeners.get(event)!.add(listener as SSIEventListener);

    // Return unsubscribe function
    return () => {
      this.eventListeners.get(event)?.delete(listener as SSIEventListener);
    };
  }

  /**
   * Emit an event
   */
  private emit<T>(type: SSIEventType, payload: T): void {
    const event: SSIEvent<T> = {
      type,
      timestamp: Date.now(),
      payload,
    };

    this.eventListeners.get(type)?.forEach((listener) => {
      try {
        listener(event as SSIEvent);
      } catch (error) {
        this.log('error', 'Event listener error', error);
      }
    });
  }

  // ============================================================
  // Private Helpers
  // ============================================================

  /**
   * Make an API request
   */
  private async request<T>(
    endpoint: string,
    options?: RequestInit
  ): Promise<ApiResponse<T>> {
    const url = `${this.config.apiUrl}${endpoint}`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Client-ID': this.config.clientId,
    };

    if (this.authState.accessToken) {
      headers['Authorization'] = `Bearer ${this.authState.accessToken}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await this.config.fetch(url, {
        ...options,
        headers: { ...headers, ...options?.headers },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        // On 401, try to refresh token once and retry.
        //
        // NOT for `/auth/refresh` ITSELF. That request IS `refreshToken()`'s
        // own call, so entering this branch on its 401 called `refreshToken()`
        // again, which returned `refreshInFlight` — the very promise being
        // awaited here — and the promise waited on itself forever. Nothing
        // settled: the caller hung, `refreshInFlight` was never cleared, and
        // every later refresh joined the same dead promise. Measured 19 Sep
        // 2026: an expired session at cold start followed by a fresh login
        // left the dashboard on "Loading your dashboard…" permanently, with no
        // credential/consent request ever reaching the backend.
        if (
          response.status === 401 &&
          this.authState.accessToken &&
          endpoint !== '/auth/refresh' &&
          !options?.headers?.['X-Retry-After-Refresh' as keyof HeadersInit]
        ) {
          try {
            await this.refreshToken();
            // The other client may have refreshed concurrently, and the
            // backend keeps one access token per session: whichever refresh
            // landed LAST in storage holds the only token still accepted.
            // Retrying with this instance's own token is how the wallet 401'd
            // twice in a row on a cold start (steno #437).
            await this.adoptSharedAccessToken();
            return this.request<T>(endpoint, {
              ...options,
              headers: { ...options?.headers, 'X-Retry-After-Refresh': '1' } as Record<string, string>,
            });
          } catch {
            // Refresh failed — clear auth and return the original 401
            await this.clearAuthState();
            this.emit('auth:stateChanged', { state: this.getAuthState() });
          }
        }

        // The post-refresh retry can itself 401 when the other client's write
        // landed after the adoption above. One bounded second chance: adopt
        // whatever is in storage NOW and send once more. The marker header
        // keeps this to a single extra round trip; if storage has not changed
        // since, the response is returned as the real error.
        if (
          response.status === 401 &&
          this.authState.accessToken &&
          options?.headers?.['X-Retry-After-Refresh' as keyof HeadersInit] &&
          !options?.headers?.['X-Retry-After-Reconcile' as keyof HeadersInit]
        ) {
          if (await this.adoptSharedAccessToken()) {
            return this.request<T>(endpoint, {
              ...options,
              headers: { ...options?.headers, 'X-Retry-After-Reconcile': '1' } as Record<string, string>,
            });
          }
        }

        const errorBody = await response.json().catch(() => ({})) as {
          message?: string;
          error?: { message?: string; code?: string };
          success?: boolean;
        };
        // Backend may wrap error as { success: false, error: { message, code } }
        const errObj = errorBody.error ?? errorBody;
        return {
          success: false,
          error: {
            code: ('code' in errObj ? errObj.code : undefined) ?? `HTTP_${response.status}`,
            message: ('message' in errObj ? errObj.message : undefined) ?? response.statusText,
            details: errorBody,
          },
        };
      }

      const raw: unknown = await response.json();
      
      // Backend wraps responses in { success, data, error } envelope.
      // Unwrap so SDK callers get the inner payload directly.
      if (raw && typeof raw === 'object' && !Array.isArray(raw) && 'success' in raw && 'data' in raw) {
        return { success: true, data: (raw as Record<string, unknown>).data as T };
      }
      
      // Non-enveloped response (e.g., OID4VCI token endpoint, or array responses)
      return { success: true, data: raw as T };
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === 'AbortError') {
        return {
          success: false,
          error: { code: 'TIMEOUT', message: 'Request timed out' },
        };
      }

      return {
        success: false,
        error: {
          code: 'NETWORK_ERROR',
          message: error instanceof Error ? error.message : 'Network error',
        },
      };
    }
  }

  /**
   * Require authentication for protected operations
   */
  private requireAuth(): void {
    if (!this.isAuthenticated()) {
      throw new Error('Authentication required');
    }
  }

  /**
   * Set and persist auth state
   */
  private async setAuthState(state: AuthState): Promise<void> {
    this.authState = state;
    await this.storage.set(STORAGE_KEYS.AUTH_STATE, JSON.stringify(state));
    // Mirror the token into the key every client reads.
    //
    // The wallet has two HTTP clients against the same API, and the backend
    // keeps ONE access token per session, so a refresh by either must be
    // visible to the other at once. Writing only AUTH_STATE left
    // `ssi_access_token` holding a token the server had already replaced, and
    // the other client's next request 401'd for a reason no reader could see
    // (measured 19 Sep 2026, steno #437).
    if (state.accessToken) {
      await this.storage.set(STORAGE_KEYS.ACCESS_TOKEN, state.accessToken);
    } else {
      await this.storage.remove(STORAGE_KEYS.ACCESS_TOKEN);
    }
    if (state.refreshToken) {
      await this.storage.set(STORAGE_KEYS.REFRESH_TOKEN, state.refreshToken);
    }
  }

  /**
   * Adopt the access token another client last wrote to shared storage.
   *
   * Returns true when the in-memory token changed. Storage is the only meeting
   * point two clients have, and because the backend keeps one access token per
   * session, the LAST writer holds the only token the server still accepts —
   * the earlier refresher's token is dead the moment the later one lands.
   */
  private async adoptSharedAccessToken(): Promise<boolean> {
    const shared = await this.storage.get(STORAGE_KEYS.ACCESS_TOKEN);
    if (!shared || shared === this.authState.accessToken) return false;
    this.authState.accessToken = shared;
    return true;
  }

  /**
   * Clear auth state
   */
  private async clearAuthState(): Promise<void> {
    this.authState = {
      isAuthenticated: false,
      isLoading: false,
    };
    await this.storage.remove(STORAGE_KEYS.AUTH_STATE);
    await this.storage.remove(STORAGE_KEYS.ACCESS_TOKEN);
    // FINDING-002: Always remove the refresh token on logout.
    // Previously missing — leaving a live refresh token after logout
    // allowed silent session resurrection on shared/compromised devices.
    await this.storage.remove(STORAGE_KEYS.REFRESH_TOKEN);
  }

  /**
   * Decode JWT header
   */
  private decodeJwtHeader(jwt: string): { alg: string; kid?: string; typ?: string } {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const header = parts[0];
    const decoded = atob(header.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded);
  }

  /**
   * Verify JWT signature using Web Crypto API
   */
  private async verifyJwtSignature(token: string): Promise<boolean> {
    if (this.config.jwtVerification !== 'strict') {
      return true; // Skip verification in permissive mode
    }

    if (!this.config.jwksUri) {
      throw new Error('JWKS URI required for strict JWT verification');
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    const header = this.decodeJwtHeader(token);

    // Get the signing key
    const key = await this.getJwkForKid(header.kid);
    if (!key) {
      throw new Error(`Signing key not found: ${header.kid || 'no kid specified'}`);
    }

    // Determine algorithm
    const algorithm = this.getWebCryptoAlgorithm(header.alg);
    if (!algorithm) {
      throw new Error(`Unsupported JWT algorithm: ${header.alg}`);
    }

    // Import the public key
    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      key.key,
      algorithm.importAlg,
      false,
      ['verify']
    );

    // Decode signature
    const signature = this.base64UrlDecode(signatureB64);

    // Verify
    const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const verified = await crypto.subtle.verify(
      algorithm.verifyAlg,
      cryptoKey,
      signature,
      data
    );

    return verified;
  }

  /**
   * Decode base64url to ArrayBuffer
   */
  private base64UrlDecode(str: string): ArrayBuffer {
    // Add padding if needed
    const padded = str + '==='.slice((str.length + 3) % 4);
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Get Web Crypto algorithm configuration
   */
  private getWebCryptoAlgorithm(alg: string): { importAlg: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams; verifyAlg: AlgorithmIdentifier | RsaPssParams | EcdsaParams } | null {
    switch (alg) {
      case 'RS256':
        return {
          importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          verifyAlg: { name: 'RSASSA-PKCS1-v1_5' },
        };
      case 'RS384':
        return {
          importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
          verifyAlg: { name: 'RSASSA-PKCS1-v1_5' },
        };
      case 'RS512':
        return {
          importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
          verifyAlg: { name: 'RSASSA-PKCS1-v1_5' },
        };
      case 'ES256':
        return {
          importAlg: { name: 'ECDSA', namedCurve: 'P-256' },
          verifyAlg: { name: 'ECDSA', hash: 'SHA-256' },
        };
      case 'ES384':
        return {
          importAlg: { name: 'ECDSA', namedCurve: 'P-384' },
          verifyAlg: { name: 'ECDSA', hash: 'SHA-384' },
        };
      case 'ES512':
        return {
          importAlg: { name: 'ECDSA', namedCurve: 'P-521' },
          verifyAlg: { name: 'ECDSA', hash: 'SHA-512' },
        };
      default:
        return null;
    }
  }

  /**
   * Get JWK for a specific key ID from JWKS
   */
  private async getJwkForKid(kid?: string): Promise<{ key: JsonWebKey; kid: string } | null> {
    // Check cache
    if (kid && this.jwksCache.has(kid) && Date.now() < this.jwksCacheExpiry) {
      return this.jwksCache.get(kid) ?? null;
    }

    // Fetch JWKS
    const response = await this.config.fetch(this.config.jwksUri, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch JWKS: ${response.status}`);
    }

    const jwks = await response.json() as { keys: JwksKey[] };

    // Cache keys for 1 hour
    this.jwksCacheExpiry = Date.now() + 3600000;
    this.jwksCache.clear();

    for (const key of jwks.keys) {
      if (key.kid) {
        this.jwksCache.set(key.kid, { key, kid: key.kid });
      }
    }

    // Return requested key
    if (kid) {
      return this.jwksCache.get(kid) ?? null;
    }

    // Return first key if no kid specified
    const firstKey = jwks.keys[0];
    return firstKey ? { key: firstKey, kid: firstKey.kid || 'default' } : null;
  }

  /**
   * Verify and decode JWT with signature validation
   */
  async verifyAndDecodeJwt(token: string): Promise<{ valid: boolean; payload: Record<string, unknown>; error?: string }> {
    try {
      const payload = decodeJwt(token);
      if (!payload) {
        return { valid: false, payload: {}, error: 'Invalid JWT format' };
      }

      if (this.config.jwtVerification === 'strict') {
        const valid = await this.verifyJwtSignature(token);
        if (!valid) {
          return { valid: false, payload, error: 'JWT signature verification failed' };
        }
      }

      // Check expiration
      const exp = payload.exp as number | undefined;
      if (exp && Date.now() >= exp * 1000) {
        return { valid: false, payload, error: 'JWT has expired' };
      }

      // Check not before
      const nbf = payload.nbf as number | undefined;
      if (nbf && Date.now() < nbf * 1000) {
        return { valid: false, payload, error: 'JWT is not yet valid' };
      }

      return { valid: true, payload };
    } catch (error) {
      return { 
        valid: false, 
        payload: {}, 
        error: error instanceof Error ? error.message : 'JWT verification failed' 
      };
    }
  }

  /**
   * Log debug messages
   */
  private log(level: 'debug' | 'info' | 'warn' | 'error', message: string, ...args: unknown[]): void {
    // FINDING-018: Respect debug flag for ALL levels — SDK must not emit console output
    // unconditionally in consumer applications. Warn/error output pollutes host app logs.
    if (!this.config.debug) return;

    const prefix = '[SSI SDK]';
    switch (level) {
      case 'debug':
        console.debug(prefix, message, ...args);
        break;
      case 'info':
        console.info(prefix, message, ...args);
        break;
      case 'warn':
        console.warn(prefix, message, ...args);
        break;
      case 'error':
        console.error(prefix, message, ...args);
        break;
    }
  }
}
