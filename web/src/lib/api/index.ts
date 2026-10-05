/**
 * SSI Healthcare - API Client
 * 
 * Type-safe API client for communication with the backend.
 * Handles authentication, error handling, request/response transformation,
 * and automatic token refresh.
 */

import type { WalletCredential, WalletCredentialStats } from '@ssi-healthcare/shared';

// API requests use relative URLs via Next.js rewrites (/api/* → backend).
// This avoids cross-origin requests that ad blockers may intercept.
function getBaseUrl(): string {
  if (typeof window !== 'undefined') return window.location.origin;
  return 'http://localhost:3000';
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// FINDING-019: align with backend ApiResponse shape
// Explicitly declare all fields (including those from the shared package)
// so TypeScript resolves the type correctly from consumer files.
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  timestamp: string;
  pagination?: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

interface RequestConfig extends RequestInit {
  params?: Record<string, string | number | boolean | undefined>;
  skipAuth?: boolean;
}

// ---------------------------------------------------------------------------
// Token Management with Refresh
// ---------------------------------------------------------------------------

let accessToken: string | null = null;
let refreshToken: string | null = null;
let tokenExpiresAt: number | null = null;
let refreshPromise: Promise<boolean> | null = null;

export function setAccessToken(token: string | null, expiresIn?: number): void {
  accessToken = token;
  if (token && expiresIn) {
    tokenExpiresAt = Date.now() + (expiresIn * 1000);
  } else {
    tokenExpiresAt = null;
  }
  
  if (typeof window !== 'undefined') {
    if (token) {
      localStorage.setItem('ssi_access_token', token);
      if (tokenExpiresAt) {
        localStorage.setItem('ssi_token_expires_at', tokenExpiresAt.toString());
      }
    } else {
      localStorage.removeItem('ssi_access_token');
      localStorage.removeItem('ssi_token_expires_at');
    }
  }
}

export function setRefreshToken(token: string | null): void {
  refreshToken = token;
  if (typeof window !== 'undefined') {
    if (token) {
      localStorage.setItem('ssi_refresh_token', token);
    } else {
      localStorage.removeItem('ssi_refresh_token');
    }
  }
}

export function getAccessToken(): string | null {
  if (accessToken) return accessToken;
  if (typeof window !== 'undefined') {
    accessToken = localStorage.getItem('ssi_access_token');
    const expiresStr = localStorage.getItem('ssi_token_expires_at');
    if (expiresStr) {
      tokenExpiresAt = parseInt(expiresStr, 10);
    }
  }
  return accessToken;
}

export function getRefreshToken(): string | null {
  if (refreshToken) return refreshToken;
  if (typeof window !== 'undefined') {
    refreshToken = localStorage.getItem('ssi_refresh_token');
  }
  return refreshToken;
}

export function clearTokens(): void {
  accessToken = null;
  refreshToken = null;
  tokenExpiresAt = null;
  if (typeof window !== 'undefined') {
    localStorage.removeItem('ssi_access_token');
    localStorage.removeItem('ssi_refresh_token');
    localStorage.removeItem('ssi_token_expires_at');
  }
}

function isTokenExpired(): boolean {
  if (!tokenExpiresAt) return false;
  // Consider token expired if it expires within 30 seconds
  return Date.now() >= tokenExpiresAt - 30000;
}

async function refreshAccessToken(): Promise<boolean> {
  // Prevent multiple simultaneous refresh attempts
  if (refreshPromise) {
    return refreshPromise;
  }
  
  const currentRefreshToken = getRefreshToken();
  if (!currentRefreshToken) {
    return false;
  }
  
  refreshPromise = (async () => {
    try {
      const response = await fetch(`${getBaseUrl()}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: currentRefreshToken }),
        credentials: 'include',
      });
      
      if (!response.ok) {
        clearTokens();
        return false;
      }
      
      const data = await response.json();
      if (data.success && data.data) {
        setAccessToken(data.data.token, data.data.expiresIn);
        if (data.data.refreshToken) {
          setRefreshToken(data.data.refreshToken);
        }
        return true;
      }
      
      clearTokens();
      return false;
    } catch {
      clearTokens();
      return false;
    } finally {
      refreshPromise = null;
    }
  })();
  
  return refreshPromise;
}

// ---------------------------------------------------------------------------
// API Error
// ---------------------------------------------------------------------------

export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public statusCode: number,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

// ---------------------------------------------------------------------------
// Request Helper with Automatic Token Refresh
// ---------------------------------------------------------------------------

async function request<T>(
  endpoint: string,
  config: RequestConfig = {},
  isRetry = false
): Promise<ApiResponse<T>> {
  const { params, skipAuth, ...fetchConfig } = config;
  
  // Build URL with query params
  const url = new URL(`${getBaseUrl()}${endpoint}`);
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        url.searchParams.append(key, String(value));
      }
    });
  }
  
  // Build headers
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...fetchConfig.headers,
  };
  
  // Add auth token if not skipped
  if (!skipAuth) {
    // Check if token needs refresh before making request
    if (isTokenExpired() && !isRetry) {
      const refreshed = await refreshAccessToken();
      if (!refreshed) {
        throw new ApiError('AUTH_EXPIRED', 'Session expired, please login again', 401);
      }
    }
    
    const token = getAccessToken();
    if (token) {
      (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
    }
  }
  
  // Request timeout (30s default, longer for large operations)
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);
  
  try {
    const response = await fetch(url.toString(), {
      ...fetchConfig,
      headers,
      credentials: 'include',
      signal: controller.signal,
    });
    
    // Handle 401 with automatic token refresh
    if (response.status === 401 && !isRetry && !skipAuth) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        // Retry the original request with new token
        return request<T>(endpoint, config, true);
      }
      throw new ApiError('AUTH_EXPIRED', 'Session expired, please login again', 401);
    }
    
    const data = await response.json() as ApiResponse<T>;
    
    if (!response.ok || !data.success) {
      throw new ApiError(
        data.error?.code || 'UNKNOWN_ERROR',
        data.error?.message || 'An unexpected error occurred',
        response.status,
        data.error?.details
      );
    }
    
    return data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiError('TIMEOUT', 'Request timed out', 0);
    }
    
    throw new ApiError(
      'NETWORK_ERROR',
      'Failed to connect to server',
      0
    );
  } finally {
    clearTimeout(timeout);
  }
}

// ---------------------------------------------------------------------------
// Auth API
// ---------------------------------------------------------------------------

interface AuthResponse {
  user: User;
  token: string;
  refreshToken?: string;
  expiresIn?: number;
  needsWalletSetup?: boolean;
}

export const authApi = {
  async register(data: {
    email: string;
    firstName?: string;
    lastName?: string;
  }) {
    const response = await request<AuthResponse>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
      skipAuth: true,
    });
    
    if (response.data) {
      setAccessToken(response.data.token, response.data.expiresIn);
      if (response.data.refreshToken) {
        setRefreshToken(response.data.refreshToken);
      }
    }
    
    return response;
  },
  
  async login(email: string) {
    return request<{ pendingToken: string; expiresIn: number; isNewUser: boolean }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email }),
      skipAuth: true,
    });
  },
  
  /**
   * Send login code to email. Alias for login() — the backend's /login
   * endpoint sends a 6-digit code (magic link style, no password).
   */
  async sendMagicLink(email: string) {
    return this.login(email);
  },
  
  /**
   * Verify the 6-digit login code and get session tokens.
   * Requires the pendingToken from login() and the code sent to the user's email.
   */
  async verifyCode(pendingToken: string, code: string) {
    const response = await request<AuthResponse>('/api/auth/verify-code', {
      method: 'POST',
      body: JSON.stringify({ pendingToken, code }),
      skipAuth: true,
    });
    
    if (response.data) {
      setAccessToken(response.data.token, response.data.expiresIn);
      if (response.data.refreshToken) {
        setRefreshToken(response.data.refreshToken);
      }
    }
    
    return response;
  },
  
  /**
   * @deprecated Use verifyCode() instead. Kept for backward compat.
   */
  async verifyMagicLink(pendingToken: string, code: string) {
    return this.verifyCode(pendingToken, code);
  },
  
  async getPasskeyRegistrationOptions() {
    return request<PublicKeyCredentialCreationOptionsJSON>('/api/auth/passkey/register/options', {
      method: 'POST',
    });
  },
  
  async verifyPasskeyRegistration(credential: unknown) {
    return request<{ verified: boolean }>('/api/auth/passkey/register/verify', {
      method: 'POST',
      body: JSON.stringify({ credential }),
    });
  },
  
  async getPasskeyAuthenticationOptions(email?: string) {
    return request<PublicKeyCredentialRequestOptionsJSON>('/api/auth/passkey/authenticate/options', {
      method: 'POST',
      body: JSON.stringify({ email }),
      skipAuth: true,
    });
  },
  
  async verifyPasskeyAuthentication(credential: unknown) {
    const response = await request<AuthResponse>('/api/auth/passkey/authenticate/verify', {
      method: 'POST',
      body: JSON.stringify({ credential }),
      skipAuth: true,
    });
    
    if (response.data) {
      setAccessToken(response.data.token, response.data.expiresIn);
      if (response.data.refreshToken) {
        setRefreshToken(response.data.refreshToken);
      }
    }
    
    return response;
  },
  
  async refresh() {
    const token = getRefreshToken();
    if (!token) {
      throw new ApiError('NO_REFRESH_TOKEN', 'No refresh token available', 401);
    }
    
    const response = await request<AuthResponse>('/api/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: token }),
      skipAuth: true,
    });
    
    if (response.data) {
      setAccessToken(response.data.token, response.data.expiresIn);
      if (response.data.refreshToken) {
        setRefreshToken(response.data.refreshToken);
      }
    }
    
    return response;
  },
  
  async logout() {
    try {
      await request<void>('/api/auth/logout', {
        method: 'POST',
      });
    } finally {
      clearTokens();
    }
  },
  
  async getCurrentUser() {
    return request<User>('/api/auth/me');
  },
  
  async setupWallet(walletType: string = 'CLOUD') {
    return request<{ did: string; walletType: string }>('/api/auth/wallet/setup', {
      method: 'POST',
      body: JSON.stringify({ walletType }),
    });
  },
  
  isAuthenticated(): boolean {
    return !!getAccessToken();
  },
  
  getTokenExpiresAt(): number | null {
    return tokenExpiresAt;
  },
};

// ---------------------------------------------------------------------------
// User API
// ---------------------------------------------------------------------------

export const userApi = {
  async getProfile() {
    return request<User>('/api/users/me');
  },
  
  async getCredentials(params?: {
    category?: string;
    status?: string;
    page?: number;
    limit?: number;
  }) {
    return request<{ credentials: Credential[]; stats: CredentialStats | null }>('/api/users/me/credentials', { params });
  },
  
  async getCredential(id: string) {
    return request<Credential>(`/api/users/me/credentials/${id}`);
  },
  
  async getConsents(params?: {
    status?: 'active' | 'revoked' | 'expired' | 'all';
    page?: number;
    limit?: number;
  }) {
    // Backend uses ?active=false to include non-active consents
    const backendParams: Record<string, string | number | undefined> = {
      page: params?.page,
      limit: params?.limit,
    };
    if (!params?.status || params.status === 'active') {
      // default backend behavior: activeOnly=true
    } else {
      // revoked/expired/all: fetch everything, backend filters not granular enough
      backendParams.active = 'false';
    }
    return request<{ consents: Consent[]; stats: ConsentStats }>('/api/users/me/consents', { params: backendParams });
  },
  
  async revokeConsent(id: string, reason?: string) {
    return request<Consent>(`/api/users/me/consents/${id}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  },
  
  async getAuditLogs(params?: {
    startDate?: string;
    endDate?: string;
    page?: number;
    limit?: number;
  }) {
    // FINDING-015: Scope audit to the authenticated user, not the admin-level endpoint.
    return request<{ events: AuditLog[]; total: number; hasMore: boolean }>('/api/users/me/audit', { params });
  },
  
  async getActivity(params?: {
    page?: number;
    limit?: number;
  }) {
    return request<ActivityItem[]>('/api/users/me/activity', { params });
  },
  
  async getSessions() {
    return request<{ sessions: UserSession[] }>('/api/users/me/sessions');
  },
  
  async revokeSessions() {
    return request<{ deletedCount: number }>('/api/users/me/sessions', {
      method: 'DELETE',
    });
  },
  
  async updateProfile(data: Partial<{
    name: string;
    firstName: string;
    lastName: string;
    displayName: string;
    phone: string;
    image: string;
    settings: Record<string, unknown>;
  }>) {
    return request<User>('/api/users/me/profile', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },
  
  async updateSecurity(data: Partial<{
    biometricEnabled: boolean;
    autoLockMinutes: number;
    totpEnabled: boolean;
  }>) {
    return request<User>('/api/users/me/security', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async updateNotifications(data: {
    emailEnabled?: boolean;
    pushEnabled?: boolean;
    emailDigest?: 'immediate' | 'daily' | 'weekly';
    quietHoursEnabled?: boolean;
    eventPreferences?: Record<string, boolean>;
  }) {
    return request<{
      emailEnabled: boolean;
      pushEnabled: boolean;
      emailDigest: string;
      quietHoursEnabled: boolean;
      eventPreferences: Record<string, boolean>;
    }>('/api/users/me/notifications', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async getNotifications() {
    return request<{
      emailEnabled: boolean;
      pushEnabled: boolean;
      emailDigest: string;
      quietHoursEnabled: boolean;
      eventPreferences: Record<string, boolean>;
    }>('/api/users/me/notifications');
  },

  async addEmergencyContact(data: {
    name: string;
    relationship: string;
    email?: string;
    phone?: string;
    allowedCredentials?: string[];
  }) {
    return request<{ id: string; name: string; relationship: string; canAccess: string[] }>(
      '/api/users/me/emergency-contacts',
      { method: 'POST', body: JSON.stringify(data) }
    );
  },

  async updateEmergencyContact(id: string, data: {
    name?: string;
    relationship?: string;
    email?: string | null;
    phone?: string | null;
    allowedCredentials?: string[];
  }) {
    return request<{ id: string; name: string; relationship: string; canAccess: string[] }>(
      `/api/users/me/emergency-contacts/${id}`,
      { method: 'PUT', body: JSON.stringify(data) }
    );
  },

  async deleteEmergencyContact(id: string) {
    return request<void>(`/api/users/me/emergency-contacts/${id}`, { method: 'DELETE' });
  },

  async deleteAccount() {
    return request<{ message: string }>('/api/users/me', { method: 'DELETE' });
  },

  async getPresentations(params?: {
    page?: number;
    limit?: number;
  }) {
    return request<{ presentations: Presentation[]; stats: unknown }>('/api/users/me/presentations', { params });
  },
};

// ---------------------------------------------------------------------------
// Credential API
// ---------------------------------------------------------------------------

export const credentialApi = {
  async acceptOffer(offerId: string) {
    return request<Credential>('/api/credentials/accept-offer', {
      method: 'POST',
      body: JSON.stringify({ offerId }),
    });
  },
  
  async rejectOffer(offerId: string, reason?: string) {
    return request<void>('/api/credentials/reject-offer', {
      method: 'POST',
      body: JSON.stringify({ offerId, reason }),
    });
  },
  
  async getOffers() {
    return request<CredentialOffer[]>('/api/credentials/offers');
  },

  async resolveOffer(preAuthorizedCode: string) {
    return request<{
      offerId: string;
      credentialType: string;
      issuerDid: string;
      issuerName: string;
      previewData: Record<string, unknown>;
      pinRequired: boolean;
      expiresAt: string;
    }>('/api/credentials/resolve-offer', {
      method: 'POST',
      body: JSON.stringify({ preAuthorizedCode }),
    });
  },
  
  async deleteCredential(id: string) {
    return request<void>(`/api/credentials/${id}`, {
      method: 'DELETE',
    });
  },

  // FINDING-013: Holder submits their own credential. This is separate from verifierApi
  // which is used by relying parties to *request* presentations from holders.
  async shareCredential(id: string, data: {
    selectedAttributes?: string[];
    recipientDid?: string;
    requestId?: string;
  }) {
    return request<{ presentationId: string }>(`/api/credentials/${id}/share`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
};

// ---------------------------------------------------------------------------
// Presentation / Verification API
// ---------------------------------------------------------------------------

export const presentationApi = {
  async createPresentation(data: {
    definition: {
      id: string;
      name?: string;
      purpose?: string;
      inputDescriptors: Array<{
        id: string;
        constraints: { fields: Array<{ path: string[] }> };
      }>;
    };
    responseUri?: string;
  }) {
    return request<{ requestId: string; requestUrl: string }>('/api/verification/request', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  
  async submitPresentation(data: {
    requestId: string;
    credentials: unknown[];
  }) {
    return request<{ verified: boolean }>('/api/verification/submit', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getRequest(requestId: string) {
    return request<{
      id: string;
      definition: Record<string, unknown>;
      verifierDid: string;
      nonce: string;
      createdAt: number;
      expiresAt: number;
      status: string;
    }>(`/api/verification/request/${requestId}`);
  },

  async submitByIds(requestId: string, credentialIds: string[]) {
    return request<{ verified: boolean; requestId: string; errors: string[] }>('/api/verification/submit-by-ids', {
      method: 'POST',
      body: JSON.stringify({ requestId, credentialIds }),
    });
  },
  
  async getPresentationHistory(params?: {
    page?: number;
    limit?: number;
  }) {
    return request<{ presentations: Presentation[]; stats: unknown }>('/api/users/me/presentations', { params });
  },
};

// ---------------------------------------------------------------------------
// Webhook API (for institutions)
// ---------------------------------------------------------------------------

export const webhookApi = {
  async getWebhooks() {
    return request<Webhook[]>('/api/webhooks');
  },
  
  async createWebhook(data: {
    url: string;
    events: string[];
    secret?: string;
  }) {
    return request<Webhook>('/api/webhooks', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  
  async updateWebhook(id: string, data: Partial<{
    url: string;
    events: string[];
    active: boolean;
  }>) {
    return request<Webhook>(`/api/webhooks/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  },
  
  async deleteWebhook(id: string) {
    return request<void>(`/api/webhooks/${id}`, {
      method: 'DELETE',
    });
  },
  
  async testWebhook(id: string) {
    return request<{ success: boolean }>(`/api/webhooks/${id}/test`, {
      method: 'POST',
    });
  },
  
  async getDeliveries(webhookId: string, params?: {
    page?: number;
    limit?: number;
  }) {
    return request<WebhookDelivery[]>(`/api/webhooks/${webhookId}/deliveries`, { params });
  },
};

// ---------------------------------------------------------------------------
// Analytics API
// ---------------------------------------------------------------------------

export const analyticsApi = {
  async trackEvent(data: {
    eventName: string;
    eventCategory: string;
    pagePath: string;
    sessionId: string;
    componentId?: string;
    properties?: Record<string, unknown>;
    durationMs?: number;
    deviceType?: string;
    browser?: string;
    os?: string;
  }) {
    return request<{ id: string }>('/api/analytics/events', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
};

// ---------------------------------------------------------------------------
// Health API
// ---------------------------------------------------------------------------

export const healthApi = {
  async check() {
    return request<HealthStatus>('/api/health');
  },
  
  async detailed() {
    return request<DetailedHealthStatus>('/api/health/readiness');
  },
};

// ---------------------------------------------------------------------------
// Emergency API
// ---------------------------------------------------------------------------

export const emergencyApi = {
  async getEmergencyData(patientDid: string) {
    return request<EmergencyData>(`/api/emergency/${encodeURIComponent(patientDid)}`);
  },
  
  async requestAccess(data: {
    patientDid: string;
    reason: string;
    credentialIds: string[];
    familyContactDid?: string;
  }) {
    return request<EmergencyAccess>('/api/emergency/request', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  
  async revokeAccess(emergencyId: string) {
    return request<void>('/api/emergency/revoke', {
      method: 'POST',
      body: JSON.stringify({ emergencyId }),
    });
  },
  
  async checkAccess(providerDid: string, patientDid: string) {
    return request<{ hasAccess: boolean; expiresAt?: string }>('/api/emergency/check', {
      method: 'POST',
      body: JSON.stringify({ providerDid, patientDid }),
    });
  },
};

// ---------------------------------------------------------------------------
// Insurance Claims API
// ---------------------------------------------------------------------------

export const claimsApi = {
  async getClaims(params?: {
    status?: string;
    page?: number;
    limit?: number;
  }) {
    return request<{ claims: InsuranceClaim[]; total: number; hasMore: boolean }>('/api/claims', { params });
  },
  
  async submitClaim(data: {
    patientDid: string;
    providerDid: string;
    insurerDid: string;
    procedureCode: string;
    diagnosisCode: string;
    amount: number;
    description?: string;
    credentialIds?: string[];
  }) {
    return request<InsuranceClaim>('/api/claims', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  
  async getClaim(id: string) {
    return request<InsuranceClaim>(`/api/claims/${id}`);
  },
  
  async updateClaimStatus(id: string, data: {
    status: string;
    reason?: string;
  }) {
    return request<InsuranceClaim>(`/api/claims/${id}/status`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },
};

// ---------------------------------------------------------------------------
// Pharmacy API
// ---------------------------------------------------------------------------

export const pharmacyApi = {
  async verifyPrescription(data: {
    prescriptionCredentialId: string;
    patientDid: string;
    pharmacyDid: string;
  }) {
    return request<PrescriptionVerification>('/api/pharmacy/verify', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  
  async dispenseMedication(data: {
    prescriptionId: string;
    pharmacyDid: string;
    medicationDetails: Record<string, unknown>;
  }) {
    return request<DispenseRecord>('/api/pharmacy/dispense', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  
  async getDispenseHistory(params?: {
    page?: number;
    limit?: number;
  }) {
    return request<{ history: DispenseRecord[]; total: number; hasMore: boolean }>('/api/pharmacy/history', { params });
  },
};

// ---------------------------------------------------------------------------
// Hospital Coupler API
// ---------------------------------------------------------------------------

export interface HospitalConnection {
  id: string;
  hospitalId: string;
  hospitalName: string;
  hospitalUrl: string;
  patientId: string;
  patientName?: string;
  isActive: boolean;
  lastSyncAt?: string;
  linkedAt: string;
}

export interface HospitalSyncResult {
  credentialsCreated: number;
  credentialIds: string[];
}

export const hospitalApi = {
  async connect(data: {
    hospitalId: string;
    hospitalName: string;
    hospitalUrl: string;
    patientId: string;
    apiKey?: string;
  }) {
    return request<HospitalConnection>('/api/hospital/connect', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getConnections() {
    const res = await request<{ items: HospitalConnection[] }>('/api/hospital/connections');
    return { ...res, data: res.data?.items ?? [] };
  },

  async removeConnection(id: string) {
    return request<void>(`/api/hospital/connections/${id}`, { method: 'DELETE' });
  },

  async sync(id: string, apiKey?: string) {
    return request<HospitalSyncResult>(`/api/hospital/sync/${id}`, {
      method: 'POST',
      body: JSON.stringify(apiKey ? { apiKey } : {}),
    });
  },

  async getHospitalRecords() {
    return request<Record<string, unknown>[]>('/api/hospital/records');
  },
};

// ---------------------------------------------------------------------------
// Issuer API (for credential issuers)
// ---------------------------------------------------------------------------

export const issuerApi = {
  async createOffer(data: {
    subjectDid: string;
    credentialType: string;
    category: string;
    claims: Record<string, unknown>;
  }) {
    return request<CredentialOffer>('/api/credentials/offer', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  
  async getIssuedCredentials(params?: {
    page?: number;
    limit?: number;
  }) {
    // FINDING-010: Use the issuer-scoped endpoint, not the holder's own credential list.
    return request<{ credentials: Credential[]; stats: unknown }>('/api/credentials/issued', { params });
  },
  
  async revokeCredential(id: string, reason: string) {
    return request<void>(`/api/credentials/${id}/revoke`, {
      method: 'PATCH',
      body: JSON.stringify({ reason }),
    });
  },
};

// ---------------------------------------------------------------------------
// Verifier API (for credential verifiers)
// ---------------------------------------------------------------------------

export const verifierApi = {
  async createPresentationRequest(data: {
    holderDid?: string;
    definition: {
      id: string;
      name?: string;
      purpose?: string;
      inputDescriptors: Array<{
        id: string;
        name?: string;
        purpose?: string;
        constraints: {
          fields: Array<{
            path: string[];
            filter?: { type: string; const?: string; enum?: string[] };
          }>;
        };
      }>;
    };
    responseUri?: string;
  }) {
    return request<{
      id: string;
      definition: typeof data.definition;
      verifierDid: string;
      nonce: string;
      status: string;
      requestUri?: string;
      requestByReference?: string;
      createdAt: number;
      expiresAt: number;
    }>('/api/verification/request', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  
  async getVerificationResult(requestId: string) {
    return request<VerificationResult>(`/api/verification/request/${requestId}`);
  },
  
  async getVerificationHistory(params?: {
    page?: number;
    limit?: number;
  }) {
    return request<{ presentations: VerificationResult[]; stats: unknown }>('/api/users/me/presentations', { params });
  },
};

// ---------------------------------------------------------------------------
// Admin/Analytics Dashboard API
// ---------------------------------------------------------------------------

export const adminApi = {
  async getDashboard() {
    return request<DashboardStats>('/api/analytics/dashboard');
  },
  
  async getAuditLogs(params?: {
    eventType?: string;
    startDate?: string;
    endDate?: string;
    page?: number;
    limit?: number;
  }) {
    return request<{ events: AuditLog[]; total: number; hasMore: boolean }>('/api/audit', { params });
  },

  async getEmergencyLogs(params?: { page?: number; limit?: number }) {
    return request<{ events: AuditLog[]; total: number; hasMore: boolean }>('/api/audit', {
      params: { eventType: 'EMERGENCY_ACCESS_GRANTED,EMERGENCY_ACCESS_REQUESTED,EMERGENCY_ACCESS_REVOKED', ...params },
    });
  },

  async getConsentLogs(params?: { page?: number; limit?: number }) {
    return request<{ events: AuditLog[]; total: number; hasMore: boolean }>('/api/audit', {
      params: { eventType: 'CONSENT_GRANTED,CONSENT_REVOKED,CONSENT_UPDATED', ...params },
    });
  },
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface User {
  id: string;
  did?: string;
  email: string;
  emailVerified?: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  avatarUrl?: string;
  phone?: string;
  totpEnabled: boolean;
  walletSetup: boolean;
  walletType?: string;
  biometricEnabled: boolean;
  autoLockMinutes: number;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
}

/**
 * A credential in the user's wallet.
 *
 * This is `WalletCredential` from `@ssi-healthcare/shared` — the single
 * authoritative definition of the wire contract, shared with the backend that
 * produces it and the mobile wallet that consumes it. It is re-exported here so
 * existing `import { type Credential } from '@/lib/api'` call sites keep
 * working, but it is deliberately NOT redefined: the previous local copy
 * mirrored Prisma columns (`credentialData`, `credentialHash`, `schemaId`) and
 * drifted the moment the backend changed shape, with the compiler none the
 * wiser because responses are cast, not validated.
 *
 * The signed VC now lives at `credential.credential`; `credentialData` is gone.
 */
export type Credential = WalletCredential;
export type CredentialStats = WalletCredentialStats;

export interface CredentialOffer {
  id: string;
  issuerDid: string;
  issuerName?: string;
  holderDid?: string;
  holderEmail?: string;
  credentialType: string;
  category: string;
  offerData: Record<string, unknown>;
  status: 'PENDING' | 'ACCEPTED' | 'REJECTED' | 'EXPIRED' | 'REVOKED';
  pinRequired: boolean;
  createdAt: string;
  expiresAt: string;
  acceptedAt?: string;
}

export interface Consent {
  id: string;
  holderDid: string;
  verifierDid: string;
  verifierName: string;
  purpose: string;
  scope: string[];
  allowedFields: string[];
  status: 'active' | 'revoked' | 'expired';
  grantedAt: string;
  expiresAt?: string;
  revokedAt?: string;
  accessCount: number;
  lastAccessedAt?: string;
}

export interface ConsentStats {
  total: number;
  active: number;
  revoked: number;
  expired: number;
}

export interface Presentation {
  id: string;
  holderDid: string;
  verifierDid: string;
  verifierName?: string;
  credentialIds: string[];
  disclosedFields: string[];
  purpose?: string;
  status: 'pending' | 'verified' | 'rejected' | 'expired';
  createdAt: string;
  verifiedAt?: string;
}

export interface AuditLog {
  id: string;
  eventType: string;
  action: string;
  actorDid?: string;
  targetDid?: string;
  resourceType?: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  timestamp: string;
}

export interface Webhook {
  id: string;
  url: string;
  events: string[];
  active: boolean;
  secret?: string;
  createdAt: string;
  updatedAt: string;
}

export interface WebhookDelivery {
  id: string;
  webhookId: string;
  eventType: string;
  payload: Record<string, unknown>;
  statusCode?: number;
  response?: string;
  success: boolean;
  attemptNumber: number;
  deliveredAt?: string;
  createdAt: string;
}

// WebAuthn types (simplified for API transport)
export interface PublicKeyCredentialCreationOptionsJSON {
  challenge: string;
  rp: { name: string; id?: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ alg: number; type: string }>;
  timeout?: number;
  attestation?: string;
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  };
}

export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{ id: string; type: string; transports?: string[] }>;
  userVerification?: string;
}

export interface ActivityItem {
  id: string;
  type: string;
  action: string;
  description: string;
  targetDid?: string;
  metadata?: Record<string, unknown>;
  timestamp: string;
}

export interface UserSession {
  id: string;
  deviceName?: string;
  userAgent?: string;
  ipAddress?: string;
  lastActiveAt: string;
  createdAt: string;
  isCurrent: boolean;
}

export interface HealthStatus {
  status: string;
  timestamp: string;
}

export interface DetailedHealthStatus {
  status: string;
  timestamp: string;
  services: {
    name: string;
    status: 'healthy' | 'degraded' | 'down';
    latency?: number;
    details?: string;
  }[];
  uptime: number;
}

export interface EmergencyData {
  patientDid: string;
  bloodType?: string;
  allergies: string[];
  medications: string[];
  emergencyContacts: Array<{ name: string; phone: string; relationship: string }>;
  conditions: string[];
  dnrStatus?: boolean;
}

export interface EmergencyAccess {
  id: string;
  patientDid: string;
  providerDid: string;
  providerName: string;
  reason: string;
  status: 'active' | 'expired' | 'deactivated';
  activatedAt: string;
  expiresAt: string;
  deactivatedAt?: string;
}

export interface EmergencySettings {
  enabled: boolean;
  emergencyContacts: Array<{ name: string; phone: string; relationship: string }>;
  sharedFields: string[];
}

export interface InsuranceClaim {
  id: string;
  patientDid: string;
  providerDid: string;
  insurerDid: string;
  procedureCode: string;
  diagnosisCode: string;
  amount: number;
  description?: string;
  status: 'SUBMITTED' | 'UNDER_REVIEW' | 'APPROVED' | 'DENIED' | 'APPEALED';
  submittedAt: string;
  updatedAt: string;
  reviewNotes?: string;
  /** Optional fields populated by UI display layer — not always present from API */
  claimNumber?: string;
  providerName?: string;
  type?: string;
  serviceDate?: string;
  statusHistory?: Array<{ status: string; timestamp: string; note?: string }>;
}

export interface PrescriptionVerification {
  verified: boolean;
  prescriptionId: string;
  patientDid: string;
  medication: string;
  dosage: string;
  prescribedBy: string;
  validUntil: string;
  /** Optional fields set locally after verification/dispensing */
  status?: 'valid' | 'filled' | 'expired' | 'invalid';
  patientName?: string;
  quantity?: number;
  dispensedAt?: string;
}

export interface DispenseRecord {
  id: string;
  prescriptionId: string;
  pharmacyDid: string;
  patientDid: string;
  medication: string;
  quantity: number;
  dispensedAt: string;
}

export interface VerificationResult {
  id: string;
  requestId: string;
  verifierDid: string;
  holderDid?: string;
  status: 'pending' | 'verified' | 'failed' | 'expired';
  requestedTypes: string[];
  purpose: string;
  verifiedAt?: string;
  createdAt: string;
}

export interface DashboardStats {
  totalUsers: number;
  totalCredentials: number;
  totalPresentations: number;
  activeConsents: number;
  recentActivity: ActivityItem[];
  systemHealth: DetailedHealthStatus;
}
