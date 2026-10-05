/**
 * Three properties the wallet's session depends on after steno #437.
 *
 *   1. WHEN A DELEGATE IS SUPPLIED, THE SDK NEVER REFRESHES ITSELF. The host
 *      app has its own HTTP client and the backend keeps ONE access token per
 *      session, so a second refresher makes the two invalidate each other's
 *      rotations. The delegate must be the only POST to /auth/refresh.
 *
 *   2. A FAILED FETCH IS NOT AN EMPTY WALLET. getCredentials used to return []
 *      for every failure — unreachable backend, expired session and a
 *      genuinely empty wallet were indistinguishable, and the dashboard showed
 *      0 Credentials while the server held four.
 *
 *   3. A REFRESH MIRRORS INTO THE TOKEN KEY THE OTHER CLIENT READS. Writing
 *      only AUTH_STATE left `ssi_access_token` holding a token the server had
 *      already replaced.
 */

import { describe, it, expect } from 'vitest';
import { SSIClient } from '../../src/core/client';
import type { AuthState, SSIClientConfig } from '../../src/types';

class MemoryStorage {
  private readonly map = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.map.get(key) ?? null;
  }

  async set(key: string, value: string): Promise<void> {
    this.map.set(key, value);
  }

  async remove(key: string): Promise<void> {
    this.map.delete(key);
  }
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function errorResponse(message: string): Response {
  return jsonResponse({ success: false, error: { code: 'AUTH_TOKEN_EXPIRED', message } }, 401);
}

async function seedStorage(storage: MemoryStorage): Promise<void> {
  const state: AuthState = {
    isAuthenticated: true,
    isLoading: false,
    accessToken: 'stale-access-token',
    refreshToken: 'stale-refresh-token',
    expiresAt: Date.now() + 60_000,
  };
  await storage.set('ssi_auth_state', JSON.stringify(state));
  await storage.set('ssi_access_token', 'stale-access-token');
  await storage.set('ssi_refresh_token', 'stale-refresh-token');
}

async function ready(client: SSIClient): Promise<void> {
  for (let i = 0; i < 50 && client.getAuthState().isLoading; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  if (client.getAuthState().isLoading) throw new Error('auth init never settled');
}

describe('session refresh across two clients', () => {
  it('delegates refresh instead of POSTing /auth/refresh, and adopts the delegate token', async () => {
    const storage = new MemoryStorage();
    await seedStorage(storage);

    const calls: string[] = [];
    let delegateCalls = 0;

    const config: SSIClientConfig = {
      apiUrl: 'http://backend.test/api',
      clientId: 'single-refresher-test',
      storage,
      timeout: 1500,
      refreshAccessToken: async () => {
        delegateCalls += 1;
        return { accessToken: 'delegated-access', refreshToken: 'delegated-refresh', expiresIn: 900 };
      },
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push(url);
        const authorization = String(
          (init?.headers as Record<string, string> | undefined)?.['Authorization'] ?? '',
        );
        if (url.endsWith('/auth/refresh')) {
          throw new Error('the SDK must not refresh itself when a delegate is supplied');
        }
        if (url.includes('/users/me/credentials')) {
          if (authorization === 'Bearer delegated-access') {
            return jsonResponse({ success: true, data: { credentials: [], stats: null } }, 200);
          }
          return errorResponse('Invalid or expired session');
        }
        return errorResponse('Invalid or expired session');
      }) as typeof fetch,
    };

    const client = new SSIClient(config);
    await ready(client);

    await client.getCredentials();

    expect(delegateCalls).toBe(1);
    expect(calls.some((url) => url.endsWith('/auth/refresh'))).toBe(false);
    expect(await storage.get('ssi_access_token')).toBe('delegated-access');
  });

  it('rejects when the fetch fails, instead of reporting an empty wallet', async () => {
    const storage = new MemoryStorage();
    await seedStorage(storage);

    const failingFetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      return url.endsWith('/auth/refresh')
        ? errorResponse('Invalid refresh token')
        : errorResponse('Invalid or expired session');
    }) as typeof fetch;

    // One client per call: the first rejection clears the shared auth state,
    // and a second call would then fail earlier, at `requireAuth`.
    const credentialsClient = new SSIClient({
      apiUrl: 'http://backend.test/api',
      clientId: 'fail-closed-credentials-test',
      storage,
      timeout: 1500,
      fetch: failingFetch,
    });
    await ready(credentialsClient);
    await expect(credentialsClient.getCredentials()).rejects.toThrow(/Invalid or expired session/);
    expect(credentialsClient.getAuthState().isAuthenticated).toBe(false);

    await seedStorage(storage);
    const consentsClient = new SSIClient({
      apiUrl: 'http://backend.test/api',
      clientId: 'fail-closed-consents-test',
      storage,
      timeout: 1500,
      fetch: failingFetch,
    });
    await ready(consentsClient);
    await expect(consentsClient.getConsents()).rejects.toThrow(/Invalid or expired session/);
  });
});
