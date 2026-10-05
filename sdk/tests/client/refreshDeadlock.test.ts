/**
 * A 401 must never leave a request waiting on its own refresh.
 *
 * Regression for the 19 Sep 2026 cold-start hang. With both tokens expired,
 * `performRefresh`'s own `/auth/refresh` call answered 401 and re-entered the
 * 401-refresh branch, which returned `refreshInFlight` — the very promise the
 * call was already awaiting. Nothing settled, the promise was never cleared,
 * and every later refresh joined the same dead promise; on the handset this
 * showed as "Loading your dashboard…" forever while no credential or consent
 * request ever reached the backend.
 *
 * The first test refuses: a rejected refresh token must SETTLE, exactly once.
 * The second is its success path — a guard against re-entering refresh is
 * exactly the kind of fix that can pass the refusal test by disabling refresh
 * altogether, so both directions are pinned.
 */

import { describe, it, expect } from 'vitest';
import { SSIClient } from '../../src/core/client';
import type { AuthState } from '../../src/types';

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

const AUTH_STATE_KEY = 'ssi_auth_state';
const REFRESH_TOKEN_KEY = 'ssi_refresh_token';
const EXPIRED_REFRESH = 'expired-refresh-token';

function storedAuthState(): AuthState {
  return {
    isAuthenticated: true,
    isLoading: false,
    accessToken: 'expired-access-token',
    refreshToken: EXPIRED_REFRESH,
    expiresAt: Date.now() + 60_000,
  };
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function rejectedRefresh(): Response {
  return jsonResponse(
    { success: false, error: { code: 'AUTH_TOKEN_EXPIRED', message: 'Invalid refresh token' } },
    401,
  );
}

async function makeClient(fetchImpl: typeof fetch): Promise<SSIClient> {
  const storage = new MemoryStorage();
  await storage.set(AUTH_STATE_KEY, JSON.stringify(storedAuthState()));
  await storage.set(REFRESH_TOKEN_KEY, EXPIRED_REFRESH);

  const client = new SSIClient({
    apiUrl: 'http://backend.test/api',
    clientId: 'refresh-deadlock-test',
    storage,
    timeout: 1500,
    fetch: fetchImpl,
  });

  for (let i = 0; i < 50 && client.getAuthState().isLoading; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  if (client.getAuthState().isLoading) throw new Error('auth init never settled');
  return client;
}

describe('refresh on 401', () => {
  it('settles when the refresh token itself is rejected, instead of awaiting its own refresh', async () => {
    const calls: string[] = [];
    const client = await makeClient((async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return rejectedRefresh();
    }) as typeof fetch);

    // Either outcome counts as settled: this test exists to pin that the
    // promise does not wait on its own refresh, and since steno #437 a failed
    // fetch REJECTS rather than resolving as an empty wallet.
    const outcome = await Promise.race([
      client.getCredentials().then(
        () => 'settled' as const,
        () => 'settled' as const,
      ),
      new Promise<'hung'>((resolve) => setTimeout(() => resolve('hung'), 3000)),
    ]);

    expect(outcome).toBe('settled');
    expect(calls.filter((url) => url.endsWith('/auth/refresh'))).toHaveLength(1);
    expect(client.getAuthState().isAuthenticated).toBe(false);
  });

  it('retries the original request once after a successful refresh', async () => {
    let refreshCalls = 0;
    let credentialCalls = 0;

    const client = await makeClient((async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/auth/refresh')) {
        refreshCalls += 1;
        return jsonResponse(
          { success: true, data: { token: 'new-access', refreshToken: 'new-refresh', expiresIn: 900 } },
          200,
        );
      }
      if (url.includes('/users/me/credentials')) {
        credentialCalls += 1;
        if (credentialCalls === 1) return rejectedRefresh();
        return jsonResponse({ success: true, data: { credentials: [], stats: null } }, 200);
      }
      return rejectedRefresh();
    }) as typeof fetch);

    await client.getCredentials();

    expect(refreshCalls).toBe(1);
    expect(credentialCalls).toBe(2);
    expect(client.getAuthState().accessToken).toBe('new-access');
  });
});
