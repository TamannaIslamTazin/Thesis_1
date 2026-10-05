/**
 * SSI Healthcare SDK - React Hooks
 *
 * React hooks for seamless SSI integration in React applications.
 */

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  useMemo,
  useRef,
  type ReactNode,
} from 'react';
import { SSIClient } from '../core/client';
import type {
  SSIClientConfig,
  AuthState,
  Credential,
  PresentationRequest,
  DisclosureSelection,
  Consent,
} from '../types';
// Wallet-held credentials use the shared envelope; `Credential` above remains
// the bare W3C VC used for verification inputs and offer acceptance.
import type { WalletCredential } from '@ssi-healthcare/shared';

// ============================================================
// Context
// ============================================================

interface SSIContextValue {
  client: SSIClient;
  authState: AuthState;
}

const SSIContext = createContext<SSIContextValue | null>(null);

/**
 * SSI Provider - Wraps your app to provide SSI context
 *
 * @example
 * ```tsx
 * function App() {
 *   return (
 *     <SSIProvider config={{ apiUrl: '...', clientId: '...' }}>
 *       <YourApp />
 *     </SSIProvider>
 *   );
 * }
 * ```
 */
export function SSIProvider({
  config,
  children,
}: {
  config: SSIClientConfig;
  children: ReactNode;
}) {
  // Recreate client when config identity changes (apiUrl or clientId)
  const configKey = `${config.apiUrl}|${config.clientId}`;
  const [client, setClient] = useState(() => new SSIClient(config));
  const prevKeyRef = useRef(configKey);
  const [authState, setAuthState] = useState<AuthState>(() => client.getAuthState());

  // Recreate client if config identity changes
  useEffect(() => {
    if (prevKeyRef.current !== configKey) {
      prevKeyRef.current = configKey;
      const newClient = new SSIClient(config);
      setClient(newClient);
      setAuthState(newClient.getAuthState());
    }
  }, [configKey, config]);

  useEffect(() => {
    // Subscribe to auth changes
    const unsubLogin = client.on('auth:login', () => {
      setAuthState(client.getAuthState());
    });

    const unsubLogout = client.on('auth:logout', () => {
      setAuthState(client.getAuthState());
    });

    // Initialize state
    setAuthState(client.getAuthState());

    return () => {
      unsubLogin();
      unsubLogout();
    };
  }, [client]);

  const value = useMemo(
    () => ({ client, authState }),
    [client, authState]
  );

  return (
    <SSIContext.Provider value={value}>
      {children}
    </SSIContext.Provider>
  );
}

/**
 * Get the SSI context
 */
function useSSIContext(): SSIContextValue {
  const context = useContext(SSIContext);
  if (!context) {
    throw new Error('useSSI must be used within an SSIProvider');
  }
  return context;
}

// ============================================================
// Authentication Hooks
// ============================================================

/**
 * Hook for authentication operations
 *
 * @example
 * ```tsx
 * function LoginButton() {
 *   const { login, logout, isAuthenticated, identity } = useAuth();
 *
 *   if (isAuthenticated) {
 *     return (
 *       <div>
 *         <span>Hello, {identity?.label}</span>
 *         <button onClick={logout}>Logout</button>
 *       </div>
 *     );
 *   }
 *
 *   return <button onClick={() => login()}>Login with SSI</button>;
 * }
 * ```
 */
export function useAuth() {
  const { client, authState } = useSSIContext();
  const [error, setError] = useState<Error | null>(null);

  const login = useCallback(
    async (options?: Parameters<SSIClient['authenticate']>[0]) => {
      setError(null);
      try {
        const result = await client.authenticate(options);
        // Return the identity from the result for immediate use
        return result.identity;
      } catch (err) {
        const error = err instanceof Error ? err : new Error('Login failed');
        setError(error);
        throw error;
      }
    },
    [client]
  );

  const logout = useCallback(async () => {
    setError(null);
    try {
      await client.logout();
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Logout failed');
      setError(error);
      throw error;
    }
  }, [client]);

  const handleCallback = useCallback(
    async (params?: URLSearchParams) => {
      setError(null);
      try {
        return await client.handleCallback(params);
      } catch (err) {
        const error = err instanceof Error ? err : new Error('Callback handling failed');
        setError(error);
        throw error;
      }
    },
    [client]
  );

  return {
    login,
    logout,
    handleCallback,
    isAuthenticated: authState.isAuthenticated,
    isLoading: authState.isLoading,
    identity: authState.identity,
    error: error ?? authState.error,
  };
}

// ============================================================
// Credential Hooks
// ============================================================

interface UseCredentialsOptions {
  /** Auto-fetch on mount */
  autoFetch?: boolean;
  /** Items per page */
  limit?: number;
}

/**
 * Hook for managing credentials
 *
 * @example
 * ```tsx
 * function CredentialList() {
 *   const { credentials, isLoading, refresh } = useCredentials();
 *
 *   if (isLoading) return <Spinner />;
 *
 *   return (
 *     <div>
 *       {credentials.map(cred => (
 *         <CredentialCard key={cred.id} credential={cred} />
 *       ))}
 *       <button onClick={refresh}>Refresh</button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useCredentials(options: UseCredentialsOptions = {}) {
  const { client, authState } = useSSIContext();
  const { autoFetch = true, limit = 20 } = options;

  const [credentials, setCredentials] = useState<WalletCredential[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [pagination, setPagination] = useState({
    page: 1,
    total: 0,
    hasMore: false,
  });

  // Track previous auth state to prevent unnecessary fetches
  const prevAuthRef = useRef(authState.isAuthenticated);
  const hasFetchedRef = useRef(false);

  const fetch = useCallback(
    async (page = 1, append = false) => {
      if (!authState.isAuthenticated) return;

      setIsLoading(true);
      setError(null);

      try {
        const response = await client.getCredentials({ page, limit });
        const creds = response.credentials ?? [];
        setCredentials(prev => append ? [...prev, ...creds] : creds);
        const totalItems = response.stats?.total ?? creds.length;
        setPagination({
          page,
          total: totalItems,
          hasMore: page * limit < totalItems,
        });
      } catch (err) {
        setError(err instanceof Error ? err : new Error('Failed to fetch credentials'));
      } finally {
        setIsLoading(false);
      }
    },
    [client, authState.isAuthenticated, limit]
  );

  // Use ref for stable refresh function to avoid infinite loops
  const fetchRef = useRef(fetch);
  fetchRef.current = fetch;

  const refresh = useCallback(() => fetchRef.current(1), []);

  const loadMore = useCallback(() => {
    if (pagination.hasMore) {
      fetchRef.current(pagination.page + 1, true);
    }
  }, [pagination.hasMore, pagination.page]);

  // Auto-fetch effect - only triggers on mount or auth state change
  useEffect(() => {
    const shouldFetch = autoFetch && authState.isAuthenticated;
    const authChanged = prevAuthRef.current !== authState.isAuthenticated;
    
    // Fetch only if: (auth changed and now authenticated) OR (first mount and should fetch)
    if (shouldFetch && (authChanged || !hasFetchedRef.current)) {
      hasFetchedRef.current = true;
      fetchRef.current(1);
    }
    
    prevAuthRef.current = authState.isAuthenticated;
  }, [autoFetch, authState.isAuthenticated]);

  // Subscribe to credential events
  useEffect(() => {
    const handleEvent = () => fetchRef.current(1);
    const unsubReceived = client.on('credential:received', handleEvent);
    const unsubDeleted = client.on('credential:deleted', handleEvent);

    return () => {
      unsubReceived();
      unsubDeleted();
    };
  }, [client]);

  return {
    credentials,
    isLoading,
    error,
    pagination,
    refresh,
    loadMore,
  };
}

/**
 * Hook for a single credential
 */
export function useCredential(id: string) {
  const { client, authState } = useSSIContext();

  const [credential, setCredential] = useState<WalletCredential | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Track if we've fetched for this ID
  const prevIdRef = useRef(id);
  const prevAuthRef = useRef(authState.isAuthenticated);

  const fetch = useCallback(async () => {
    if (!authState.isAuthenticated || !id) return;

    setIsLoading(true);
    setError(null);

    try {
      const data = await client.getCredential(id);
      setCredential(data);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to fetch credential'));
    } finally {
      setIsLoading(false);
    }
  }, [client, authState.isAuthenticated, id]);

  // Use ref for stable fetch reference
  const fetchRef = useRef(fetch);
  fetchRef.current = fetch;

  const deleteCredential = useCallback(async () => {
    if (!id) return;
    try {
      await client.deleteCredential(id);
      setCredential(null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to delete credential'));
      throw err; // Re-throw so callers can handle
    }
  }, [client, id]);

  // Only fetch when id changes or auth state changes
  useEffect(() => {
    const idChanged = prevIdRef.current !== id;
    const authChanged = prevAuthRef.current !== authState.isAuthenticated;
    
    if (authState.isAuthenticated && id && (idChanged || authChanged)) {
      fetchRef.current();
    }
    
    prevIdRef.current = id;
    prevAuthRef.current = authState.isAuthenticated;
  }, [id, authState.isAuthenticated]);

  return {
    credential,
    isLoading,
    error,
    refresh: useCallback(() => fetchRef.current(), []),
    deleteCredential,
  };
}

// ============================================================
// Presentation Hooks
// ============================================================

/**
 * Hook for handling presentation requests
 *
 * @example
 * ```tsx
 * function PresentationHandler({ requestData }) {
 *   const {
 *     request,
 *     matchingCredentials,
 *     submit,
 *     isSubmitting,
 *   } = usePresentation(requestData);
 *
 *   return (
 *     <div>
 *       <h2>{request?.purpose}</h2>
 *       {matchingCredentials.map(({ credential }) => (
 *         <CredentialSelector key={credential.id} credential={credential} />
 *       ))}
 *       <button onClick={() => submit(selections)} disabled={isSubmitting}>
 *         Share
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */
export function usePresentation(requestData?: string) {
  const { client, authState } = useSSIContext();

  const [request, setRequest] = useState<PresentationRequest | null>(null);
  const [matchingCredentials, setMatchingCredentials] = useState<
    { credential: WalletCredential; matchedAttributes: string[] }[]
  >([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Parse request data — FINDING-031: use async parser for proper signature verification
  useEffect(() => {
    if (!requestData) return;

    let cancelled = false;
    client.parsePresentationRequestAsync(requestData)
      .then(parsed => {
        if (!cancelled) setRequest(parsed);
      })
      .catch(err => {
        if (!cancelled) setError(err instanceof Error ? err : new Error('Invalid request'));
      });

    return () => { cancelled = true; };
  }, [client, requestData]);

  // Fetch matching credentials
  useEffect(() => {
    if (!request || !authState.isAuthenticated) return;

    const fetchMatches = async () => {
      setIsLoading(true);
      try {
        const matches = await client.getMatchingCredentials(request);
        setMatchingCredentials(matches);
      } catch (err) {
        setError(err instanceof Error ? err : new Error('Failed to find matches'));
      } finally {
        setIsLoading(false);
      }
    };

    fetchMatches();
  }, [client, request, authState.isAuthenticated]);

  const submit = useCallback(
    async (selections: DisclosureSelection[]) => {
      if (!request) throw new Error('No request to submit');

      setIsSubmitting(true);
      setError(null);

      try {
        await client.presentCredentials(request, selections);
      } catch (err) {
        const error = err instanceof Error ? err : new Error('Submission failed');
        setError(error);
        throw error;
      } finally {
        setIsSubmitting(false);
      }
    },
    [client, request]
  );

  return {
    request,
    matchingCredentials,
    isLoading,
    isSubmitting,
    error,
    submit,
  };
}

// ============================================================
// Consent Hooks
// ============================================================

/**
 * Hook for managing consents
 */
export function useConsents(options: { autoFetch?: boolean; active?: boolean } = {}) {
  const { client, authState } = useSSIContext();
  const { autoFetch = true, active } = options;

  const [consents, setConsents] = useState<Consent[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Track previous auth state to prevent unnecessary fetches
  const prevAuthRef = useRef(authState.isAuthenticated);
  const hasFetchedRef = useRef(false);

  const fetch = useCallback(async () => {
    if (!authState.isAuthenticated) return;

    setIsLoading(true);
    setError(null);

    try {
      const response = await client.getConsents({ active });
      setConsents(response.consents ?? []);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to fetch consents'));
    } finally {
      setIsLoading(false);
    }
  }, [client, authState.isAuthenticated, active]);

  // Use ref for stable refresh function
  const fetchRef = useRef(fetch);
  fetchRef.current = fetch;

  const refresh = useCallback(() => fetchRef.current(), []);

  const revoke = useCallback(
    async (consentId: string) => {
      await client.revokeConsent(consentId);
      setConsents((prev) => prev.filter((c) => c.id !== consentId));
    },
    [client]
  );

  // Auto-fetch effect - only triggers on mount or auth state change
  useEffect(() => {
    const shouldFetch = autoFetch && authState.isAuthenticated;
    const authChanged = prevAuthRef.current !== authState.isAuthenticated;
    
    if (shouldFetch && (authChanged || !hasFetchedRef.current)) {
      hasFetchedRef.current = true;
      fetchRef.current();
    }
    
    prevAuthRef.current = authState.isAuthenticated;
  }, [autoFetch, authState.isAuthenticated]);

  // Subscribe to consent events
  useEffect(() => {
    const handleRefresh = () => fetchRef.current();
    const unsubGranted = client.on('consent:granted', handleRefresh);
    const unsubRevoked = client.on('consent:revoked', handleRefresh);

    return () => {
      unsubGranted();
      unsubRevoked();
    };
  }, [client]);

  const grant = useCallback(
    async (params: Parameters<SSIClient['grantConsent']>[0]) => {
      try {
        const consent = await client.grantConsent(params);
        return consent;
      } catch (err) {
        setError(err instanceof Error ? err : new Error('Failed to grant consent'));
        throw err;
      }
    },
    [client]
  );

  return {
    consents,
    isLoading,
    error,
    refresh,
    grant,
    revoke,
  };
}

// ============================================================
// Credential Offer Hook
// ============================================================

/**
 * Hook for handling credential offers
 */
export function useCredentialOffer(offerData?: string) {
  const { client, authState } = useSSIContext();

  const [offer, setOffer] = useState<ReturnType<SSIClient['parseCredentialOffer']> | null>(null);
  const [isAccepting, setIsAccepting] = useState(false);
  const [acceptedCredential, setAcceptedCredential] = useState<Credential | null>(null);
  const [error, setError] = useState<Error | null>(null);

  // Parse offer data
  useEffect(() => {
    if (!offerData) return;

    try {
      const parsed = client.parseCredentialOffer(offerData);
      setOffer(parsed);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Invalid offer'));
    }
  }, [client, offerData]);

  const accept = useCallback(async () => {
    if (!offer) throw new Error('No offer to accept');
    if (!authState.isAuthenticated) throw new Error('Authentication required');

    setIsAccepting(true);
    setError(null);

    try {
      const credential = await client.acceptCredentialOffer(offer);
      setAcceptedCredential(credential);
      return credential;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Accept failed');
      setError(error);
      throw error;
    } finally {
      setIsAccepting(false);
    }
  }, [client, offer, authState.isAuthenticated]);

  return {
    offer,
    isAccepting,
    acceptedCredential,
    error,
    accept,
  };
}

// ============================================================
// SSI Client Hook
// ============================================================

/**
 * Direct access to SSI client for advanced use cases
 */
export function useSSIClient(): SSIClient {
  const { client } = useSSIContext();
  return client;
}
