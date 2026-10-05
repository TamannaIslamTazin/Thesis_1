/**
 * SSI Healthcare - Authentication Hook
 * 
 * React hook for managing authentication state and operations.
 * Includes automatic token refresh, session persistence, and error handling.
 */

'use client';

import { useState, useEffect, useCallback, createContext, useContext, useMemo, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { authApi, clearTokens, getAccessToken, type User, ApiError } from '@/lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
}

interface AuthContextValue extends AuthState {
  login: (email: string) => Promise<{ pendingToken: string }>;
  register: (email: string, firstName?: string, lastName?: string) => Promise<void>;
  loginWithPasskey: () => Promise<void>;
  registerPasskey: () => Promise<void>;
  logout: () => Promise<void>;
  setupWallet: () => Promise<{ did: string }>;
  refreshUser: () => Promise<void>;
  clearError: () => void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Refresh token 5 minutes before expiry
const REFRESH_BUFFER_MS = 5 * 60 * 1000;

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const AuthContext = createContext<AuthContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    isLoading: true,
    isAuthenticated: false,
    error: null,
  });
  
  const refreshTimerRef = useRef<NodeJS.Timeout | null>(null);
  
  // Setup token refresh timer
  const setupRefreshTimer = useCallback(() => {
    // Clear existing timer
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
    
    const expiresAt = authApi.getTokenExpiresAt();
    if (!expiresAt) return;
    
    const now = Date.now();
    const timeUntilRefresh = expiresAt - now - REFRESH_BUFFER_MS;
    
    if (timeUntilRefresh <= 0) {
      // Token already expired or about to expire, refresh now
      authApi.refresh().catch(() => {
        // Refresh failed — clear tokens and redirect to login
        clearTokens();
        setState({
          user: null,
          isLoading: false,
          isAuthenticated: false,
          error: 'Session expired. Please login again.',
        });
        // FINDING-021: Redirect immediately — cleared state leaves user on authenticated page
        if (typeof window !== 'undefined') {
          window.location.replace('/auth?reason=session_expired');
        }
      });
      return;
    }
    
    // Schedule refresh
    refreshTimerRef.current = setTimeout(async () => {
      try {
        await authApi.refresh();
        setupRefreshTimer(); // Setup next refresh
      } catch {
        // Refresh failed, let user know
        clearTokens();
        setState({
          user: null,
          isLoading: false,
          isAuthenticated: false,
          error: 'Session expired. Please login again.',
        });
        // FINDING-021: Redirect immediately on expired session
        if (typeof window !== 'undefined') {
          window.location.replace('/auth?reason=session_expired');
        }
      }
    }, timeUntilRefresh);
  }, []);
  
  // Cleanup timer on unmount
  useEffect(() => {
    return () => {
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
      }
    };
  }, []);
  
  // Check for existing session on mount
  useEffect(() => {
    const checkAuth = async () => {
      const token = getAccessToken();
      if (!token) {
        setState(prev => ({ ...prev, isLoading: false }));
        return;
      }
      
      try {
        const response = await authApi.getCurrentUser();
        setState({
          user: response.data || null,
          isLoading: false,
          isAuthenticated: true,
          error: null,
        });
        setupRefreshTimer();
      } catch (error) {
        // If auth check fails, try to refresh the token
        try {
          await authApi.refresh();
          const response = await authApi.getCurrentUser();
          setState({
            user: response.data || null,
            isLoading: false,
            isAuthenticated: true,
            error: null,
          });
          setupRefreshTimer();
        } catch {
          clearTokens();
          setState({
            user: null,
            isLoading: false,
            isAuthenticated: false,
            error: null,
          });
        }
      }
    };
    
    checkAuth();
  }, [setupRefreshTimer]);
  
  const login = useCallback(async (email: string): Promise<{ pendingToken: string }> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      const response = await authApi.login(email);
      setState(prev => ({ ...prev, isLoading: false }));
      
      if (response.data) {
        return {
          pendingToken: response.data.pendingToken,
        };
      }
      throw new Error('No response data');
    } catch (error) {
      const message = error instanceof ApiError ? error.message : 'Login failed';
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      throw error;
    }
  }, []);
  
  const register = useCallback(async (email: string, firstName?: string, lastName?: string) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      const response = await authApi.register({ email, firstName, lastName });
      if (response.data) {
        setState({
          user: response.data.user,
          isLoading: false,
          isAuthenticated: true,
          error: null,
        });
        setupRefreshTimer();
      }
    } catch (error) {
      const message = error instanceof ApiError ? error.message : 'Registration failed';
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      throw error;
    }
  }, [setupRefreshTimer]);
  
  const loginWithPasskey = useCallback(async () => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      // Get authentication options from backend
      const optionsRes = await authApi.getPasskeyAuthenticationOptions();
      if (!optionsRes.data) throw new Error('Failed to get passkey options');

      // Trigger WebAuthn browser prompt
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: Uint8Array.from(atob(optionsRes.data.challenge), c => c.charCodeAt(0)),
          timeout: optionsRes.data.timeout ?? 60000,
          rpId: optionsRes.data.rpId ?? window.location.hostname,
          allowCredentials: (optionsRes.data.allowCredentials ?? []).map((c: { id: string; type: string; transports?: string[] }) => ({
            id: Uint8Array.from(atob(c.id), ch => ch.charCodeAt(0)),
            type: c.type as 'public-key',
            transports: c.transports as AuthenticatorTransport[] | undefined,
          })),
          userVerification: (optionsRes.data.userVerification ?? 'preferred') as UserVerificationRequirement,
        },
      });

      if (!credential) throw new Error('Passkey authentication cancelled');

      // Verify with backend
      const authRes = await authApi.verifyPasskeyAuthentication(credential);
      if (authRes.data) {
        setState({
          user: authRes.data.user,
          isLoading: false,
          isAuthenticated: true,
          error: null,
        });
        setupRefreshTimer();
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Passkey authentication failed';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      throw error;
    }
  }, [setupRefreshTimer]);

  const registerPasskey = useCallback(async () => {
    try {
      const optionsRes = await authApi.getPasskeyRegistrationOptions();
      if (!optionsRes.data) throw new Error('Failed to get registration options');

      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: Uint8Array.from(atob(optionsRes.data.challenge), c => c.charCodeAt(0)),
          rp: optionsRes.data.rp,
          user: {
            id: Uint8Array.from(atob(optionsRes.data.user.id), c => c.charCodeAt(0)),
            name: optionsRes.data.user.name,
            displayName: optionsRes.data.user.displayName,
          },
          pubKeyCredParams: optionsRes.data.pubKeyCredParams.map(p => ({
            ...p,
            type: p.type as 'public-key',
          })),
          timeout: optionsRes.data.timeout ?? 60000,
          authenticatorSelection: optionsRes.data.authenticatorSelection as AuthenticatorSelectionCriteria | undefined,
        },
      });

      if (!credential) throw new Error('Passkey registration cancelled');

      await authApi.verifyPasskeyRegistration(credential);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Passkey registration failed';
      setState(prev => ({ ...prev, error: message }));
      throw error;
    }
  }, []);
  
  const logout = useCallback(async () => {
    // Clear refresh timer
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
    
    try {
      await authApi.logout();
    } finally {
      setState({
        user: null,
        isLoading: false,
        isAuthenticated: false,
        error: null,
      });
    }
  }, []);
  
  const refreshUser = useCallback(async () => {
    try {
      const response = await authApi.getCurrentUser();
      if (response.data) {
        setState(prev => ({
          ...prev,
          user: response.data!,
          isLoading: false,
          isAuthenticated: true,
        }));
      }
    } catch {
      // Silent fail for refresh
    }
  }, []);
  
  const setupWallet = useCallback(async () => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      const response = await authApi.setupWallet();
      if (response.data) {
        // Refresh user to get updated DID
        await refreshUser();
        return { did: response.data.did };
      }
      throw new Error('Failed to setup wallet');
    } catch (error) {
      const message = error instanceof ApiError ? error.message : 'Wallet setup failed';
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      throw error;
    }
  }, [refreshUser]);
  
  const clearError = useCallback(() => {
    setState(prev => ({ ...prev, error: null }));
  }, []);
  
  const value = useMemo(() => ({
    ...state,
    login,
    register,
    loginWithPasskey,
    registerPasskey,
    logout,
    setupWallet,
    refreshUser,
    clearError,
  }), [state, login, register, loginWithPasskey, registerPasskey, logout, setupWallet, refreshUser, clearError]);
  
  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// ---------------------------------------------------------------------------
// Protected Route Helper
// ---------------------------------------------------------------------------

export function useRequireAuth(redirectTo = '/auth') {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.replace(redirectTo);
    }
  }, [isAuthenticated, isLoading, redirectTo, router]);
  
  return { isAuthenticated, isLoading };
}
