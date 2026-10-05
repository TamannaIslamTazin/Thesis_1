'use client';

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import {
  getCurrentUser,
  getSession,
  login as apiLogin,
  setSession,
  verifyCode as apiVerifyCode,
  type CurrentUser,
} from '@/lib/api';
import { resolveAuthorityIdentity, type AuthorityIdentity } from '@/lib/authorityIdentity';

interface AuthState {
  status: 'loading' | 'signed-out' | 'signed-in';
  user: CurrentUser | null;
  identity: AuthorityIdentity | null;
}

interface AuthContextValue extends AuthState {
  requestCode: (email: string) => Promise<{ pendingToken: string }>;
  submitCode: (pendingToken: string, code: string) => Promise<void>;
  signOut: () => void;
  refreshIdentity: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: 'loading', user: null, identity: null });

  const loadIdentity = useCallback(async (user: CurrentUser) => {
    const identity = await resolveAuthorityIdentity(user.email);
    setState({ status: 'signed-in', user, identity });
  }, []);

  useEffect(() => {
    const session = getSession();
    if (!session) {
      setState({ status: 'signed-out', user: null, identity: null });
      return;
    }
    getCurrentUser()
      .then(loadIdentity)
      .catch(() => {
        setSession(null);
        setState({ status: 'signed-out', user: null, identity: null });
      });
  }, [loadIdentity]);

  const requestCode = useCallback(async (email: string) => {
    const result = await apiLogin(email);
    return { pendingToken: result.pendingToken };
  }, []);

  const submitCode = useCallback(
    async (pendingToken: string, code: string) => {
      const result = await apiVerifyCode(pendingToken, code);
      setSession({ token: result.token, refreshToken: result.refreshToken, expiresAt: Date.now() + result.expiresIn * 1000 });
      const user = await getCurrentUser();
      await loadIdentity(user);
    },
    [loadIdentity],
  );

  const signOut = useCallback(() => {
    setSession(null);
    setState({ status: 'signed-out', user: null, identity: null });
  }, []);

  const refreshIdentity = useCallback(async () => {
    if (state.user) await loadIdentity(state.user);
  }, [state.user, loadIdentity]);

  return (
    <AuthContext.Provider value={{ ...state, requestCode, submitCode, signOut, refreshIdentity }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
