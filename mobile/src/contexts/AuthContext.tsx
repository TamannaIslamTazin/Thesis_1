/**
 * SSI Healthcare Mobile - Authentication Context
 *
 * Provides authentication state management for the mobile app.
 * Handles login, registration, logout, and biometric authentication.
 * Integrates with apiService for API calls and SecureStore for token persistence.
 */

import React, { createContext, useContext, useReducer, useEffect, useCallback, useMemo } from 'react';
import {
  apiService,
  biometricAuthService,
  deviceKeyGate,
  recoveryKeyRelease,
  secureStorage,
  STORAGE_KEYS,
} from '../services';
import type { BiometricGateRefusalReason } from '../services';
import { resolveApiBase } from '../services/api';
import { ssiClient as ssiClientService } from '../services/ssiClient';
import { bytesToBase64Url, signWithRecoveryKey, zeroise } from '@ssi-healthcare/shared';

export type BiometricLockChangeResult =
  | { readonly status: 'ENABLED' }
  | { readonly status: 'DISABLED' }
  | { readonly status: 'REFUSED'; readonly reason: BiometricGateRefusalReason }
  | { readonly status: 'FAILED'; readonly message: string };

export interface User {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  did?: string;
  walletSetup?: boolean;
  biometricEnabled?: boolean;
  autoLockMinutes?: number;
  totpEnabled?: boolean;
  createdAt?: string;
}

export interface AuthContextValue {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  /**
   * True once the initial session restore has finished, and never false again.
   *
   * Navigation must gate on THIS, not on `isLoading`. `isLoading` also goes true
   * for every in-flight login/register, and gating the navigator on it unmounts
   * the screen that is awaiting the result — so a failed registration remounted
   * a fresh AuthScreen at step 'email', discarding the error it was about to
   * display. The user saw a flash back to the login page with no explanation.
   */
  isInitialized: boolean;
  isBiometricAvailable: boolean;
  isBiometricLockEnabled: boolean;
  /** Register a new user (no OTP, immediate session). */
  register: (firstName?: string, lastName?: string) => Promise<void>;
  /**
   * Sign in by proving control of the DID's key, with no email anywhere.
   *
   * The passphrase opens the keystore envelope to recover the seed; the seed
   * signs the server's challenge. The seed is used and discarded — it is never
   * written to storage by this path.
   *
   * No DID is passed in: #402 has the keystore answer BY HANDLE and return the
   * DID with the envelope, so the DID that signs is the one the envelope
   * belongs to by construction.
   */
  passphraseLogin: (handle: string, passphrase: string) => Promise<void>;
  logout: () => Promise<void>;
  biometricLogin: () => Promise<void>;
  setBiometricLockEnabled: (enabled: boolean) => Promise<BiometricLockChangeResult>;
  refreshUser: () => Promise<void>;
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isBiometricAvailable: boolean;
  isBiometricLockEnabled: boolean;
  isInitialized: boolean;
}

type AuthAction =
  | { type: 'AUTH_INIT_START' }
  | {
      type: 'AUTH_INIT_COMPLETE';
      user: User | null;
      isBiometricAvailable: boolean;
      isBiometricLockEnabled: boolean;
    }
  | { type: 'LOGIN_START' }
  | { type: 'LOGIN_SUCCESS'; user: User }
  | { type: 'LOGIN_FAILURE' }
  | { type: 'LOGOUT' }
  | { type: 'SET_USER'; user: User }
  | { type: 'SET_BIOMETRIC_AVAILABLE'; available: boolean }
  | { type: 'SET_BIOMETRIC_LOCK_ENABLED'; enabled: boolean };

const initialState: AuthState = {
  user: null,
  isAuthenticated: false,
  isLoading: true,
  isBiometricAvailable: false,
  isBiometricLockEnabled: false,
  isInitialized: false,
};

function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'AUTH_INIT_START':
      return { ...state, isLoading: true };
    case 'AUTH_INIT_COMPLETE':
      return {
        ...state,
        isLoading: false,
        isInitialized: true,
        user: action.user,
        isAuthenticated: !!action.user,
        isBiometricAvailable: action.isBiometricAvailable,
        isBiometricLockEnabled: action.isBiometricLockEnabled,
      };
    case 'LOGIN_START':
      return { ...state, isLoading: true };
    case 'LOGIN_SUCCESS':
      return {
        ...state,
        isLoading: false,
        user: action.user,
        isAuthenticated: true,
      };
    case 'LOGIN_FAILURE':
      return { ...state, isLoading: false };
    case 'LOGOUT':
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        isLoading: false,
      };
    case 'SET_USER':
      return { ...state, user: action.user };
    case 'SET_BIOMETRIC_AVAILABLE':
      return { ...state, isBiometricAvailable: action.available };
    case 'SET_BIOMETRIC_LOCK_ENABLED':
      return { ...state, isBiometricLockEnabled: action.enabled };
    default:
      return state;
  }
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const USER_STORAGE_KEY = STORAGE_KEYS.USER_DATA;

/**
 * Ensure the signed-in user has a wallet DID, provisioning one if not.
 *
 * WHY THIS EXISTS
 * ---------------
 * `POST /auth/register` does not create a DID. Nothing in the mobile app ever
 * called `POST /auth/wallet/setup` either, so a mobile-registered user reached
 * the wallet with `user.did === null`. The credentials endpoint short-circuits
 * to `{ credentials: [], stats: null }` for such a user, which is why every
 * screen rendered an empty-but-healthy wallet: there was no error to show.
 *
 * WHY IT RUNS ON EVERY AUTHENTICATION, NOT JUST REGISTRATION
 * ----------------------------------------------------------
 * Users created before this fix exist with `did === null`. Gating on
 * registration alone would leave them permanently unable to hold a credential.
 * The call is safe to repeat: the server returns the existing DID when the
 * wallet is already provisioned, precisely so a retry cannot mint a second DID
 * and orphan credentials stored against the first.
 *
 * WHY FAILURE IS NOT FATAL
 * ------------------------
 * Provisioning needs the network. A user who has authenticated should still
 * reach the app on a flaky connection; they simply have no wallet until a
 * later sign-in succeeds. Throwing here would turn a transient network fault
 * into a failed login.
 *
 * CUSTODY — the key is generated and held by the backend agent today (hence
 * `walletType: 'CLOUD'`). The device does not yet hold signing material and
 * this function must not be read as asserting that it does.
 */
async function ensureWalletProvisioned(user: User): Promise<User> {
  if (user.did && user.walletSetup) {
    return user;
  }

  try {
    const result = await apiService.setupWallet('CLOUD');
    return { ...user, did: result.did, walletSetup: true };
  } catch (error) {
    console.warn(
      '[AuthContext] Wallet provisioning failed; wallet will be empty until it succeeds',
      error,
    );
    return user;
  }
}

interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  const initializeAuth = useCallback(async () => {
    dispatch({ type: 'AUTH_INIT_START' });
    
    try {
      // Pick a reachable backend before the first request. Non-fatal by design:
      // if nothing answers we keep the first candidate so the failure surfaces
      // as a real request error rather than as a blank startup.
      await resolveApiBase();

      const isBiometricAvailable = await biometricAuthService.isAvailable();
      const isBiometricLockEnabled = await deviceKeyGate.isEnabledOnThisDevice();
      const hasToken = await apiService.hasAuthToken();

      if (!hasToken) {
        dispatch({
          type: 'AUTH_INIT_COMPLETE',
          user: null,
          isBiometricAvailable,
          isBiometricLockEnabled,
        });
        return;
      }

      const storedUserData = await secureStorage.get(USER_STORAGE_KEY);
      let user: User | null = null;

      if (storedUserData) {
        try {
          user = JSON.parse(storedUserData) as User;
        } catch {
          console.warn('[AuthContext] Failed to parse stored user data');
        }
      }

      if (!user) {
        try {
          const userData = await apiService.getCurrentUser() as User;
          user = userData;
          await secureStorage.set(USER_STORAGE_KEY, JSON.stringify(user));
        } catch (error) {
          console.warn('[AuthContext] Failed to fetch current user, clearing auth');
          await apiService.clearAuth();
          await secureStorage.delete(USER_STORAGE_KEY);
          user = null;
        }
      }

      // Self-heal accounts created before wallet provisioning was wired, and
      // accounts whose cached profile predates provisioning. Returns the user
      // unchanged (and does not call the server) once a DID is present.
      if (user) {
        user = await ensureWalletProvisioned(user);
        await secureStorage.set(USER_STORAGE_KEY, JSON.stringify(user));
      }

      dispatch({
        type: 'AUTH_INIT_COMPLETE',
        user,
        isBiometricAvailable,
        isBiometricLockEnabled,
      });
    } catch (error) {
      console.error('[AuthContext] Initialization error:', error);
      dispatch({
        type: 'AUTH_INIT_COMPLETE',
        user: null,
        isBiometricAvailable: false,
        isBiometricLockEnabled: false,
      });
    }
  }, []);

  useEffect(() => {
    initializeAuth();
  }, [initializeAuth]);

  // A 401 the client cannot refresh means the session is gone. Returning the
  // navigator to sign-in is the only useful response; the alternative, which is
  // what shipped, was to stay inside the wallet reporting the failure on every
  // screen. Storage is already cleared by the caller, so this only moves the UI.
  useEffect(() => {
    apiService.setSessionExpiredHandler(() => {
      dispatch({ type: 'LOGOUT' });
    });
    return () => apiService.setSessionExpiredHandler(undefined);
  }, []);

  // Alias for backward compatibility

  const register = useCallback(async (firstName?: string, lastName?: string): Promise<void> => {
    dispatch({ type: 'LOGIN_START' });
    
    try {
      const result = await apiService.register(firstName, lastName);

      // Sync auth token to SDK so credential/consent operations work
      await ssiClientService.setAuthToken(result.token, result.refreshToken, result.expiresIn);

      // DELIBERATELY NOT PROVISIONED HERE.
      //
      // The DID is minted by the enrolment gate, once the device has generated
      // its recovery key, so that the key ends up as the DID's `#key-1`.
      // Provisioning at registration mints an agent-generated key instead, and
      // the holder is then left unable to sign a login challenge — which is
      // precisely why the email path stayed load-bearing after it was ruled
      // out. Registration therefore hands over to `PassphraseSetupScreen`, and
      // no path reaches the wallet without passing through it.
      const user = result.user as User;

      await secureStorage.set(USER_STORAGE_KEY, JSON.stringify(user));

      dispatch({ type: 'LOGIN_SUCCESS', user });
    } catch (error) {
      console.error('[AuthContext] Registration failed:', error);
      dispatch({ type: 'LOGIN_FAILURE' });
      throw error;
    }
  }, []);

  const passphraseLogin = useCallback(
    async (handle: string, passphrase: string): Promise<void> => {
      dispatch({ type: 'LOGIN_START' });
      try {
        const { seed, did } = await recoveryKeyRelease.releaseToWallet(handle, passphrase);
        try {
          const challenge = await apiService.requestDidChallenge(did);
          // The server returns the materialised canonical payload, so the bytes
          // signed here are the bytes it will verify. Nothing is reconstructed.
          const signature = bytesToBase64Url(
            signWithRecoveryKey(seed, new TextEncoder().encode(challenge.payloadTemplate)),
          );
          const result = await apiService.didLogin(did, challenge.nonce, signature);
          await ssiClientService.setAuthToken(result.token, result.refreshToken, result.expiresIn);
          const user = result.user as User;
          await secureStorage.set(USER_STORAGE_KEY, JSON.stringify(user));
          dispatch({ type: 'LOGIN_SUCCESS', user });
        } finally {
          // Held only for the moment it takes to sign.
          zeroise(seed);
        }
      } catch (error) {
        console.error('[AuthContext] DID login failed:', error);
        dispatch({ type: 'LOGIN_FAILURE' });
        throw error;
      }
    },
    [],
  );

  const logout = useCallback(async (): Promise<void> => {
    try {
      await apiService.logout();
    } catch (error) {
      console.warn('[AuthContext] Logout API call failed:', error);
    } finally {
      await secureStorage.delete(USER_STORAGE_KEY);
      // The recovery record is deliberately KEPT. It names the account it
      // belongs to, so a different user signing in here is re-gated by the
      // ownership check rather than by deleting it — and keeping it is what
      // lets this handset sign back in with a passphrase alone, no email.
      dispatch({ type: 'LOGOUT' });
    }
  }, []);

  const biometricLogin = useCallback(async (): Promise<void> => {
    const biometricName = await biometricAuthService.getBiometricTypeName();
    const release = await deviceKeyGate.release(`Sign in with ${biometricName}`);

    if (release.status === 'NOT_ENABLED') {
      throw new Error('Biometric login is not enabled');
    }
    if (release.status === 'INVALIDATED') {
      dispatch({ type: 'SET_BIOMETRIC_LOCK_ENABLED', enabled: false });
      throw new Error(
        'Your device biometrics changed since App Lock was set up. Sign in with your email to continue, then re-enable App Lock.',
      );
    }
    if (release.status === 'FAILED') {
      throw new Error(release.message);
    }

    dispatch({ type: 'AUTH_INIT_START' });

    try {
      const hasToken = await apiService.hasAuthToken();
      if (!hasToken) {
        dispatch({ type: 'LOGIN_FAILURE' });
        throw new Error('No saved session. Please log in with your password first.');
      }

      let user: User | null = null;
      const storedUserData = await secureStorage.get(USER_STORAGE_KEY);

      if (storedUserData) {
        try {
          user = JSON.parse(storedUserData) as User;
        } catch {
          user = null;
        }
      }

      if (!user) {
        const userData = await apiService.getCurrentUser() as User;
        user = userData;
        await secureStorage.set(USER_STORAGE_KEY, JSON.stringify(user));
      }

      // Sync the existing token to SSI client so SDK operations work after biometric login
      const accessToken = await secureStorage.get(STORAGE_KEYS.ACCESS_TOKEN);
      const refreshToken = await secureStorage.get(STORAGE_KEYS.REFRESH_TOKEN);
      if (accessToken) {
        await ssiClientService.setAuthToken(accessToken, refreshToken || undefined);
      }

      user = await ensureWalletProvisioned(user);
      await secureStorage.set(USER_STORAGE_KEY, JSON.stringify(user));

      dispatch({ type: 'LOGIN_SUCCESS', user });
    } catch (error) {
      dispatch({ type: 'LOGIN_FAILURE' });
      throw error;
    }
  }, []);

  const setBiometricLockEnabled = useCallback(
    async (enabled: boolean): Promise<BiometricLockChangeResult> => {
      if (!enabled) {
        await deviceKeyGate.disable();
        dispatch({ type: 'SET_BIOMETRIC_LOCK_ENABLED', enabled: false });
        try {
          await apiService.updateSecurity({ biometricEnabled: false });
        } catch {}
        return { status: 'DISABLED' };
      }

      const outcome = await deviceKeyGate.enable();
      if (outcome.status === 'REFUSED') {
        return { status: 'REFUSED', reason: outcome.reason };
      }
      if (outcome.status === 'FAILED') {
        return { status: 'FAILED', message: outcome.message };
      }

      dispatch({ type: 'SET_BIOMETRIC_LOCK_ENABLED', enabled: true });
      try {
        await apiService.updateSecurity({ biometricEnabled: true });
      } catch {}
      return { status: 'ENABLED' };
    },
    [],
  );

  const refreshUser = useCallback(async (): Promise<void> => {
    try {
      const userData = await apiService.getCurrentUser() as User;
      await secureStorage.set(USER_STORAGE_KEY, JSON.stringify(userData));
      dispatch({ type: 'SET_USER', user: userData });
    } catch (error) {
      console.error('[AuthContext] Failed to refresh user:', error);
      throw error;
    }
  }, []);

  const value = useMemo<AuthContextValue>(() => ({
    user: state.user,
    isAuthenticated: state.isAuthenticated,
    isLoading: state.isLoading,
    isInitialized: state.isInitialized,
    isBiometricAvailable: state.isBiometricAvailable,
    isBiometricLockEnabled: state.isBiometricLockEnabled,
    register,
    logout,
    biometricLogin,
    setBiometricLockEnabled,
    refreshUser,
    passphraseLogin,
  }), [
    state.user,
    state.isAuthenticated,
    state.isLoading,
    state.isInitialized,
    state.isBiometricAvailable,
    state.isBiometricLockEnabled,
    register,
    logout,
    biometricLogin,
    setBiometricLockEnabled,
    refreshUser,
    passphraseLogin,
  ]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export { AuthContext };
