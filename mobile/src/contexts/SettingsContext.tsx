/**
 * SSI Healthcare Mobile - Settings Context
 *
 * Manages user preferences including Simple/Advanced mode toggle.
 * Advanced mode reveals technical details (DIDs, cryptographic info)
 * while Simple mode shows plain English explanations.
 */

import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useMemo,
  ReactNode,
} from 'react';
import { secureStorage, STORAGE_KEYS } from '../services';
import type { Language } from '../i18n';

// -- Types --

export interface SettingsContextValue {
  /** Whether advanced mode is enabled (shows technical details) */
  isAdvancedMode: boolean;
  
  /** Toggle between simple and advanced mode */
  toggleAdvancedMode: () => Promise<void>;
  
  /** Set advanced mode to a specific value */
  setAdvancedMode: (enabled: boolean) => Promise<void>;

  /**
   * The language the holder reads. 'en' until they choose otherwise.
   *
   * An empty Bangla translation falls back to English (see i18n/index.ts), so a
   * half-finished translation is still usable — and the holder is never shown a
   * raw key.
   */
  language: Language;

  /** Choose the language. Persisted; the choice outlives the session. */
  setLanguage: (language: Language) => Promise<void>;
  
  /**
   * The holder's own storage server, or null for the ministry-hosted locker.
   *
   * A LOCKED DECISION WITH NO SURFACE UNTIL NOW. The design says the
   * ministry locker is an OPTION and never the only path — the wallet must
   * offer the holder's own server as a first-class target, and that is what
   * separates this from centralised storage with extra steps. The URL was
   * baked into app.json, so the holder had no say at all, and the setting
   * that DID exist in its place was a "Language" row that opened a dialog
   * saying English was the only language.
   *
   * Stored as a plain URL. The bytes are encrypted under the holder's key
   * before they leave the device either way, so this changes who holds the
   * ciphertext, not who can read it.
   */
  storageServer: string | null;

  /** One host for the backend and both lockers. Null uses the built-in list. */
  serverHost: string | null;
  setServerHost: (host: string | null) => Promise<void>;

  /** Pass null to go back to the ministry-hosted locker. */
  setStorageServer: (url: string | null) => Promise<void>;

  /** Whether settings are still loading from storage */
  isLoading: boolean;
}

// -- Context --

const SettingsContext = createContext<SettingsContextValue | undefined>(undefined);

// -- Provider --

export interface SettingsProviderProps {
  children: ReactNode;
}

export function SettingsProvider({ children }: SettingsProviderProps) {
  const [isAdvancedMode, setIsAdvancedModeState] = useState(false);
  const [storageServer, setStorageServerState] = useState<string | null>(null);
  const [serverHost, setServerHostState] = useState<string | null>(null);
  const [language, setLanguageState] = useState<Language>('en');
  const [isLoading, setIsLoading] = useState(true);

  // Load saved preference on mount
  useEffect(() => {
    async function loadSettings() {
      try {
        const savedMode = await secureStorage.get(STORAGE_KEYS.ADVANCED_MODE);
        if (savedMode === 'true') {
          setIsAdvancedModeState(true);
        }
        const savedServer = await secureStorage.get(STORAGE_KEYS.STORAGE_SERVER);
        if (savedServer) setStorageServerState(savedServer);
        const savedHost = await secureStorage.get(STORAGE_KEYS.SERVER_HOST);
        if (savedHost) setServerHostState(savedHost);
        const savedLanguage = await secureStorage.get(STORAGE_KEYS.LANGUAGE);
        if (savedLanguage === 'bn' || savedLanguage === 'en') setLanguageState(savedLanguage);
      } catch (error) {
        console.error('[Settings] Failed to load advanced mode preference:', error);
      } finally {
        setIsLoading(false);
      }
    }

    loadSettings();
  }, []);

  // Set the language with persistence. Write the state FIRST so the UI changes
  // immediately; a storage failure then costs the memory of the choice, not the
  // choice itself.
  const setLanguage = useCallback(async (next: Language) => {
    setLanguageState(next);
    try {
      await secureStorage.set(STORAGE_KEYS.LANGUAGE, next);
    } catch (error) {
      console.error('[Settings] Failed to persist the language:', error);
    }
  }, []);

  // Set advanced mode with persistence
  const setAdvancedMode = useCallback(async (enabled: boolean) => {
    try {
      await secureStorage.set(STORAGE_KEYS.ADVANCED_MODE, enabled.toString());
      setIsAdvancedModeState(enabled);
    } catch (error) {
      console.error('[Settings] Failed to save advanced mode preference:', error);
      throw error;
    }
  }, []);

  const setStorageServer = useCallback(async (url: string | null) => {
    // REFUSE A NON-http URL rather than storing it. An unreachable or
    // malformed target fails at the moment a document is submitted, which is
    // the worst time to discover it — the same shape as the HMS base URL that
    // silently became a DID and surfaced as "Network request failed".
    const trimmed = url?.trim() ?? '';
    if (trimmed.length > 0 && !/^https?:\/\//i.test(trimmed)) {
      throw new Error('A storage server address must start with http:// or https://');
    }
    await secureStorage.set(STORAGE_KEYS.STORAGE_SERVER, trimmed);
    setStorageServerState(trimmed.length > 0 ? trimmed : null);
  }, []);

  const setServerHost = useCallback(async (host: string | null) => {
    // A HOST, not a URL. Accepting a URL here would let a scheme or a path in,
    // and the three services are then derived on different ports, so a stray
    // ":3001" or trailing slash produces addresses that are wrong in a way
    // that only shows up as a network failure much later.
    const trimmed = (host ?? '').trim().replace(/^https?:\/\//i, '').replace(/[/:].*$/, '');
    if (trimmed.length > 0 && !/^[a-z0-9.-]+$/i.test(trimmed)) {
      throw new Error('Enter an address like 192.168.0.110, with no http:// and no port');
    }
    await secureStorage.set(STORAGE_KEYS.SERVER_HOST, trimmed);
    setServerHostState(trimmed.length > 0 ? trimmed : null);
  }, []);

  // Toggle advanced mode
  const toggleAdvancedMode = useCallback(async () => {
    await setAdvancedMode(!isAdvancedMode);
  }, [isAdvancedMode, setAdvancedMode]);

  // Memoize context value
  const value = useMemo<SettingsContextValue>(
    () => ({
      isAdvancedMode,
      language,
      setLanguage,
      toggleAdvancedMode,
      setAdvancedMode,
      storageServer,
      setStorageServer,
      serverHost,
      setServerHost,
      isLoading,
    }),
    [isAdvancedMode, toggleAdvancedMode, setAdvancedMode, storageServer, setStorageServer, serverHost, setServerHost, isLoading]
  );

  return (
    <SettingsContext.Provider value={value}>
      {children}
    </SettingsContext.Provider>
  );
}

// -- Hook --

export function useSettings(): SettingsContextValue {
  const context = useContext(SettingsContext);
  if (context === undefined) {
    throw new Error('useSettings must be used within a SettingsProvider');
  }
  return context;
}

// Export context for testing purposes
export { SettingsContext };
