/**
 * SSI Healthcare Mobile - Credential Store
 *
 * Zustand store for credential state management.
 * Handles fetching, caching, and disclosure state.
 * 
 * Features:
 * - Fetches credentials from backend via SDK
 * - Persists credentials in the encrypted on-device database (SQLCipher) for offline access
 * - Manages disclosure state for selective sharing
 * - Groups credentials into folders by category
 */

import { create } from 'zustand';
import { ssiClient } from '../services/ssiClient';
import { secureStorage, STORAGE_KEYS } from '../services/secureStorage';
import type {
  Credential,
  CredentialFolder,
  CredentialCategory,
  CredentialField,
} from '../types';
import type { WalletCredential } from '@ssi-healthcare/sdk';
import {
  listCredentialEnvelopes,
  replaceCredentialEnvelopes,
  clearCredentialEnvelopes,
} from '../db';
// The wire-contract -> view-model mapping lives in its own module so it can be
// exercised without React Native. See credentialTransform.ts.
import { transformCredential, renderClaimValue } from './credentialTransform';
import { walletCredentialFromIssued } from './issuedCredential';
import { colors } from '../theme';

// -- State Interface --

interface CredentialState {
  // Data
  credentials: Credential[];
  folders: CredentialFolder[];
  selectedCredential: Credential | null;
  disclosureState: Record<string, Record<string, boolean>>; // credentialId -> fieldId -> disclosed
  
  // Loading states
  isLoading: boolean;
  isRefreshing: boolean;
  error: string | null;
  
  // Actions
  fetchCredentials: () => Promise<void>;
  fetchCredentialById: (id: string) => Promise<void>;
  refreshCredentials: () => Promise<void>;
  ingestIssuedCredential: (jwt: string) => Promise<void>;
  setSelectedCredential: (credential: Credential | null) => void;
  toggleFieldDisclosure: (credentialId: string, fieldId: string) => void;
  setAllFieldsDisclosure: (credentialId: string, disclosed: boolean) => void;
  getDisclosedFields: (credentialId: string) => string[];
  clearError: () => void;
  clearCache: () => Promise<void>;
}

// -- Folder Configuration --

const FOLDER_CONFIG: Record<CredentialCategory, { name: string; icon: string; color: string }> = {
  medical_record: { name: 'Medical Records', icon: 'document-text', color: colors.brand.primary },
  vaccination: { name: 'Vaccinations', icon: 'medical', color: colors.semantic.success },
  prescription: { name: 'Prescriptions', icon: 'medkit', color: colors.credential.prescription },
  lab_result: { name: 'Lab Results', icon: 'flask', color: colors.credential.lab },
  insurance: { name: 'Insurance', icon: 'shield-checkmark', color: colors.credential.insurance },
  emergency: { name: 'Emergency', icon: 'alert-circle', color: colors.credential.emergency },
  identity: { name: 'Identity', icon: 'person', color: colors.brand.primary },
  other: { name: 'Other', icon: 'folder', color: colors.text.secondary },
};

// -- Helper Functions --

function groupCredentialsByCategory(credentials: Credential[]): CredentialFolder[] {
  const grouped: Record<string, Credential[]> = {};
  
  credentials.forEach((cred) => {
    const category = cred.category || 'other';
    if (!grouped[category]) {
      grouped[category] = [];
    }
    grouped[category].push(cred);
  });

  return Object.entries(grouped).map(([category, creds]) => {
    const config = FOLDER_CONFIG[category as CredentialCategory] || FOLDER_CONFIG.other;
    return {
      id: category,
      name: config.name,
      category: category as CredentialCategory,
      icon: config.icon,
      color: config.color,
      count: creds.length,
      credentials: creds,
    };
  });
}

function extractFieldsFromCredential(credential: Credential): CredentialField[] {
  const subject = credential.verifiableCredential?.credentialSubject || {};
  const fields: CredentialField[] = [];
  
  Object.entries(subject).forEach(([key, value]) => {
    if (key !== 'id' && value !== undefined) {
      fields.push({
        id: key,
        label: formatFieldLabel(key),
        value: renderClaimValue(value),
        // DEFAULT CLOSED, and the default lives here because this seeds the
        // store state the detail screen reads. A presentation builder starts
        // with nothing selected so that sharing is the deliberate act; the
        // previous `!isSensitiveField(key)` marked every non-sensitive claim
        // as already shared before the holder had seen the screen.
        disclosed: false,
        sensitive: isSensitiveField(key),
      });
    }
  });
  
  return fields;
}

function formatFieldLabel(key: string): string {
  return key
    .replace(/([A-Z])/g, ' $1')
    .replace(/[_-]/g, ' ')
    .replace(/^\w/, (c) => c.toUpperCase())
    .trim();
}

function isSensitiveField(key: string): boolean {
  const sensitiveFields = [
    'ssn',
    'socialSecurityNumber',
    'dateOfBirth',
    'dob',
    'address',
    'phone',
    'email',
    'bloodType',
    'allergies',
  ];
  return sensitiveFields.includes(key.toLowerCase());
}

// -- Local Persistence --

/**
 * The encrypted database is the wallet's local copy; the network fetch is the
 * source it refreshes from. The previous implementation kept the WHOLE
 * credential array in ONE SecureStore value, which the platform rejects above
 * roughly 2 KB — the four ACTIVE health cards already exceed it (#440).
 */
async function loadCachedCredentials(): Promise<Credential[] | null> {
  try {
    const envelopes = await listCredentialEnvelopes();
    if (envelopes.length === 0) return null;
    return envelopes.map(transformCredential);
  } catch (error) {
    console.warn('[credentialStore] failed to read the local credential database:', error);
    return null;
  }
}

async function persistCredentialEnvelopes(envelopes: readonly WalletCredential[]): Promise<void> {
  try {
    await replaceCredentialEnvelopes(envelopes);
    await purgeLegacyCredentialCache();
  } catch (error) {
    // The fetch already succeeded; failing the screen because the local mirror
    // could not be written would trade a visible state for an invisible one.
    // The next successful fetch rewrites the mirror.
    console.warn('[credentialStore] failed to persist credentials locally:', error);
  }
}

/**
 * Union a server list with the rows already on this device — NEVER a replace.
 *
 * A credential issued directly by an authority lives on this device and is
 * absent from the server's list, so replacing the local mirror with the
 * server's answer deletes it. Measured 23 Sep 2026: the prescription vanished
 * from Cards the first time the app returned to the foreground, because the
 * foreground refresh re-fetched and overwrote the device copy.
 *
 * Fetched rows win on an id collision: they carry the server's revocation state.
 */
async function mergeWithLocalCredentials(
  fetched: readonly WalletCredential[],
): Promise<WalletCredential[]> {
  const local = await listCredentialEnvelopes().catch(() => [] as WalletCredential[]);
  const byId = new Map<string, WalletCredential>();
  for (const envelope of [...fetched, ...local]) {
    if (!byId.has(envelope.id)) byId.set(envelope.id, envelope);
  }
  return [...byId.values()];
}

async function clearCredentialCache(): Promise<void> {
  try {
    await clearCredentialEnvelopes();
  } catch (error) {
    console.warn('[credentialStore] failed to clear the local credential database:', error);
  }
  await purgeLegacyCredentialCache();
}

/**
 * Delete the pre-database cache blob written by older builds. Its value holds
 * the whole credential array in cleartext for SecureStore's purposes, and
 * nothing reads it any more.
 */
async function purgeLegacyCredentialCache(): Promise<void> {
  try {
    await secureStorage.delete(STORAGE_KEYS.CREDENTIAL_CACHE);
  } catch {
    // The key not existing is the expected steady state.
  }
}

/**
 * Process credentials into folders and disclosure state
 * Extracted to avoid duplication between fetch and refresh
 */
function processCredentials(credentials: Credential[]): {
  folders: CredentialFolder[];
  disclosureState: Record<string, Record<string, boolean>>;
} {
  const folders = groupCredentialsByCategory(credentials);
  const disclosureState: Record<string, Record<string, boolean>> = {};
  
  credentials.forEach((cred: Credential) => {
    const fields = extractFieldsFromCredential(cred);
    disclosureState[cred.id] = {};
    fields.forEach((field: CredentialField) => {
      disclosureState[cred.id][field.id] = field.disclosed;
    });
  });
  
  return { folders, disclosureState };
}

// -- Store --

export const useCredentialStore = create<CredentialState>((set, get) => ({
  // Initial state
  credentials: [],
  folders: [],
  selectedCredential: null,
  disclosureState: {},
  isLoading: false,
  isRefreshing: false,
  error: null,

  // Fetch all credentials (with offline cache support)
  fetchCredentials: async () => {
    const { isLoading } = get();
    if (isLoading) return;

    set({ isLoading: true, error: null });

    try {
      // Try to load from network first
      const sdkCredentials = await ssiClient.getCredentials();
      const fetched = Array.isArray(sdkCredentials) ? sdkCredentials : [];
      const envelopes = await mergeWithLocalCredentials(fetched);
      const credentials = envelopes.map(transformCredential);
      const { folders, disclosureState } = processCredentials(credentials);

      // Mirror the fetch into the encrypted local database for offline access.
      await persistCredentialEnvelopes(envelopes);
      
      set({ credentials, folders, disclosureState, isLoading: false });
    } catch {
      // Network failed - try loading from cache
      const cachedCredentials = await loadCachedCredentials();
      if (cachedCredentials && cachedCredentials.length > 0) {
        const { folders, disclosureState } = processCredentials(cachedCredentials);
        set({ 
          credentials: cachedCredentials, 
          folders, 
          disclosureState, 
          isLoading: false,
          // Note: We set a warning but still show cached data
          error: 'Showing cached data. Pull to refresh.',
        });
        return;
      }
      
      // No cache available - show error
      set({
        credentials: [],
        folders: [],
        error: 'Failed to fetch credentials',
        isLoading: false,
      });
    }
  },

  // Fetch single credential by ID
  fetchCredentialById: async (id: string) => {
    set({ isLoading: true, error: null });

    // Written once because the disclosure state is a property of the
    // credential, not of where it was read from.
    const select = (credential: Credential): void => {
      const fields = extractFieldsFromCredential(credential);
      const fieldState: Record<string, boolean> = {};
      fields.forEach((field: CredentialField) => {
        fieldState[field.id] = field.disclosed;
      });
      set((state) => ({
        selectedCredential: credential,
        disclosureState: {
          ...state.disclosureState,
          [credential.id]: fieldState,
        },
        isLoading: false,
      }));
    };

    try {
      const sdkCredential = await ssiClient.getCredential(id);
      if (!sdkCredential) {
        throw new Error('Credential not found');
      }
      select(transformCredential(sdkCredential));
    } catch (error) {
      // OFFLINE FALLBACK. The credential is already in the encrypted database,
      // so a failed network call must not turn a STORED credential into
      // "Failed to Load" - the same local-first rule fetchCredentials follows.
      // Measured 22 Sep 2026: tapping a health card with the backend down
      // showed "Failed to Load / Network request failed" for a card the wallet
      // was holding.
      const cached = await loadCachedCredentials();
      const stored = cached?.find((c) => c.id === id);
      if (stored) {
        select(stored);
        return;
      }
      set({
        error: error instanceof Error ? error.message : 'Failed to fetch credential',
        isLoading: false,
      });
    }
  },

  // Refresh credentials (force network fetch, bypass cache)
  refreshCredentials: async () => {
    set({ isRefreshing: true, error: null });
    
    try {
      // Force network fetch - don't use cache
      const sdkCredentials = await ssiClient.getCredentials();
      const fetched = Array.isArray(sdkCredentials) ? sdkCredentials : [];
      const envelopes = await mergeWithLocalCredentials(fetched);
      const credentials = envelopes.map(transformCredential);
      const { folders, disclosureState } = processCredentials(credentials);

      // Update the local mirror with fresh data.
      await persistCredentialEnvelopes(envelopes);
      
      set({ credentials, folders, disclosureState, isRefreshing: false, error: null });
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : 'Failed to refresh credentials',
        isRefreshing: false,
      });
    }
  },

  /**
   * Store a credential received straight from an issuer over OID4VCI.
   *
   * The issuer keeps no copy on our behalf, so this is the ONLY place the
   * credential is written down. It goes into the local encrypted database —
   * which also enqueues it for the datastore sync — and the store then renders
   * from that persisted list, so the Cards screen shows what actually saved.
   */
  ingestIssuedCredential: async (jwt: string) => {
    const envelope = walletCredentialFromIssued(jwt);
    const existing = await listCredentialEnvelopes().catch(() => [] as WalletCredential[]);
    const merged = [...existing.filter((item) => item.id !== envelope.id), envelope];

    await persistCredentialEnvelopes(merged);

    const credentials = merged.map(transformCredential);
    const { folders, disclosureState } = processCredentials(credentials);
    set({ credentials, folders, disclosureState });
  },

  // Set selected credential
  setSelectedCredential: (credential: Credential | null) => {
    set({ selectedCredential: credential });
  },

  // Toggle field disclosure
  toggleFieldDisclosure: (credentialId: string, fieldId: string) => {
    set((state) => ({
      disclosureState: {
        ...state.disclosureState,
        [credentialId]: {
          ...state.disclosureState[credentialId],
          [fieldId]: !state.disclosureState[credentialId]?.[fieldId],
        },
      },
    }));
  },

  // Set all fields disclosure
  setAllFieldsDisclosure: (credentialId: string, disclosed: boolean) => {
    set((state) => {
      const currentState = state.disclosureState[credentialId] || {};
      const newState: Record<string, boolean> = {};
      Object.keys(currentState).forEach((fieldId: string) => {
        newState[fieldId] = disclosed;
      });
      return {
        disclosureState: {
          ...state.disclosureState,
          [credentialId]: newState,
        },
      };
    });
  },

  // Get disclosed fields
  getDisclosedFields: (credentialId: string): string[] => {
    const state = get().disclosureState[credentialId] || {};
    return Object.entries(state)
      .filter(([, disclosed]) => disclosed)
      .map(([fieldId]) => fieldId);
  },

  // Clear error
  clearError: () => {
    set({ error: null });
  },
  
  // Clear credential cache (useful for logout)
  clearCache: async () => {
    await clearCredentialCache();
    set({ credentials: [], folders: [], disclosureState: {} });
  },
}));

export default useCredentialStore;
