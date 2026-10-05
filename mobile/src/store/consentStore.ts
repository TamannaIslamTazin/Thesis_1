/**
 * SSI Healthcare Mobile - Consent Store
 *
 * Zustand store for consent state management.
 */

import { create } from 'zustand';
import { ssiClient } from '../services/ssiClient';
import type { Consent, ConsentStatus } from '../types';
import {
  listConsentRecords,
  replaceConsentRecords,
  revokeConsentRecord,
} from '../db';
import type { ConsentApiRecord } from '../db';

// -- Type Transformation --

/**
 * Map an API consent record onto the mobile domain model.
 *
 * Array fields are defensively defaulted: this is a privacy surface, and
 * rendering an empty scope is honest, whereas throwing inside a list map would
 * blank the whole screen.
 */
function transformConsent(record: ConsentApiRecord): Consent {
  const credentialTypes = record.scope ?? [];
  const allowedFields = record.allowedFields ?? [];

  return {
    id: record.id,
    requesterId: record.verifierDid,
    requesterName: record.verifierName,
    purpose: {
      id: 'purpose',
      name: record.purpose,
    },
    scope: {
      id: 'scope',
      name: 'Data Access',
      description:
        credentialTypes.length > 0
          ? `Access to ${credentialTypes.join(', ')}`
          : 'Access to shared credentials',
      dataTypes: allowedFields,
    },
    status: record.status as ConsentStatus,
    createdAt: record.grantedAt,
    expiresAt: record.expiresAt,
    revokedAt: record.revokedAt,
    accessCount: record.accessCount,
    lastAccessedAt: record.lastAccessedAt,
    // Default FALSE, not true: an older row that predates this field records a
    // presentation, and reading an unknown as "access continues" would restore
    // the very claim being corrected.
    standingAccess: record.standingAccess ?? false,
  };
}

// -- Local Persistence --

async function loadCachedConsents(): Promise<Consent[] | null> {
  try {
    const records = await listConsentRecords();
    if (records.length === 0) return null;
    return records.map(transformConsent);
  } catch (error) {
    console.warn('[consentStore] failed to read the local consent database:', error);
    return null;
  }
}

async function persistConsentRecords(records: readonly ConsentApiRecord[]): Promise<void> {
  try {
    await replaceConsentRecords(records);
  } catch (error) {
    console.warn('[consentStore] failed to persist consents locally:', error);
  }
}

async function persistConsentRevocation(consentId: string): Promise<void> {
  try {
    await revokeConsentRecord(consentId, new Date().toISOString());
  } catch (error) {
    console.warn('[consentStore] failed to persist the revocation locally:', error);
  }
}

// -- State Interface --

interface ConsentState {
  // Data
  consents: Consent[];
  activeConsents: Consent[];
  revokedConsents: Consent[];

  // Loading states
  isLoading: boolean;
  isRevoking: string | null;
  error: string | null;

  // Actions
  fetchConsents: () => Promise<void>;
  revokeConsent: (consentId: string) => Promise<void>;
  clearError: () => void;
}

// -- Store --

export const useConsentStore = create<ConsentState>((set, get) => ({
  // Initial state
  consents: [],
  activeConsents: [],
  revokedConsents: [],
  isLoading: false,
  isRevoking: null,
  error: null,

  // Fetch consents
  fetchConsents: async () => {
    const { isLoading } = get();
    if (isLoading) return;

    set({ isLoading: true, error: null });

    try {
      // The one acknowledged cast: `getConsents()` is typed against the stale
      // SDK `Consent` shape, but the endpoint actually sends `ConsentApiRecord`.
      const sdkConsents = (await ssiClient.getConsents()) as unknown as ConsentApiRecord[];
      
      // Validate SDK response format
      if (!Array.isArray(sdkConsents)) {
        console.warn('[ConsentStore] SDK returned non-array consents, using empty array:', typeof sdkConsents);
      }
      
      const records = Array.isArray(sdkConsents) ? sdkConsents : [];
      const consents = records.map(transformConsent);
      
      const activeConsents = consents.filter((c: Consent) => c.status === 'active');
      const revokedConsents = consents.filter((c: Consent) => c.status === 'revoked' || c.status === 'expired');

      set({ consents, activeConsents, revokedConsents, isLoading: false });

      await persistConsentRecords(records);
    } catch (error) {
      const cached = await loadCachedConsents();
      if (cached && cached.length > 0) {
        set({
          consents: cached,
          activeConsents: cached.filter((c) => c.status === 'active'),
          revokedConsents: cached.filter((c) => c.status === 'revoked' || c.status === 'expired'),
          isLoading: false,
          error: 'Showing cached data. Pull to refresh.',
        });
        return;
      }

      // NO demo data fallback - users must see real state
      set({
        consents: [],
        activeConsents: [],
        revokedConsents: [],
        error: error instanceof Error ? error.message : 'Failed to fetch consents',
        isLoading: false,
      });
    }
  },

  // Revoke consent
  revokeConsent: async (consentId: string) => {
    set({ isRevoking: consentId, error: null });

    try {
      await ssiClient.revokeConsent(consentId);
      await persistConsentRevocation(consentId);
      
      // Update local state
      set((state) => {
        const consent = state.consents.find((c: Consent) => c.id === consentId);
        if (!consent) return state;

        const updatedConsent: Consent = {
          ...consent,
          status: 'revoked',
          revokedAt: new Date().toISOString(),
        };

        const consents = state.consents.map((c: Consent) =>
          c.id === consentId ? updatedConsent : c
        );

        return {
          consents,
          activeConsents: consents.filter((c: Consent) => c.status === 'active'),
          revokedConsents: consents.filter((c: Consent) => c.status === 'revoked' || c.status === 'expired'),
          isRevoking: null,
        };
      });
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : 'Failed to revoke consent',
        isRevoking: null,
      });
    }
  },

  // Clear error
  clearError: () => {
    set({ error: null });
  },
}));

export default useConsentStore;
