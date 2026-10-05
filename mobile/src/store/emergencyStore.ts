/**
 * SSI Healthcare Mobile - Emergency Store
 *
 * Zustand store for emergency access state management.
 */

import { create } from 'zustand';
import { failureMessage } from '../utils/userFacingError';
import { apiService } from '../services/api';
import type { EmergencyRecord, EmergencyContact } from '../types';

// -- State Interface --

interface EmergencyState {
  // Data
  records: EmergencyRecord[];
  activeRecords: EmergencyRecord[];
  contacts: EmergencyContact[];
  emergencyEnabled: boolean;
  lastPatientDid: string | null;

  // Loading states
  isLoading: boolean;
  isRefreshing: boolean;
  /** Id of the grant currently being stopped, or null. */
  isRevoking: string | null;
  error: string | null;
  /** True when the most recent check did not complete. Never means "no access". */
  lastCheckFailed: boolean;
  /** When records were last confirmed against the backend. */
  lastCheckedAt: number | null;

  // Actions
  fetchRecords: (patientDid?: string) => Promise<void>;
  revokeAccess: (emergencyId: string) => Promise<void>;
  refreshRecords: () => Promise<void>;
  addContact: (contact: EmergencyContact) => void;
  removeContact: (contactId: string) => void;
  toggleEmergency: (enabled: boolean) => void;
  clearError: () => void;
}

// -- Store --

export const useEmergencyStore = create<EmergencyState>((set, get) => ({
  // Initial state
  records: [],
  activeRecords: [],
  contacts: [],
  emergencyEnabled: false,
  lastPatientDid: null,
  isLoading: false,
  isRefreshing: false,
  isRevoking: null,
  error: null,
  lastCheckFailed: false,
  lastCheckedAt: null,

  // Fetch records from API
  fetchRecords: async (patientDid?: string) => {
    const { isLoading } = get();
    if (isLoading) return;

    if (!patientDid) {
      set({ records: [], activeRecords: [], isLoading: false });
      return;
    }

    set({ isLoading: true, error: null, lastPatientDid: patientDid });

    try {
      const response = await apiService.queryEmergencyRecords(patientDid);
      const records = (Array.isArray(response) ? response : []) as EmergencyRecord[];
      const activeRecords = records.filter((r: EmergencyRecord) => r.status === 'granted');

      set({ records, activeRecords, isLoading: false, lastCheckFailed: false, lastCheckedAt: Date.now() });
    } catch (error) {
      // A FAILED CHECK MUST NOT ERASE WHAT WE ALREADY KNEW.
      //
      // This previously set `records: []` on any failure, so losing the network
      // for a moment discarded the last known state, and the screen then had
      // nothing to show and rendered "Failed to Load" over the whole surface.
      // On the one screen whose purpose is to say whether a hospital is reading
      // your records, going blank is the worst available answer: it is
      // indistinguishable from "nothing is happening" to anyone who does not
      // read the title carefully.
      //
      // The existing records are kept and marked stale. Under an auto-grant
      // model the asymmetry is clear: showing a grant that has since been
      // revoked costs the holder a look at a screen, while hiding one that is
      // live costs them the only control they have.
      set({
        error: failureMessage(error, 'check emergency access'),
        isLoading: false,
        lastCheckFailed: true,
      });
    }
  },

  /**
   * Stop an active emergency grant.
   *
   * Revocation is the holder's ONLY lever here, and it is load-bearing: the
   * grant model is auto-grant, so nothing prevented the access — being able to
   * end it, quickly, is what makes that defensible. It re-fetches rather than
   * patching local state, because the authoritative answer to "is this access
   * still live" is the server's, and a wallet that showed "revoked" while the
   * grant was still honoured would be the worst possible lie on this screen.
   */
  revokeAccess: async (emergencyId: string) => {
    set({ isRevoking: emergencyId, error: null });
    try {
      await apiService.revokeEmergencyAccess(emergencyId);
      const { lastPatientDid } = get();
      set({ isRevoking: null });
      if (lastPatientDid) await get().fetchRecords(lastPatientDid);
    } catch (error) {
      set({
        isRevoking: null,
        error: error instanceof Error ? error.message : 'Failed to stop emergency access',
      });
    }
  },

  // Refresh records using last known patientDid
  refreshRecords: async () => {
    const { lastPatientDid } = get();
    if (!lastPatientDid) return;
    set({ isRefreshing: true });
    await get().fetchRecords(lastPatientDid);
    set({ isRefreshing: false });
  },

  // Add contact
  addContact: (contact: EmergencyContact) => {
    set((state) => ({
      contacts: [...state.contacts, contact],
    }));
  },

  // Remove contact
  removeContact: (contactId: string) => {
    set((state) => ({
      contacts: state.contacts.filter((c: EmergencyContact) => c.id !== contactId),
    }));
  },

  // Toggle emergency
  toggleEmergency: (enabled: boolean) => {
    set({ emergencyEnabled: enabled });
  },

  // Clear error
  clearError: () => {
    set({ error: null });
  },
}));

export default useEmergencyStore;
