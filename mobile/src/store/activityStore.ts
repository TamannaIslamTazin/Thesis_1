/**
 * SSI Healthcare Mobile - Activity Store
 *
 * Zustand store for activity log state management.
 */

import { create } from 'zustand';
import { apiService } from '../services/api';
import { useCredentialStore } from './credentialStore';
import type { ActivityItem } from '../types';

// -- Backend Response Shape --

interface BackendAuditLog {
  id: string;
  eventType: string;
  action: string;
  timestamp: string;
  details?: Record<string, unknown>;
}

/**
 * Map backend eventType to mobile ActivityItem type
 */
function mapEventType(eventType: string): ActivityItem['type'] {
  const mapping: Record<string, ActivityItem['type']> = {
    CREDENTIAL_ISSUED: 'credential_issued',
    CREDENTIAL_SHARED: 'credential_shared',
    PRESENTATION_CREATED: 'credential_shared',
    CONSENT_GRANTED: 'consent_granted',
    CONSENT_CREATED: 'consent_granted',
    CONSENT_REVOKED: 'consent_revoked',
    PRESENTATION_VERIFIED: 'verification_request',
    PRESENTATION_REJECTED: 'verification_request',
    PRESCRIPTION_DISPENSED: 'other',
    USER_LOGIN: 'login',
    USER_LOGOUT: 'logout',
  };
  // 'other', NOT 'login'. Defaulting an unrecognised audit event to "you signed
  // in" does not merely mislabel it — it asserts an event that did not happen,
  // on the one screen whose entire purpose is an accurate record. A sign-out was
  // being reported as a sign-in for the same reason.
  return mapping[eventType] || 'other';
}

/**
 * Generate a human-readable title from backend eventType
 */
function generateTitle(eventType: string): string {
  const titles: Record<string, string> = {
    CREDENTIAL_ISSUED: 'Credential Issued',
    CREDENTIAL_SHARED: 'Credential Shared',
    PRESENTATION_CREATED: 'Presentation Created',
    CONSENT_GRANTED: 'Consent Granted',
    CONSENT_CREATED: 'Consent Created',
    CONSENT_REVOKED: 'Consent Revoked',
    PRESENTATION_VERIFIED: 'Verification Completed',
    PRESENTATION_REJECTED: 'Verification Refused',
    PRESCRIPTION_DISPENSED: 'Prescription',
    USER_LOGIN: 'Signed In',
    USER_LOGOUT: 'Signed Out',
  };
  return titles[eventType] || eventType.replace(/_/g, ' ').toLowerCase();
}

/**
 * The dispense entry, rendered from what the WALLET can see.
 *
 * TWO DELIBERATE CHOICES HERE.
 *
 * 1. THE WALLET DOES NOT DECIDE EXPIRY. A device clock can be changed, so the
 *    wallet must never conclude "this token expired". It renders only what the
 *    settlement fields say: paid, declined, or still open. The expiry verdict
 *    belongs to the backend, which is why the Home card takes its state from
 *    `GET /settlement/mine` and this function does not recompute it.
 *
 * 2. THE MEDICINES COME FROM THE HOLDER'S OWN CREDENTIAL, not from the operator.
 *    Shipping medicine names to the backend would put clinical detail in the
 *    operator's database, which is the opposite of what this system is for. The
 *    wallet already holds the prescription, so it renders the names itself and
 *    the backend never sees them.
 */
function describeDispense(
  details: Record<string, unknown>,
  medicines: string | null,
): string {
  const token = typeof details.queueToken === 'number' ? details.queueToken : null;
  const pharmacy = String(details.pharmacyDid ?? '').split(':').pop() ?? '';
  const what = medicines ?? 'Prescription';
  const where = pharmacy ? ` at ${pharmacy}` : '';
  const withToken = token !== null ? ` with token ${token}` : '';

  if (details.settledAt) {
    return `${what} dispensed${where}${withToken}`;
  }
  if (details.abandonedReason === 'declined') {
    return `${what} not collected${where}${withToken}`;
  }
  // Open, or expired by the backend's clock. Saying "dispensed" here would
  // assert medicine the holder may never have taken, so it stays neutral.
  return `Token issued${where}${withToken}`;
}

/**
 * Transform backend audit log to mobile ActivityItem
 */
/**
 * The ONE place backend audit events become activity items.
 *
 * Exported so the full activity log renders through the same transform as the
 * home feed. They previously differed: home mapped, and the log screen cast the
 * raw API shape to `ActivityItem[]`, which typechecked and then crashed.
 */
export function transformActivities(raw: unknown): ActivityItem[] {
  // Not `.map(transformActivity)`: map passes the INDEX as the second argument,
  // which would arrive as `credentials`. A silent wrong-argument bug.
  return (Array.isArray(raw) ? (raw as BackendAuditLog[]) : []).map((log) => transformActivity(log));
}

/**
 * The holder's own medicine names for a prescription, read from the LOCAL
 * credential store. Returns null when the credential is not held, and the caller
 * falls back to a neutral noun rather than inventing a name.
 */
function medicinesFor(prescriptionId: string, credentials: readonly unknown[]): string | null {
  if (!prescriptionId) return null;
  for (const raw of credentials) {
    const c = raw as { claims?: Record<string, unknown>; credentialData?: Record<string, unknown> } | null;
    if (!c) continue;
    const subject = (c.claims ?? (c.credentialData?.credentialSubject as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    const id = String(subject.id ?? subject.prescriptionId ?? '');
    if (!id || id !== prescriptionId) continue;
    const name = subject.medication ?? subject.medicine ?? subject.name;
    if (typeof name === 'string' && name.trim()) return name.trim();
  }
  return null;
}

function transformActivity(log: BackendAuditLog, credentials: readonly unknown[] = []): ActivityItem {
  const details = (log.details ?? {}) as Record<string, unknown>;
  // The dispense entry carries the token, the pharmacy and the settlement state,
  // and it is the ONE event whose wording depends on state rather than on type.
  const description =
    log.eventType === 'PRESCRIPTION_DISPENSED'
      ? describeDispense(details, medicinesFor(String(details.prescriptionId ?? ''), credentials))
      : log.action || `${log.eventType} event`;
  return {
    id: log.id,
    type: mapEventType(log.eventType),
    title: generateTitle(log.eventType),
    description,
    timestamp: log.timestamp,
    metadata: log.details,
  };
}

// -- State Interface --

interface ActivityState {
  // Data
  activities: ActivityItem[];

  // Loading states
  isLoading: boolean;
  error: string | null;

  // Actions
  fetchActivities: () => Promise<void>;
  addActivity: (activity: ActivityItem) => void;
  clearError: () => void;
}

// -- Store --

export const useActivityStore = create<ActivityState>((set, get) => ({
  // Initial state
  activities: [],
  isLoading: false,
  error: null,

  // Fetch activities from API
  fetchActivities: async () => {
    const { isLoading } = get();
    if (isLoading) return;

    set({ isLoading: true, error: null });

    try {
      // Fetch real activity data from API and transform from backend shape
      const response = await apiService.getActivity();
      const rawLogs = (Array.isArray(response) ? response : []) as BackendAuditLog[];
      // The holder's own credentials are read here so the dispense entry can name
      // the medicine WITHOUT the operator ever holding that name. A missing
      // credential degrades the wording; it never invents one.
      const credentials = useCredentialStore.getState().credentials;
      const activities = rawLogs.map((log) => transformActivity(log, credentials));
      set({ activities, isLoading: false });
    } catch (error) {
      // NO demo data fallback - users must see real state
      set({
        activities: [],
        error: error instanceof Error ? error.message : 'Failed to fetch activities',
        isLoading: false,
      });
    }
  },

  // Add activity (for local/optimistic updates)
  addActivity: (activity: ActivityItem) => {
    set((state) => ({
      activities: [activity, ...state.activities],
    }));
  },

  // Clear error
  clearError: () => {
    set({ error: null });
  },
}));

export default useActivityStore;
