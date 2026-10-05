/**
 * Pairing this pharmacy with an L1 officer's onboarding session.
 *
 * ===========================================================================
 * THIS CALL SENDS NO SESSION, AND THAT IS THE DESIGN
 * ===========================================================================
 * Every other call to the backend from this app carries `PHARMACY_SESSION_TOKEN`
 * (see backend.ts). This one must not: the pairing code IS the credential of a
 * software that has no account yet. That is precisely the problem the enrolment
 * token exists to solve — an institution's software cannot authenticate before it
 * is an institution.
 *
 * So the security of this call is entirely the token's: secret, single-use, and
 * valid for ten minutes. Which is why the token is never logged here, never
 * echoed back to the page, and never persisted.
 *
 * ===========================================================================
 * THE PUBLIC KEY IS THIS PHARMACY'S CONTRIBUTION
 * ===========================================================================
 * It goes up with the claim, and the officer's confirmation turns it into
 * #key-officer-2 on the minted DID. Without it the institution would be a 1-of-1
 * whose only key lives in the ministry's backend.
 */
import { BACKEND_URL, BackendError } from './backend';

export interface ClaimResult {
  readonly enrolmentId: string;
  readonly authorityId: string;
}

/**
 * Claim a pairing code.
 *
 * The response deliberately carries NO institution and NO DID: claiming pairs the
 * software and creates nothing. The DID exists only after the officer confirms
 * what they saw on site — and this software cannot poll for it, because the
 * status endpoint is the officer's and scoped to their session.
 */
export async function claimEnrolment(token: string, publicKeyMultibase: string): Promise<ClaimResult> {
  const res = await fetch(
    `${BACKEND_URL}/api/authority/enrolments/${encodeURIComponent(token)}/claim`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        claimedBy: process.env.PHARMACY_DISPLAY_NAME ?? 'Pharmacy counter PC',
        publicKeyMultibase,
      }),
      cache: 'no-store',
    },
  );

  const body = (await res.json().catch(() => null)) as
    | { success?: boolean; data?: ClaimResult; error?: { message?: string } }
    | null;

  if (!res.ok || !body?.success || !body.data) {
    // The backend's message is safe to surface: it names a token state
    // ('unknown token', 'token already claimed', 'token expired') and nothing
    // about the holder or the officer.
    throw new BackendError(
      body?.error?.message ?? `Pairing failed with status ${res.status}.`,
      res.status,
    );
  }

  return body.data;
}

/**
 * Report a dispense to the backend so the shared ledger accumulates.
 *
 * THIS IS THE JOIN THAT WAS MISSING. The desk display used to record a dispense
 * into the pharmacy's own SQLite and stop there, so the ledger every other
 * counter reads never learned it had happened — and the same prescription could
 * be filled again elsewhere with nothing to notice.
 *
 * No session is sent: the SIGNATURE is the authorisation (see the backend's
 * dispenseAppend.ts). The pharmacy's DID comes from it having been onboarded.
 */
export async function reportAppend(payload: {
  prescriptionId: string;
  quantity: number;
  dispenseId: string;
  dispensedAt: string;
  pharmacyDid: string;
  /** Who the dispense is about. Signed; the wallet reads its tokens by this. */
  holderDid: string;
  /**
   * The counter's own queue number. NOT signed: it is a display value, and two
   * pharmacies may each have a "token 1". The dispenseId is the protocol address.
   */
  queueToken?: number;
  signature: string;
}): Promise<{ recorded: boolean; dispensedTotal: number }> {
  const res = await fetch(`${BACKEND_URL}/api/pharmacy/appends`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    cache: 'no-store',
  });

  const body = (await res.json().catch(() => null)) as
    | { success?: boolean; data?: { recorded: boolean; dispensedTotal: number }; error?: { message?: string } }
    | null;

  if (!res.ok || !body?.success || !body.data) {
    throw new BackendError(
      body?.error?.message ?? `Recording the dispense failed with status ${res.status}.`,
      res.status,
    );
  }
  return body.data;
}

/** Ask the backend which DID belongs to this pharmacy's public key. */
export async function fetchMyDid(publicKeyMultibase: string): Promise<string | null> {
  const res = await fetch(
    `${BACKEND_URL}/api/pharmacy/identity?key=${encodeURIComponent(publicKeyMultibase)}`,
    { cache: 'no-store' },
  );
  if (!res.ok) return null;
  const body = (await res.json().catch(() => null)) as { data?: { did: string | null } } | null;
  return body?.data?.did ?? null;
}
