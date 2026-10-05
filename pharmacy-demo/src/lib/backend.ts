/**
 * The pharmacy's server-side link to the BDHealthTrust backend.
 *
 * WHY A SESSION TOKEN SITS IN ENV, AND WHAT IT STANDS IN FOR.
 * `POST /oid4vp/authorization-request` is behind `requireAuth`, because asking a
 * holder to present credentials is an act an accountable party performs, not an
 * anonymous one.
 *
 * THIS COMMENT USED TO SAY the pharmacy would "sign in with SSI" (OID4VP) and
 * get its session that way. THAT DECISION CHANGED on 24 Sep 2026: a pharmacy is
 * verified PHYSICALLY — an L1 officer visits the premises and onboards the
 * institution through the issuer console (see
 * misc/design-reviews/L2-ONBOARDING-NOTE.md). Wallet-based verification of a
 * pharmacy was dropped precisely because an entity with premises cannot be
 * established by a credential alone.
 *
 * So the session token here remains a stand-in, but for a DIFFERENT missing
 * piece than before: not "SSI login is unbuilt", but "the onboarding flow now
 * exists and this demo has not yet paired". Once it pairs, its identity is the
 * institutional DID minted at onboarding, and the session should derive from
 * that rather than from a provisioned token.
 *
 * The token NEVER reaches the browser. Every call that uses it happens in a
 * route handler on this server; the page only ever receives a QR payload and a
 * verification result.
 */

export const BACKEND_URL = process.env.BACKEND_URL ?? 'http://127.0.0.1:3001';

/** Stand-in for the L2 institution session. See the note above. */
const SESSION_TOKEN = process.env.PHARMACY_SESSION_TOKEN ?? '';

/** This deployment's verifier identity — the audience every presentation names. */
export const VERIFIER_DID =
  process.env.PHARMACY_VERIFIER_DID ??
  'did:cheqd:bdhealthtestnet:9f2b1c44-6d0e-4a7b-8c31-5e0a7d21b6f4';

export class BackendError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'BackendError';
  }
}

export async function backend<T>(
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<T> {
  if (!SESSION_TOKEN) {
    throw new BackendError(
      'PHARMACY_SESSION_TOKEN is not set. Run scripts/provision-session.mjs and put the ' +
        'token in .env.local — this demo cannot ask the backend for anything without a session.',
      500,
    );
  }

  const res = await fetch(`${BACKEND_URL}${path}`, {
    method: init.method ?? 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${SESSION_TOKEN}`,
    },
    ...(init.body ? { body: JSON.stringify(init.body) } : {}),
    cache: 'no-store',
  });

  const text = await res.text();
  let parsed: unknown = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    throw new BackendError(`Backend returned a non-JSON body (${res.status}): ${text.slice(0, 200)}`, res.status);
  }

  const body = parsed as { success?: boolean; data?: T; error?: { message?: string } };
  if (!res.ok || body?.success === false) {
    throw new BackendError(body?.error?.message ?? `Backend answered ${res.status}`, res.status);
  }
  return body.data as T;
}
