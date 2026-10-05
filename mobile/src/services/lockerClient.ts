/**
 * Direct wallet-to-locker object transport (OFFICER-DOCUMENT-ACCESS.md §2).
 * The bearer token comes from `apiService.walletLockerSession` — see
 * __docs__/frontend/WALLET-CUSTODY-NOTE.md for why the backend mints it.
 * No document bytes reach the backend from here.
 */
import Constants from 'expo-constants';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { secureStorage, STORAGE_KEYS } from './secureStorage';

export class LockerClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LockerClientError';
  }
}

/** Same probing shape as `resolveApiBase` in api.ts — see that function for why a list, not one hardcoded host. */

/**
 * Bases that have already answered. A resolved locker is remembered for the
 * life of the process so the probe does not run again at a moment when the app
 * may be suspended — see `probeFirstReachable` for why that matters.
 */
const resolvedBases = new Map<string, string>();

/**
 * First candidate that answers `/healthz`, or a refusal naming what was tried.
 *
 * THE TIMEOUT MUST NOT SPAN A SUSPENSION. A `setTimeout` abort counts
 * WALL-CLOCK time, not time spent working. When this runs while the JS thread
 * is parked behind a biometric prompt, the timer expires during the pause and
 * the abort fires the instant the app resumes — so a locker that is perfectly
 * healthy is reported unreachable. Measured 8 Sep 2026: enrolment failed with
 * "No keystore locker answered" while both lockers returned 200 on `/healthz`
 * from that same handset, seconds later.
 *
 * Two defences, because either alone is thin. An aborted attempt is RETRIED
 * once when the elapsed wall time overshot the budget, which is the signature
 * of a suspension rather than a slow network. And a base that answers is
 * cached, so the common path after the prompt does no I/O at all.
 */
async function probeFirstReachable(
  candidates: string[],
  timeoutMs: number,
  what: string,
): Promise<string> {
  const cached = resolvedBases.get(what);
  if (cached) return cached;


  const attempt = async (base: string): Promise<'ok' | 'suspended' | 'unreachable'> => {
    const startedAt = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`${base}/healthz`, { signal: controller.signal });
      return res.ok ? 'ok' : 'unreachable';
    } catch {
      // Overshooting the budget by a wide margin means the process was parked,
      // not that the host is slow. A genuinely unreachable host fails at or
      // near the timeout, never far beyond it.
      return Date.now() - startedAt > timeoutMs * 2 ? 'suspended' : 'unreachable';
    } finally {
      clearTimeout(timer);
    }
  };

  for (const base of candidates) {
    let verdict = await attempt(base);
    if (verdict === 'suspended') verdict = await attempt(base);
    if (verdict === 'ok') {
      resolvedBases.set(what, base);
      return base;
    }
  }
  throw new LockerClientError(
    `No ${what} answered. Tried: ${candidates.join(', ') || '(none configured)'}.`,
  );
}

/**
 * Forget a resolved base so the next call re-probes.
 *
 * A CACHED BASE THAT HAS STOPPED WORKING MUST NOT BE USED FOREVER. The cache had
 * no invalidation at all: the first reachable candidate won permanently, so a
 * handset that resolved `127.0.0.1` while a USB port-forward was up kept posting
 * there after the forward died, and every later call failed with a bare "Network
 * request failed" while a perfectly good LAN candidate sat next in the list.
 *
 * Measured 9 Sep: the datastore resolved over `adb reverse`, the cable
 * re-enumerated, and three consecutive submissions failed at `locker-session`
 * with the LAN address reachable the whole time.
 *
 * Called on a TRANSPORT failure only. A 4xx from the locker means we reached it
 * and it refused us, which is an answer — re-probing there would turn a clear
 * refusal into a confusing scan.
 */
export function forgetResolvedBase(what?: string): void {
  if (what) resolvedBases.delete(what);
  else resolvedBases.clear();
}

/** The KEYSTORE locker (role `keystore`), which holds recovery envelopes. */
export function keystoreCandidates(): string[] {
  const extra = (Constants.expoConfig?.extra ?? {}) as { keystoreLockerUrls?: string[] };
  return Array.isArray(extra.keystoreLockerUrls) ? extra.keystoreLockerUrls : [];
}

export async function resolveKeystoreBase(timeoutMs = 2500): Promise<string> {
  let list = keystoreCandidates();
  try {
    const host = await secureStorage.get(STORAGE_KEYS.SERVER_HOST);
    if (host && host.trim()) list = [`http://${host.trim()}:4541`, ...list];
  } catch {
    // fall through to the compiled-in list
  }
  return probeFirstReachable(list, timeoutMs, 'keystore locker');
}

/**
 * Where to look for a datastore, HOLDER'S OWN SERVER FIRST.
 *
 * The ministry locker is an option, never the only path — that is what keeps
 * this from being centralised storage with extra steps. A holder who has named
 * their own server is asking for their documents to live there, so it is tried
 * before anything shipped in the build, not merely alongside it.
 *
 * Async because the preference is in secure storage. Callers that cannot await
 * fall back to the built-in list, which is the previous behaviour exactly.
 */
export async function lockerCandidatesAsync(): Promise<string[]> {
  let own: string | null = null;
  try {
    // A host set in Settings applies to the lockers too: one address for the
    // whole deployment, so a build can be pointed at a new network in one edit.
    const host = await secureStorage.get(STORAGE_KEYS.SERVER_HOST);
    if (host && host.trim()) own = `http://${host.trim()}:4540`;
    if (!own) own = await secureStorage.get(STORAGE_KEYS.STORAGE_SERVER);
  } catch {
    // A storage fault must not make the locker unreachable; fall through to
    // the configured list rather than failing the whole submission.
  }
  const trimmed = own?.trim().replace(/\/$/, '') ?? '';
  return [...new Set([...(trimmed ? [trimmed] : []), ...lockerCandidates()])];
}

export function lockerCandidates(): string[] {
  const extra = Constants.expoConfig?.extra ?? {};
  const configured: string[] = Array.isArray(extra.datastoreLockerUrls) ? extra.datastoreLockerUrls : [];
  return [...new Set(configured)];
}

export async function resolveLockerBase(timeoutMs = 2500): Promise<string> {
  const candidates = await lockerCandidatesAsync();
  for (const base of candidates) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(`${base}/healthz`, { signal: controller.signal });
      clearTimeout(timer);
      if (res.ok) return base;
    } catch {
      // try the next candidate
    }
  }
  if (candidates.length === 0) {
    throw new LockerClientError(
      'No storage server is set. Choose one in Settings, or set your own address there.',
    );
  }
  return candidates[0];
}

function sha256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

/** PUT one object. Idempotent by design (same objectId + generation overwrites), so a retried upload after a failed later step is safe. */
export async function putLockerObject(
  lockerBaseUrl: string,
  token: string,
  objectId: string,
  bytes: Uint8Array,
  /**
   * File a handle pointer at this object, so a future handset can find it with
   * a phone number and a passphrase alone. Keystore only, and only ever on the
   * caller's own object — the locker enforces both.
   */
  recoveryHandle?: string,
): Promise<{ contentHash: string }> {
  const contentHash = sha256Hex(bytes);
  // RN's fetch accepts a typed array at runtime; the lib.dom BodyInit typing
  // this project compiles against does not list Uint8Array, only ArrayBuffer
  // — slice() copies into a plain ArrayBuffer, which satisfies both.
  const body = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const res = await fetch(`${lockerBaseUrl}/v1/objects/${encodeURIComponent(objectId)}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      'X-Locker-Object-Hash': contentHash,
      'Content-Type': 'application/octet-stream',
      ...(recoveryHandle ? { 'X-Locker-Recovery-Handle': recoveryHandle } : {}),
    },
    body,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new LockerClientError(
      `Storing '${objectId}' in the locker failed (status ${res.status}): ${JSON.stringify(body)}`,
    );
  }
  return { contentHash };
}

/**
 * Open a locker session by proving control of the DID's key ON THIS DEVICE.
 *
 * Replaces `apiService.walletLockerSession`, which asked the ISSUER's backend to
 * sign a holder challenge because the holder's key used to live there. It does
 * not any more, and a broker that signs for the holder is a custodian with extra
 * steps. The locker echoes a fully materialised `payloadTemplate`, so the wallet
 * signs exact bytes rather than reconstructing the canonical form.
 */
export async function openLockerSession(
  lockerBaseUrl: string,
  did: string,
  sign: (payload: Uint8Array) => Promise<string>,
): Promise<{ token: string; expiresAt: string }> {
  const challengeRes = await fetch(`${lockerBaseUrl}/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did }),
  });
  if (!challengeRes.ok) {
    const body = await challengeRes.text().catch(() => '');
    throw new LockerClientError(
      `The locker refused a challenge for '${did}' (status ${challengeRes.status}): ${body}`,
    );
  }
  const challenge = (await challengeRes.json()) as {
    nonce: string;
    payloadTemplate: string;
  };

  // `payloadTemplate` is a TEMPLATE, not the final bytes: the locker builds it
  // with `iat:0` and then reconstructs the payload with OUR `iat` to verify.
  // Signing it verbatim signs `iat:0` and the signature never matches.
  const issuedAtSeconds = Math.floor(Date.now() / 1000);
  const payload = challenge.payloadTemplate.replace(/iat:0\n?$/, `iat:${issuedAtSeconds}\n`);
  if (payload === challenge.payloadTemplate) {
    // Refuse rather than sign bytes we cannot account for. A silently
    // unsubstituted template produces a valid signature over the wrong
    // message, which reads as a key problem and is not one.
    throw new LockerClientError(
      "The locker's payload template did not end in 'iat:0' as expected, so this " +
        `wallet cannot fill in its issued-at. Template was: ${JSON.stringify(challenge.payloadTemplate)}`,
    );
  }

  const signature = await sign(new TextEncoder().encode(payload));

  const tokenRes = await fetch(`${lockerBaseUrl}/v1/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      nonce: challenge.nonce,
      signature,
      // `authentication` on the patient DID is exactly `<did>#key-1` (S-1 §8.1).
      verificationMethodId: `${did}#key-1`,
      iat: issuedAtSeconds,
    }),
  });
  if (!tokenRes.ok) {
    const body = await tokenRes.text().catch(() => '');
    throw new LockerClientError(
      `The locker rejected the signature for '${did}' (status ${tokenRes.status}): ${body}`,
    );
  }
  return (await tokenRes.json()) as { token: string; expiresAt: string };
}

/** Read one object back. Used to fetch the recovery envelope from the keystore. */
export async function getLockerObject(
  lockerBaseUrl: string,
  token: string,
  objectId: string,
): Promise<Uint8Array | null> {
  const res = await fetch(`${lockerBaseUrl}/v1/objects/${encodeURIComponent(objectId)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new LockerClientError(
      `Reading '${objectId}' from the locker failed (status ${res.status}): ${body}`,
    );
  }
  return new Uint8Array(await res.arrayBuffer());
}

/**
 * Fetch a recovery envelope by handle, with no session.
 *
 * This is the ONLY locker call that is unauthenticated, and it has to be: the
 * device asking has a phone number and a passphrase and nothing else, because
 * the key that would authenticate it is the key it is trying to recover.
 * Returns the DID alongside, since the caller cannot know it either.
 */
export async function fetchRecoveryEnvelopeByHandle(
  keystoreBaseUrl: string,
  handle: string,
): Promise<{ envelope: unknown; did: string } | null> {
  const res = await fetch(`${keystoreBaseUrl}/v1/recovery/envelope`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ handle }),
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new LockerClientError(
      `The keystore refused a recovery lookup (status ${res.status}): ${body}`,
    );
  }
  const payload = (await res.json()) as { envelope: string; did: string };
  return { envelope: JSON.parse(payload.envelope), did: payload.did };
}
