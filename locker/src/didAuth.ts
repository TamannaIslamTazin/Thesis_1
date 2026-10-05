/**
 * DID challenge-response (#340 ruling 2).
 *
 * ===========================================================================
 * WHAT IS SIGNED, AND WHY IT IS NOT THE BARE NONCE
 * ===========================================================================
 * The wallet signs a CANONICAL STRUCTURED PAYLOAD, not the nonce alone:
 *
 *     bdhealthtrust/locker-auth/v1
 *     aud:<this locker's audience id>
 *     did:<the subject DID>
 *     nonce:<the server-issued nonce>
 *     iat:<unix seconds>
 *
 * The `aud` line is the load-bearing one, and it is load-bearing BECAUSE OF
 * THE ARCHITECTURE: #340 deliberately makes lockers plural — a user may run
 * their own, or use a ministry cluster, or both. A bare-nonce signature would
 * be a bearer credential valid at any locker that happened to issue the same
 * nonce, and "happened to" is not a security argument. Binding the audience
 * makes a signature captured at locker A structurally useless at locker B,
 * including a malicious locker B that harvested it on purpose.
 *
 * ===========================================================================
 * WHY THE NONCE IS OURS
 * ===========================================================================
 * A nonce the presenter supplies is not a nonce. It is generated here, stored
 * here, and spent here — `professionalChallenge.ts` states the same rule, and
 * the compare-and-swap in `db.ts:consumeChallenge` is what makes single use a
 * claim rather than a hope.
 *
 * ===========================================================================
 * WHAT A CAPTURED SIGNATURE BUYS AN ATTACKER: NOTHING
 * ===========================================================================
 *   - the nonce is already SPENT, so the CAS fails and the replay is refused
 *   - the TTL is 120 seconds, so even an unspent capture ages out fast
 *   - the `aud` binds it to one locker
 *   - the `did` binds it to one subject, so it cannot be replayed as someone else
 *
 * WHAT IT DOES NOT COVER, STATED PLAINLY: the session token issued after a
 * successful exchange IS a bearer token, and a stolen one is replayable for
 * its lifetime. That is why the token authorises reads and listings only, and
 * why every WRITE carries its own signature over the object it writes (see
 * server.ts). A single short-lived bearer token is a smaller thing to steal
 * than a write capability.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';

import {
  authenticationKeyMultibase,
  resolveDid,
  type DidResolution,
} from './didResolver.js';
import { LockerError } from './db.js';

/** Long enough to tap approve, not long enough to shop around. */
export const CHALLENGE_TTL_MS = 120 * 1000;

const AUTH_PAYLOAD_DOMAIN = 'bdhealthtrust/locker-auth/v1';

/** `z` + base58btc, and the multicodec that says "this is Ed25519". */
const MULTIBASE_BASE58BTC_PREFIX = 'z';
const ED25519_MULTICODEC_PREFIX = Uint8Array.from([0xed, 0x01]);
const ED25519_RAW_KEY_LENGTH = 32;

export function generateNonce(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * The exact bytes the wallet must sign. Built here and never accepted from the
 * caller — a payload the client supplies is a payload the client controls.
 */
export function authPayload(args: {
  audience: string;
  did: string;
  nonce: string;
  issuedAtSeconds: number;
}): Uint8Array {
  const canonical =
    `${AUTH_PAYLOAD_DOMAIN}\n` +
    `aud:${args.audience}\n` +
    `did:${args.did}\n` +
    `nonce:${args.nonce}\n` +
    `iat:${args.issuedAtSeconds}\n`;
  return new TextEncoder().encode(canonical);
}

/**
 * Decode a `publicKeyMultibase` into a raw Ed25519 key.
 *
 * The multicodec prefix is VERIFIED, not skipped. A document carrying an
 * X25519 key under an Ed25519 verification-method type would otherwise be
 * truncated into 32 bytes of something else, and the later `verify` would
 * return false for a reason that looks like a bad signature rather than a bad
 * key — a misdiagnosis that could take days. Same check as
 * `cheqdDidShapes.ts:ed25519PublicKeyFromMultibase`.
 */
export function ed25519PublicKeyFromMultibase(publicKeyMultibase: string): Uint8Array {
  if (!publicKeyMultibase.startsWith(MULTIBASE_BASE58BTC_PREFIX)) {
    throw new LockerError(
      `publicKeyMultibase '${publicKeyMultibase}' is not base58btc multibase (no 'z' prefix). ` +
        'Refusing to guess the encoding.',
      400,
      'BAD_KEY_ENCODING',
    );
  }

  let decoded: Uint8Array;
  try {
    decoded = base58.decode(publicKeyMultibase.slice(MULTIBASE_BASE58BTC_PREFIX.length));
  } catch (error) {
    throw new LockerError(
      `publicKeyMultibase '${publicKeyMultibase}' is not decodable base58: ${
        error instanceof Error ? error.message : String(error)
      }`,
      400,
      'BAD_KEY_ENCODING',
    );
  }

  if (
    decoded.length !== ED25519_MULTICODEC_PREFIX.length + ED25519_RAW_KEY_LENGTH ||
    decoded[0] !== ED25519_MULTICODEC_PREFIX[0] ||
    decoded[1] !== ED25519_MULTICODEC_PREFIX[1]
  ) {
    throw new LockerError(
      `publicKeyMultibase '${publicKeyMultibase}' does not carry the Ed25519 multicodec prefix ` +
        `ed01 followed by ${ED25519_RAW_KEY_LENGTH} bytes; it decoded to ${decoded.length} ` +
        `bytes starting ${Buffer.from(decoded.slice(0, 2)).toString('hex')}. Refusing to guess ` +
        'at the key type.',
      400,
      'BAD_KEY_TYPE',
    );
  }

  return decoded.slice(ED25519_MULTICODEC_PREFIX.length);
}

export type AuthOutcome =
  | { readonly ok: true; readonly did: string }
  | { readonly ok: false; readonly httpStatus: number; readonly code: string; readonly reason: string };

/**
 * Verify a signed challenge response against the DID document.
 *
 * FAILS CLOSED ON EVERY UNCERTAINTY, and distinguishes the reasons because
 * they mean different things operationally:
 *
 *   UNREACHABLE  -> 503. We do not know. Retry later; nothing is wrong with you.
 *   NOT_FOUND    -> 404. Authoritative: no such DID.
 *   DEACTIVATED  -> 409. Terminal; `x/did` has no revival path.
 *   key not in `authentication` -> 403. The key exists but may not act as the DID.
 *   bad signature -> 401.
 *
 * Collapsing these would be the cheqdLedger.ts mistake: a stopped validator
 * would tell every user their identity does not exist.
 */
export async function verifySignedChallenge(args: {
  did: string;
  audience: string;
  nonce: string;
  issuedAtSeconds: number;
  verificationMethodId: string;
  signatureBase64Url: string;
  resolverUrl: string;
  resolverTimeoutMs: number;
}): Promise<AuthOutcome> {
  let resolution: DidResolution;
  try {
    resolution = await resolveDid(args.did, args.resolverUrl, args.resolverTimeoutMs);
  } catch (error) {
    return {
      ok: false,
      httpStatus: 503,
      code: 'RESOLVER_UNREACHABLE',
      reason: `DID resolution threw: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  if (resolution.outcome === 'UNREACHABLE') {
    // Never a cache fallback. A stale document would let a key that has been
    // rotated away from a stolen device keep working.
    return {
      ok: false,
      httpStatus: 503,
      code: 'RESOLVER_UNREACHABLE',
      reason: resolution.detail,
    };
  }

  if (resolution.outcome === 'NOT_FOUND') {
    return { ok: false, httpStatus: 404, code: 'DID_NOT_FOUND', reason: resolution.detail };
  }

  const document = resolution.document;

  if (document.deactivated) {
    return {
      ok: false,
      httpStatus: 409,
      code: 'DID_DEACTIVATED',
      reason: `'${args.did}' is DEACTIVATED. Deactivation is terminal — no signature can help.`,
    };
  }

  const multibase = authenticationKeyMultibase(document, args.verificationMethodId);
  if (!multibase) {
    return {
      ok: false,
      httpStatus: 403,
      code: 'KEY_NOT_AUTHORISED',
      reason:
        `'${args.verificationMethodId}' is not listed under this DID's \`authentication\` ` +
        'relationship. A key that the document merely CONTAINS is not a key the DID says ' +
        'may act as it.',
    };
  }

  let publicKey: Uint8Array;
  try {
    publicKey = ed25519PublicKeyFromMultibase(multibase);
  } catch (error) {
    return {
      ok: false,
      httpStatus: 400,
      code: 'BAD_KEY',
      reason: error instanceof Error ? error.message : String(error),
    };
  }

  let signature: Uint8Array;
  try {
    signature = Buffer.from(args.signatureBase64Url, 'base64url');
  } catch {
    return { ok: false, httpStatus: 400, code: 'BAD_SIGNATURE_ENCODING', reason: 'signature is not base64url' };
  }

  const payload = authPayload({
    audience: args.audience,
    did: args.did,
    nonce: args.nonce,
    issuedAtSeconds: args.issuedAtSeconds,
  });

  let verified = false;
  try {
    verified = ed25519.verify(signature, payload, publicKey);
  } catch {
    // A malformed signature makes noble throw rather than return false. Both
    // are the same answer to the caller and neither is distinguished for them.
    verified = false;
  }

  if (!verified) {
    return {
      ok: false,
      httpStatus: 401,
      code: 'BAD_SIGNATURE',
      reason: 'the signature does not verify against the authentication key in the DID document',
    };
  }

  return { ok: true, did: args.did };
}

// ---------------------------------------------------------------------------
// Session tokens
// ---------------------------------------------------------------------------

/**
 * Session tokens are random and looked up, never self-describing.
 *
 * A signed/HMAC'd token would let this process validate without state, which
 * sounds attractive until a key has to be revoked before its expiry — at which
 * point statelessness is precisely the property preventing it. Sessions are
 * few and short; a map lookup costs nothing.
 */
export interface Session {
  readonly did: string;
  readonly expiresAtMs: number;
}

export const SESSION_TTL_MS = 10 * 60 * 1000;

export class SessionStore {
  private readonly sessions = new Map<string, Session>();

  issue(did: string): { token: string; expiresAt: string } {
    const token = randomBytes(32).toString('base64url');
    const expiresAtMs = Date.now() + SESSION_TTL_MS;
    this.sessions.set(hashToken(token), { did, expiresAtMs });
    return { token, expiresAt: new Date(expiresAtMs).toISOString() };
  }

  /** Returns the DID this token speaks for, or null. Expired tokens are evicted on read. */
  resolve(token: string | undefined): string | null {
    if (!token) return null;
    const key = hashToken(token);
    const session = this.sessions.get(key);
    if (!session) return null;
    if (session.expiresAtMs <= Date.now()) {
      this.sessions.delete(key);
      return null;
    }
    return session.did;
  }

  /** Bounded growth: sessions are small, but unbounded is unbounded. */
  prune(): number {
    const now = Date.now();
    let removed = 0;
    for (const [key, session] of this.sessions) {
      if (session.expiresAtMs <= now) {
        this.sessions.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  get size(): number {
    return this.sessions.size;
  }
}

/**
 * Tokens are stored hashed so that a memory dump or a heap snapshot does not
 * hand over live credentials. Cheap, and the reason is the same one that keeps
 * password hashes out of memory in plaintext.
 */
function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** Constant-time compare for any secret equality check at this boundary. */
export function secretEquals(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a, 'utf8').digest();
  const hb = createHash('sha256').update(b, 'utf8').digest();
  return timingSafeEqual(ha, hb);
}
