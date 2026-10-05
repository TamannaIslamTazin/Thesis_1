/**
 * DID challenge-response login (AUTH-AND-KEYSTORE-API.md §1).
 *
 * ===========================================================================
 * THE PATTERN IS SHARED. THE CODE IS NOT — AND HERE IS WHY
 * ===========================================================================
 * `packages/locker/src/didAuth.ts` already implements the design this endpoint
 * pair needs: a canonical, domain-separated payload naming `aud`/`did`/`nonce`/
 * `iat`, a nonce that is generated, stored and spent by this side only, single
 * use by compare-and-swap, and a resolution outcome that never collapses
 * "unreachable" into "not found". That file's header is the read-first
 * reference the round brief points at, and every one of those properties is
 * reproduced below.
 *
 * It is reproduced rather than imported for two separate reasons:
 *
 *   1. STORAGE. Locker keeps its challenge table in a `node:sqlite` file
 *      because it is a small, single-process, self-hostable service. This
 *      backend already has Postgres via Prisma, and running two databases
 *      for one nonce table would be the second, divergent implementation the
 *      brief warns against, just moved one layer down.
 *
 *   2. RESOLUTION. Locker resolves DIDs over plain HTTP + `@noble/curves`
 *      specifically BECAUSE it must not embed a Credo agent — its own
 *      config.ts says embedding one "in a container a user self-hosts would
 *      be indefensible". This backend already embeds one, and already has a
 *      stronger property available: `resolveOnChain` in `cheqdLedger.ts` reads
 *      the chain's query service directly, never Credo's local cache, which
 *      matters more here than anywhere else in this codebase — a cache
 *      fallback at LOGIN would let a key rotated away from a stolen device
 *      keep authenticating.
 *
 * ===========================================================================
 * WHY A DIFFERENT DOMAIN STRING FROM THE LOCKER'S
 * ===========================================================================
 * `aud` is supposed to stop a signature captured at one service from working
 * at another, but that property would otherwise depend entirely on an
 * operator never reusing an audience string across a locker deployment and a
 * backend deployment. A distinct domain tag (`bdhealthtrust/backend-auth/v1`
 * vs. locker's `bdhealthtrust/locker-auth/v1`) removes that dependency: even
 * an accidental audience collision leaves the two canonical payloads
 * byte-different, so a signature valid at one is not merely mis-scoped at the
 * other — it does not parse as the same message at all.
 */

import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import type { Agent } from '@credo-ts/core';
import { ed25519PublicKeyFromMultibase } from '@ssi-healthcare/sdk/ledger';
import { ERROR_CODES } from '@ssi-healthcare/shared';

import { db } from '../db/index.js';
import { resolveOnChain, type ResolvedCheqdDid } from './cheqdLedger.js';

/** Long enough to tap approve, not long enough to shop around — same figure locker uses. */
export const CHALLENGE_TTL_MS = 120 * 1000;

const AUTH_PAYLOAD_DOMAIN = 'bdhealthtrust/backend-auth/v1';

export function generateNonce(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * The exact bytes the wallet must sign. Built here and never accepted from the
 * caller — a payload the client supplies is a payload the client controls.
 *
 * NO `iat` LINE, UNLIKE LOCKER'S PAYLOAD. AUTH-AND-KEYSTORE-API.md §1 documents
 * a three-field request body (`did`, `nonce`, `signature`) with no signing
 * timestamp and no verification-method hint, so this payload carries exactly
 * what that contract has room for. Freshness and replay-prevention do not
 * depend on `iat` — they come from the nonce's 120-second TTL and its
 * single-use compare-and-swap, which is the same thing locker's own docblock
 * says: "a captured signature buys an attacker nothing" because the nonce is
 * spent and short-lived, not because of anything `iat` adds. Dropping it here
 * is a deliberate simplification against the documented contract, not an
 * oversight.
 */
export function authPayload(args: {
  readonly audience: string;
  readonly did: string;
  readonly nonce: string;
}): Uint8Array {
  const canonical =
    `${AUTH_PAYLOAD_DOMAIN}\n` +
    `aud:${args.audience}\n` +
    `did:${args.did}\n` +
    `nonce:${args.nonce}\n`;
  return new TextEncoder().encode(canonical);
}

// ---------------------------------------------------------------------------
// Challenge store — a Prisma-backed implementation, and the interface a fast
// test can substitute so the compare-and-swap property is provable without a
// live Postgres.
// ---------------------------------------------------------------------------

export interface StoredChallenge {
  readonly did: string;
  readonly audience: string;
  readonly state: 'ISSUED' | 'SPENT' | 'EXPIRED';
  readonly expiresAt: Date;
}

export interface ChallengeStore {
  create(args: { nonce: string; did: string; audience: string; expiresAt: Date }): Promise<void>;
  findByNonce(nonce: string): Promise<StoredChallenge | null>;
  /** Atomically moves the row from ISSUED to SPENT. Resolves true iff THIS call won the race. */
  trySpend(nonce: string): Promise<boolean>;
  /** Best-effort bookkeeping; a refusal never depends on this landing. */
  markExpired(nonce: string): Promise<void>;
}

export const prismaChallengeStore: ChallengeStore = {
  async create(args) {
    await db.authChallenge.create({
      data: { nonce: args.nonce, did: args.did, audience: args.audience, expiresAt: args.expiresAt },
    });
  },
  async findByNonce(nonce) {
    const row = await db.authChallenge.findUnique({ where: { nonce } });
    if (!row) return null;
    return { did: row.did, audience: row.audience, state: row.state, expiresAt: row.expiresAt };
  },
  async trySpend(nonce) {
    const claimed = await db.authChallenge.updateMany({
      where: { nonce, state: 'ISSUED' },
      data: { state: 'SPENT' },
    });
    return claimed.count === 1;
  },
  async markExpired(nonce) {
    await db.authChallenge
      .updateMany({ where: { nonce, state: 'ISSUED' }, data: { state: 'EXPIRED' } })
      .catch(() => undefined);
  },
};

export interface IssuedChallenge {
  readonly nonce: string;
  readonly audience: string;
  readonly expiresAt: string;
  /**
   * The exact template the wallet must fill in and sign, `iat` aside. Echoed
   * so a wallet implementation cannot guess the canonical form wrong — the
   * same reason locker's `/v1/auth/challenge` echoes it.
   */
  readonly payloadTemplate: string;
}

export async function issueChallenge(
  did: string,
  audience: string,
  store: ChallengeStore = prismaChallengeStore,
): Promise<IssuedChallenge> {
  const nonce = generateNonce();
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
  await store.create({ nonce, did, audience, expiresAt });
  return {
    nonce,
    audience,
    expiresAt: expiresAt.toISOString(),
    payloadTemplate: new TextDecoder().decode(authPayload({ audience, did, nonce })),
  };
}

export type ChallengeConsumption =
  | { readonly ok: true; readonly did: string; readonly audience: string }
  | { readonly ok: false; readonly reason: string };

/**
 * Spend a challenge, atomically.
 *
 * SINGLE USE BY COMPARE-AND-SWAP: `store.trySpend` moves the row out of ISSUED
 * in one conditional update, and only the caller that observes `true` may
 * proceed. Two requests racing the same captured signature cannot both win —
 * a read-then-write could never promise that, because the other request fits
 * between the read and the write.
 */
export async function consumeChallenge(
  nonce: string,
  store: ChallengeStore = prismaChallengeStore,
): Promise<ChallengeConsumption> {
  const row = await store.findByNonce(nonce);
  if (!row) return { ok: false, reason: 'unknown challenge' };

  if (row.expiresAt <= new Date()) {
    await store.markExpired(nonce);
    return { ok: false, reason: 'challenge expired' };
  }

  const won = await store.trySpend(nonce);
  if (!won) {
    return { ok: false, reason: `challenge already ${row.state.toLowerCase()}` };
  }

  return { ok: true, did: row.did, audience: row.audience };
}

// ---------------------------------------------------------------------------
// Signature verification against an already-resolved document
// ---------------------------------------------------------------------------

/** The subset of a resolved DID document this module needs. */
export interface DidAuthDocument {
  readonly authentication: readonly string[];
  readonly verificationMethod: readonly { readonly id: string; readonly publicKeyMultibase: string }[];
}

/** Resolve one `authentication` entry to its verification method, matching by absolute or fragment id. */
function resolveAuthenticationMethod(
  did: string,
  document: DidAuthDocument,
  authenticationEntry: string,
): { readonly id: string; readonly publicKeyMultibase: string } | null {
  const absolute = authenticationEntry.startsWith('#')
    ? `${did}${authenticationEntry}`
    : authenticationEntry;
  return (
    document.verificationMethod.find(
      (candidate) => candidate.id === absolute || candidate.id === authenticationEntry,
    ) ?? null
  );
}

export type DidLoginOutcome =
  | { readonly ok: true; readonly did: string }
  | { readonly ok: false; readonly httpStatus: number; readonly code: string; readonly reason: string };

/**
 * Verify a signed challenge response against an ALREADY-RESOLVED document.
 *
 * Split out from {@link verifySignedDidLogin} so the cryptographic check —
 * the part with no network or chain dependency — is unit-testable against a
 * hand-built document and a locally generated key pair.
 *
 * NO CLIENT-SUPPLIED `verificationMethodId`, on purpose: the round brief and
 * AUTH-AND-KEYSTORE-API.md both say "verify against A verification method in
 * the resolved DID document", not one the caller names. Every id listed under
 * `authentication` is tried in turn; the first that verifies wins. A document
 * with one authentication key — the common case here — costs one verify
 * attempt. This does not weaken anything a named-key design would have
 * checked: whichever key the caller signed with still has to be listed under
 * `authentication` and still has to produce a valid signature over the exact
 * canonical payload.
 */
export function verifySignatureAgainstDocument(args: {
  readonly document: DidAuthDocument;
  readonly did: string;
  readonly audience: string;
  readonly nonce: string;
  readonly signatureBase64Url: string;
}): DidLoginOutcome {
  if (args.document.authentication.length === 0) {
    return {
      ok: false,
      httpStatus: 403,
      code: ERROR_CODES.AUTH_FORBIDDEN,
      reason: `'${args.did}' names no authentication verification method. Nothing can sign for it.`,
    };
  }

  let signature: Uint8Array;
  try {
    signature = Buffer.from(args.signatureBase64Url, 'base64url');
  } catch {
    return {
      ok: false,
      httpStatus: 400,
      code: ERROR_CODES.VALIDATION_FAILED,
      reason: 'signature is not valid base64url',
    };
  }

  const payload = authPayload({ audience: args.audience, did: args.did, nonce: args.nonce });

  const skipped: string[] = [];
  for (const entry of args.document.authentication) {
    const method = resolveAuthenticationMethod(args.did, args.document, entry);
    if (!method) {
      skipped.push(`${entry}: no matching verificationMethod entry`);
      continue;
    }

    let publicKey: Uint8Array;
    try {
      publicKey = ed25519PublicKeyFromMultibase(method.publicKeyMultibase);
    } catch (error) {
      skipped.push(`${entry}: ${error instanceof Error ? error.message : String(error)}`);
      continue;
    }

    let verified = false;
    try {
      verified = ed25519.verify(signature, payload, publicKey);
    } catch {
      // A malformed signature makes noble throw rather than return false. Both
      // are the same answer to the caller, and neither is distinguished for them.
      verified = false;
    }

    if (verified) {
      return { ok: true, did: args.did };
    }
  }

  return {
    ok: false,
    httpStatus: 401,
    code: ERROR_CODES.AUTH_FAILED,
    reason:
      `the signature did not verify against any of ${args.document.authentication.length} ` +
      `authentication key(s) on '${args.did}'` +
      (skipped.length > 0 ? ` (${skipped.length} unusable: ${skipped.join('; ')})` : ''),
  };
}

/**
 * The full flow: resolve on chain, then verify.
 *
 * FAILS CLOSED ON EVERY UNCERTAINTY, distinguished because they mean different
 * things operationally — same discipline as locker's `verifySignedChallenge`:
 *
 *   DID_RESOLVER_UNREACHABLE -> 503. We do not know. Retry later.
 *   DID_NOT_FOUND            -> 404. Authoritative: no such DID on chain.
 *   DID_DEACTIVATED          -> 409. Terminal; `x/did` has no revival path.
 *   key not an authentication method -> 403.
 *   bad signature            -> 401.
 */
export async function verifySignedDidLogin(args: {
  readonly agent: Agent;
  readonly did: string;
  readonly audience: string;
  readonly nonce: string;
  readonly signatureBase64Url: string;
}): Promise<DidLoginOutcome> {
  let resolved: ResolvedCheqdDid | null;
  try {
    resolved = await resolveOnChain(args.agent, args.did);
  } catch (error) {
    return {
      ok: false,
      httpStatus: 503,
      code: ERROR_CODES.DID_RESOLVER_UNREACHABLE,
      reason: `The chain query service did not answer: ${
        error instanceof Error ? error.message : String(error)
      }. This is NOT evidence that '${args.did}' does not exist.`,
    };
  }

  if (!resolved) {
    return {
      ok: false,
      httpStatus: 404,
      code: ERROR_CODES.DID_NOT_FOUND,
      reason: `The chain returns no DID document for '${args.did}'.`,
    };
  }

  if (resolved.deactivated) {
    return {
      ok: false,
      httpStatus: 409,
      code: ERROR_CODES.DID_DEACTIVATED,
      reason: `'${args.did}' is DEACTIVATED. Deactivation is terminal — no signature can help.`,
    };
  }

  return verifySignatureAgainstDocument({
    document: resolved,
    did: args.did,
    audience: args.audience,
    nonce: args.nonce,
    signatureBase64Url: args.signatureBase64Url,
  });
}
