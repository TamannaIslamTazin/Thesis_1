/**
 * The officer's read capability (OFFICER-DOCUMENT-ACCESS.md §3).
 *
 * ===========================================================================
 * WHAT THIS VERIFIES, AND WHAT IT DOES NOT
 * ===========================================================================
 * A session token (`didAuth.ts`) proves who is CALLING. This module proves
 * that whoever is calling was GRANTED a specific, scoped read by the holder
 * whose objects those are. The two checks are independent and both required:
 * the route this feeds refuses a capability with no session, and refuses a
 * session with no valid capability.
 *
 * ===========================================================================
 * THE SIX STEPS, IN THE ORDER OFFICER-DOCUMENT-ACCESS.md §3 GIVES THEM
 * ===========================================================================
 *   1. signature against a verification method in the holder's resolved DID
 *      document
 *   2. `aud` equals the DID the caller authenticated as (via the session
 *      already established by `didAuth.ts` — no second authentication path)
 *   3. the window is current (and within the policy's own ceiling — see
 *      MAX_CAPABILITY_WINDOW_SECONDS in `@ssi-healthcare/shared`)
 *   4. `jti` is not revoked
 *   5. the requested object id appears in `obj`
 *   6. the object resolves under `HMAC(pepper, iss)`
 *
 * Refusal is checked in this order and stops at the first failure. Step 6 is
 * enforced by CONSTRUCTION rather than as a late assertion: every step above
 * it operates on `claims.iss` as a plain string, and the storage key is only
 * ever built from `HMAC(pepper, claims.iss)` computed HERE — never from a
 * subject reference the caller could supply. A capability naming another
 * holder's object id in `obj` still only ever resolves against ITS OWN
 * issuer's prefix, which is empty for an object it does not own, exactly as
 * `server.ts`'s own header note describes for session-based access:
 * cross-subject reach is not checked, it is unconstructable.
 *
 * ===========================================================================
 * WHY THE HTTP RESPONSE COLLAPSES EVERY ONE OF THESE INTO ONE SHAPE
 * ===========================================================================
 * OFFICER-DOCUMENT-ACCESS.md §6: "Every refusal returns the same shape and
 * does not distinguish 'no such object' from 'not permitted'." A capability
 * endpoint that answered differently for "bad signature" vs "object doesn't
 * exist" vs "wrong audience" would let a caller probe it — send capabilities
 * naming object ids they don't already know exist, and read the response
 * differences to enumerate another subject's objects one bit at a time. So
 * every one of the six failures below, AND a step-6-pass-but-object-absent
 * outcome checked by the caller in `server.ts`, produce the identical
 * `CAPABILITY_REFUSED` response.
 *
 * The one exception is RESOLVER_UNREACHABLE, kept distinct at 503 rather than
 * folded into the same 403. This is deliberate, not an oversight: it carries
 * no information about THIS capability, THIS object, or THIS subject — it
 * says the locker could not check anything at all, which is the same fact
 * regardless of who asked or what they asked for. Collapsing it into the
 * refusal shape would repeat the `didResolver.ts` mistake this codebase has
 * already named and fixed once (`cheqdLedger.ts`'s `isDefinitivelyNotFound`):
 * an outage would read to every officer as "every capability I hold is
 * invalid", which is false and would prompt exactly the wrong response.
 */

import { ed25519 } from '@noble/curves/ed25519';
import type { DatabaseSync } from 'node:sqlite';

import {
  canonicalCapabilityPayload,
  capabilitySignatureBytes,
  MAX_CAPABILITY_WINDOW_SECONDS,
  type LockerCapabilityClaims,
  type LockerCapabilityToken,
} from '@ssi-healthcare/shared/capability';

import { ed25519PublicKeyFromMultibase } from './didAuth.js';
import { authenticationKeyMultibase, resolveDid, type DidResolution } from './didResolver.js';
import { isCapabilityRevoked, subjectRef as computeSubjectRef } from './db.js';

export type CapabilityRefusalStep =
  | 'MALFORMED'
  | 'SIGNATURE'
  | 'AUDIENCE'
  | 'WINDOW'
  | 'REVOKED'
  | 'OBJECT_NOT_IN_SCOPE';

export type CapabilityOutcome =
  | { readonly ok: true; readonly holderSubjectRef: string; readonly claims: LockerCapabilityClaims }
  | {
      readonly ok: false;
      /** What the CALLER receives. Uniform across every step but resolver outage — see module header. */
      readonly httpStatus: number;
      readonly publicCode: string;
      /**
       * What actually failed, for the server's own logs only. Never put this
       * string in an HTTP response body — that would be the oracle §6 refuses
       * to be.
       */
      readonly step: CapabilityRefusalStep | 'RESOLVER_UNREACHABLE';
      readonly internalReason: string;
    };

const CAPABILITY_REFUSED = {
  httpStatus: 403,
  publicCode: 'CAPABILITY_REFUSED',
} as const;

function refuse(step: CapabilityRefusalStep, internalReason: string): CapabilityOutcome {
  return { ok: false, ...CAPABILITY_REFUSED, step, internalReason };
}

export interface VerifyCapabilityArgs {
  readonly token: unknown;
  /** The DID the caller authenticated as via the existing session (didAuth.ts). */
  readonly callerDid: string;
  readonly requestedObjectId: string;
  readonly resolverUrl: string;
  readonly resolverTimeoutMs: number;
  readonly db: DatabaseSync;
  readonly subjectPepper: string;
  /** Injectable for tests; defaults to the real clock. */
  readonly now?: Date;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Structural check only: is this even shaped like a capability token. This is
 * a caller-input-format problem, not a security judgement about a specific
 * object or subject, so it is refused with its own code (400) rather than
 * folded into the uniform `CAPABILITY_REFUSED` — the distinction here is
 * "your request is malformed", which reveals nothing about any subject's
 * data, versus "your capability was evaluated and failed", which the six
 * steps below deliberately keep uniform.
 */
function parseToken(token: unknown): LockerCapabilityToken | null {
  if (!isPlainObject(token)) return null;
  const { claims, signature, verificationMethodId } = token;
  if (!isPlainObject(claims)) return null;
  if (typeof signature !== 'string' || signature.length === 0) return null;
  if (typeof verificationMethodId !== 'string' || verificationMethodId.length === 0) return null;

  const { iss, aud, obj, sub, jti, nbf, exp } = claims as Record<string, unknown>;
  if (typeof iss !== 'string' || !iss.startsWith('did:')) return null;
  if (typeof aud !== 'string' || !aud.startsWith('did:')) return null;
  if (!Array.isArray(obj) || obj.length === 0 || !obj.every((id) => typeof id === 'string' && id.length > 0)) {
    return null;
  }
  if (typeof sub !== 'string' || sub.length === 0) return null;
  if (typeof jti !== 'string' || jti.length === 0) return null;
  if (typeof nbf !== 'number' || !Number.isFinite(nbf)) return null;
  if (typeof exp !== 'number' || !Number.isFinite(exp) || exp <= nbf) return null;

  return {
    claims: { iss, aud, obj: obj as string[], sub, jti, nbf, exp },
    signature,
    verificationMethodId,
  };
}

export async function verifyLockerCapability(args: VerifyCapabilityArgs): Promise<CapabilityOutcome> {
  const token = parseToken(args.token);
  if (!token) {
    return {
      ok: false,
      httpStatus: 400,
      publicCode: 'CAPABILITY_MALFORMED',
      step: 'MALFORMED',
      internalReason: 'request body is not a well-formed capability token',
    };
  }
  const { claims } = token;

  // -------------------------------------------------------------- step 1 --
  // Signature against a verification method in the HOLDER's resolved DID
  // document. The holder is `claims.iss`, never the caller.
  let resolution: DidResolution;
  try {
    resolution = await resolveDid(claims.iss, args.resolverUrl, args.resolverTimeoutMs);
  } catch (error) {
    return {
      ok: false,
      httpStatus: 503,
      publicCode: 'CAPABILITY_VERIFICATION_UNAVAILABLE',
      step: 'RESOLVER_UNREACHABLE',
      internalReason: `DID resolution threw: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  if (resolution.outcome === 'UNREACHABLE') {
    return {
      ok: false,
      httpStatus: 503,
      publicCode: 'CAPABILITY_VERIFICATION_UNAVAILABLE',
      step: 'RESOLVER_UNREACHABLE',
      internalReason: resolution.detail,
    };
  }
  if (resolution.outcome === 'NOT_FOUND') {
    return refuse('SIGNATURE', `iss '${claims.iss}' does not resolve: ${resolution.detail}`);
  }
  const document = resolution.document;
  if (document.deactivated) {
    return refuse('SIGNATURE', `iss '${claims.iss}' is DEACTIVATED`);
  }
  const multibase = authenticationKeyMultibase(document, token.verificationMethodId);
  if (!multibase) {
    return refuse(
      'SIGNATURE',
      `'${token.verificationMethodId}' is not an authentication key on '${claims.iss}'`,
    );
  }
  let publicKey: Uint8Array;
  try {
    publicKey = ed25519PublicKeyFromMultibase(multibase);
  } catch (error) {
    return refuse('SIGNATURE', error instanceof Error ? error.message : String(error));
  }
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = capabilitySignatureBytes(token);
  } catch (error) {
    return refuse(
      'SIGNATURE',
      `signature is not decodable base64url: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const payload = canonicalCapabilityPayload(claims);
  let verified = false;
  try {
    verified = ed25519.verify(signatureBytes, payload, publicKey);
  } catch {
    verified = false;
  }
  if (!verified) {
    return refuse('SIGNATURE', 'signature does not verify against the resolved authentication key');
  }

  // -------------------------------------------------------------- step 2 --
  // `aud` must equal the DID the caller authenticated as. This is the ONLY
  // place the caller's own identity enters the check — everything above is
  // about the holder, everything below is about the capability's own claims.
  if (claims.aud !== args.callerDid) {
    return refuse(
      'AUDIENCE',
      `claims.aud '${claims.aud}' does not match the authenticated caller '${args.callerDid}'`,
    );
  }

  // -------------------------------------------------------------- step 3 --
  // The window is current, and does not exceed the policy ceiling. The
  // ceiling is re-checked here rather than trusted from the wallet: a locker
  // that only checked "is now within [nbf, exp]" would honour whatever window
  // a compromised or buggy minting path wrote, however long.
  const nowSeconds = Math.floor((args.now ?? new Date()).getTime() / 1000);
  if (nowSeconds < claims.nbf || nowSeconds >= claims.exp) {
    return refuse(
      'WINDOW',
      `now=${nowSeconds} is outside [nbf=${claims.nbf}, exp=${claims.exp})`,
    );
  }
  if (claims.exp - claims.nbf > MAX_CAPABILITY_WINDOW_SECONDS) {
    return refuse(
      'WINDOW',
      `window of ${claims.exp - claims.nbf}s exceeds the ${MAX_CAPABILITY_WINDOW_SECONDS}s policy ceiling`,
    );
  }

  // -------------------------------------------------------------- step 4 --
  // `jti` is not revoked. Scoped to the holder's own subjectRef: only a
  // session authenticated as `claims.iss` can have written this revocation
  // (see `revokeCapability` in db.ts and its call site in server.ts), so
  // looking it up under `HMAC(pepper, iss)` is itself part of what makes
  // revocation an act only the holder can perform.
  const holderSubjectRef = computeSubjectRef(claims.iss, args.subjectPepper);
  if (isCapabilityRevoked(args.db, holderSubjectRef, claims.jti)) {
    return refuse('REVOKED', `jti '${claims.jti}' is revoked`);
  }

  // -------------------------------------------------------------- step 5 --
  if (!claims.obj.includes(args.requestedObjectId)) {
    return refuse(
      'OBJECT_NOT_IN_SCOPE',
      `requested object '${args.requestedObjectId}' is not in claims.obj`,
    );
  }

  // -------------------------------------------------------------- step 6 --
  // The object resolves under HMAC(pepper, iss) — computed above, and it is
  // the ONLY subjectRef this function ever returns. There is no code path
  // here that could return a subjectRef derived from anything else, which is
  // what makes cross-subject reach unconstructable rather than merely
  // checked. The caller (server.ts) still has to actually attempt the S3
  // read under this subjectRef and refuse identically if that read 404s —
  // this function only proves WHICH prefix is the right one to look under.
  return { ok: true, holderSubjectRef, claims };
}
