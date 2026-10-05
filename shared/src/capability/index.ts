/**
 * The officer's read capability (OFFICER-DOCUMENT-ACCESS.md §3).
 *
 * ===========================================================================
 * WHAT THIS CLOSES
 * ===========================================================================
 * Round 3 released the wrapped content key to an officer but gave them no way
 * to fetch the ciphertext it opens: the locker addresses objects by
 * `HMAC(pepper, holderDid)`, and an officer authenticating as the authority
 * computes a different subjectRef. This module is the one place that builds
 * — and, on the locker side, re-derives — the bytes a holder signs to grant a
 * named authority a time-bounded, object-scoped read.
 *
 * ===========================================================================
 * WHY THE CONSTRUCTION LIVES HERE AND NOT IN THE WALLET OR THE LOCKER
 * ===========================================================================
 * Two parties have to agree on the exact byte layout that gets signed: the
 * wallet, which signs it, and the locker, which re-derives it from the claims
 * it was handed and checks the signature against that re-derivation. If each
 * built its own version of "the canonical bytes", a change to one and not the
 * other would silently break every capability without a code diff that looks
 * suspicious — the same failure mode `keyEnvelope.ts` and the disclosure
 * module in this package already guard against for their own claims. One
 * function, imported by both, is what makes drift a compile error rather than
 * a field incident.
 *
 * ===========================================================================
 * CANONICALISATION: ONE FIELD PER LINE, NO SEPARATOR AMBIGUITY
 * ===========================================================================
 * `didAuth.ts` in the locker signs `key:value\n` lines rather than JSON, and
 * this module follows the same shape for the same reason: it avoids field-
 * separator characters inside values entirely. The one place that would be
 * genuinely ambiguous — the `obj` array — is NOT joined with a delimiter
 * character (a comma inside an object id would let `["a,b"]` and `["a","b"]`
 * sign identically). Instead the count is stated up front and each id gets
 * its own line, so array framing is unambiguous by construction rather than
 * by hoping object ids never contain the separator.
 *
 * Every claim value is checked for an embedded newline before signing or
 * verifying (see {@link assertNoEmbeddedNewline}): a value that could smuggle
 * one would let a single claim be read back as two lines, i.e. as a different
 * claim set than the one that was actually signed.
 */

import { base64UrlToBytes, bytesToBase64Url } from '../recovery/base64Url.js';

export const LOCKER_CAPABILITY_DOMAIN = 'bdhealthtrust/locker-capability/v1';

/**
 * Hard ceiling on `exp - nbf`, enforced by BOTH {@link mintLockerCapability}
 * (so a caller cannot mint an absurdly long-lived capability by mistake) and
 * the locker's own verification (so a locker never trusts a wallet's window
 * claim unchecked — the wallet is not a trust boundary from the locker's
 * point of view). OFFICER-DOCUMENT-ACCESS.md §3 asks for "short"; one hour
 * covers one review sitting without approaching the single-use key's
 * lifetime being the tighter control.
 */
export const MAX_CAPABILITY_WINDOW_SECONDS = 60 * 60;

/** What {@link mintLockerCapability} uses when the caller does not say. */
export const DEFAULT_CAPABILITY_WINDOW_SECONDS = 15 * 60;

export class LockerCapabilityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LockerCapabilityError';
  }
}

/**
 * The claims a holder signs. Field names match OFFICER-DOCUMENT-ACCESS.md §3
 * exactly, so the brief and the code can be read side by side.
 */
export interface LockerCapabilityClaims {
  /** Holder DID — the subject whose objects these are. */
  readonly iss: string;
  /** Authority DID — the only party this capability admits. */
  readonly aud: string;
  /** The exact object ids covered. Nothing else is reachable. */
  readonly obj: readonly string[];
  /** The issuance request id, so a capability is traceable to one submission. */
  readonly sub: string;
  /** Unique id, for revocation. */
  readonly jti: string;
  /** Unix seconds. Not valid before. */
  readonly nbf: number;
  /** Unix seconds. Not valid at or after. */
  readonly exp: number;
}

/** The signed capability, as it travels from wallet to locker. */
export interface LockerCapabilityToken {
  readonly claims: LockerCapabilityClaims;
  /** base64url Ed25519 signature over {@link canonicalCapabilityPayload}(claims). */
  readonly signature: string;
  /** The `id` of the verification method in the holder's DID document used to sign. */
  readonly verificationMethodId: string;
}

function assertNoEmbeddedNewline(value: string, what: string): void {
  if (value.includes('\n')) {
    throw new LockerCapabilityError(
      `${what} must not contain a newline. Canonicalisation is newline-delimited, so a value ` +
        'carrying one could be read back as a different claim set than the one actually signed.',
    );
  }
}

/**
 * Structural validation only — this does not check the signature, the
 * audience, the window, revocation, or object membership. Those are the
 * locker's job, in the order OFFICER-DOCUMENT-ACCESS.md §3 states, and doing
 * them here would be a second place that order could drift from the brief.
 *
 * What belongs here: the shape has to be well-formed before anyone can even
 * compute the bytes that were supposedly signed.
 */
export function assertWellFormedLockerCapabilityClaims(
  claims: unknown,
): asserts claims is LockerCapabilityClaims {
  if (typeof claims !== 'object' || claims === null) {
    throw new LockerCapabilityError('capability claims must be an object');
  }
  const c = claims as Record<string, unknown>;

  for (const field of ['iss', 'aud', 'sub', 'jti'] as const) {
    if (typeof c[field] !== 'string' || c[field].length === 0) {
      throw new LockerCapabilityError(`capability claims.${field} must be a non-empty string`);
    }
    assertNoEmbeddedNewline(c[field] as string, `claims.${field}`);
  }
  if (!c.iss || !(c.iss as string).startsWith('did:')) {
    throw new LockerCapabilityError('capability claims.iss must be a DID');
  }
  if (!c.aud || !(c.aud as string).startsWith('did:')) {
    throw new LockerCapabilityError('capability claims.aud must be a DID');
  }
  if (!Array.isArray(c.obj) || c.obj.length === 0) {
    throw new LockerCapabilityError('capability claims.obj must be a non-empty array of object ids');
  }
  for (const [index, id] of c.obj.entries()) {
    if (typeof id !== 'string' || id.length === 0) {
      throw new LockerCapabilityError(`capability claims.obj[${index}] must be a non-empty string`);
    }
    assertNoEmbeddedNewline(id, `claims.obj[${index}]`);
  }
  if (typeof c.nbf !== 'number' || !Number.isFinite(c.nbf)) {
    throw new LockerCapabilityError('capability claims.nbf must be a finite unix-seconds number');
  }
  if (typeof c.exp !== 'number' || !Number.isFinite(c.exp)) {
    throw new LockerCapabilityError('capability claims.exp must be a finite unix-seconds number');
  }
  if (c.exp <= c.nbf) {
    throw new LockerCapabilityError('capability claims.exp must be after claims.nbf');
  }
}

/**
 * The exact bytes a holder signs. Built here and re-derived by the locker
 * from the claims it was handed — never accepted as opaque bytes from either
 * side — so what is checked is always "does this signature match THESE
 * claims", not "does this signature match whatever bytes came with it".
 */
export function canonicalCapabilityPayload(claims: LockerCapabilityClaims): Uint8Array {
  assertWellFormedLockerCapabilityClaims(claims);

  const lines = [
    `${LOCKER_CAPABILITY_DOMAIN}`,
    `iss:${claims.iss}`,
    `aud:${claims.aud}`,
    `sub:${claims.sub}`,
    `jti:${claims.jti}`,
    `nbf:${claims.nbf}`,
    `exp:${claims.exp}`,
    `obj-count:${claims.obj.length}`,
    ...claims.obj.map((id, index) => `obj:${index}:${id}`),
  ];
  return new TextEncoder().encode(lines.join('\n') + '\n');
}

export interface MintLockerCapabilityArgs {
  readonly holderDid: string;
  readonly authorityDid: string;
  /** The exact object ids this capability will admit reading. */
  readonly objectIds: readonly string[];
  /** The issuance request this capability belongs to. */
  readonly issuanceRequestId: string;
  /** The `id` of the holder DID's verification method that will sign. */
  readonly verificationMethodId: string;
  /**
   * Seconds of validity from `now`. Defaults to
   * {@link DEFAULT_CAPABILITY_WINDOW_SECONDS}; capped at
   * {@link MAX_CAPABILITY_WINDOW_SECONDS} — a caller asking for longer gets a
   * thrown error, not a silently clamped value, because a silent clamp would
   * let a caller believe it minted a longer-lived capability than it did.
   */
  readonly validitySeconds?: number;
  /** Injectable for tests; defaults to `new Date()`. */
  readonly now?: Date;
  /**
   * Signs the canonical payload with the holder's DID key. Takes a callback
   * rather than raw key material: this module has no opinion on whether that
   * key lives in a KMS, a secure enclave, or an in-memory Ed25519 seed, which
   * is the same separation `recoveryKey.ts` draws between "the bytes to sign"
   * and "how a signature over them gets produced".
   */
  readonly sign: (payload: Uint8Array) => Uint8Array | Promise<Uint8Array>;
}

/**
 * Generate a `jti`. 16 random bytes, base64url — the same construction
 * `generateNonce` in the locker's `didAuth.ts` uses for its challenge nonces,
 * for the same reason: collision probability negligible at this scale, and no
 * dependency on `crypto.randomUUID` being present in every runtime this code
 * might execute in (React Native's Hermes did not always have it).
 */
function generateJti(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

/**
 * Build and sign a locker capability.
 *
 * Returns the full wire token — claims, signature, and the verification
 * method id the locker needs to find the right key in the holder's resolved
 * DID document. Nothing here talks to a locker or a resolver; this is
 * construction only, matching {@link canonicalCapabilityPayload}'s own scope.
 */
export async function mintLockerCapability(
  args: MintLockerCapabilityArgs,
): Promise<LockerCapabilityToken> {
  const validitySeconds = args.validitySeconds ?? DEFAULT_CAPABILITY_WINDOW_SECONDS;
  if (validitySeconds <= 0 || validitySeconds > MAX_CAPABILITY_WINDOW_SECONDS) {
    throw new LockerCapabilityError(
      `validitySeconds must be between 1 and ${MAX_CAPABILITY_WINDOW_SECONDS} (got ${validitySeconds}). ` +
        'A locker enforces this ceiling independently at verification time; asking for more here ' +
        'would mint a capability the locker refuses on the window check regardless.',
    );
  }

  const nowSeconds = Math.floor((args.now ?? new Date()).getTime() / 1000);
  const claims: LockerCapabilityClaims = {
    iss: args.holderDid,
    aud: args.authorityDid,
    obj: [...args.objectIds],
    sub: args.issuanceRequestId,
    jti: generateJti(),
    nbf: nowSeconds,
    exp: nowSeconds + validitySeconds,
  };

  const payload = canonicalCapabilityPayload(claims);
  const signature = await args.sign(payload);
  const signatureBytes = signature instanceof Uint8Array ? signature : new Uint8Array(signature);

  return {
    claims,
    signature: bytesToBase64Url(signatureBytes),
    verificationMethodId: args.verificationMethodId,
  };
}

/** Decode a token's base64url signature back to raw bytes, for a verifier. */
export function capabilitySignatureBytes(token: LockerCapabilityToken): Uint8Array {
  return base64UrlToBytes(token.signature);
}
