/**
 * ============================================================================
 * THE SD-JWT WIRE FORMAT, READ ONCE
 * ============================================================================
 *
 * WHY THIS FILE EXISTS. `packages/backend/src/services/sdJwtVc.ts` and
 * `./presentation.ts` are two verifiers of the same artifact — deliberately, and
 * they are documented as such. What was NOT deliberate is that they had grown
 * two copies of the plumbing underneath: `didOf` byte-identical in both, the
 * fourteen envelope claims maintained as a hand-kept mirror (the SDK copy said
 * so in its own comment), the `data:` URI reader written twice, the media type
 * and `typ` constants declared twice, and the positional `~` split expressed
 * twice in different shapes. That is #341's drift, in the plumbing rather than
 * in the checks.
 *
 * None of it is verification LOGIC, so consolidating it flattens nothing. The
 * two verifiers keep their different check sets and their different verdicts;
 * they now agree about how to take the artifact apart, which they were only
 * agreeing about by hand before.
 *
 * ============================================================================
 * WHAT IS DELIBERATELY NOT HERE
 * ============================================================================
 *
 * The key-binding JWT PARSER stays in the backend. The asymmetry between the
 * two verifiers is intentional and is not an accident to be tidied away: the
 * backend VERIFIES a KB-JWT (`verifyKeyBinding`, #290/#321), and this SDK
 * REFUSES a presentation that carries one, because it cannot verify it (#344).
 * Refusal only needs to know whether the slot is occupied, which
 * {@link keyBindingSlot} answers. Giving the SDK a parser it has decided not to
 * act on would be capability with no caller — and the next person to find it
 * would reasonably wire it up.
 *
 * Claims EXTRACTION is not here either, and cannot be: the backend resolves
 * disclosures through Credo's `prettyClaims` and this SDK through the vendored
 * `@sd-jwt/core`. Those are two different parsers by design. Only the step
 * AFTER resolution — dropping the envelope's own claims — is common, and that
 * is {@link credentialClaimsOf}.
 */

import { SD_SEPARATOR } from '../vendor/sd-jwt/types';

/**
 * The `~` between an SD-JWT's segments, re-exported from the vendored library.
 *
 * Passed through rather than redeclared. A local `'~'` literal is how the two
 * sides of this boundary came to have separate ideas about the wire format in
 * the first place, and the RFC 9807 §4.3 `sd_hash` range is defined in terms of
 * this exact byte — a caller rebuilding that range must join on the same
 * constant the encoder split on.
 */
export { SD_SEPARATOR };

/** `typ` header Credo stamps on a VC 2.0 SD-JWT credential. */
export const VC_SD_JWT_TYP = 'vc+sd-jwt';

/** `typ` header Credo stamps on a VC 2.0 SD-JWT presentation. */
export const VP_SD_JWT_TYP = 'vp+sd-jwt';

/** Media type used in an `EnvelopedVerifiableCredential` data URI. */
export const SD_JWT_MEDIA_TYPE = 'application/vc+sd-jwt';

/** A compact SD-JWT taken apart the way the wire format actually defines it. */
export interface SdJwtCompactParts {
  /** The issuer-signed JWS. */
  issuerJwt: string;
  /** Disclosures, still base64url-encoded, in wire order. */
  disclosures: string[];
  /** The key-binding JWT, or `''` when the artifact carries none. */
  keyBindingJwt: string;
}

/**
 * Split a compact SD-JWT into issuer JWT, disclosures and KEY-BINDING JWT.
 *
 * THE TRAILING SLOT IS NOT A DISCLOSURE. The wire format is
 * `<jws>~<d1>~…~<dn>~<kb-jwt>`, and the element after the FINAL `~` is the
 * key-binding position — empty when there is no key binding, which is why an
 * artifact with disclosures and no KB-JWT ends in `~`. Measured against
 * `@sd-jwt/core@0.19.0`: `issue()` always emits that trailing separator, and
 * `SDJwt.encodeSDJwt` pushes `''` for the absent KB-JWT rather than omitting
 * the slot.
 *
 * A `.split('~').slice(1).filter(Boolean)` therefore reads a REAL KB-JWT as one
 * more disclosure — it hashes to nothing the issuer committed to, and the
 * honest presentation carrying it is rejected (steno #290). Position, not
 * content, is what tells the two apart, so the split has to be positional.
 *
 * Empty disclosure slots are dropped: they carry nothing and an artifact ending
 * `~~` would otherwise be reported as a malformed disclosure rather than as the
 * absent key binding it is.
 */
export function splitSdJwtCompact(compact: string): SdJwtCompactParts {
  const segments = compact.split(SD_SEPARATOR);
  // No separator at all: not an SD-JWT, so there is neither a disclosure nor a
  // key-binding slot to attribute anything to.
  if (segments.length === 1) {
    return { issuerJwt: segments[0]!, disclosures: [], keyBindingJwt: '' };
  }
  return {
    issuerJwt: segments[0]!,
    disclosures: segments.slice(1, -1).filter((segment) => segment.length > 0),
    keyBindingJwt: segments[segments.length - 1]!,
  };
}

/**
 * The issuer-signed JWS of a compact SD-JWT — everything before the first `~`.
 *
 * A NAMED ACCESSOR, not a second reading of the wire format. It exists so a
 * caller that only wants the JWS never handles the disclosure list at all:
 * disclosure parsing belongs to the vendored `@sd-jwt/core`, which gets the
 * key-binding position right, and a caller holding raw disclosures is one
 * `filter(Boolean)` away from reintroducing #290.
 */
export function issuerSignedJws(compact: string): string {
  return splitSdJwtCompact(compact).issuerJwt;
}

/**
 * The key-binding slot of an SD-JWT compact, or `null` when it is empty.
 *
 * Occupancy only. Whether the occupant is a well-formed KB-JWT, and whether it
 * is genuine, are separate questions answered on the backend side; a verifier
 * that cannot answer them should refuse on occupancy alone rather than look
 * past the slot.
 */
export function keyBindingSlot(compact: string): string | null {
  const slot = splitSdJwtCompact(compact).keyBindingJwt;
  return slot.length > 0 ? slot : null;
}

/**
 * Does this compact artifact use the SD-JWT securing mechanism?
 *
 * A LAST-RESORT READER, not the primary one. The authoritative answer is the
 * format recorded at issuance. Use this only where no recorded format exists —
 * a credential arriving from outside this system, or a pre-column row.
 */
export function looksLikeSdJwt(compact: string): boolean {
  return compact.includes(SD_SEPARATOR);
}

/**
 * Claims that belong to the SD-JWT envelope rather than to the credential.
 *
 * ONE SET, SHARED. This was previously declared in both verifiers, and the SDK
 * copy carried a comment saying it had to be kept in step by hand — a relying
 * party comparing what our backend reported against what it verified locally
 * must not see a spurious difference caused by one side leaking `iat` into the
 * claims and the other not. A hand-kept mirror is a promise; this is a fact.
 *
 * `_sd` itself never survives into resolved claims — matched digests are
 * replaced by their values and unmatched ones are dropped — but it is listed
 * for safety at nested levels. `_sd_alg` is the hash algorithm identifier
 * SD-JWT stamps on the payload.
 */
export const SD_JWT_ENVELOPE_CLAIMS: ReadonlySet<string> = new Set([
  'iat',
  'cnf',
  'nbf',
  'exp',
  'iss',
  'sub',
  'jti',
  'aud',
  'nonce',
  'kid',
  'typ',
  'cty',
  '_sd',
  '_sd_alg',
]);

/** Strip envelope-only claims from resolved claims, leaving the credential's own JSON. */
export function credentialClaimsOf(
  claims: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(claims)) {
    if (SD_JWT_ENVELOPE_CLAIMS.has(key)) continue;
    result[key] = value;
  }
  return result;
}

/**
 * Read the compact `vc+sd-jwt` out of a VC 2.0 `EnvelopedVerifiableCredential`.
 *
 * The media type is checked, not assumed: the JWT securing mechanism uses the
 * same envelope shape with a different type, and the two are kept apart so
 * neither can silently decode the other's artifact.
 */
export function envelopedCredentialToSdJwt(entry: unknown): string | null {
  if (!entry || typeof entry !== 'object') return null;

  const id = (entry as { id?: unknown }).id;
  if (typeof id !== 'string' || !id.startsWith('data:')) return null;

  const comma = id.indexOf(',');
  if (comma === -1) return null;
  if (id.slice('data:'.length, comma) !== SD_JWT_MEDIA_TYPE) return null;

  const compact = id.slice(comma + 1);
  return compact.length > 0 ? compact : null;
}

/** The DID part of a DID URL, discarding fragment and query. */
export function didOf(didUrl: string): string {
  const hash = didUrl.indexOf('#');
  const base = hash === -1 ? didUrl : didUrl.slice(0, hash);
  const query = base.indexOf('?');
  return query === -1 ? base : base.slice(0, query);
}
