/**
 * ============================================================================
 * LOCAL VERIFICATION OF A `vp+sd-jwt` PRESENTATION
 * ============================================================================
 *
 * WHY THIS FILE EXISTS AT ALL.
 *
 * `@ssi-healthcare/sdk` is published as "an OAuth2 alternative". Until this
 * module, it could not verify anything: a relying party called
 * `SSIClient.verifyPresentation`, our backend answered with a boolean, and the
 * relying party believed it. That is exactly the centralised trust OAuth2 has,
 * wearing SSI vocabulary — the issuer's signature is the thing that is supposed
 * to be checkable by anyone, and nobody outside our infrastructure could check
 * it. Everything below runs in the relying party's own process, against key
 * material the relying party chose to trust.
 *
 * ============================================================================
 * THE TRAP THIS API IS SHAPED TO AVOID
 * ============================================================================
 *
 * `@sd-jwt/core` — which this SDK now vendors — closes the DISCLOSURE layer:
 * digests, the frame walker, RFC 9807 §7.3. It does NOT close the PRESENTATION
 * layer. Two of the four measured holes in this system's stack live above it:
 *
 *   - challenge / domain replay: a captured presentation replays forever,
 *     against any verifier, if nobody compares `nonce` and `aud`.
 *   - holder binding: nothing compares the credential's `cnf` — the binding the
 *     ISSUER signed — to the party that signed the presentation, so a captured
 *     credential can be re-presented by whoever captured it.
 *
 * Both are documented in `CREDO-SECURITY-REPORT.md`, both were demonstrated end
 * to end against real DIDs on this project's ledger, and our backend
 * compensates for both at `packages/backend/src/services/sdJwtVc.ts`.
 *
 * So an SDK `verify` that stopped at `@sd-jwt/core` would be a THIRD
 * verification path, WEAKER than our own backend's, handed to third parties as
 * the trustworthy one. This project has shipped that mistake once already —
 * `packages/backend/src/routes/verification.ts.bak`, retired to `Backup/` with
 * a DO NOT RESTORE header, mounted a verifier that never checked the
 * presentation signature at all.
 *
 * The resolution, chosen deliberately over "scope the API so it cannot be
 * mistaken for presentation verification": CARRY THE PRESENTATION-LAYER CHECKS
 * IN TOO. Scoping down would have left the relying party with nothing but a
 * remote boolean for the checks that actually stop replay and theft, which is
 * the problem this work exists to fix.
 *
 * HOW THIS RELATES TO THE BACKEND BOUNDARY, precisely. An earlier version of
 * this comment claimed every check the backend makes is made here and that
 * where they differ this one is stricter. THAT WAS TRUE WHEN WRITTEN AND IS NOT
 * TRUE NOW — steno #344. The two check sets are not ordered by strength:
 *
 *   - Only here: `structure`, `validityWindow`, and signatures split into
 *     `holderSignature` + `issuerSignature`, verified in this process via
 *     `jose` rather than delegated to Credo's single verdict.
 *   - Only there: `keyBinding`, the RFC 9807 KB-JWT check (#290, #321).
 *
 * The KB-JWT gap is closed here by REFUSAL rather than verification — see the
 * key-binding block in `verifySdJwtPresentation`. Neither side is a superset,
 * so do not treat one as a drop-in for the other; keep both honest instead.
 *
 * ============================================================================
 * HOW THE BOUNDARY IS MADE UNMISREADABLE FROM THE OUTSIDE
 * ============================================================================
 *
 * 1. There is no bare-boolean entry point, and no convenience overload that
 *    omits an input. `challenge`, `audience` and `resolveVerificationKey` are
 *    required in the type AND asserted at runtime, because a JavaScript caller
 *    has no type checker and a silently-absent challenge is the exact fail-open
 *    shape every bug in this area has taken.
 * 2. Every check starts `false` and must be actively satisfied. `isValid` is
 *    their conjunction. "There was nothing to check" is not a passing outcome.
 * 3. `credentials` is empty unless every check passed. A caller that reads
 *    claims out of a failed verification is acting on unauthenticated data, and
 *    the reliable way to prevent that is to not hand the claims over.
 * 4. The result carries `notChecked`, naming in the return value itself what
 *    this function does NOT establish. A verifier that needs revocation status
 *    should be told so by the API, not by a paragraph of documentation it did
 *    not read.
 * 5. Trust is the caller's. `resolveVerificationKey` has no default. There is
 *    deliberately no "ask the BDHealthTrust backend" fallback, because that
 *    would rebuild the centralised trust this module exists to remove. A
 *    relying party that chooses to resolve DIDs through our resolver is making
 *    a far weaker assumption than before — we could serve it wrong key
 *    material, but we can no longer simply assert that an invalid presentation
 *    is valid.
 */
import { compactVerify, importJWK, calculateJwkThumbprint } from 'jose';
import { SDJwt } from '../vendor/sd-jwt/core';
import { base64urlDecode } from '../vendor/sd-jwt/utils';
import { webCryptoHasher } from './crypto';
// The wire-format plumbing, shared with the backend verifier so the two cannot
// drift about how an artifact is taken apart. The CHECKS stay different; see
// ./sdJwtWire.ts for what is deliberately not shared.
import {
  VC_SD_JWT_TYP as VC_TYP,
  VP_SD_JWT_TYP as VP_TYP,
  credentialClaimsOf,
  didOf,
  envelopedCredentialToSdJwt as envelopedCredentialToCompact,
  issuerSignedJws,
  keyBindingSlot,
} from './sdJwtWire';

// Re-exported because `@ssi-healthcare/sdk/verify` has published it from this
// module since the verifier shipped; the definition moved, the export must not.
export { didOf };

/**
 * Signature algorithms accepted by default.
 *
 * An ALLOWLIST, not a denylist, and it does not include `none`. `alg` comes
 * from the artifact's own header, so a verifier that accepts whatever it is
 * told lets the attacker pick the algorithm. EdDSA is what this system issues;
 * the ES* entries are there so a relying party can verify credentials from
 * other issuers in the same federation without widening the list itself.
 */
export const DEFAULT_ALLOWED_ALGORITHMS: readonly string[] = Object.freeze([
  'EdDSA',
  'ES256',
  'ES384',
  'ES512',
]);

/**
 * What this function establishes — and, by omission, what it does not.
 *
 * Returned inside every result as `notChecked`, so the limits travel with the
 * verdict instead of living in prose the integrator did not read.
 */
export const NOT_CHECKED: readonly string[] = Object.freeze([
  'revocation: the credential may have been revoked since issuance. Check its credentialStatus separately.',
  'issuer authority: whether the issuing DID is one you trust is decided entirely by your resolveVerificationKey.',
  'schema: claim names and shapes are not validated against any credential schema.',
  'consent and purpose limitation: whether you are permitted to process these claims is not a cryptographic question.',
  'key binding (RFC 9807 KB-JWT): not verified. An artifact carrying one is refused outright rather than accepted unchecked; the holder signature over the presentation is what binds possession here.',
]);

/** Public key material for one verification, as a JWK. */
export type VerificationJwk = JsonWebKey & { kty: string };

/**
 * Resolve the public key that should have signed a given artifact.
 *
 * THIS IS THE RELYING PARTY'S ROOT OF TRUST and there is no default. Returning
 * a key here is a statement that you accept this key as authentic for this
 * `kid`; every signature check below is only as strong as that statement.
 *
 * Throwing (or rejecting) is the correct response to a `kid` you cannot or will
 * not resolve. It fails the corresponding check; it never passes it.
 */
export type ResolveVerificationKey = (request: {
  /** `kid` from the artifact's JOSE header. May be a relative fragment. */
  kid: string;
  /** DID the artifact attributes the key to, when it names one. */
  did: string | null;
  /** Which signature is being checked. */
  purpose: 'holder' | 'issuer';
}) => Promise<VerificationJwk> | VerificationJwk;

export interface VerifySdJwtPresentationOptions {
  /** The compact `vp+sd-jwt` exactly as received. */
  presentation: string;
  /**
   * The nonce YOU generated for THIS exchange, read back from your own state.
   *
   * Never take this from the submission. Comparing a presentation against a
   * nonce it supplied itself is not a replay check, it is a formality.
   */
  challenge: string;
  /**
   * The audience identifier YOU published, e.g. `https://pharmacy.example`.
   *
   * Required here although the backend boundary treats it as optional. A
   * presentation that names no audience, or names someone else's, is one the
   * holder did not intend for you specifically, and accepting it re-opens the
   * cross-verifier replay path that the nonce only closes within one verifier.
   */
  audience: string;
  /** @see ResolveVerificationKey — no default, on purpose. */
  resolveVerificationKey: ResolveVerificationKey;
  /** Overrides {@link DEFAULT_ALLOWED_ALGORITHMS}. An empty array is rejected. */
  algorithms?: readonly string[];
  /** Evaluation time for the validity window. Defaults to now. */
  now?: Date;
  /** Tolerance for clock drift, in seconds. Defaults to 0. */
  clockSkewSeconds?: number;
}

export interface SdJwtPresentationChecks {
  /** Parses as a `vp+sd-jwt` carrying at least one enveloped `vc+sd-jwt`. */
  structure: boolean;
  /** The presentation JWS verifies under the key its `kid` names. */
  holderSignature: boolean;
  /** Every enveloped credential's JWS verifies under its issuer's key. */
  issuerSignature: boolean;
  /** Every disclosure carried resolves to a digest the issuer signed. RFC 9807 §7.3. */
  disclosureIntegrity: boolean;
  /** Presentation `nonce` equals the challenge you issued. Closes replay. */
  challenge: boolean;
  /** Presentation `aud` includes you. Closes cross-verifier replay. */
  audience: boolean;
  /** Each credential's `cnf` names the key that signed the presentation. Closes theft. */
  holderBinding: boolean;
  /** Every credential is inside its validity window at `now`. */
  validityWindow: boolean;
}

export interface VerifiedSdJwtCredential {
  /** Disclosed claims as W3C JSON. Withheld claims are absent, not blank. */
  claims: Record<string, unknown>;
  /** The compact `vc+sd-jwt`, for a revocation check you run yourself. */
  envelope: string;
  /** `iss` from the credential envelope. */
  issuer: string | null;
  /** The holder binding the issuer signed. */
  cnfKeyId: string | null;
}

export interface SdJwtPresentationVerification {
  /** The conjunction of every entry in {@link checks}. Nothing else. */
  isValid: boolean;
  /** Every reason it failed. Empty on success. */
  errors: string[];
  checks: SdJwtPresentationChecks;
  /** @see NOT_CHECKED */
  notChecked: readonly string[];
  /** Populated only when `isValid` is true. */
  credentials: VerifiedSdJwtCredential[];
  /** The key that signed the presentation, as its header named it. */
  holderKeyId: string | null;
}

interface DecodedJws {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  jws: string;
}

/**
 * Normalise a JOSE `kid` to an absolute DID URL.
 *
 * A `kid` may legitimately be a relative fragment (`#key-1`), in which case the
 * DID it belongs to comes from the artifact's holder or issuer. Comparing a
 * relative `kid` to an absolute `cnf.kid` as plain strings would reject every
 * honest presentation that used the relative form, so normalise before
 * comparing rather than after discovering the mismatch.
 */
function absoluteKeyId(kid: unknown, subjectDid: string | null): string | null {
  if (typeof kid !== 'string' || kid.length === 0) return null;
  if (kid.startsWith('#')) return subjectDid ? `${subjectDid}${kid}` : null;
  return kid.startsWith('did:') ? kid : null;
}

/**
 * The DID a credential names as its issuer.
 *
 * TWO FIELDS, DELIBERATELY, AND READING ONLY THE FIRST WAS A FAIL-OPEN.
 *
 * `iss` is the JWT registered claim that IETF SD-JWT VC uses. `issuer` is what
 * the W3C VC 2.0 data model uses, and it is what Credo emits when it secures a
 * VC 2.0 credential as `vc+sd-jwt`. MEASURED: every credential BDHealthTrust
 * issues carries `issuer` and no `iss` at all.
 *
 * With the issuer read as null, the binding check below had nothing to compare
 * the signing key id against, and `resolveVerificationKey` was called with
 * `did: null` — which tells a conformant resolver "this key id stands on its
 * own", disabling its own belongs-to-this-DID guard. MEASURED
 * (scripts/probe-issuer-binding.mts in the backend): a professional licence
 * naming a PINNED ACCREDITATION AUTHORITY as its `issuer`, signed by an
 * unrelated DID's key, verified with `isValid: true` and an empty error list.
 * `authoriseProfessional` then reads that same `issuer` field to decide trust,
 * so the forgery would have been granted clinical authority.
 */
function issuerDidOf(payload: Record<string, unknown>): string | null {
  if (typeof payload.iss === 'string') return payload.iss;
  const issuer = payload.issuer;
  if (typeof issuer === 'string') return issuer;
  if (issuer && typeof issuer === 'object' && typeof (issuer as { id?: unknown }).id === 'string') {
    return (issuer as { id: string }).id;
  }
  return null;
}

/** Decode header and payload without checking anything. */
function decodeJws(compact: string): DecodedJws | null {
  const jws = issuerSignedJws(compact);
  const parts = jws.split('.');
  if (parts.length !== 3) return null;
  try {
    return {
      header: JSON.parse(base64urlDecode(parts[0]!)) as Record<string, unknown>,
      payload: JSON.parse(base64urlDecode(parts[1]!)) as Record<string, unknown>,
      jws,
    };
  } catch {
    return null;
  }
}

function asArray(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

/**
 * Verify one JWS against a key the caller chose to trust.
 *
 * Returns an error string rather than throwing, so one credential's bad
 * signature is reported alongside the other checks instead of aborting them.
 */
async function verifySignature(
  jws: string,
  header: Record<string, unknown>,
  key: VerificationJwk,
  algorithms: readonly string[],
): Promise<string | null> {
  // Check `alg` against the allowlist BEFORE it reaches key import. `alg`
  // arrives on the artifact, so an attacker chooses it; letting an unchecked
  // value select the import path is how algorithm-confusion bugs start. The
  // same list is passed to `compactVerify`, which is belt and braces on
  // purpose.
  const alg = header.alg;
  if (typeof alg !== 'string' || !algorithms.includes(alg)) {
    return `signature algorithm '${String(alg)}' is not in the accepted list (${algorithms.join(', ')})`;
  }
  try {
    const imported = await importJWK(key as Parameters<typeof importJWK>[0], alg);
    await compactVerify(jws, imported, { algorithms: [...algorithms] });
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

/**
 * Compare a credential's `cnf` to the key that signed the presentation.
 *
 * Both `cnf` shapes are handled. `cnf.kid` is what Credo writes and is compared
 * as an absolutised DID URL. `cnf.jwk` is the RFC's other form and is compared
 * by RFC 7638 thumbprint against the resolved holder key — comparing raw JWK
 * members would fail on nothing more than key order or an extra `alg`.
 *
 * A missing `cnf` FAILS. An unbound credential is a bearer token, and treating
 * "no binding" as "nothing to check" is the fail-open shape this check exists
 * to remove.
 */
async function checkHolderBinding(
  claims: Record<string, unknown>,
  proverKeyId: string | null,
  proverKey: VerificationJwk | null,
): Promise<string | null> {
  const cnf = claims.cnf as { kid?: unknown; jwk?: unknown } | undefined;
  if (!cnf || typeof cnf !== 'object') {
    return 'Credential carries no cnf holder binding, so possession of it proves nothing';
  }

  if (typeof cnf.kid === 'string') {
    const boundKeyId = absoluteKeyId(cnf.kid, didOf(cnf.kid));
    if (!boundKeyId) {
      return `Credential cnf.kid '${String(cnf.kid)}' is not an absolute DID URL, so it cannot be compared to the presentation signer`;
    }
    if (!proverKeyId) {
      return 'Presentation does not name the key that signed it, so it cannot be bound to a holder';
    }
    if (boundKeyId === proverKeyId) return null;
    // Same DID, different key is a holder using a key the issuer did not commit
    // to; different DID is theft. Both refused — an operator reading the log
    // should still be able to tell them apart.
    return didOf(boundKeyId) === didOf(proverKeyId)
      ? `Presentation was signed with '${proverKeyId}', but the credential is bound to a different key of the same holder ('${boundKeyId}')`
      : `Presentation was signed by '${didOf(proverKeyId)}', but the credential is bound to '${didOf(boundKeyId)}'`;
  }

  if (cnf.jwk && typeof cnf.jwk === 'object') {
    if (!proverKey) {
      return 'Credential is bound by cnf.jwk, but the presentation signer key could not be resolved for comparison';
    }
    try {
      const [bound, prover] = await Promise.all([
        calculateJwkThumbprint(cnf.jwk as Parameters<typeof calculateJwkThumbprint>[0]),
        calculateJwkThumbprint(proverKey as Parameters<typeof calculateJwkThumbprint>[0]),
      ]);
      return bound === prover
        ? null
        : 'Presentation was signed by a key other than the one the credential is bound to';
    } catch (error) {
      return `Credential cnf.jwk could not be compared to the presentation signer: ${
        error instanceof Error ? error.message : String(error)
      }`;
    }
  }

  return 'Credential cnf carries neither a kid nor a jwk, so the holder binding cannot be compared';
}

/** Check one credential's validity window. Returns an error string or null. */
function checkValidityWindow(
  claims: Record<string, unknown>,
  payload: Record<string, unknown>,
  nowSeconds: number,
  skewSeconds: number,
): string | null {
  // VC 2.0 names them validFrom/validUntil, VC 1.1 issuanceDate/expirationDate,
  // and the SD-JWT envelope carries nbf/exp. A credential from before the VC 2.0
  // migration uses the old names, so reading only one pair is how a credential
  // silently verifies as "always valid".
  const notBefore =
    (claims.validFrom as string | undefined) ?? (claims.issuanceDate as string | undefined);
  const notAfter =
    (claims.validUntil as string | undefined) ?? (claims.expirationDate as string | undefined);

  const toSeconds = (iso: string | undefined): number | null => {
    if (typeof iso !== 'string') return null;
    const ms = Date.parse(iso);
    return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
  };

  const starts = toSeconds(notBefore) ?? (typeof payload.nbf === 'number' ? payload.nbf : null);
  const ends = toSeconds(notAfter) ?? (typeof payload.exp === 'number' ? payload.exp : null);

  if (starts !== null && nowSeconds + skewSeconds < starts) {
    return `Credential is not valid until ${notBefore ?? new Date(starts * 1000).toISOString()}`;
  }
  if (ends !== null && nowSeconds - skewSeconds > ends) {
    return `Credential expired at ${notAfter ?? new Date(ends * 1000).toISOString()}`;
  }
  return null;
}

/**
 * Verify a `vp+sd-jwt` presentation locally, end to end.
 *
 * FAIL CLOSED THROUGHOUT. Read the file header before changing anything here:
 * every one of these checks is load bearing and two of them exist because the
 * layer below does not perform them.
 *
 * @throws TypeError if a required option is absent. This is the one thing that
 *   throws rather than returning `isValid: false` — a caller that forgot to
 *   pass a challenge has a bug in its own code, and returning a verdict would
 *   let that bug look like a verification outcome.
 */
export async function verifySdJwtPresentation(
  options: VerifySdJwtPresentationOptions,
): Promise<SdJwtPresentationVerification> {
  assertOptions(options);

  const algorithms = options.algorithms ?? DEFAULT_ALLOWED_ALGORITHMS;
  const nowSeconds = Math.floor((options.now?.getTime() ?? Date.now()) / 1000);
  const skewSeconds = options.clockSkewSeconds ?? 0;

  const errors: string[] = [];
  const checks: SdJwtPresentationChecks = {
    structure: false,
    holderSignature: false,
    issuerSignature: false,
    disclosureIntegrity: false,
    challenge: false,
    audience: false,
    holderBinding: false,
    validityWindow: false,
  };
  const fail = (
    reason: string,
    holderKeyId: string | null = null,
  ): SdJwtPresentationVerification => {
    errors.push(reason);
    return {
      isValid: false,
      errors,
      checks,
      notChecked: NOT_CHECKED,
      credentials: [],
      holderKeyId,
    };
  };

  // ------------------------------------------------------------------ structure
  const vp = decodeJws(options.presentation);
  if (!vp) return fail('Presentation is not a readable compact SD-JWT');
  if (vp.header.typ !== VP_TYP) {
    // Refusing a `vc+sd-jwt` here is the point: a bare credential carries no
    // nonce, no aud and no holder signature, so every presentation-layer check
    // below would have nothing to compare and this function would degrade into
    // the weaker thing it exists not to be.
    return fail(
      `Presentation header typ is '${String(vp.header.typ)}', expected '${VP_TYP}'`,
    );
  }

  const holderDid =
    typeof vp.payload.holder === 'string' ? didOf(vp.payload.holder) : null;
  const holderKeyId = absoluteKeyId(vp.header.kid, holderDid);

  const envelopes = asArray(vp.payload.verifiableCredential);
  if (envelopes.length === 0) {
    return fail('Presentation contains no credentials', holderKeyId);
  }

  const compacts: string[] = [];
  for (const entry of envelopes) {
    const compact = envelopedCredentialToCompact(entry);
    if (!compact) {
      return fail(
        `Presentation carries an entry that is not an enveloped ${VC_TYP} credential`,
        holderKeyId,
      );
    }
    compacts.push(compact);
  }

  // ------------------------------------------------------------- key binding
  // A KB-JWT here is REFUSED, not ignored and not verified.
  //
  // This module does not verify key binding. Verifying it needs the `cnf` key
  // resolved to check the KB-JWT's own signature, which would widen
  // `resolveVerificationKey` from "the key this artifact names" to "arbitrary
  // key lookup" — a contract change bought for a property we do not need here,
  // since the VP-layer holder signature is already the unconditional
  // possession proof and IS checked below.
  //
  // Tolerating one instead was the fail-OPEN shape: measured, a kb+jwt with a
  // wrong `sd_hash`, a stale `nonce`, another verifier's `aud` and a garbage
  // signature verified as `isValid: true` with no errors, because nothing
  // looked at it. An artifact carrying an unverifiable possession proof must
  // not be accepted as though it carried none.
  //
  // INTEROP COST, accepted deliberately: a legitimate implementation that puts
  // a KB-JWT in this slot is now rejected where it used to pass. Nobody can be
  // relying on that KB-JWT being VERIFIED, because it was ignored, so refusal
  // breaks only a false sense of security. A loud break is recoverable and
  // teaches us the flow exists; a silent accept of forged material is neither.
  // There is deliberately no option to relax this — an option that exists gets
  // switched on, and it would be switched on at exactly the wrong moment.
  const kbBearing = [options.presentation, ...compacts].find(
    (compact) => keyBindingSlot(compact) !== null,
  );
  if (kbBearing !== undefined) {
    return fail(
      'Artifact carries a key-binding JWT, which this SDK does not verify. It is ' +
        'refused rather than ignored, because accepting an unverifiable possession ' +
        'proof as though it were absent is a fail-open. Present the credential in a ' +
        'vp+sd-jwt whose holder signature covers it, which this module does verify.',
      holderKeyId,
    );
  }
  checks.structure = true;

  // -------------------------------------------------------- disclosure integrity
  // Runs the vendored decoder, which rejects any disclosure the issuer never
  // committed to (RFC 9807 §7.3, divergence D3). Applies to the presentation
  // envelope AND to every credential inside it — both levels carry disclosures.
  // Resolved claims are captured here and reused below, so nothing downstream
  // ever reads a raw disclosure list.
  let vpClaims: Record<string, unknown> | null = null;
  const credentialClaims: Array<Record<string, unknown>> = [];
  try {
    vpClaims = await resolveClaims(options.presentation);
    for (const compact of compacts) {
      credentialClaims.push(await resolveClaims(compact));
    }
    checks.disclosureIntegrity = true;
  } catch (error) {
    errors.push(
      `Disclosure integrity failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  // --------------------------------------------------------------- challenge
  const nonce = vp.payload.nonce;
  if (typeof nonce !== 'string' || nonce.length === 0) {
    errors.push(
      'Presentation carries no nonce, so it cannot be bound to this verification request',
    );
  } else if (nonce !== options.challenge) {
    errors.push('Presentation nonce does not match the challenge issued for this request');
  } else {
    checks.challenge = true;
  }

  // ----------------------------------------------------------------- audience
  const audiences = asArray(vp.payload.aud);
  if (audiences.includes(options.audience)) {
    checks.audience = true;
  } else {
    errors.push(
      `Presentation audience does not include this verifier ('${options.audience}')`,
    );
  }

  // ---------------------------------------------------------- holder signature
  let proverKey: VerificationJwk | null = null;
  if (!holderKeyId) {
    errors.push(
      'Presentation does not name the key that signed it, so it cannot be bound to a holder',
    );
  } else {
    try {
      proverKey = await options.resolveVerificationKey({
        kid: holderKeyId,
        did: holderDid,
        purpose: 'holder',
      });
    } catch (error) {
      errors.push(
        `Presentation signing key '${holderKeyId}' could not be resolved: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    if (proverKey) {
      const failure = await verifySignature(vp.jws, vp.header, proverKey, algorithms);
      if (failure) {
        errors.push(`Presentation signature is not valid: ${failure}`);
      } else {
        checks.holderSignature = true;
      }
    }
  }

  // ---------------------------------- issuer signature / binding / validity
  const issuerErrors: string[] = [];
  const bindingErrors: string[] = [];
  const validityErrors: string[] = [];
  const verified: VerifiedSdJwtCredential[] = [];

  for (let index = 0; index < compacts.length; index++) {
    const compact = compacts[index]!;
    const credential = decodeJws(compact);
    if (!credential) {
      issuerErrors.push('Presented credential could not be decoded');
      continue;
    }
    if (credential.header.typ !== VC_TYP) {
      issuerErrors.push(
        `Presented credential header typ is '${String(credential.header.typ)}', expected '${VC_TYP}'`,
      );
      continue;
    }

    const issuer = issuerDidOf(credential.payload);
    const issuerKeyId = absoluteKeyId(
      credential.header.kid,
      issuer ? didOf(issuer) : null,
    );
    if (!issuerKeyId) {
      issuerErrors.push('Presented credential does not name the key that signed it');
    } else if (issuer && didOf(issuerKeyId) !== didOf(issuer)) {
      // ENFORCED HERE, not left to `resolveVerificationKey`. A relying party's
      // resolver SHOULD refuse a key id outside the DID it was asked about, but
      // this module cannot verify that every caller wrote that check, and the
      // consequence of one that did not is a forged credential reported as
      // genuine. The comparison costs nothing and is not delegable.
      issuerErrors.push(
        `Presented credential names '${issuer}' as its issuer but was signed by a key under ` +
          `'${didOf(issuerKeyId)}'`,
      );
    } else {
      try {
        const issuerKey = await options.resolveVerificationKey({
          kid: issuerKeyId,
          did: issuer ? didOf(issuer) : null,
          purpose: 'issuer',
        });
        const failure = await verifySignature(
          credential.jws,
          credential.header,
          issuerKey,
          algorithms,
        );
        if (failure) {
          issuerErrors.push(`Credential signature is not valid: ${failure}`);
        }
      } catch (error) {
        issuerErrors.push(
          `Credential issuer key '${issuerKeyId}' could not be resolved: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
    }

    // Claims come from the resolved disclosure walk, never from the raw
    // disclosure list. When that walk failed there is nothing safe to read, so
    // the remaining per-credential checks are recorded as failures rather than
    // attempted against unverified data.
    const claims = credentialClaims[index];
    if (!claims) {
      bindingErrors.push('Credential claims could not be resolved, so its holder binding cannot be checked');
      validityErrors.push('Credential claims could not be resolved, so its validity window cannot be checked');
      continue;
    }

    const bindingError = await checkHolderBinding(claims, holderKeyId, proverKey);
    if (bindingError) bindingErrors.push(bindingError);

    const validityError = checkValidityWindow(
      claims,
      credential.payload,
      nowSeconds,
      skewSeconds,
    );
    if (validityError) validityErrors.push(validityError);

    const cnf = claims.cnf as { kid?: unknown } | undefined;
    verified.push({
      claims: credentialClaimsOf(claims),
      envelope: compact,
      issuer,
      cnfKeyId: typeof cnf?.kid === 'string' ? cnf.kid : null,
    });
  }

  if (issuerErrors.length === 0 && verified.length === compacts.length) {
    checks.issuerSignature = true;
  } else {
    errors.push(...new Set(issuerErrors));
  }
  if (bindingErrors.length === 0 && verified.length === compacts.length) {
    checks.holderBinding = true;
  } else {
    errors.push(...new Set(bindingErrors));
  }
  if (validityErrors.length === 0 && verified.length === compacts.length) {
    checks.validityWindow = true;
  } else {
    errors.push(...new Set(validityErrors));
  }

  // `vpClaims` is resolved above so that a tampered presentation-level
  // disclosure is caught; nothing reads it, because every claim a verifier acts
  // on belongs to a credential rather than to the envelope around it.
  void vpClaims;

  const isValid = Object.values(checks).every(Boolean);
  return {
    isValid,
    errors,
    checks,
    notChecked: NOT_CHECKED,
    credentials: isValid ? verified : [],
    holderKeyId,
  };
}

/**
 * Resolve a compact SD-JWT's claims through the vendored decoder.
 *
 * Throws `SdJwtDisclosureError` on an unmatched disclosure (divergence D3),
 * which is what makes this the disclosure-integrity check rather than merely a
 * decode step.
 */
async function resolveClaims(compact: string): Promise<Record<string, unknown>> {
  const sdJwt = await SDJwt.fromEncode(compact, webCryptoHasher);
  return sdJwt.getClaims<Record<string, unknown>>(webCryptoHasher);
}

/**
 * Reject a call that omitted a required input.
 *
 * Types do not reach a JavaScript caller, and the failure mode of a missing
 * `challenge` is not a crash — it is a replay check that silently compares
 * `undefined` to `undefined` and passes. Assert at the boundary instead.
 */
function assertOptions(options: VerifySdJwtPresentationOptions): void {
  const missing: string[] = [];
  if (typeof options?.presentation !== 'string' || options.presentation.length === 0) {
    missing.push('presentation');
  }
  if (typeof options?.challenge !== 'string' || options.challenge.length === 0) {
    missing.push('challenge');
  }
  if (typeof options?.audience !== 'string' || options.audience.length === 0) {
    missing.push('audience');
  }
  if (typeof options?.resolveVerificationKey !== 'function') {
    missing.push('resolveVerificationKey');
  }
  if (missing.length > 0) {
    throw new TypeError(
      `verifySdJwtPresentation is missing required option(s): ${missing.join(', ')}. None of them has a default — a verifier that does not supply its own challenge and audience is not performing a replay check.`,
    );
  }
  if (options.algorithms && options.algorithms.length === 0) {
    throw new TypeError(
      'verifySdJwtPresentation was given an empty algorithms allowlist, which would reject every signature. Omit the option to use the default.',
    );
  }
}
