/**
 * SSI Healthcare Backend - JWT-VC Encoding Helpers
 *
 * Every credential this system issues is signed with `ClaimFormat.JwtVc`, so
 * the authoritative artifact for a credential is a compact JWT string. This
 * module is the single place that knows how to move between that compact form
 * and the W3C Verifiable Credential JSON that clients consume.
 *
 * WHY THIS MODULE EXISTS
 * ----------------------
 * `agent.w3cCredentials.signCredential({ format: ClaimFormat.JwtVc, ... })`
 * returns a Credo `W3cJwtVerifiableCredential` instance. That class has **no**
 * `toJson()` method — its only own enumerable properties are `jwt` and the
 * private `_credential`. Both issuance paths did:
 *
 *     signed.toJson ? signed.toJson() : (signed as VerifiableCredential)
 *
 * `signed.toJson` is always `undefined`, so both fell through to the cast and
 * persisted a dump of Credo's internal class shape:
 *
 *     { "jwt": { "serializedJwt": "...", "payload": {...}, "header": {...},
 *                "signature": { "type": "Buffer", "data": [...] } },
 *       "_credential": { "context": [...],
 *                        "credentialSubject": { "id": "...", "claims": {...} } } }
 *
 * That object has no `@context`, no `credentialSubject` and no `issuer` at the
 * top level, which is precisely why every reader of `credentialData` — the
 * wallet transform, the OID4VP share sheet, the pharmacy prescription check and
 * the ZKP attribute resolver — silently found nothing.
 *
 * Note the shape is also lossy in the other direction: Credo nests subject
 * claims under `_credential.credentialSubject.claims`, which is Credo's
 * in-memory model, not the W3C data model. Reconstructing from the JWT payload
 * avoids inheriting that quirk.
 */

import { VC_CONTEXTS, ERROR_CODES, type VerifiableCredential } from '@ssi-healthcare/shared';
import { AppError } from '../middleware/errorHandler.js';
import {
  W3cV2JwtVerifiableCredential,
  W3cV2JwtVerifiablePresentation,
  // `W3cJsonLdVerifiablePresentation` and `JsonTransformer` are no longer
  // imported: their only use was `toJsonLdVerifiablePresentation`, retired with
  // the JSON VP branch. Restore both if Data Integrity support is implemented.
} from '@credo-ts/core';
import { sdJwtVcToW3cJson, envelopedCredentialToSdJwt } from './sdJwtVc.js';
import { logger } from '../utils/logger.js';

/** Proof type used to carry a compact JWT-VC inside W3C JSON. */
export const JWT_PROOF_TYPE = 'JwtProof2020';

/**
 * Decode a compact JWT's payload without verifying its signature.
 *
 * Verification is a separate concern handled by the Credo agent (internal
 * issuance) or JWKS (external issuance). This function only reads.
 */
export function decodeJwtPayload(rawJwt: string): Record<string, unknown> | null {
  return decodeJwtSegment(rawJwt, 1);
}

/**
 * Decode a compact JWT's protected header without verifying its signature.
 *
 * The header is how this module tells the two data models apart: Credo stamps
 * `typ: 'JWT'` on a VC 1.1 credential and `typ: 'vc+jwt'` on a VC 2.0 one.
 */
export function decodeJwtHeader(rawJwt: string): Record<string, unknown> | null {
  return decodeJwtSegment(rawJwt, 0);
}

function decodeJwtSegment(rawJwt: string, index: 0 | 1): Record<string, unknown> | null {
  const parts = rawJwt.split('.');
  if (parts.length !== 3) return null;

  try {
    const segment = parts[index] as string;
    const padded = segment + '='.repeat((4 - (segment.length % 4)) % 4);
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf-8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** `typ` header value Credo stamps on a VC 2.0 enveloped credential. */
export const VC_JWT_TYP_V2 = 'vc+jwt';

/**
 * Decide which data model a compact JWT-VC encodes.
 *
 * WHY THIS EXISTS AT ALL — this is the trap this migration had to avoid.
 * The two encodings are structurally incompatible, and the v1 decoder applied
 * to a v2 credential does not throw. It returns a credential-shaped object with
 * every field empty: no `iss` means `issuer: ''`, no `jti` means `id: ''`, no
 * `nbf` means an epoch-0 date, no `vc` claim means `credentialSubject: {}`, and
 * the `@context` fallback stamps it v1. Silent, total data loss — exactly the
 * failure mode that let Credo class dumps sit in the database for months.
 *
 *   VC 1.1 (`typ: JWT`)          registered claims carry the credential:
 *     { iss, sub, jti, nbf, exp, vc: { '@context', type, credentialSubject } }
 *
 *   VC 2.0 (`typ: vc+jwt`)       the payload IS the credential, flattened:
 *     { '@context', id, type, issuer, validFrom, validUntil,
 *       credentialSubject, credentialStatus, iat, cnf? }
 *
 * See `W3cV2JwtCredentialService.signCredential`, which builds the payload as
 * `new JwtPayload({ additionalClaims: JsonTransformer.toJSON(credential) })` —
 * no `vc` wrapper and no registered-claim mapping. `W3cV2Credential` even
 * declares `vc?: never` to forbid the v1 shape outright.
 *
 * Detection order: the `typ` header is authoritative when present; otherwise
 * fall back on structure, since a `vc` claim is conclusive for v1 and a
 * top-level `@context` is conclusive for v2.
 */
export function detectVcJwtDataModel(
  header: Record<string, unknown> | null,
  payload: Record<string, unknown>,
): 'v1' | 'v2' {
  if (typeof header?.typ === 'string' && header.typ.toLowerCase() === VC_JWT_TYP_V2) return 'v2';
  if (payload.vc && typeof payload.vc === 'object') return 'v1';
  if (payload['@context']) return 'v2';
  return 'v1';
}

/**
 * Convert a compact JWT-VC into W3C Verifiable Credential JSON.
 *
 * Applies the JWT-VC decoding rules from the W3C VC Data Model: the registered
 * JWT claims take precedence over their `vc` counterparts, because the
 * registered claims are the ones covered by the signature in every profile.
 *
 *   `iss` -> `issuer`   `sub` -> `credentialSubject.id`
 *   `jti` -> `id`       `nbf` -> `issuanceDate`   `exp` -> `expirationDate`
 *
 * The compact JWT is preserved in `proof.jwt`. It — not this JSON — is what a
 * holder presents to a verifier; re-serialized JSON carries no signature.
 *
 * Returns `null` when the input is not a decodable JWT-VC. Callers decide
 * whether that is fatal; this function does not throw, because it runs inside
 * response mapping where one malformed row must not fail the whole list.
 */
export function jwtVcToW3cJson(rawJwt: string): VerifiableCredential | null {
  // AN SD-JWT MUST NOT REACH THE JWT RULES, and it does not announce itself by
  // failing. A compact SD-JWT is `header.payload.signature~d1~d2~`, which still
  // splits into exactly three `.`-separated segments — the tildes ride along on
  // the third. So `decodeJwtPayload` SUCCEEDS on one and returns the
  // issuer-signed payload, in which every selectively disclosable claim is an
  // opaque `_sd` digest instead of a value. The caller would receive a
  // structurally valid credential with the patient data replaced by hashes and
  // nothing anywhere reporting a problem.
  //
  // This is the same class of bug as the v1 decoder silently hollowing out a v2
  // credential (see `detectVcJwtDataModel`), one securing mechanism further
  // along. Route it to the module that owns the mechanism instead.
  if (rawJwt.includes('~')) return sdJwtVcToW3cJson(rawJwt);

  const payload = decodeJwtPayload(rawJwt);
  if (!payload) return null;

  const header = decodeJwtHeader(rawJwt);
  if (detectVcJwtDataModel(header, payload) === 'v2') {
    return v2JwtVcToW3cJson(rawJwt, payload);
  }

  const vcClaim = (payload.vc as Record<string, unknown> | undefined) ?? {};

  const subjectClaims = (vcClaim.credentialSubject as Record<string, unknown> | undefined) ?? {};
  const subjectId = typeof payload.sub === 'string' ? payload.sub : undefined;

  // Fallback context for a JWT-VC whose `vc` claim omits `@context`. It must
  // name v1: this function implements the VC-JWT 1.1 decoding rules, and the
  // issuance paths sign VC 1.1 (see the note in routes/oid4vci.ts). Defaulting
  // to v2 would stamp a v2 label onto a credential that is v1 in every other
  // respect — the same mislabelling that made issuance fail in the first place,
  // only silent here because nothing validates a reconstructed context.
  const context = Array.isArray(vcClaim['@context'])
    ? (vcClaim['@context'] as string[])
    : [VC_CONTEXTS.W3C_CREDENTIALS_V1];

  const type = Array.isArray(vcClaim.type) ? (vcClaim.type as string[]) : ['VerifiableCredential'];

  const issuer =
    typeof payload.iss === 'string'
      ? payload.iss
      : ((vcClaim.issuer as string | { id: string }) ?? '');

  // VC-JWT 1.1 maps `issuanceDate` to `nbf`, so that wins. But a great many
  // real issuers emit only `iat`, and the previous fallback chain ended at
  // `new Date(0)` — fabricating an issuance date of 1970-01-01 for those
  // credentials rather than admitting the date was unknown. That sentinel then
  // travelled into `Credential.issuedAt` as though it were fact.
  //
  // Read `iat` before giving up, and if there is genuinely no date anywhere,
  // omit the field. A caller that needs a validity start should fail on its
  // absence, not silently trust the Unix epoch.
  const issuanceDate =
    typeof payload.nbf === 'number'
      ? new Date(payload.nbf * 1000).toISOString()
      : ((vcClaim.issuanceDate as string | undefined) ??
        (typeof payload.iat === 'number'
          ? new Date(payload.iat * 1000).toISOString()
          : undefined));

  const expirationDate =
    typeof payload.exp === 'number'
      ? new Date(payload.exp * 1000).toISOString()
      : (vcClaim.expirationDate as string | undefined);

  const id =
    (typeof payload.jti === 'string' ? payload.jti : undefined) ??
    (vcClaim.id as string | undefined) ??
    '';

  return {
    '@context': context,
    id,
    type,
    issuer,
    ...(issuanceDate ? { issuanceDate } : {}),
    ...(expirationDate ? { expirationDate } : {}),
    credentialSubject: {
      ...subjectClaims,
      ...(subjectId ? { id: subjectId } : {}),
    },
    ...(vcClaim.credentialStatus
      ? { credentialStatus: vcClaim.credentialStatus as VerifiableCredential['credentialStatus'] }
      : {}),
    proof: { type: JWT_PROOF_TYPE, jwt: rawJwt },
  };
}

/**
 * JWT claims that belong to the envelope rather than to the credential.
 *
 * VC 2.0's enveloped form puts the credential at the top level of the payload,
 * so anything here that also appears there is JOSE metadata and must not be
 * copied into the credential. `cnf` is the holder binding, `iat` is stamped by
 * Credo at signing time; the rest are registered claims that other issuers may
 * add redundantly (vc-jose-cose permits it) and that carry no VC meaning.
 */
const ENVELOPE_ONLY_CLAIMS = new Set([
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
]);

/**
 * Decode a VC 2.0 enveloped (`vc+jwt`) credential into W3C JSON.
 *
 * The payload *is* the credential, so this is a strip-and-copy rather than the
 * claim remapping v1 needs. Two things it deliberately does not do:
 *
 *   - It does not synthesize `issuanceDate`/`expirationDate`. A VC 2.0
 *     credential's validity window is `validFrom`/`validUntil`, and inventing
 *     the v1 names would recreate the mislabelling this migration exists to
 *     remove. Readers use `credentialValidFrom()` / `credentialValidUntil()`.
 *   - It does not attach a `proof`. In VC 2.0 the JWT is an *enveloping* proof:
 *     it wraps the credential instead of being a member of it. Stuffing the JWT
 *     into `proof.jwt` would produce a credential that claims an embedded proof
 *     it does not have. The envelope is carried alongside instead — see
 *     `WalletCredential.credentialJwt` and the `credentialJwt` column.
 */
function v2JwtVcToW3cJson(
  rawJwt: string,
  payload: Record<string, unknown>,
): VerifiableCredential | null {
  const credential: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (ENVELOPE_ONLY_CLAIMS.has(key)) continue;
    credential[key] = value;
  }

  // A VC 2.0 credential without these is not a credential. Returning null lets
  // the caller fail loudly rather than persist an empty husk — the exact
  // outcome the v1 decoder used to produce silently for v2 input.
  const context = credential['@context'];
  if (!Array.isArray(context) || context.length === 0) {
    logger.error('VC 2.0 JWT payload has no @context — refusing to decode', {
      jwtPrefix: rawJwt.slice(0, 16),
    });
    return null;
  }
  if (!credential.credentialSubject || typeof credential.credentialSubject !== 'object') {
    logger.error('VC 2.0 JWT payload has no credentialSubject — refusing to decode', {
      jwtPrefix: rawJwt.slice(0, 16),
    });
    return null;
  }

  return credential as unknown as VerifiableCredential;
}

/**
 * Extract the compact JWT from whatever `signCredential` returned.
 *
 * Credo exposes it as `serializedJwt` and (identically) `encoded` on
 * `W3cJwtVerifiableCredential`. Both are getters on the prototype, so they
 * survive property access but not `JSON.stringify` — read them here, before the
 * value is ever serialized.
 */
export function extractSerializedJwt(signed: unknown): string | null {
  if (typeof signed === 'string') return signed;
  if (!signed || typeof signed !== 'object') return null;

  const candidate = signed as { serializedJwt?: unknown; encoded?: unknown; jwt?: { serializedJwt?: unknown } };

  if (typeof candidate.serializedJwt === 'string') return candidate.serializedJwt;
  if (typeof candidate.encoded === 'string') return candidate.encoded;
  if (candidate.jwt && typeof candidate.jwt.serializedJwt === 'string') return candidate.jwt.serializedJwt;

  return null;
}

/**
 * Normalize a freshly signed credential into the W3C JSON that gets persisted
 * in `Credential.credentialData`.
 *
 * Throws when the signed credential yields neither a compact JWT nor usable
 * W3C JSON: storing an unreadable blob is worse than failing issuance loudly,
 * because the failure would only surface later in the holder's wallet.
 */
export function signedCredentialToStoredJson(signed: unknown): VerifiableCredential {
  const serializedJwt = extractSerializedJwt(signed);

  if (serializedJwt) {
    const w3c = jwtVcToW3cJson(serializedJwt);
    if (w3c) return w3c;
    logger.error('Signed JWT-VC could not be decoded into W3C JSON');
  }

  // Data Integrity (non-JWT) proofs already are W3C JSON.
  if (signed && typeof signed === 'object' && '@context' in (signed as object)) {
    return signed as VerifiableCredential;
  }

  throw new Error('Signed credential is neither a JWT-VC nor W3C JSON — refusing to store');
}

/**
 * Read a persisted `Credential.credentialData` value back as W3C JSON.
 *
 * Tolerates the three shapes this column has actually held:
 *   1. W3C JSON — what `signedCredentialToStoredJson` and
 *      `storeExternalCredential` write.
 *   2. A compact JWT string.
 *   3. The Credo `W3cJwtVerifiableCredential` class dump described at the top
 *      of this file, written by the two issuance paths before they were fixed.
 *      Rows in that shape are recovered through their embedded
 *      `jwt.serializedJwt`, which is intact and signed.
 *
 * Returns `null` for anything else rather than throwing, so a single corrupt
 * row cannot take down a wallet listing.
 */
export function storedCredentialToW3cJson(stored: unknown): VerifiableCredential | null {
  if (!stored) return null;

  if (typeof stored === 'string') return jwtVcToW3cJson(stored);

  if (typeof stored !== 'object') return null;

  const record = stored as Record<string, unknown>;

  // Shape 1: already W3C JSON.
  if ('@context' in record && 'credentialSubject' in record) {
    return record as unknown as VerifiableCredential;
  }

  // Shape 3: Credo class dump — recover from the embedded compact JWT.
  const embeddedJwt = extractSerializedJwt(record);
  if (embeddedJwt) return jwtVcToW3cJson(embeddedJwt);

  return null;
}

/** `typ` header value Credo stamps on a VC 2.0 enveloped presentation. */
export const VP_JWT_TYP_V2 = 'vp+jwt';

/**
 * Resolve the holder binding to attach to a credential at issuance.
 *
 * WHAT THIS BUYS, AND WHY IT IS NOT OPTIONAL IN PRACTICE.
 *
 * 1. Security: it makes the credential holder-bound rather than BEARER. Without
 *    a `cnf` claim, anyone who obtains the compact JWT can present it as their
 *    own — the credential names its subject but nothing ties presentation to
 *    possession of the subject's key.
 *
 * 2. It is what makes VC 2.0 presentations possible AT ALL in Credo 0.6.
 *    `W3cV2JwtCredentialService.signPresentation` derives the signing key by
 *    calling `extractHolderFromPresentationCredentials`, which reads the
 *    binding off the credential being presented and throws
 *    "No holder binding found in credential included in presentation" when
 *    there is none. An unbound v2 credential is therefore unpresentable.
 *
 * 3. It is the same `cnf` mechanism SD-JWT key binding uses next round, so
 *    doing it here does not have to be redone.
 *
 * Credo requires an ABSOLUTE did URL for `cnf.kid` — `parseHolderBindingFromCredential`
 * rejects anything without a `did:` prefix and a `#` fragment.
 *
 * WHY THIS RETURNS A REASON AND NOT `null`.
 *
 * This used to return `binding | null`, and both callers logged a warning and
 * issued anyway. That produced an HTTP 200 carrying a credential that Credo
 * 0.6 will refuse to present — permanently, for the life of the credential —
 * with nothing in the response, the row, or the wire contract recording it. The
 * holder discovered it at presentation time, disconnected from the cause.
 *
 * Callers now fail closed. For that to be actionable they must be able to tell
 * two very different situations apart, which `null` collapsed into one:
 *
 *   - `resolution-failed`  the ledger or resolver did not answer. This is
 *                          plausibly TRANSIENT — the localnet is down, the
 *                          network blipped. Retrying may well succeed, so the
 *                          caller should say "try again" (503), not "your
 *                          request is wrong".
 *   - `no-binding-key`     the DID resolved fine and simply has no key we can
 *                          bind to. This is PERMANENT and retrying is futile;
 *                          the holder's DID document has to change (400).
 *
 * Collapsing these would mean a wallet retrying forever against a malformed
 * DID, or giving up permanently on a five-second outage.
 */
export type HolderBindingFailureReason = 'resolution-failed' | 'no-binding-key';

export type HolderBindingResult =
  | { ok: true; binding: { method: 'did'; didUrl: string } }
  | { ok: false; reason: HolderBindingFailureReason; detail: string };

/**
 * DID resolution errors that are a DEFINITIVE answer about the DID itself.
 *
 * The rule that separates transient from permanent here is: did the resolver
 * ANSWER? A resolver that says `notFound` or `invalidDid` has looked and told
 * us the DID is not usable — retrying changes nothing until the holder changes
 * their DID. A resolver that throws, times out, or returns neither a document
 * nor an error code has not answered at all, and "we could not check" must not
 * be reported to the holder as "your DID is wrong".
 *
 * Values are from the W3C DID Resolution spec's error registry.
 *
 * `notFound` IS DELIBERATELY NOT IN THIS SET, and that is a measured decision
 * rather than a cautious one. Resolving an unregistered DID against the cheqd
 * resolver returns:
 *
 *     { error: 'notFound', message: "... Error: Invalid DID" }
 *
 * and resolving the SAME DID with the ledger container stopped returns a
 * byte-identical response. The resolver cannot distinguish "this DID does not
 * exist" from "I could not reach the ledger", so neither can we. Treating
 * `notFound` as definitive would tell a holder their DID is permanently
 * unusable (400, do not retry) during a routine ledger outage — the exact
 * misclassification this split exists to prevent.
 *
 * The remaining values cannot be produced by an outage: they describe the DID
 * string or an explicit tombstone, both of which require an actual answer.
 */
const DEFINITIVE_RESOLUTION_ERRORS = new Set([
  'invalidDid',
  'invalidDidUrl',
  // Both spellings: 'methodNotSupported' is the W3C value, 'unsupportedDidMethod' is what Credo 0.6 emits.
  'methodNotSupported',
  'unsupportedDidMethod',
  'deactivated',
]);

export async function resolveHolderBinding(
  agent: {
    dids: {
      resolve: (
        did: string,
      ) => Promise<{ didDocument?: unknown; didResolutionMetadata?: unknown }>;
    };
  },
  holderDid: string,
): Promise<HolderBindingResult> {
  let result: { didDocument?: unknown; didResolutionMetadata?: unknown };
  try {
    result = await agent.dids.resolve(holderDid);
  } catch (error) {
    // The resolver threw. We genuinely do not know whether this DID is bad or
    // the ledger is unreachable, and the safe reading of "we could not check"
    // is the retryable one.
    const detail = error instanceof Error ? error.message : String(error);
    logger.warn('Holder DID resolution threw — cannot bind credential', { holderDid, detail });
    return { ok: false, reason: 'resolution-failed', detail };
  }

  try {
    const didDocument = result.didDocument as
      | {
          authentication?: Array<string | { id: string }>;
          assertionMethod?: Array<string | { id: string }>;
          verificationMethod?: Array<{ id: string }>;
        }
      | undefined;

    if (!didDocument) {
      // Distinguish "the resolver told us this DID is not usable" from "the
      // resolver did not tell us anything". Only the former is the holder's
      // problem to fix; the latter may clear on its own.
      const meta = result.didResolutionMetadata as
        | { error?: string; message?: string }
        | undefined;
      const resolverError = meta?.error;

      if (resolverError && DEFINITIVE_RESOLUTION_ERRORS.has(resolverError)) {
        return {
          ok: false,
          reason: 'no-binding-key',
          detail: `resolver reported '${resolverError}'${meta?.message ? `: ${meta.message}` : ''}`,
        };
      }

      return {
        ok: false,
        reason: 'resolution-failed',
        detail: resolverError
          ? `resolver reported '${resolverError}' (not a definitive answer about the DID)`
          : 'resolver returned no DID document and no error code',
      };
    }

    // Prefer `authentication`: presenting is an authentication act, and that is
    // the purpose Credo dereferences the holder key against when verifying a
    // presentation (`getVerificationMethodForJwt(..., ['authentication'])`).
    const candidate =
      didDocument.authentication?.[0] ??
      didDocument.assertionMethod?.[0] ??
      didDocument.verificationMethod?.[0];

    const rawId = typeof candidate === 'string' ? candidate : candidate?.id;
    if (!rawId) {
      return {
        ok: false,
        reason: 'no-binding-key',
        detail: 'DID document has no authentication, assertionMethod or verificationMethod entry',
      };
    }

    // Relative references (`#key-1`) are legal in a DID document but Credo
    // requires the absolute form here.
    const didUrl = rawId.startsWith('#') ? `${holderDid}${rawId}` : rawId;
    if (!didUrl.startsWith('did:') || !didUrl.includes('#')) {
      return {
        ok: false,
        reason: 'no-binding-key',
        detail: `verification method id is not an absolute DID URL: ${didUrl}`,
      };
    }

    return { ok: true, binding: { method: 'did', didUrl } };
  } catch (error) {
    // Shape-reading failed on a document we did receive. That is a property of
    // the document, not of the network, so it is not retryable.
    const detail = error instanceof Error ? error.message : String(error);
    logger.warn('Could not select a holder binding key from the DID document', {
      holderDid,
      detail,
    });
    return { ok: false, reason: 'no-binding-key', detail };
  }
}

/**
 * Refuse to issue a VC 2.0 credential that could never be presented.
 *
 * THE POLICY, AND WHY IT IS FAIL-CLOSED.
 *
 * An unbound v2 credential is not "slightly worse" than a bound one. It is a
 * bearer token that Credo 0.6 also refuses to place into a presentation at all,
 * so it cannot be used for the one thing a credential is for. Issuing it with
 * HTTP 200 does not give the holder a degraded credential; it gives them a
 * guaranteed future failure, at a moment and in a stack trace that point
 * nowhere near issuance. Refusing costs the holder one legible error now
 * instead of one illegible error later.
 *
 * Lives here, called by BOTH issuance paths, because the alternative is the
 * same policy expressed twice — and the two paths have already drifted apart
 * once on exactly this question.
 *
 * The two codes are deliberately distinct; see ERROR_CODES for why a client
 * must be able to tell "retry" from "your DID cannot work".
 */
export function assertHolderBound(
  result: HolderBindingResult,
  credentialId: string,
  holderDid: string,
): asserts result is { ok: true; binding: { method: 'did'; didUrl: string } } {
  if (result.ok) return;

  const isTransient = result.reason === 'resolution-failed';

  logger.error('Refusing to issue an unpresentable credential — holder binding failed', {
    credentialId,
    holderDid,
    reason: result.reason,
    detail: result.detail,
    retryable: isTransient,
  });

  throw new AppError(
    isTransient ? ERROR_CODES.HOLDER_BINDING_UNAVAILABLE : ERROR_CODES.HOLDER_BINDING_UNSUPPORTED,
    isTransient
      ? 'Could not resolve the holder DID to bind the credential to. This may be temporary — please retry.'
      : 'The holder DID has no key that a credential can be bound to. A credential issued to it could never be presented.',
    // 503 invites a retry; 400 says the request itself cannot succeed.
    isTransient ? 503 : 400,
    { reason: result.reason, holderDid },
  );
}

/**
 * Wrap a compact JWT in the Credo class its VC 2.0 API insists on.
 *
 * THE V1 AND V2 APIS DIFFER HERE AND THE DIFFERENCE IS RUNTIME-ONLY.
 * `agent.w3cCredentials.verifyCredential` accepts a compact JWT string and
 * deserializes it internally. `agent.w3cV2Credentials.verifyCredential` does
 * NOT: its dispatcher (`W3cV2CredentialService.verifyCredential`) branches on
 * `instanceof` and throws
 *
 *   "Unsupported credential type in options. Credential must be either a
 *    W3cV2JwtVerifiablePresentation or a W3cV2SdJwtVerifiablePresentation"
 *
 * for anything else — including the string that the inner
 * `W3cV2JwtCredentialService.verifyCredential` one level down would have
 * happily accepted. Both options types are declared `unknown`, so passing a
 * string typechecks perfectly and fails only when the code actually runs.
 *
 * Returns `null` rather than throwing when the input is not a well-formed
 * JWT-VC, so callers can record a verification failure instead of a 500.
 */
export function toV2VerifiableCredential(compactJwt: string): W3cV2JwtVerifiableCredential | null {
  try {
    return W3cV2JwtVerifiableCredential.fromCompact(compactJwt);
  } catch (error) {
    logger.warn('Compact JWT could not be read as a VC 2.0 credential', {
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

/*
 * RETIRED — NOT AN OVERSIGHT. See steno #192 and OpenDiscussion §P3.
 *
 * `toJsonLdVerifiablePresentation` wrapped a JSON-LD presentation object in the
 * Credo class its v1 API insists on. Its single caller was the JSON/ldp_vp
 * branch of `routes/oid4vp.ts`, which was removed because no JSON VP can verify
 * for the DIDs this system issues: our `did:cheqd` documents declare the
 * `jws-2020` context, which is not in Credo 0.6's cached document-loader set,
 * and they use `JsonWebKey2020` verification methods while Credo's Data
 * Integrity suites consume `Ed25519VerificationKey2018`. Two independent
 * blockers, both established by execution. Restoring this function alone
 * accomplishes nothing; it is useful only as part of implementing Data
 * Integrity proof support.
 *
 * The docstring is preserved verbatim below because the mismatch it documents
 * is a real Credo 0.6 trap that will bite again on any v1 API:
 *
 *   THE SAME RUNTIME-ONLY MISMATCH THE V2 PATH HAD, on the v1 path.
 *   `W3cCredentialService.verifyPresentation` dispatches purely on `instanceof`:
 *
 *       if (presentation instanceof W3cJsonLdVerifiablePresentation) ...
 *       if (presentation instanceof W3cJwtVerifiablePresentation
 *           || typeof presentation === 'string') ...
 *       throw new CredoError('Unsupported credential type in options. ...')
 *
 *   A plain parsed-JSON object satisfies neither branch, so it hits the throw
 *   every single time. The route passed `vp_token as unknown as string` — a cast
 *   that silenced the compiler without changing the runtime value — which made
 *   the JSON VP branch dead: every JSON presentation was rejected regardless of
 *   whether its signature was good.
 *
 *   Returns null when the object is not a readable presentation, which the
 *   caller must treat as a rejection rather than a pass.
 *
 * export function toJsonLdVerifiablePresentation(
 *   presentation: unknown,
 * ): W3cJsonLdVerifiablePresentation | null {
 *   try {
 *     if (typeof presentation !== 'object' || presentation === null) return null;
 *     return JsonTransformer.fromJSON(presentation, W3cJsonLdVerifiablePresentation);
 *   } catch (error) {
 *     logger.warn('Object could not be read as a JSON-LD verifiable presentation', {
 *       error: error instanceof Error ? error.message : String(error),
 *     });
 *     return null;
 *   }
 * }
 */

/** The presentation counterpart of {@link toV2VerifiableCredential}. */
export function toV2VerifiablePresentation(
  compactJwt: string,
): W3cV2JwtVerifiablePresentation | null {
  try {
    return W3cV2JwtVerifiablePresentation.fromCompact(compactJwt);
  } catch (error) {
    logger.warn('Compact JWT could not be read as a VC 2.0 presentation', {
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

/** A credential pulled out of a presentation, with the envelope that secures it. */
export interface PresentedCredential {
  /** The credential as W3C JSON, decoded from its envelope. */
  credential: VerifiableCredential;
  /**
   * The compact JWT that secures it, or `null` for an embedded-proof credential
   * presented as bare JSON. A `null` here means there is nothing to verify a
   * signature against — callers must treat that as a failure, not a pass.
   */
  envelopeJwt: string | null;
  /**
   * Whether `envelopeJwt` is a compact SD-JWT rather than a plain JWT.
   *
   * RECORDED, NEVER SNIFFED. A compact SD-JWT does not fail a JWT decoder — it
   * SUCCEEDS and hands back the issuer-signed payload with the disclosable
   * claims replaced by digests. A caller that guesses therefore gets a
   * well-formed credential with claims silently missing, which is the exact
   * shape of a bug that verifies clean. The reader is chosen by what the
   * envelope was decoded AS, here, once.
   */
  isSdJwt: boolean;
}

/**
 * Pull the credentials out of a compact JWT Verifiable Presentation.
 *
 * THIS IS THE FIX FOR A SILENT TOTAL BYPASS. The OID4VP path used to do
 * `jwt.decode(vp_token).verifiableCredential`, which is `undefined` for a VC 1.1
 * presentation because Credo nests the presentation under a `vp` claim
 * (`getJwtPayloadFromPresentation` in jwt-vc/presentationTransformer.mjs). The
 * per-credential loop therefore iterated an empty array and every check inside
 * it — expiry, type, signature, revocation — was skipped for every presentation
 * ever submitted, while the endpoint reported success.
 *
 * Fixing the nesting alone is not enough: in BOTH data models the entries are
 * not credential objects.
 *
 *   VC 1.1 (`typ: JWT`)     payload.vp.verifiableCredential
 *                           -> array of COMPACT JWT STRINGS
 *
 *   VC 2.0 (`typ: vp+jwt`)  payload.verifiableCredential   (top level)
 *                           -> array of EnvelopedVerifiableCredential objects,
 *                              each `{ '@context', type, id }` where `id` is a
 *                              `data:application/vc+jwt,<compact-jwt>` URI
 *
 * Either way the credential has to be decoded out of an envelope before any
 * field on it can be read. Returns `[]` for a presentation carrying none, which
 * callers must treat as a failed presentation rather than a vacuous pass.
 */
export function extractPresentationCredentials(vpJwt: string): PresentedCredential[] {
  const payload = decodeJwtPayload(vpJwt);
  if (!payload) return [];

  const header = decodeJwtHeader(vpJwt);
  const isV2 =
    (typeof header?.typ === 'string' && header.typ.toLowerCase() === VP_JWT_TYP_V2) ||
    (!payload.vp && Boolean(payload.verifiableCredential));

  const rawEntries = isV2
    ? payload.verifiableCredential
    : (payload.vp as Record<string, unknown> | undefined)?.verifiableCredential;

  if (!rawEntries) return [];

  const entries = Array.isArray(rawEntries) ? rawEntries : [rawEntries];
  const presented: PresentedCredential[] = [];

  for (const entry of entries) {
    // VC 1.1: the entry is the compact JWT itself.
    if (typeof entry === 'string') {
      const credential = jwtVcToW3cJson(entry);
      if (credential) presented.push({ credential, envelopeJwt: entry, isSdJwt: false });
      continue;
    }

    if (!entry || typeof entry !== 'object') continue;
    const record = entry as Record<string, unknown>;

    // VC 2.0: the entry is an EnvelopedVerifiableCredential whose `id` is a
    // data URI wrapping the compact JWT.
    const envelopeJwt = envelopedCredentialToJwt(record);
    if (envelopeJwt) {
      const credential = jwtVcToW3cJson(envelopeJwt);
      if (credential) presented.push({ credential, envelopeJwt, isSdJwt: false });
      continue;
    }

    // VC 2.0 SD-JWT: `data:application/vc+sd-jwt,<jwt>~<disclosure>~…`.
    //
    // This branch did not exist until 9 Sep 2026, and its absence is what made
    // selective disclosure unreachable over OID4VP: a holder who narrowed their
    // credential produced an envelope this loop DROPPED, so the presentation
    // arrived carrying no readable credentials and was rejected. The only shape
    // that got through was the whole, unnarrowed `vc+jwt` — the wallet was
    // pushed toward full disclosure by the verifier's own reader.
    const sdJwtEnvelope = envelopedCredentialToSdJwt(record);
    if (sdJwtEnvelope) {
      const credential = sdJwtVcToW3cJson(sdJwtEnvelope);
      if (credential) presented.push({ credential, envelopeJwt: sdJwtEnvelope, isSdJwt: true });
      continue;
    }

    // A bare credential object — a Data Integrity proof, or a non-conformant
    // sender. Kept so it can be checked and rejected downstream rather than
    // vanishing from the list the way the old code made everything vanish.
    if ('@context' in record && 'credentialSubject' in record) {
      presented.push({
        credential: record as unknown as VerifiableCredential,
        envelopeJwt: typeof (record.proof as { jwt?: unknown } | undefined)?.jwt === 'string'
          ? ((record.proof as { jwt: string }).jwt)
          : null,
        isSdJwt: false,
      });
    }
  }

  return presented;
}

/**
 * Read the compact JWT out of a VC 2.0 `EnvelopedVerifiableCredential`.
 *
 * The data URI form is `data:application/vc+jwt,<compact-jwt>`. Returns `null`
 * for anything else, INCLUDING `application/vc+sd-jwt`, which is decoded by
 * `envelopedCredentialToSdJwt` in `sdJwtVc.ts`.
 *
 * The two stay separate on purpose. Credo refuses to mix mechanisms within one
 * presentation, so a `vp+jwt` carrying an SD-JWT credential is malformed input;
 * a reader that quietly accepted both would turn that into a silent success.
 */
export function envelopedCredentialToJwt(entry: Record<string, unknown>): string | null {
  const id = entry.id;
  if (typeof id !== 'string' || !id.startsWith('data:')) return null;

  const commaIndex = id.indexOf(',');
  if (commaIndex === -1) return null;

  const mediaType = id.slice('data:'.length, commaIndex);
  if (mediaType !== 'application/vc+jwt') return null;

  const compact = id.slice(commaIndex + 1);
  return compact.length > 0 ? compact : null;
}

/**
 * Get the compact JWT that secures a stored credential, whichever data model
 * and whichever storage generation it belongs to.
 *
 * THE ONLY CORRECT WAY TO GET THE PRESENTABLE ARTIFACT. Callers used to read
 * `credentialData.proof.jwt` directly, which returns `undefined` for every VC
 * 2.0 credential — v2 has no embedded `proof` — and would have made every newly
 * issued credential unpresentable with no compile-time signal.
 *
 * Looks, in order:
 *   1. the `credentialJwt` column — VC 2.0's enveloping proof, and the
 *      authoritative location going forward;
 *   2. `credentialData.proof.jwt` — legacy VC 1.1 rows;
 *   3. the Credo class dump's embedded `jwt.serializedJwt` — pre-fix rows.
 */
export function credentialEnvelopeJwt(row: {
  credentialJwt?: string | null;
  credentialData?: unknown;
}): string | null {
  if (typeof row.credentialJwt === 'string' && row.credentialJwt.length > 0) {
    return row.credentialJwt;
  }

  const data = row.credentialData;
  if (!data) return null;
  if (typeof data === 'string') return data;
  if (typeof data !== 'object') return null;

  const record = data as Record<string, unknown>;

  const proof = record.proof as { type?: unknown; jwt?: unknown } | undefined;
  if (proof && typeof proof.jwt === 'string' && proof.jwt.length > 0) return proof.jwt;

  return extractSerializedJwt(record);
}
