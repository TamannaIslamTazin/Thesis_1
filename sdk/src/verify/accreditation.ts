/**
 * Verify ONE hop of a delegation chain — the piece #262 named as missing.
 *
 * WHY THIS EXISTS. `validateAccreditationChain` decides ENTITLEMENT, not
 * authenticity, and says so in its own contract: every link handed to it must
 * ALREADY have had its signature and revocation verified by the caller. Nothing
 * did that, so no caller could ever supply a chain, and `authoriseProfessional`
 * collapsed to "the issuer must itself be a pinned root" — which is exactly the
 * gap that stops an L2 (hospital) from issuing anything a third party will
 * accept. This is the missing half: signature first, then the claims, then
 * revocation, and only then a link that the chain walk may trust.
 *
 * ORDER MATTERS. The payload is decoded before it is verified, because the
 * issuer in it decides which key to verify WITH — the same bootstrap every JWS
 * verifier performs. Nothing in the decoded payload is read as fact until
 * `compactVerify` has returned; the decode is for key selection only.
 */
import { compactVerify, decodeProtectedHeader, importJWK, type JWK } from 'jose';
import {
  AccreditationSubjectSchema,
  VERIFIABLE_ACCREDITATION_TYPE,
  type AccreditationLink,
} from '@ssi-healthcare/shared';
import { base64urlDecode } from '../vendor/sd-jwt/utils';

/** A public key for an accreditation's issuer, resolved by the caller. */
export interface AccreditationKeyResolver {
  /**
   * Return the issuer's public key, or throw. Throwing FAILS the link — a key
   * the resolver will not vouch for must never be skipped past.
   */
  resolvePublicJwk(params: { did: string; kid?: string }): Promise<JWK>;
}

/** Revocation, read the same way the licence path reads it. */
export interface AccreditationRevocationPort {
  check(status: unknown): Promise<{ checked: boolean; revoked: boolean; error?: string }>;
}

export type AccreditationLinkResult =
  | { readonly ok: true; readonly link: AccreditationLink }
  | { readonly ok: false; readonly reasons: readonly string[] };

/** The subset of a VC payload this verifier reads. */
interface DecodedAccreditation {
  issuer?: string | { id?: string };
  type?: string[];
  credentialSubject?: unknown;
  credentialStatus?: unknown;
}

// The vendored decoder, not `Buffer`: this file runs on the handset, where
// Buffer is not a global, and the vendored one already backs the rest of
// sdk/verify.
function base64UrlToJson(segment: string): DecodedAccreditation | null {
  try {
    return JSON.parse(base64urlDecode(segment)) as DecodedAccreditation;
  } catch {
    return null;
  }
}

function issuerOf(issuer: DecodedAccreditation['issuer']): string | null {
  if (typeof issuer === 'string') return issuer;
  if (issuer && typeof issuer === 'object' && typeof issuer.id === 'string') return issuer.id;
  return null;
}

export async function verifyAccreditationLink(params: {
  credential: string;
  resolveKey: AccreditationKeyResolver;
  revocation: AccreditationRevocationPort;
}): Promise<AccreditationLinkResult> {
  const reasons: string[] = [];

  const parts = params.credential.split('.');
  if (parts.length !== 3) {
    return { ok: false, reasons: ['Accreditation is not a compact JWS (three segments expected)'] };
  }

  const decoded = base64UrlToJson(parts[1]);
  if (!decoded) {
    return { ok: false, reasons: ['Accreditation payload is not readable JSON'] };
  }

  const issuerDid = issuerOf(decoded.issuer);
  if (!issuerDid) {
    return { ok: false, reasons: ['Accreditation names no issuer, so no key can be chosen'] };
  }

  // ------------------------------------------------------------------- type
  if (!Array.isArray(decoded.type) || !decoded.type.includes(VERIFIABLE_ACCREDITATION_TYPE)) {
    return {
      ok: false,
      reasons: [
        `Credential is not a ${VERIFIABLE_ACCREDITATION_TYPE} (it is ${
          Array.isArray(decoded.type) ? decoded.type.join(', ') : 'untyped'
        })`,
      ],
    };
  }

  // -------------------------------------------------------------- signature
  let kid: string | undefined;
  try {
    const header = decodeProtectedHeader(params.credential);
    if (typeof header.kid === 'string') kid = header.kid;
  } catch {
    return { ok: false, reasons: ['Accreditation header is not readable'] };
  }

  let key: JWK;
  try {
    key = await params.resolveKey.resolvePublicJwk({ did: issuerDid, kid });
  } catch (error) {
    return {
      ok: false,
      reasons: [
        `Could not resolve a key for '${issuerDid}': ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }

  let verifiedPayload: Uint8Array;
  try {
    const imported = await importJWK(key, 'EdDSA');
    const verified = await compactVerify(params.credential, imported);
    verifiedPayload = verified.payload;
  } catch (error) {
    return {
      ok: false,
      reasons: [
        `Accreditation signature did not verify against '${issuerDid}': ${
          error instanceof Error ? error.message : String(error)
        }`,
      ],
    };
  }

  // From here the bytes are the ones the issuer signed, so they may be read.
  let signed: DecodedAccreditation | null = null;
  try {
    signed = JSON.parse(new TextDecoder().decode(verifiedPayload)) as DecodedAccreditation;
  } catch {
    return { ok: false, reasons: ['Verified accreditation payload is not readable JSON'] };
  }
  if (!signed) {
    return { ok: false, reasons: ['Verified accreditation payload is empty'] };
  }

  // ----------------------------------------------------------------- claims
  const subject = AccreditationSubjectSchema.safeParse(signed.credentialSubject);
  if (!subject.success) {
    return {
      ok: false,
      reasons: [
        `Accreditation claims are malformed: ${subject.error.issues
          .map((issue) => `${issue.path.join('.') || '(root)'} ${issue.message}`)
          .join('; ')}`,
      ],
    };
  }

  // ------------------------------------------------------------- revocation
  const status = await params.revocation.check(signed.credentialStatus);
  if (!status.checked) {
    // An unreadable status list is a REFUSAL, never "not revoked" — the same
    // rule the licence path follows, and the same fail-open shape this codebase
    // keeps finding in itself.
    reasons.push(
      `Accreditation revocation could not be established (${status.error ?? 'no reason given'})`,
    );
  } else if (status.revoked) {
    reasons.push(`Accreditation by '${issuerDid}' has been revoked`);
  }

  if (reasons.length > 0) {
    return { ok: false, reasons };
  }

  return {
    ok: true,
    link: {
      issuerDid,
      id: subject.data.id,
      professions: subject.data.professions,
      scope: subject.data.scope,
      validFrom: subject.data.validFrom,
      validUntil: subject.data.validUntil,
    },
  };
}
