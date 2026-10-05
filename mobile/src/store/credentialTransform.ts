/**
 * SSI Healthcare Mobile — WalletCredential -> mobile view model.
 *
 * WHY THIS IS ITS OWN MODULE.
 *
 * Mapping the wire contract onto the mobile view model is a different
 * responsibility from managing store state, and it is the one that has broken
 * repeatedly: reading `sdkCred.issuer` off the envelope, guessing the category
 * by substring, reading `issuanceDate` on a VC 2.0 credential, and dropping the
 * enveloping proof. Every one of those was invisible to the compiler and
 * unreachable from a test, because it lived inside a Zustand store that cannot
 * be imported without React Native present.
 *
 * Split out, this file imports no React Native and no storage, so the
 * transformation can be exercised directly against a real backend payload.
 */

import type { WalletCredential, WalletCredentialCategory } from '@ssi-healthcare/sdk';
import { authorityDisplayName, credentialValidFrom } from '@ssi-healthcare/sdk';
import type { Credential, CredentialCategory, Issuer } from '../types';

/** "prescribedBy" -> "Prescribed by"; "startDate" -> "Start date". */
function humaniseKey(key: string): string {
  const spaced = key.replace(/[_-]+/g, ' ').replace(/([a-z0-9])([A-Z])/g, '$1 $2').trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}

/**
 * Render a claim value as the string the holder reads.
 *
 * `String(value)` on a claim that is an object produced the literal text
 * "[object Object]" on the card. The prescription's `medication` and
 * `prescribedBy` ARE objects by schema, so this is the normal case rather than
 * an edge one. Nested values are spelled out instead of stringified. Nothing
 * here parses, rewrites or validates the claim — the signed credential is
 * untouched, so this cannot affect what a verifier checks.
 */
export function renderClaimValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    return value.map(renderClaimValue).filter((part) => part.length > 0).join(', ');
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(
      ([key, item]) => key !== 'id' && item !== null && item !== undefined && item !== '',
    );
    // A single-field wrapper — `{ name: 'Dr X' }` — reads as its value alone.
    if (entries.length === 1) return renderClaimValue(entries[0][1]);
    return entries.map(([key, item]) => `${humaniseKey(key)}: ${renderClaimValue(item)}`).join('\n');
  }
  return String(value);
}

/**
 * Map the server's storage category onto the mobile folder taxonomy.
 *
 * The category is authoritative data chosen at issuance. The previous
 * implementation ignored it and guessed by substring-matching the credential
 * type — a heuristic where `'identity'.includes('id')` also matched
 * `'ProvIDerCredential'`, and where a type array the server never sent
 * produced `''`, so everything fell through to `other`.
 */
const CATEGORY_BY_STORAGE_CATEGORY: Record<WalletCredentialCategory, CredentialCategory> = {
  BLOOD_WORK: 'lab_result',
  LAB_RESULTS: 'lab_result',
  PRESCRIPTIONS: 'prescription',
  VACCINATIONS: 'vaccination',
  IMAGING: 'medical_record',
  INSURANCE: 'insurance',
  IDENTITY: 'identity',
  PROFESSIONAL: 'identity',
  GENERAL: 'other',
};

/**
 * Map the server's lifecycle status onto the mobile status vocabulary.
 *
 * `status` is the only field that carries revocation. Deriving status purely
 * from `expirationDate`, as the previous implementation did, silently
 * displayed a revoked credential as `valid`.
 */
export function toMobileStatus(walletCred: WalletCredential): Credential['status'] {
  switch (walletCred.status) {
    case 'REVOKED':
    case 'SUSPENDED':
      return 'revoked';
    case 'EXPIRED':
      return 'expired';
    case 'PENDING':
      return 'pending';
    case 'ACTIVE':
    default:
      // The server marks rows EXPIRED lazily (a sweep job), so re-check the
      // date locally rather than trusting ACTIVE past the expiry instant.
      return walletCred.expiresAt && new Date(walletCred.expiresAt) < new Date()
        ? 'expired'
        : 'valid';
  }
}

/**
 * Transform a `WalletCredential` envelope into the mobile view model.
 *
 * The envelope has two halves and this function must read from the right one:
 * wallet metadata (`id`, `status`, `category`, `name`, timestamps) lives at the
 * top level, and the issuer's signed claims live under `credential`.
 *
 * The previous version read `sdkCred.issuer` and `sdkCred.credentialSubject`
 * off the top level. Neither field was ever on the wire, so
 * `typeof undefined === 'string'` was false and the very next line
 * dereferenced `undefined.id` — a TypeError on the first credential rendered.
 * The compiler could not see it because the SDK cast the response instead of
 * validating it; the SDK now validates against `WalletCredentialSchema`.
 */
export function transformCredential(walletCred: WalletCredential): Credential {
  const vc = walletCred.credential;

  // Put a NAME to the issuer. The VC string form carries only a DID, and a DID
  // is not something a holder recognises — the previous version left `name`
  // undefined for exactly that form, which the detail screen then rendered as
  // "Unknown Issuer" for a credential issued by the ministry itself. The
  // pinned authority literals are the only place a trustworthy name can come
  // from, and resolving it offline is what lets a credential be shown in a
  // basement with no signal.
  const issuerId = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
  const issuerObj: Issuer = {
    id: issuerId,
    name:
      (typeof vc.issuer === 'string' ? undefined : vc.issuer.name) ??
      authorityDisplayName(issuerId),
  };

  const category = CATEGORY_BY_STORAGE_CATEGORY[walletCred.category] ?? 'other';

  // The specific type is the last entry; the first is always the generic
  // "VerifiableCredential" marker.
  const specificType = walletCred.type[walletCred.type.length - 1] ?? 'VerifiableCredential';

  return {
    id: walletCred.id,
    type: specificType,
    category,
    issuer: issuerObj,
    // Read across both data models. VC 2.0 names this `validFrom`; only VC 1.1
    // has `issuanceDate`. Reading `vc.issuanceDate` directly — as this did
    // before the VC 2.0 migration — yielded `undefined` for every newly issued
    // credential, and `new Date(undefined)` renders as "Invalid Date" on the
    // card and the detail screen. Nothing would have failed to compile.
    issuanceDate: credentialValidFrom(vc) ?? walletCred.issuedAt,
    expirationDate: walletCred.expiresAt,
    status: toMobileStatus(walletCred),
    metadata: {
      displayName: walletCred.name,
      description: walletCred.description,
    },
    // Carry the enveloping proof through. VC 2.0 keeps the signature OUT of the
    // credential body, so `verifiableCredential` below is the unsigned data
    // model and this JWT is the only signed artifact that exists. Dropping it
    // here — as this did until now — left the wallet holding a credential it
    // could render but never present, and nothing failed to compile because the
    // unsigned data model is structurally a perfectly good credential.
    //
    // Undefined for pre-migration VC 1.1 rows, which carry their proof inline.
    ...(walletCred.credentialJwt ? { credentialJwt: walletCred.credentialJwt } : {}),
    // Pass the VC through as received. Re-assembling it field by field, as the
    // previous version did, silently dropped `credentialStatus` and rewrote
    // `@context` to a hard-coded v1 value — both of which a verifier checks.
    verifiableCredential: {
      ...vc,
      id: vc.id ?? walletCred.id,
      credentialSubject: {
        ...vc.credentialSubject,
        id: String(vc.credentialSubject.id ?? ''),
      },
    },
  };
}
