/**
 * Document-type routing for L1 identity and licence issuance
 * (IDENTITY-VERIFICATION-API.md §3, IDENTITY-AND-ISSUANCE-SPEC.md §2).
 *
 * The wallet shows a document-type dropdown; the type determines the
 * authority, the documents required and the credential issued on approval.
 * This is the ONE place that mapping lives. A wallet that hardcoded an
 * authority DID instead of reading it from here would drift from this table
 * the first time an authority DID changes.
 *
 * ---------------------------------------------------------------------------
 * WHY LICENCE TYPES POINT AT `PROFESSIONAL_TRUST_ROOTS`, NOT A SEPARATE LIST
 * ---------------------------------------------------------------------------
 * A credential issued here under `issuingAuthorityDid` is later checked by
 * `wasAuthorisedToAccredit`, which reads `PROFESSIONAL_TRUST_ROOTS`. Naming a
 * different DID for "the authority that issues medical licences" here than
 * the one verification checks against would make every licence this system
 * issues unverifiable by its own verifier. `licenceAuthority()` below reads
 * the trust-root literal directly rather than copying its `did` field, so the
 * two cannot drift.
 *
 * ---------------------------------------------------------------------------
 * WHY THE MINISTRY IS ITS OWN LITERAL AND NOT A FOURTH TRUST ROOT
 * ---------------------------------------------------------------------------
 * `AccreditationAuthority.professions` and `.maxScope` answer "what may this
 * body accredit a PROFESSIONAL to do" — a question that does not apply to a
 * ministry issuing an identity credential. Folding the ministry into
 * `PROFESSIONAL_TRUST_ROOTS` would mean either inventing a profession/scope
 * for it that means nothing, or teaching `wasAuthorisedToAccredit`'s callers
 * to special-case a fourth entry that never accredits anyone. A second literal
 * with its own narrower shape ({@link MinistryAuthority}) keeps the two
 * questions — "is this a professional accreditor" and "is this the health-card
 * issuer" — answerable without a runtime check on which kind of thing a root
 * is.
 */

import {
  PROFESSIONAL_TRUST_ROOTS,
  PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  deepFreeze,
} from '../accreditation/index.js';

// ---------------------------------------------------------------------------
// The ministry — identity, not accreditation
// ---------------------------------------------------------------------------

export interface MinistryAuthority {
  readonly did: string;
  readonly name: string;
  readonly shortName: string;
  /** True while the DID is a stand-in rather than the ministry's real DID. */
  readonly placeholder: boolean;
  /**
   * base64url raw X25519 public key — round 5's target for
   * `crypto/contentKeyWrap.ts`. See `AccreditationAuthority.contentKeyPublicKey`
   * for why this lives here and not on a DID document.
   */
  readonly contentKeyPublicKey: string;
}

/**
 * The ministry DID this deployment pins for health-card issuance.
 *
 * MINTED ON CHAIN 7 Sep 2026, replacing the all-zeros placeholder that resolved
 * to nothing and made `identityVerified` unreachable — `accept-offer` failed
 * with "not found: unknown request" because the issuer did not exist.
 *
 * Institution shape: self-controlled, three verification methods, so any one
 * officer key can act and a lost key is replaceable by a sibling (S-4 R1).
 * Read back from chain: not deactivated, all three methods in namespace.
 *
 * MINTED 7 Sep 2026. The three council DIDs in `accreditation/index.ts` are
 * chain-minted too as of 8 Sep 2026 (steno #420), so professional licences are
 * issuable and the placeholder flag is false.
 */
export const MINISTRY_OF_HEALTH: MinistryAuthority = deepFreeze({
  did: 'did:cheqd:bdhealthtestnet:5d3c6ffe-c151-4c30-9223-c86d24594753',
  name: 'Ministry of Health and Family Welfare',
  shortName: 'MOHFW',
  placeholder: false,
  // Matches the private seed in packages/issuer-console/.env.local
  // (ISSUER_CONTENT_KEY_X25519_SEED) — the only one of the four keys in this
  // file with a configured private half, since the console is single-tenant
  // (ISSUER_LOCKER_DID is likewise pinned to MOHFW only).
  contentKeyPublicKey: 'r3bdX_lL_l_YnQLz-KgDUCQ9vfk6IiHMt1u5oj5SsEk',
});

export const HEALTH_CARD_CREDENTIAL_TYPE = 'HealthCardCredential';

/**
 * Display name for a pinned authority DID, or undefined for anything else.
 *
 * A credential's `issuer` reaches the wallet as a bare DID string, and a DID is
 * not a name a holder recognises. Resolving it from the SAME pinned literals
 * that issuance routes on means the name shown to a holder cannot drift from
 * the authority the system trusts — and the wallet needs no network call to put
 * a name to its own issuer, which matters when the credential is shown offline.
 */
export function authorityDisplayName(did: string): string | undefined {
  if (did === MINISTRY_OF_HEALTH.did) return MINISTRY_OF_HEALTH.name;
  return PROFESSIONAL_TRUST_ROOTS.find((root) => root.did === did)?.name;
}

/**
 * The `credentialSubject` of a health-card credential.
 *
 * Deliberately thin. The officer's review compares the submitted document
 * against a record the ministry already holds (IDENTITY-AND-ISSUANCE-SPEC.md
 * §3.5) — the credential attests that the comparison was made, not a copy of
 * the record itself. Duplicating NID fields into the credential would put
 * PII into every verifier's hands that presents this credential asks for it,
 * for no verification benefit: "is this holder DID a verified persona" only
 * needs a yes, not the document that produced it.
 */
export interface HealthCardCredentialSubject {
  /** DID of the verified holder. Must equal the presentation's holder. */
  id: string;
  /** ISO 8601. When the officer confirmed the match. */
  verifiedAt: string;
  /** How the match was performed. One value today; kept as a string so a
   * future verification channel does not require a schema migration. */
  verificationMethod: 'nid-record-comparison';
}

// ---------------------------------------------------------------------------
// Required documents and the routing table
// ---------------------------------------------------------------------------

export interface RequiredDocumentSlot {
  readonly id: string;
  readonly label: string;
  readonly acceptedMediaTypes: readonly string[];
}

export interface DocumentTypeDefinition {
  readonly id: string;
  readonly label: string;
  readonly issuingAuthorityDid: string;
  readonly issuingAuthorityName: string;
  readonly credentialType: string;
  readonly requiredDocuments: readonly RequiredDocumentSlot[];
  /** True while the issuing authority's DID is a testnet stand-in. */
  readonly placeholder: boolean;
  /**
   * base64url raw X25519 public key the wallet wraps a submission's content
   * key to (`crypto/contentKeyWrap.ts`). See `MinistryAuthority.contentKeyPublicKey`
   * for why this travels here instead of via DID resolution.
   */
  readonly contentKeyPublicKey: string;
}

const SCAN_MEDIA_TYPES = ['image/jpeg', 'image/png', 'application/pdf'] as const;

/** The pinned trust root for one of the three councils, by its short name. Throws at module load if the literal it depends on ever drops a council, rather than routing licences to `undefined`. */
function licenceAuthority(shortName: 'BMDC' | 'BNMC' | 'PCB') {
  const authority = PROFESSIONAL_TRUST_ROOTS.find((root) => root.shortName === shortName);
  if (!authority) {
    throw new Error(`documentTypes.ts expected a pinned trust root named '${shortName}'`);
  }
  return authority;
}

export const DOCUMENT_TYPES: readonly DocumentTypeDefinition[] = deepFreeze([
  {
    id: 'health-card',
    label: 'Health Card',
    issuingAuthorityDid: MINISTRY_OF_HEALTH.did,
    issuingAuthorityName: MINISTRY_OF_HEALTH.name,
    credentialType: HEALTH_CARD_CREDENTIAL_TYPE,
    requiredDocuments: [
      {
        id: 'nid-scan',
        label: 'National ID card (front and back)',
        acceptedMediaTypes: SCAN_MEDIA_TYPES,
      },
    ],
    placeholder: MINISTRY_OF_HEALTH.placeholder,
    contentKeyPublicKey: MINISTRY_OF_HEALTH.contentKeyPublicKey,
  },
  {
    id: 'medical-licence',
    label: 'Medical Licence',
    issuingAuthorityDid: licenceAuthority('BMDC').did,
    issuingAuthorityName: licenceAuthority('BMDC').name,
    credentialType: PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
    requiredDocuments: [
      {
        id: 'registration-certificate',
        label: 'BMDC registration certificate',
        acceptedMediaTypes: SCAN_MEDIA_TYPES,
      },
    ],
    placeholder: licenceAuthority('BMDC').placeholder,
    contentKeyPublicKey: licenceAuthority('BMDC').contentKeyPublicKey,
  },
  {
    id: 'nursing-licence',
    label: 'Nursing Licence',
    issuingAuthorityDid: licenceAuthority('BNMC').did,
    issuingAuthorityName: licenceAuthority('BNMC').name,
    credentialType: PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
    requiredDocuments: [
      {
        id: 'registration-certificate',
        label: 'BNMC registration certificate',
        acceptedMediaTypes: SCAN_MEDIA_TYPES,
      },
    ],
    placeholder: licenceAuthority('BNMC').placeholder,
    contentKeyPublicKey: licenceAuthority('BNMC').contentKeyPublicKey,
  },
  {
    id: 'pharmacy-licence',
    label: 'Pharmacy Licence',
    issuingAuthorityDid: licenceAuthority('PCB').did,
    issuingAuthorityName: licenceAuthority('PCB').name,
    credentialType: PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
    requiredDocuments: [
      {
        id: 'registration-certificate',
        label: 'PCB registration certificate',
        acceptedMediaTypes: SCAN_MEDIA_TYPES,
      },
    ],
    placeholder: licenceAuthority('PCB').placeholder,
    contentKeyPublicKey: licenceAuthority('PCB').contentKeyPublicKey,
  },
] as const satisfies readonly DocumentTypeDefinition[]);

export function documentTypeById(id: string): DocumentTypeDefinition | undefined {
  return DOCUMENT_TYPES.find((documentType) => documentType.id === id);
}

/** True while any document type routes to a placeholder authority DID. Log it; do not ship on it. */
export const ISSUANCE_AUTHORITIES_ARE_PLACEHOLDERS: boolean = DOCUMENT_TYPES.some(
  (documentType) => documentType.placeholder,
);
