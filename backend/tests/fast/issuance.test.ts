/**
 * L1 identity/licence issuance (IDENTITY-VERIFICATION-API.md) — the pure
 * logic in `services/issuance.ts`: the wrapped-key shape guard, the
 * documents-satisfy-requirements check, the wrapped-key-targets-authority
 * structural check, and what an approval actually issues as claims.
 *
 * NOT COVERED HERE: the HTTP routes (`routes/issuance.ts`, `routes/authority.ts`)
 * and `middleware/requireAuthorityMember.ts`, all of which need a live
 * Postgres — see the round report for what was instead exercised manually
 * against the running stack.
 */
import { describe, it, expect } from 'vitest';

import {
  wrappedContentKeyShape,
  lockerCapabilityTokenShape,
  assertDocumentsSatisfyRequirements,
  assertWrappedKeyTargetsAuthority,
  assertCapabilityMatchesSubmission,
  buildApprovalCredentialClaims,
  type SubmittedDocument,
  type WrappedContentKey,
} from '../../src/services/issuance.js';
import { AppError } from '../../src/middleware/errorHandler.js';
import {
  DOCUMENT_TYPES,
  documentTypeById,
  type DocumentTypeDefinition,
  type LockerCapabilityToken,
} from '@ssi-healthcare/shared';

const HEALTH_CARD = documentTypeById('health-card')!;
const MEDICAL_LICENCE = documentTypeById('medical-licence')!;

const VALID_WRAPPED_KEY: WrappedContentKey = {
  version: 1,
  wrappedToVerificationMethodId: `${HEALTH_CARD.issuingAuthorityDid}#key-1`,
  ciphertext: 'Y2lwaGVydGV4dA',
  nonce: 'bm9uY2U',
};

describe('DOCUMENT_TYPES registry — the one place the routing lives', () => {
  it('has exactly the four types the brief names', () => {
    expect(DOCUMENT_TYPES.map((d) => d.id).sort()).toEqual(
      ['health-card', 'medical-licence', 'nursing-licence', 'pharmacy-licence'].sort(),
    );
  });

  it('every id is unique', () => {
    const ids = DOCUMENT_TYPES.map((d) => d.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('documentTypeById returns undefined for an unknown id, never throws', () => {
    expect(documentTypeById('passport')).toBeUndefined();
  });
});

describe('wrappedContentKeyShape — validates structure, never opens the envelope', () => {
  it('accepts a well-formed key', () => {
    expect(wrappedContentKeyShape.safeParse(VALID_WRAPPED_KEY).success).toBe(true);
  });

  const malformed: ReadonlyArray<readonly [string, unknown]> = [
    ['wrong version', { ...VALID_WRAPPED_KEY, version: 2 }],
    ['missing ciphertext', { ...VALID_WRAPPED_KEY, ciphertext: undefined }],
    ['empty wrappedToVerificationMethodId', { ...VALID_WRAPPED_KEY, wrappedToVerificationMethodId: '' }],
    ['not an object at all', 'just a string'],
  ];

  it.each(malformed)('refuses %s', (_label, input) => {
    expect(wrappedContentKeyShape.safeParse(input).success).toBe(false);
  });
});

describe('assertDocumentsSatisfyRequirements', () => {
  const validDoc: SubmittedDocument = {
    lockerObjectId: 'obj-1',
    contentHash: 'a'.repeat(64),
    mediaType: 'image/jpeg',
  };

  it('accepts a submission meeting the document type requirement', () => {
    expect(() => assertDocumentsSatisfyRequirements(HEALTH_CARD, [validDoc])).not.toThrow();
  });

  it('refuses fewer documents than the type requires', () => {
    expect(() => assertDocumentsSatisfyRequirements(HEALTH_CARD, [])).toThrow(AppError);
  });

  it('refuses an unsupported media type', () => {
    expect(() =>
      assertDocumentsSatisfyRequirements(HEALTH_CARD, [{ ...validDoc, mediaType: 'application/zip' }]),
    ).toThrow(AppError);
  });

  it('the media-type guard actually gates — deleting it would let a zip through', () => {
    // Same check as above, written out so it is legible as a regression test:
    // if `assertDocumentsSatisfyRequirements` stopped checking `mediaType`
    // against `requiredDocuments[].acceptedMediaTypes`, this would go green
    // for a payload that should be refused. Verified by hand that removing
    // the `.filter((doc) => !accepted.has(doc.mediaType))` guard in
    // services/issuance.ts turns this test red (was: passes because no
    // AppError is thrown; after the guard is removed: fails because none is
    // thrown) — restored afterwards.
    const zipBomb: SubmittedDocument = { ...validDoc, mediaType: 'application/zip' };
    expect(() => assertDocumentsSatisfyRequirements(HEALTH_CARD, [zipBomb])).toThrow(AppError);
  });
});

describe('assertWrappedKeyTargetsAuthority', () => {
  it('accepts a verification method id anchored to the document type\'s authority DID', () => {
    expect(() => assertWrappedKeyTargetsAuthority(HEALTH_CARD, VALID_WRAPPED_KEY)).not.toThrow();
  });

  it('refuses a key wrapped to a DIFFERENT authority than the document type names', () => {
    const wrongTarget: WrappedContentKey = {
      ...VALID_WRAPPED_KEY,
      wrappedToVerificationMethodId: `${MEDICAL_LICENCE.issuingAuthorityDid}#key-1`,
    };
    // Submitting a health-card request with a key wrapped to BMDC's DID
    // instead of the ministry's must be refused.
    expect(() => assertWrappedKeyTargetsAuthority(HEALTH_CARD, wrongTarget)).toThrow(AppError);
  });

  it('refuses a verification method id with no authority prefix at all', () => {
    const bareFragment: WrappedContentKey = { ...VALID_WRAPPED_KEY, wrappedToVerificationMethodId: '#key-1' };
    expect(() => assertWrappedKeyTargetsAuthority(HEALTH_CARD, bareFragment)).toThrow(AppError);
  });
});

describe('buildApprovalCredentialClaims — health card', () => {
  it('returns a thin, self-attesting subject; no claims body is required', () => {
    const subject = buildApprovalCredentialClaims(HEALTH_CARD, 'did:cheqd:bdhealthtestnet:holder', undefined);
    expect(subject.id).toBe('did:cheqd:bdhealthtestnet:holder');
    expect(subject.verificationMethod).toBe('nid-record-comparison');
    expect(typeof subject.verifiedAt).toBe('string');
    expect(Number.isNaN(Date.parse(subject.verifiedAt as string))).toBe(false);
  });
});

describe('buildApprovalCredentialClaims — professional licence', () => {
  const holderDid = 'did:cheqd:bdhealthtestnet:holder';

  const validClaims = {
    licenceNumber: 'BMDC-A-45123',
    register: 'BMDC Register',
    practiceScope: ['view-patient-record', 'prescribe'],
    licenceValidFrom: '2026-01-01T00:00:00.000Z',
    licenceValidUntil: '2027-01-01T00:00:00.000Z',
  };

  it('accepts claims that narrow the accrediting council\'s mandate, and fills in the profession', () => {
    const subject = buildApprovalCredentialClaims(MEDICAL_LICENCE, holderDid, validClaims);
    expect(subject).toMatchObject({ id: holderDid, profession: 'doctor', licenceNumber: 'BMDC-A-45123' });
  });

  it('refuses when claims are entirely missing', () => {
    expect(() => buildApprovalCredentialClaims(MEDICAL_LICENCE, holderDid, undefined)).toThrow(AppError);
  });

  it('refuses practiceScope outside BMDC\'s maxScope — the narrowing guard is load-bearing', () => {
    // BMDC's pinned maxScope (accreditation/index.ts) does not include
    // 'dispense'. Verified by hand that commenting out the `narrowsScope`
    // check in buildApprovalCredentialClaims turns this test red — an
    // officer's approve() body could then mint a doctor's licence carrying a
    // pharmacist-only scope. Restored afterwards.
    const overReaching = { ...validClaims, practiceScope: ['dispense'] };
    expect(() => buildApprovalCredentialClaims(MEDICAL_LICENCE, holderDid, overReaching)).toThrow(AppError);
  });

  it('refuses licenceValidFrom on or after licenceValidUntil', () => {
    const invertedWindow = {
      ...validClaims,
      licenceValidFrom: '2027-01-01T00:00:00.000Z',
      licenceValidUntil: '2026-01-01T00:00:00.000Z',
    };
    expect(() => buildApprovalCredentialClaims(MEDICAL_LICENCE, holderDid, invertedWindow)).toThrow(AppError);
  });

  it('refuses an unrecognised practiceScope value rather than passing it through', () => {
    const bogusScope = { ...validClaims, practiceScope: ['perform-surgery-unsupervised'] };
    expect(() => buildApprovalCredentialClaims(MEDICAL_LICENCE, holderDid, bogusScope)).toThrow(AppError);
  });

  it('every licence document type resolves to a pinned trust root — approval cannot 500 on a misconfigured registry entry', () => {
    for (const documentType of DOCUMENT_TYPES) {
      if (documentType.credentialType !== MEDICAL_LICENCE.credentialType) continue;
      expect(() => buildApprovalCredentialClaims(documentType, holderDid, validClaims)).not.toThrow(
        /not a pinned trust root/,
      );
    }
  });
});

describe('assertCapabilityMatchesSubmission — OFFICER-DOCUMENT-ACCESS.md §6a', () => {
  const holderDid = 'did:cheqd:bdhealthtestnet:holder';
  const requestId = 'req_abcdefghijklmnop';
  const doc: SubmittedDocument = { lockerObjectId: 'obj-1', contentHash: 'a'.repeat(64), mediaType: 'image/jpeg' };

  function validToken(overrides: Partial<LockerCapabilityToken['claims']> = {}): LockerCapabilityToken {
    return {
      claims: {
        iss: holderDid,
        aud: HEALTH_CARD.issuingAuthorityDid,
        obj: [doc.lockerObjectId],
        sub: requestId,
        jti: 'jti-1',
        nbf: 0,
        exp: 9999999999,
        ...overrides,
      },
      signature: 'c2ln',
      verificationMethodId: `${holderDid}#key-1`,
    };
  }

  it('accepts a capability consistent with its submission', () => {
    expect(() =>
      assertCapabilityMatchesSubmission({
        documentType: HEALTH_CARD,
        holderDid,
        requestId,
        documents: [doc],
        capability: validToken(),
      }),
    ).not.toThrow();
  });

  it('refuses when iss is not the caller\'s own DID', () => {
    // Regression for a capability minted for one holder being attached to
    // another holder's submission — verified by hand that removing this
    // check (commenting the `claims.iss !== args.holderDid` branch) lets the
    // call below through silently; restored afterwards.
    expect(() =>
      assertCapabilityMatchesSubmission({
        documentType: HEALTH_CARD,
        holderDid,
        requestId,
        documents: [doc],
        capability: validToken({ iss: 'did:cheqd:bdhealthtestnet:someone-else' }),
      }),
    ).toThrow(AppError);
  });

  it('refuses when aud does not name the document type\'s issuing authority', () => {
    expect(() =>
      assertCapabilityMatchesSubmission({
        documentType: HEALTH_CARD,
        holderDid,
        requestId,
        documents: [doc],
        capability: validToken({ aud: MEDICAL_LICENCE.issuingAuthorityDid }),
      }),
    ).toThrow(AppError);
  });

  it('refuses when sub does not name this submission', () => {
    expect(() =>
      assertCapabilityMatchesSubmission({
        documentType: HEALTH_CARD,
        holderDid,
        requestId,
        documents: [doc],
        capability: validToken({ sub: 'a-different-request' }),
      }),
    ).toThrow(AppError);
  });

  it('refuses when obj does not cover every attached document', () => {
    // The load-bearing guard step 5 of OFFICER-DOCUMENT-ACCESS.md §3 names:
    // a capability must not admit reading an object it never listed.
    expect(() =>
      assertCapabilityMatchesSubmission({
        documentType: HEALTH_CARD,
        holderDid,
        requestId,
        documents: [doc, { ...doc, lockerObjectId: 'obj-2' }],
        capability: validToken({ obj: ['obj-1'] }),
      }),
    ).toThrow(AppError);
  });

  it('rejects malformed claims via lockerCapabilityTokenShape before assertCapabilityMatchesSubmission ever runs', () => {
    expect(lockerCapabilityTokenShape.safeParse({ ...validToken(), claims: { ...validToken().claims, obj: [] } }).success).toBe(false);
    expect(lockerCapabilityTokenShape.safeParse(validToken()).success).toBe(true);
  });
});

describe('buildApprovalCredentialClaims — unknown credential type', () => {
  it('fails closed rather than issuing claims for a type it does not recognise', () => {
    const bogusType: DocumentTypeDefinition = {
      ...HEALTH_CARD,
      id: 'bogus',
      credentialType: 'SomeUnregisteredCredential',
    };
    expect(() => buildApprovalCredentialClaims(bogusType, 'did:cheqd:bdhealthtestnet:holder', undefined)).toThrow(
      AppError,
    );
  });
});
