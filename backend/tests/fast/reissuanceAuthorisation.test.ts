/**
 * THE AUTHENTICATION OF AN IDENTITY RE-ISSUANCE — R5, research question 2.
 *
 * These belong in the FAST tier for the same reason `didShapes.test.ts` does:
 * every property here is a pure function over a document, and every one of them
 * is the last gate in front of an irreversible act. If they lived behind a
 * running validator, a stopped container would silently stop checking whether
 * an identity can be seized on a forged authorisation.
 *
 * Real Ed25519 throughout — `node:crypto` generates the keys and produces the
 * signatures, and the verifier is handed a document shaped exactly like a
 * chain-resolved one. What is left out is the network, not the cryptography.
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign as edSign, randomUUID } from 'node:crypto';
import { toMultibaseRaw } from '@cheqd/sdk/utils';

import {
  AUTHORISATION_STATEMENT_VERSION,
  MAX_AUTHORISATION_TTL_MS,
  assertStatementWellFormed,
  assertWithinValidityWindow,
  authorisationDigest,
  canonicalAuthorisationBytes,
  digestEvidence,
  ed25519PublicKeyFromMultibase,
  verifyAuthorisationSignature,
  type ReissuanceAuthorisationStatement,
  type ResolvedInstitutionalDocument,
} from '../../src/services/reissuance/authorisation.js';

const INSTITUTION = 'did:cheqd:bdhealthtestnet:11111111-1111-1111-1111-111111111111';
const OLD_DID = 'did:cheqd:bdhealthtestnet:22222222-2222-2222-2222-222222222222';
const OTHER_INSTITUTION = 'did:cheqd:bdhealthtestnet:33333333-3333-3333-3333-333333333333';

interface Officer {
  readonly verificationMethodId: string;
  readonly publicKeyMultibase: string;
  sign(bytes: Uint8Array): string;
}

/** An institutional key slot, with real Ed25519 material behind it. */
function officerKey(did: string, fragment: string): Officer {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = Buffer.from((publicKey.export({ format: 'jwk' }) as { x: string }).x, 'base64url');

  return {
    verificationMethodId: `${did}${fragment}`,
    publicKeyMultibase: toMultibaseRaw(raw),
    sign: (bytes) => edSign(null, Buffer.from(bytes), privateKey).toString('base64'),
  };
}

function institutionDocument(
  officers: readonly Officer[],
  overrides: Partial<ResolvedInstitutionalDocument> = {},
): ResolvedInstitutionalDocument {
  return {
    did: INSTITUTION,
    deactivated: false,
    verificationMethod: officers.map((officer) => ({
      id: officer.verificationMethodId,
      controller: INSTITUTION,
      publicKeyMultibase: officer.publicKeyMultibase,
    })),
    ...overrides,
  };
}

function statement(
  overrides: Partial<ReissuanceAuthorisationStatement> = {},
): ReissuanceAuthorisationStatement {
  const now = new Date('2026-08-22T10:00:00.000Z');
  return {
    version: AUTHORISATION_STATEMENT_VERSION,
    oldDid: OLD_DID,
    userId: 'user-1',
    institutionalDid: INSTITUTION,
    officerId: 'officer-7',
    evidenceKind: 'NATIONAL_ID_IN_PERSON',
    evidenceDigest: digestEvidence('NID-CASE-2026-0041'),
    nonce: randomUUID(),
    notBefore: now.toISOString(),
    notAfter: new Date(now.getTime() + 10 * 60 * 1000).toISOString(),
    ...overrides,
  };
}

describe('the signed authorisation is what authenticates a re-issuance', () => {
  it('verifies a well-formed authorisation signed by one of the institution’s N keys', () => {
    // 1-of-N: the SECOND officer signs, and that is sufficient (S-4 M1).
    const first = officerKey(INSTITUTION, '#key-officer-1');
    const second = officerKey(INSTITUTION, '#key-officer-2');
    const claim = statement();

    expect(() =>
      verifyAuthorisationSignature({
        statement: claim,
        signatureBase64: second.sign(canonicalAuthorisationBytes(claim)),
        verificationMethodId: second.verificationMethodId,
        institution: institutionDocument([first, second]),
      }),
    ).not.toThrow();
  });

  it('REFUSES a statement altered after signing — every field is covered', () => {
    const officer = officerKey(INSTITUTION, '#key-officer-1');
    const original = statement();
    const signature = officer.sign(canonicalAuthorisationBytes(original));
    const institution = institutionDocument([officer]);

    // Each of these is a different attack. Redirecting the migration to another
    // account, another old DID, or extending its life — all must fail.
    const tampered: Partial<ReissuanceAuthorisationStatement>[] = [
      { userId: 'user-attacker' },
      { oldDid: 'did:cheqd:bdhealthtestnet:99999999-9999-9999-9999-999999999999' },
      { officerId: 'officer-nobody' },
      { evidenceDigest: digestEvidence('NID-CASE-FABRICATED') },
      { notAfter: new Date('2026-08-22T10:09:59.000Z').toISOString() },
      { nonce: randomUUID() },
    ];

    for (const change of tampered) {
      expect(() =>
        verifyAuthorisationSignature({
          statement: { ...original, ...change },
          signatureBase64: signature,
          verificationMethodId: officer.verificationMethodId,
          institution,
        }),
      ).toThrow(/does NOT verify/);
    }
  });

  it('REFUSES a key the institution does not publish, even if the signature is valid', () => {
    // The forger holds a real key and produces a real signature. What they do
    // not have is a slot in the institution's on-chain document.
    const officer = officerKey(INSTITUTION, '#key-officer-1');
    const forger = officerKey(INSTITUTION, '#key-officer-99');
    const claim = statement();

    expect(() =>
      verifyAuthorisationSignature({
        statement: claim,
        signatureBase64: forger.sign(canonicalAuthorisationBytes(claim)),
        verificationMethodId: forger.verificationMethodId,
        institution: institutionDocument([officer]),
      }),
    ).toThrow(/not in the on-chain document/);
  });

  it('REFUSES an EVICTED key retroactively — the document is the authority, not the signature', () => {
    // S-4 H1: one officer can evict another. A key that was valid when it signed
    // must not still be able to move an identity once it is gone from the
    // document, because the document is what a verifier reads.
    const evicted = officerKey(INSTITUTION, '#key-officer-2');
    const survivor = officerKey(INSTITUTION, '#key-officer-1');
    const claim = statement();
    const signedWhileValid = evicted.sign(canonicalAuthorisationBytes(claim));

    expect(() =>
      verifyAuthorisationSignature({
        statement: claim,
        signatureBase64: signedWhileValid,
        verificationMethodId: evicted.verificationMethodId,
        institution: institutionDocument([survivor]),
      }),
    ).toThrow(/not in the on-chain document/);
  });

  it('REFUSES a verification method whose id sits under a DIFFERENT DID (S-4 V2)', () => {
    // Attribution is by id prefix and never by the controller field. A slot
    // named under someone else's namespace is a signature by someone else, and
    // the ledger would silently ignore it rather than reject it.
    const foreign = officerKey(OTHER_INSTITUTION, '#key-officer-1');
    const claim = statement();

    expect(() =>
      verifyAuthorisationSignature({
        statement: claim,
        signatureBase64: foreign.sign(canonicalAuthorisationBytes(claim)),
        verificationMethodId: foreign.verificationMethodId,
        institution: {
          did: INSTITUTION,
          deactivated: false,
          // The foreign key is even PRESENT in the document. It still must not count.
          verificationMethod: [
            {
              id: foreign.verificationMethodId,
              controller: INSTITUTION,
              publicKeyMultibase: foreign.publicKeyMultibase,
            },
          ],
        },
      }),
    ).toThrow(/Attribution is by id prefix/);
  });

  it('REFUSES verification against a document for a different institution', () => {
    const officer = officerKey(INSTITUTION, '#key-officer-1');
    const claim = statement({ institutionalDid: OTHER_INSTITUTION });

    expect(() =>
      verifyAuthorisationSignature({
        statement: claim,
        signatureBase64: officer.sign(canonicalAuthorisationBytes(claim)),
        verificationMethodId: officer.verificationMethodId,
        institution: institutionDocument([officer]),
      }),
    ).toThrow(/the statement names/);
  });

  it('REFUSES an authorisation from a DEACTIVATED institution (fail closed)', () => {
    const officer = officerKey(INSTITUTION, '#key-officer-1');
    const claim = statement();

    expect(() =>
      verifyAuthorisationSignature({
        statement: claim,
        signatureBase64: officer.sign(canonicalAuthorisationBytes(claim)),
        verificationMethodId: officer.verificationMethodId,
        institution: institutionDocument([officer], { deactivated: true }),
      }),
    ).toThrow(/DEACTIVATED/);
  });

  it('REFUSES an institution authorising the replacement of ITSELF', () => {
    const officer = officerKey(INSTITUTION, '#key-officer-1');
    const claim = statement({ oldDid: INSTITUTION });

    expect(() =>
      verifyAuthorisationSignature({
        statement: claim,
        signatureBase64: officer.sign(canonicalAuthorisationBytes(claim)),
        verificationMethodId: officer.verificationMethodId,
        institution: institutionDocument([officer]),
      }),
    ).toThrow(/vouching for its own succession/);
  });
});

describe('the validity window is a gate, not a hint', () => {
  it('refuses a TTL longer than the ceiling at construction time', () => {
    const now = new Date('2026-08-22T10:00:00.000Z');
    expect(() =>
      assertStatementWellFormed(
        statement({
          notBefore: now.toISOString(),
          notAfter: new Date(now.getTime() + MAX_AUTHORISATION_TTL_MS + 1000).toISOString(),
        }),
      ),
    ).toThrow(/standing permission to seize an identity/);
  });

  it('refuses a window that is valid for no instant at all', () => {
    const now = new Date('2026-08-22T10:00:00.000Z');
    expect(() =>
      assertStatementWellFormed(
        statement({ notBefore: now.toISOString(), notAfter: now.toISOString() }),
      ),
    ).toThrow(/not after notBefore/);
  });

  it('refuses before notBefore and after notAfter, and accepts in between', () => {
    const claim = statement();

    expect(() =>
      assertWithinValidityWindow(claim, new Date('2026-08-22T09:59:59.000Z')),
    ).toThrow(/not yet valid/);

    expect(() =>
      assertWithinValidityWindow(claim, new Date('2026-08-22T10:10:01.000Z')),
    ).toThrow(/EXPIRED/);

    expect(() =>
      assertWithinValidityWindow(claim, new Date('2026-08-22T10:05:00.000Z')),
    ).not.toThrow();
  });

  it('refuses an empty officer or an empty nonce — every field is load-bearing', () => {
    expect(() => assertStatementWellFormed(statement({ officerId: '   ' }))).toThrow(/is empty/);
    expect(() => assertStatementWellFormed(statement({ nonce: '' }))).toThrow(/is empty/);
  });
});

describe('key decoding refuses to guess', () => {
  it('round-trips a real Ed25519 key through publicKeyMultibase', () => {
    const officer = officerKey(INSTITUTION, '#key-officer-1');
    expect(ed25519PublicKeyFromMultibase(officer.publicKeyMultibase)).toHaveLength(32);
  });

  it('refuses a multibase value that is not an Ed25519 multicodec', () => {
    // 32 bytes of base58btc with no `ed01` prefix — the shape a naive
    // implementation would happily truncate into "a key".
    const notEd25519 = toMultibaseRaw(Buffer.alloc(8, 7)).replace(/^z/, 'z');
    expect(() => ed25519PublicKeyFromMultibase(notEd25519)).toThrow(/Ed25519 multicodec/);
  });

  it('refuses undecodable multibase rather than treating it as an empty key', () => {
    expect(() => ed25519PublicKeyFromMultibase('not-multibase-at-all!!')).toThrow();
  });
});

describe('the digest is stable and covers the whole statement', () => {
  it('is order-independent over object keys but changes with any value', () => {
    const claim = statement();
    const reordered: ReissuanceAuthorisationStatement = {
      notAfter: claim.notAfter,
      nonce: claim.nonce,
      evidenceDigest: claim.evidenceDigest,
      evidenceKind: claim.evidenceKind,
      officerId: claim.officerId,
      institutionalDid: claim.institutionalDid,
      userId: claim.userId,
      oldDid: claim.oldDid,
      version: claim.version,
      notBefore: claim.notBefore,
    };

    expect(authorisationDigest(reordered)).toBe(authorisationDigest(claim));
    expect(authorisationDigest({ ...claim, officerId: 'someone-else' })).not.toBe(
      authorisationDigest(claim),
    );
  });

  it('never carries the evidence itself, only its digest', () => {
    const claim = statement();
    const serialised = new TextDecoder().decode(canonicalAuthorisationBytes(claim));
    expect(serialised).not.toContain('NID-CASE-2026-0041');
    expect(serialised).toContain(digestEvidence('NID-CASE-2026-0041'));
  });
});
