/**
 * THE TRUST ROOT STORE AND THE TWO TEMPORAL QUESTIONS.
 *
 * Pure predicates from `@ssi-healthcare/shared/accreditation`. No chain, no
 * database, no agent — these are decisions about dates and set membership, and
 * putting them in the live tier would only mean they run less often.
 *
 * ---------------------------------------------------------------------------
 * WHY IMMUTABILITY IS ASSERTED AT ALL
 * ---------------------------------------------------------------------------
 * The security argument for pinning roots in code rather than in a table is
 * that an attacker cannot INSERT into it. That argument evaporates if the
 * exported array is merely a plain array anyone can `push` to at runtime — a
 * compromised module, a careless `sort()` in a UI layer, a test that mutates
 * shared state. `deepFreeze` is what makes the claim true and this is what
 * makes the freeze non-optional.
 *
 * ---------------------------------------------------------------------------
 * WHY "AUTHORISED AT ISSUANCE" IS TESTED SEPARATELY FROM REVOCATION
 * ---------------------------------------------------------------------------
 * They are different questions with different answers for the same authority
 * (#214). An authority whose mandate ENDED keeps every licence it lawfully
 * issued while it held one; an authority that was never authorised at that
 * instant issued nothing valid. A single "is this issuer trusted now" flag
 * gets the first case wrong, and gets it wrong in the direction that
 * invalidates real doctors' licences. The retired-authority case below is the
 * one that pins the distinction.
 */
import { describe, it, expect } from 'vitest';
import {
  MAX_DELEGATION_DEPTH,
  PROFESSIONAL_TRUST_ROOTS,
  ProfessionalLicenceSubjectSchema,
  TRUST_ROOTS_ARE_PLACEHOLDERS,
  narrowsScope,
  trustRootForDid,
  uncoveredScope,
  validateAccreditationChain,
  wasAuthorisedToAccredit,
  windowCovers,
  type AccreditationAuthority,
  type AccreditationLink,
} from '@ssi-healthcare/shared';

const BMDC = PROFESSIONAL_TRUST_ROOTS.find((a) => a.shortName === 'BMDC')!;
const BNMC = PROFESSIONAL_TRUST_ROOTS.find((a) => a.shortName === 'BNMC')!;
const PCB = PROFESSIONAL_TRUST_ROOTS.find((a) => a.shortName === 'PCB')!;

/** Comfortably inside every placeholder mandate window. */
const AFTER_MANDATE_BEGAN = '2026-08-21T00:00:00.000Z';
/** Before any of them began. */
const BEFORE_MANDATE_BEGAN = '2025-06-01T00:00:00.000Z';

describe('the root store is a root store', () => {
  it('names the three real accrediting authorities and nothing else', () => {
    expect(PROFESSIONAL_TRUST_ROOTS.map((a) => a.shortName).sort()).toEqual([
      'BMDC',
      'BNMC',
      'PCB',
    ]);
  });

  it('cannot be extended at runtime', () => {
    // The whole argument for config-over-table is that this is impossible.
    expect(() =>
      (PROFESSIONAL_TRUST_ROOTS as AccreditationAuthority[]).push({
        did: 'did:cheqd:bdhealthtestnet:99999999-9999-4999-8999-999999999999',
        name: 'Attacker Council',
        shortName: 'EVIL',
        professions: ['doctor'],
        maxScope: ['prescribe'],
        authorisedFrom: '2020-01-01T00:00:00.000Z',
        placeholder: false,
      }),
    ).toThrow();
    expect(PROFESSIONAL_TRUST_ROOTS).toHaveLength(3);
  });

  it('cannot have an existing authority widened at runtime', () => {
    // The subtler attack: not a new root, but an existing one quietly granted
    // a profession it does not accredit.
    expect(() => {
      (BNMC.professions as unknown as string[]).push('doctor');
    }).toThrow();
    expect(BNMC.professions).toEqual(['nurse']);
  });

  it('announces that the pinned DIDs are still placeholders', () => {
    // This flag is what a deployment check asserts on. If it ever silently
    // reads false while the DIDs are still stand-ins, the check is dead.
    expect(TRUST_ROOTS_ARE_PLACEHOLDERS).toBe(true);
    expect(PROFESSIONAL_TRUST_ROOTS.every((a) => a.placeholder)).toBe(true);
  });

  it('resolves a DID to exactly one authority, and unknown DIDs to none', () => {
    expect(trustRootForDid(BMDC.did)?.shortName).toBe('BMDC');
    expect(trustRootForDid('did:cheqd:bdhealthtestnet:not-a-root')).toBeUndefined();
    // No prefix or substring matching — a DID that merely starts like a root
    // must not resolve to it.
    expect(trustRootForDid(`${BMDC.did}#key-1`)).toBeUndefined();
  });
});

describe('TEMPORAL 1 — was the issuer authorised to accredit at issuance time', () => {
  it('admits the right council for the right profession', () => {
    const decision = wasAuthorisedToAccredit({
      authorityDid: BMDC.did,
      profession: 'doctor',
      at: AFTER_MANDATE_BEGAN,
    });
    expect(decision.authorised).toBe(true);
    expect(decision.reasons).toEqual([]);
  });

  it('refuses a council accrediting a profession it does not regulate', () => {
    // The nursing council signing a doctor's licence. Cryptographically
    // impeccable, institutionally meaningless.
    const decision = wasAuthorisedToAccredit({
      authorityDid: BNMC.did,
      profession: 'doctor',
      at: AFTER_MANDATE_BEGAN,
    });
    expect(decision.authorised).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/does not accredit 'doctor'/);
  });

  it('refuses a DID that is not pinned at all', () => {
    const decision = wasAuthorisedToAccredit({
      authorityDid: 'did:cheqd:bdhealthtestnet:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      profession: 'doctor',
      at: AFTER_MANDATE_BEGAN,
    });
    expect(decision.authorised).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/not a pinned accrediting authority/);
  });

  it('refuses a credential issued BEFORE the authority held its mandate', () => {
    // A backdated licence. The signature verifies; the authority did not exist
    // in the register on the date it claims to have signed.
    const decision = wasAuthorisedToAccredit({
      authorityDid: BMDC.did,
      profession: 'doctor',
      at: BEFORE_MANDATE_BEGAN,
    });
    expect(decision.authorised).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/held no mandate at the credential's issuance time/);
  });

  it('refuses when the issuance time is unreadable rather than assuming now', () => {
    // Fail closed. An undated credential must not inherit the current instant,
    // which would make every backdating check unreachable.
    expect(
      wasAuthorisedToAccredit({ authorityDid: BMDC.did, profession: 'doctor', at: '' }).authorised,
    ).toBe(false);
    expect(
      wasAuthorisedToAccredit({ authorityDid: BMDC.did, profession: 'doctor', at: 'yesterday' })
        .authorised,
    ).toBe(false);
  });

  it('a RETIRED authority still validly accredited during its mandate', () => {
    // THE CASE THE WHOLE SPLIT EXISTS FOR. Retirement is not fraud: licences
    // issued while the mandate stood remain good, and only revocation — the
    // other question, answered elsewhere — can take them away.
    const retired: AccreditationAuthority = {
      ...BMDC,
      authorisedUntil: '2026-03-01T00:00:00.000Z',
    };
    const during = windowCovers(
      { from: retired.authorisedFrom, until: retired.authorisedUntil },
      '2026-02-01T00:00:00.000Z',
    );
    const after = windowCovers(
      { from: retired.authorisedFrom, until: retired.authorisedUntil },
      '2026-08-01T00:00:00.000Z',
    );
    expect(during.covers).toBe(true);
    expect(after.covers).toBe(false);
  });
});

describe('validity windows fail closed on absence, not open', () => {
  it('treats a missing bound as a refusal', () => {
    expect(windowCovers({ from: undefined, until: '2030-01-01T00:00:00.000Z' }, AFTER_MANDATE_BEGAN).covers)
      .toBe(false);
    expect(windowCovers({ from: '2020-01-01T00:00:00.000Z', until: undefined }, AFTER_MANDATE_BEGAN).covers)
      .toBe(false);
  });

  it('reports not-yet-in-force and expired as different reasons', () => {
    const early = windowCovers(
      { from: '2030-01-01T00:00:00.000Z', until: '2031-01-01T00:00:00.000Z' },
      AFTER_MANDATE_BEGAN,
    );
    const late = windowCovers(
      { from: '2020-01-01T00:00:00.000Z', until: '2021-01-01T00:00:00.000Z' },
      AFTER_MANDATE_BEGAN,
    );
    expect(early.reasons.join(' ')).toMatch(/Not yet in force/);
    expect(late.reasons.join(' ')).toMatch(/Expired/);
  });
});

describe('scope narrows and never widens', () => {
  it('a subset narrows; a superset does not', () => {
    expect(narrowsScope(['prescribe', 'dispense'], ['dispense'])).toBe(true);
    expect(narrowsScope(['dispense'], ['dispense', 'prescribe'])).toBe(false);
  });

  it('an equal set narrows — delegation may pass authority on unchanged', () => {
    expect(narrowsScope(['dispense'], ['dispense'])).toBe(true);
  });

  it('names precisely which scopes were not covered', () => {
    expect(uncoveredScope(['dispense'], ['dispense', 'prescribe'])).toEqual(['prescribe']);
    expect(uncoveredScope(['dispense', 'prescribe'], ['dispense'])).toEqual([]);
  });

  it('the pharmacy council cannot itself grant prescribing', () => {
    // Pinned ceilings are the first place a scope escalation would show up.
    expect(PCB.maxScope).not.toContain('prescribe');
    expect(BNMC.maxScope).not.toContain('prescribe');
    expect(BMDC.maxScope).toContain('prescribe');
  });
});

describe('delegation chains (design-level — no request path accepts one yet)', () => {
  const hospital = 'did:cheqd:bdhealthtestnet:44444444-4444-4444-8444-444444444444';
  const ward = 'did:cheqd:bdhealthtestnet:55555555-5555-4555-8555-555555555555';

  const hop = (overrides: Partial<AccreditationLink> = {}): AccreditationLink => ({
    issuerDid: BMDC.did,
    id: hospital,
    professions: ['doctor'],
    scope: ['prescribe', 'view-patient-record'],
    validFrom: '2026-02-01T00:00:00.000Z',
    validUntil: '2027-02-01T00:00:00.000Z',
    ...overrides,
  });

  it('an empty chain means the root issues directly', () => {
    const decision = validateAccreditationChain({
      rootDid: BMDC.did,
      chain: [],
      at: AFTER_MANDATE_BEGAN,
    });
    expect(decision.valid).toBe(true);
    expect(decision.accreditedIssuerDid).toBe(BMDC.did);
    expect(decision.effectiveScope).toEqual([...BMDC.maxScope]);
  });

  it('one hop narrows the effective scope to the delegated subset', () => {
    const decision = validateAccreditationChain({
      rootDid: BMDC.did,
      chain: [hop()],
      at: AFTER_MANDATE_BEGAN,
    });
    expect(decision.valid).toBe(true);
    expect(decision.accreditedIssuerDid).toBe(hospital);
    expect(decision.effectiveScope.sort()).toEqual(['prescribe', 'view-patient-record']);
  });

  it('refuses a hop that widens scope beyond what it was given', () => {
    // A hospital accredited for lab results cannot delegate prescribing (#214).
    const decision = validateAccreditationChain({
      rootDid: PCB.did,
      chain: [hop({ issuerDid: PCB.did, professions: ['pharmacist'], scope: ['prescribe'] })],
      at: AFTER_MANDATE_BEGAN,
    });
    expect(decision.valid).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/widens scope/);
  });

  it('refuses a hop that widens the professions it may accredit', () => {
    const decision = validateAccreditationChain({
      rootDid: BMDC.did,
      chain: [hop({ professions: ['doctor', 'nurse'] })],
      at: AFTER_MANDATE_BEGAN,
    });
    expect(decision.valid).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/widens professions/);
  });

  it('refuses a chain whose links do not join up', () => {
    // Hop 2 claims to be issued by someone hop 1 never delegated to. Without
    // this a valid accreditation could be spliced onto an unrelated root.
    const decision = validateAccreditationChain({
      rootDid: BMDC.did,
      chain: [hop(), hop({ issuerDid: 'did:cheqd:bdhealthtestnet:deadbeef', id: ward })],
      at: AFTER_MANDATE_BEGAN,
    });
    expect(decision.valid).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/the previous hop delegated to/);
  });

  it('refuses a chain deeper than the cap', () => {
    const decision = validateAccreditationChain({
      rootDid: BMDC.did,
      chain: [hop(), hop({ issuerDid: hospital, id: ward }), hop({ issuerDid: ward, id: ward })],
      at: AFTER_MANDATE_BEGAN,
    });
    expect(decision.valid).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(
      new RegExp(`over the cap of ${MAX_DELEGATION_DEPTH}`),
    );
  });

  it('refuses a hop whose own delegation has expired', () => {
    const decision = validateAccreditationChain({
      rootDid: BMDC.did,
      chain: [hop({ validUntil: '2026-03-01T00:00:00.000Z' })],
      at: AFTER_MANDATE_BEGAN,
    });
    expect(decision.valid).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/Hop 1: Expired/);
  });
});

describe('licence claims are refused when the holder withholds any of them', () => {
  const complete = {
    id: 'did:cheqd:bdhealthtestnet:7cd03fdc-6a88-4895-9d89-e63445abe0c1',
    profession: 'pharmacist',
    licenceNumber: 'PCB-A-9931',
    register: 'Register of Pharmacists, Grade A',
    practiceScope: ['dispense', 'view-patient-record'],
    licenceValidFrom: '2026-02-01T00:00:00.000Z',
    licenceValidUntil: '2027-02-01T00:00:00.000Z',
  };

  it('accepts a fully disclosed licence', () => {
    expect(ProfessionalLicenceSubjectSchema.safeParse(complete).success).toBe(true);
  });

  it.each([
    'profession',
    'licenceNumber',
    'register',
    'practiceScope',
    'licenceValidFrom',
    'licenceValidUntil',
    'id',
  ])('refuses when %s is withheld', (claim) => {
    // Under selective disclosure the holder chooses. A withheld claim must read
    // as "not proven" — the alternative is authority granted on a claim nobody
    // asserted.
    const partial = { ...complete } as Record<string, unknown>;
    delete partial[claim];
    expect(ProfessionalLicenceSubjectSchema.safeParse(partial).success).toBe(false);
  });

  it('refuses an unknown scope rather than ignoring it', () => {
    expect(
      ProfessionalLicenceSubjectSchema.safeParse({
        ...complete,
        practiceScope: ['dispense', 'perform-surgery'],
      }).success,
    ).toBe(false);
  });

  it('refuses smuggled extra claims', () => {
    // `.strict()`. An issuer cannot slip an unrecognised member past a verifier
    // that would silently keep it.
    expect(
      ProfessionalLicenceSubjectSchema.safeParse({ ...complete, canPrescribe: true }).success,
    ).toBe(false);
  });
});
