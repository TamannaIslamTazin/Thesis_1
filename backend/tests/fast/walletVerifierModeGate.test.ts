/**
 * VERIFIER MODE IS OFFERED ON WHAT THE WALLET HOLDS — AND ON NOTHING ELSE.
 *
 * R4's claim is that role is a credential, not a column. The mobile app has a
 * second, quieter place that claim can be lost: the decision about which
 * screens to show. If verifier mode appeared because the user picked "doctor"
 * at onboarding, the app would be routing on a self-declaration — the same
 * shape as a `role` column, one layer up — and the thesis claim would be false
 * in the client even while it held in the backend.
 *
 * So the gate reads professional licence CREDENTIALS and there is deliberately
 * no parameter through which a profile field, a preference or an onboarding
 * answer could reach it. These tests exist to keep it that way.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS IN THE FAST TIER AND IN THE BACKEND'S TEST DIRECTORY
 * ---------------------------------------------------------------------------
 * The predicate lives in `@ssi-healthcare/shared` rather than in
 * `packages/mobile` for exactly the reason `credentialTransform.ts` was split
 * out of the Zustand store: logic that cannot be imported without React Native
 * present is logic no test ever reaches, and every bug that module's header
 * lists was invisible for precisely that reason. Here it is pure, it needs no
 * chain and no database, and it runs in milliseconds.
 *
 * ---------------------------------------------------------------------------
 * WHAT THESE TESTS DO NOT CLAIM
 * ---------------------------------------------------------------------------
 * Nothing here is a security property. A wallet that offers verifier mode may
 * still be refused by `authoriseProfessional`, and that is the intended
 * asymmetry: the gate is a usability property (an entry point that appears for
 * everyone and fails on tap is worse than none) sitting in front of an
 * authorization decision made somewhere else entirely.
 */
import { describe, it, expect } from 'vitest';
import {
  PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  PROFESSIONAL_TRUST_ROOTS,
  professionalLicencesHeld,
  walletOffersVerifierMode,
  type AccreditationAuthority,
  type HeldCredential,
} from '@ssi-healthcare/shared';

const HOLDER = 'did:cheqd:bdhealthtestnet:7cd03fdc-6a88-4895-9d89-e63445abe0c1';
const COUNCIL = 'did:cheqd:bdhealthtestnet:fa3fc79f-9d49-43f5-9aa7-4f2df973bbb0';

/** Fixed instant, so "in force" never depends on the day the suite runs. */
const NOW = '2027-06-01T00:00:00.000Z';

const LICENCE_CLAIMS = {
  id: HOLDER,
  profession: 'pharmacist',
  licenceNumber: 'PCB-A-7742',
  register: 'Register of Pharmacists, Grade A',
  practiceScope: ['dispense', 'view-patient-record'],
  licenceValidFrom: '2026-02-01T00:00:00.000Z',
  licenceValidUntil: '2030-02-01T00:00:00.000Z',
};

const TESTNET_ROOTS: readonly AccreditationAuthority[] = [
  {
    did: COUNCIL,
    name: 'Test council',
    shortName: 'TESTNET',
    professions: ['doctor', 'nurse', 'pharmacist'],
    maxScope: ['dispense', 'view-patient-record', 'prescribe'],
    authorisedFrom: '2026-01-01T00:00:00.000Z',
    placeholder: true,
  },
];

function licence(overrides: Partial<HeldCredential> = {}, claims: object = {}): HeldCredential {
  return {
    id: 'cred-1',
    type: ['VerifiableCredential', PROFESSIONAL_LICENCE_CREDENTIAL_TYPE],
    credentialSubject: { ...LICENCE_CLAIMS, ...claims },
    issuerDid: COUNCIL,
    ...overrides,
  };
}

const VACCINATION: HeldCredential = {
  id: 'cred-vax',
  type: ['VerifiableCredential', 'VaccinationCredential'],
  credentialSubject: { id: HOLDER, vaccine: 'MMR' },
  issuerDid: COUNCIL,
};

describe('a wallet holding a licence is offered verifier mode', () => {
  it('recognises the licence and reports what it authorises', () => {
    const held = professionalLicencesHeld([VACCINATION, licence()], {
      at: NOW,
      roots: TESTNET_ROOTS,
    });

    expect(held).toHaveLength(1);
    expect(held[0]!.credentialId).toBe('cred-1');
    expect(held[0]!.profession).toBe('pharmacist');
    expect(held[0]!.practiceScope).toEqual(['dispense', 'view-patient-record']);
    expect(held[0]!.inForce).toBe(true);
    expect(held[0]!.notInForceReasons).toEqual([]);
    // Named so the app can tell the holder WHO vouched for them, rather than
    // showing a bare DID to a user who cannot evaluate one.
    expect(held[0]!.accreditedByName).toBe('TESTNET');

    expect(walletOffersVerifierMode([VACCINATION, licence()], { at: NOW, roots: TESTNET_ROOTS }))
      .toBe(true);
  });

  it('does not mutate the caller\'s scope array', () => {
    const scope = ['dispense'];
    const held = professionalLicencesHeld([licence({}, { practiceScope: scope })], { at: NOW });
    held[0]!.practiceScope.push('prescribe');
    expect(scope).toEqual(['dispense']);
  });
});

describe('a wallet holding no licence is not offered verifier mode', () => {
  it('an empty wallet offers nothing', () => {
    expect(walletOffersVerifierMode([], { at: NOW })).toBe(false);
  });

  it('a wallet of ordinary health credentials offers nothing', () => {
    expect(walletOffersVerifierMode([VACCINATION], { at: NOW })).toBe(false);
  });

  it('a credential CLAIMING the licence type but carrying no licence claims is not a licence', () => {
    // The type array is not a signature and anything can assert it. Reading the
    // claims is what stops a hand-crafted row unlocking the menu.
    const impostor: HeldCredential = {
      id: 'cred-impostor',
      type: ['VerifiableCredential', PROFESSIONAL_LICENCE_CREDENTIAL_TYPE],
      credentialSubject: { id: HOLDER },
      issuerDid: COUNCIL,
    };
    expect(professionalLicencesHeld([impostor], { at: NOW })).toEqual([]);
    expect(walletOffersVerifierMode([impostor], { at: NOW })).toBe(false);
  });
});

describe('malformed licence claims are rejected one field at a time', () => {
  // A per-claim matrix rather than one "bad credential" case: a build that
  // stopped checking a single field would still fail a lumped test for the
  // wrong reason, and pass it as soon as any other field caught the problem.
  const CASES: Array<[string, object]> = [
    ['an unrecognised profession', { profession: 'chiropractor' }],
    ['a profession that is not a string', { profession: 7 }],
    ['an empty licence number', { licenceNumber: '' }],
    ['a missing register', { register: undefined }],
    ['an empty practice scope', { practiceScope: [] }],
    ['a scope atom this system does not define', { practiceScope: ['dispense', 'operate'] }],
    ['a practice scope that is not an array', { practiceScope: 'dispense' }],
    ['a non-string validity start', { licenceValidFrom: 20260201 }],
    ['a missing validity end', { licenceValidUntil: undefined }],
  ];

  for (const [label, claims] of CASES) {
    it(`${label} disqualifies the credential`, () => {
      expect(professionalLicencesHeld([licence({}, claims)], { at: NOW })).toEqual([]);
    });
  }

  it('a subject that is not an object at all is rejected rather than thrown on', () => {
    // One malformed row must not break the whole wallet listing.
    for (const subject of [null, 'a string', ['an', 'array'], 42]) {
      expect(professionalLicencesHeld([licence({ credentialSubject: subject })], { at: NOW }))
        .toEqual([]);
    }
  });
});

describe('a licence the wallet already knows is unusable does not open the menu', () => {
  it('an EXPIRED licence is listed with a reason but does not offer verifier mode', () => {
    const expired = licence({}, { licenceValidUntil: '2026-12-31T00:00:00.000Z' });

    // Still listed: the holder should be able to see WHY their licence stopped
    // working, rather than have it silently vanish from the wallet.
    const held = professionalLicencesHeld([expired], { at: NOW });
    expect(held).toHaveLength(1);
    expect(held[0]!.inForce).toBe(false);
    expect(held[0]!.notInForceReasons.join(' ')).toMatch(/Expired/);

    // But the entry point stays closed, because presenting it is a guaranteed
    // refusal and "fails on tap" is the case the gate exists to prevent.
    expect(walletOffersVerifierMode([expired], { at: NOW })).toBe(false);
  });

  it('a licence not yet in force does not offer verifier mode either', () => {
    const future = licence({}, { licenceValidFrom: '2030-01-01T00:00:00.000Z' });
    expect(walletOffersVerifierMode([future], { at: NOW })).toBe(false);
  });

  it('a LOCALLY REVOKED licence is excluded entirely', () => {
    expect(professionalLicencesHeld([licence({ locallyRevoked: true })], { at: NOW })).toEqual([]);
  });

  it('one unusable licence does not hide a usable one', () => {
    const wallet = [
      licence({ id: 'expired' }, { licenceValidUntil: '2026-12-31T00:00:00.000Z' }),
      licence({ id: 'good' }),
    ];
    expect(walletOffersVerifierMode(wallet, { at: NOW })).toBe(true);
  });
});

describe('the wallet does not decide accreditation, and says so by not refusing on it', () => {
  it('an issuer the wallet does not recognise still offers verifier mode', () => {
    // AGAINST THE SHIPPED ROOTS, where this issuer is not pinned. The wallet
    // reports `accreditedByName: undefined` so the holder can be told, but it
    // does NOT hide the menu — the verifier's root store is the one that
    // decides, it may differ from ours, and a wallet that pre-empted that
    // decision would be making an authorization call it has no standing to
    // make. This is the asymmetry in the module header, as a test.
    const held = professionalLicencesHeld([licence()], {
      at: NOW,
      roots: PROFESSIONAL_TRUST_ROOTS,
    });

    expect(held).toHaveLength(1);
    expect(held[0]!.accreditedByName).toBeUndefined();
    expect(walletOffersVerifierMode([licence()], { at: NOW, roots: PROFESSIONAL_TRUST_ROOTS }))
      .toBe(true);
  });

  it('a licence with no recorded issuer is still listed', () => {
    const held = professionalLicencesHeld([licence({ issuerDid: undefined })], { at: NOW });
    expect(held).toHaveLength(1);
    expect(held[0]!.issuerDid).toBeUndefined();
    expect(held[0]!.accreditedByName).toBeUndefined();
  });
});

describe('the gate has no seam through which a self-declared group could reach it', () => {
  it('a self-declared group passed in anyway changes nothing, in either direction', () => {
    // THE POINT OF THE WHOLE FILE, asserted as behaviour rather than as shape.
    // An earlier draft asserted `Function.length` instead; that was a proxy, and
    // a wrong one — an optional parameter does not count towards arity, so the
    // check measured nothing about the inputs it claimed to constrain.
    //
    // This is the property itself: a self-declaration cannot turn the menu on
    // for a wallet holding no licence, and cannot turn it off for one that does.
    // TypeScript rejects the extra member, which is the first line of defence;
    // the cast is what lets the test prove the runtime ignores it too, for the
    // JavaScript caller the compiler never sees.
    const declaresDoctor = { at: NOW, declaredGroup: 'doctor' } as unknown as { at: string };

    expect(walletOffersVerifierMode([VACCINATION], declaresDoctor)).toBe(false);
    expect(walletOffersVerifierMode([licence()], { ...declaresDoctor, declaredGroup: 'patient' } as unknown as { at: string }))
      .toBe(true);
  });

  it('a wallet whose owner says they are a doctor, holding no licence, is offered nothing', () => {
    // There is deliberately no way to express the self-declaration in this
    // call. That is the assertion.
    expect(walletOffersVerifierMode([VACCINATION], { at: NOW })).toBe(false);
  });
});
