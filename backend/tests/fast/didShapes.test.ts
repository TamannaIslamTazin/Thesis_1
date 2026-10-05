/**
 * THE SHAPES THAT DECIDE WHETHER AN IDENTITY IS RECOVERABLE — TESTING_MANUAL §R5.
 *
 * These are in the FAST tier deliberately. Every property here is a pure
 * function of a document, and every one of them is a one-way door: a DID minted
 * in the wrong shape works perfectly until the day recovery is needed and can
 * then only be re-issued. Putting them behind a running validator would mean a
 * stopped container silently stops checking them.
 *
 * The live tier proves the same shapes SURVIVE THE CHAIN. This tier proves the
 * wrong ones cannot be built in the first place.
 */
import { describe, it, expect } from 'vitest';

import {
  ED25519_VERIFICATION_KEY_2020,
  signerDidsForCreate,
  signerDidsForUpdate,
  verificationMethodDelta,
  type CheqdDidDocumentShape,
  assertInstitutionalShape,
  assertPatientRecoverableShape,
  assertRecoveryControllerShape,
  assertRotationIsSurvivable,
  classifyPatientDid,
} from '@ssi-healthcare/sdk/ledger';

const INST = 'did:cheqd:bdhealthtestnet:11111111-1111-1111-1111-111111111111';
const RCK = 'did:cheqd:bdhealthtestnet:22222222-2222-2222-2222-222222222222';
const PATIENT = 'did:cheqd:bdhealthtestnet:33333333-3333-3333-3333-333333333333';
const OTHER = 'did:cheqd:bdhealthtestnet:44444444-4444-4444-4444-444444444444';

const KEY_A = 'z6MkwdbLTjwhXBh2kMmXr3t5t5hJPQFf4iDCvY9uE3WXDLbc';
const KEY_B = 'z6Mkomcw8rTsqBoh3W4nqCbertYFiYf1K2KDxkGdTSuiHFXv';
const KEY_C = 'z6MkgX7vfgjbBdY6YTnxMX2hwk3oThMKP5qT6Seg8bUwq3HC';

function slot(id: string, controller: string, publicKeyMultibase: string) {
  return { id, type: ED25519_VERIFICATION_KEY_2020, controller, publicKeyMultibase } as const;
}

function institution(overrides: Partial<CheqdDidDocumentShape> = {}): CheqdDidDocumentShape {
  return {
    '@context': [],
    id: INST,
    controller: [INST],
    verificationMethod: [
      slot(`${INST}#key-officer-1`, INST, KEY_A),
      slot(`${INST}#key-officer-2`, INST, KEY_B),
    ],
    authentication: [`${INST}#key-officer-1`],
    assertionMethod: [`${INST}#key-officer-1`, `${INST}#key-officer-2`],
    ...overrides,
  };
}

function patient(overrides: Partial<CheqdDidDocumentShape> = {}): CheqdDidDocumentShape {
  return {
    '@context': [],
    id: PATIENT,
    controller: [RCK, INST],
    verificationMethod: [slot(`${PATIENT}#key-1`, RCK, KEY_A)],
    authentication: [`${PATIENT}#key-1`],
    ...overrides,
  };
}

function recoveryController(overrides: Partial<CheqdDidDocumentShape> = {}): CheqdDidDocumentShape {
  return {
    '@context': [],
    id: RCK,
    controller: [RCK],
    verificationMethod: [slot(`${RCK}#key-1`, RCK, KEY_A)],
    authentication: [`${RCK}#key-1`],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------

describe('a wrong-shaped INSTITUTIONAL DID cannot be constructed', () => {
  it('accepts the 1-of-N self-controlled shape', () => {
    expect(() => assertInstitutionalShape(institution())).not.toThrow();
  });

  it('REFUSES a slot whose controller is another DID', () => {
    // S-4 §6.1, the condition the whole 1-of-N ruling rests on. Rotating that
    // slot would need OTHER's signature, so 1-of-2 is really 1-of-1 plus an
    // unrecoverable slot — and nobody finds out until the day it matters.
    const wrong = institution({
      verificationMethod: [
        slot(`${INST}#key-officer-1`, INST, KEY_A),
        slot(`${INST}#key-officer-2`, OTHER, KEY_B),
      ],
    });
    expect(() => assertInstitutionalShape(wrong)).toThrowError(/1-of-N custody degrades/);
  });

  it('REFUSES a slot outside its own namespace', () => {
    // S-4 V2: attribution is by id prefix, never by the controller field. A
    // slot living under someone else's DID is scored as THEIR signature.
    const wrong = institution({
      verificationMethod: [
        slot(`${INST}#key-officer-1`, INST, KEY_A),
        slot(`${OTHER}#key-officer-2`, INST, KEY_B),
      ],
      assertionMethod: [`${INST}#key-officer-1`],
    });
    expect(() => assertInstitutionalShape(wrong)).toThrowError(/not under the institution/);
  });

  it('REFUSES a foreign controller on the document', () => {
    expect(() => assertInstitutionalShape(institution({ controller: [OTHER] }))).toThrowError(
      /must be self-controlled/,
    );
  });

  it('REFUSES two slots sharing a fragment, which would shadow a key', () => {
    const wrong = institution({
      verificationMethod: [
        slot(`${INST}#key-officer-1`, INST, KEY_A),
        slot(`${INST}#key-officer-1`, INST, KEY_B),
      ],
      assertionMethod: [`${INST}#key-officer-1`],
    });
    expect(() => assertInstitutionalShape(wrong)).toThrowError(/Duplicate verification-method/);
  });

  it('REFUSES a relationship pointing at a slot that does not exist', () => {
    expect(() =>
      assertInstitutionalShape(institution({ authentication: [`${INST}#key-officer-9`] })),
    ).toThrowError(/is not\s+one of its verification methods|not\s*one of its verification/);
  });
});

// ---------------------------------------------------------------------------

describe('the PATIENT shape is S-1 §8.1 as amended by S-4 §6.3', () => {
  const expectation = { recoveryControllerDid: RCK, institutionalDid: INST };

  it('accepts the recoverable shape', () => {
    expect(() => assertPatientRecoverableShape(patient(), expectation)).not.toThrow();
  });

  it('REFUSES a self-controlled verification method — the R0 defect itself', () => {
    const wrong = patient({
      verificationMethod: [slot(`${PATIENT}#key-1`, PATIENT, KEY_A)],
    });
    expect(() => assertPatientRecoverableShape(wrong, expectation)).toThrowError(
      /SELF-CONTROLLED verification method/,
    );
  });

  it('REFUSES the patient DID inside its own controller array — the S-4 V2 amendment', () => {
    // Inert today only because the patient DID is outside its own controller
    // array. The moment it is inside, the device key (whose id lives under the
    // patient DID) silently regains full authority over the identity.
    const wrong = patient({ controller: [PATIENT, RCK, INST] });
    expect(() => assertPatientRecoverableShape(wrong, expectation)).toThrowError(
      /appears in its own controller array/,
    );
  });

  it('REFUSES multi-VM for patients — measured strictly worse on three counts', () => {
    const wrong = patient({
      verificationMethod: [
        slot(`${PATIENT}#key-1`, RCK, KEY_A),
        slot(`${PATIENT}#key-2`, RCK, KEY_B),
      ],
    });
    expect(() => assertPatientRecoverableShape(wrong, expectation)).toThrowError(
      /exactly one verification method/,
    );
  });

  it('REFUSES a VM controller that is neither the patient nor the recovery controller', () => {
    const wrong = patient({ verificationMethod: [slot(`${PATIENT}#key-1`, OTHER, KEY_A)] });
    expect(() => assertPatientRecoverableShape(wrong, expectation)).toThrowError(
      /must be the patient's own recovery controller/,
    );
  });

  it('REFUSES a controller set that is not exactly [RCK, institution]', () => {
    expect(() => assertPatientRecoverableShape(patient({ controller: [RCK] }), expectation))
      .toThrowError(/must be controlled by exactly/);
    expect(() =>
      assertPatientRecoverableShape(patient({ controller: [RCK, INST, OTHER] }), expectation),
    ).toThrowError(/must be controlled by exactly/);
  });

  it('REFUSES the institution doubling as the recovery controller', () => {
    // Otherwise the 2-of-2 AND collapses to 1-of-1 and the institution alone
    // can move the patient identity — the custodial outcome the set prevents.
    expect(() =>
      assertPatientRecoverableShape(patient({ controller: [INST] }), {
        recoveryControllerDid: INST,
        institutionalDid: INST,
      }),
    ).toThrowError(/same DID/);
  });
});

// ---------------------------------------------------------------------------

describe('the RECOVERY-CONTROLLER shape (#240) cannot be constructed wrong', () => {
  // Added alongside making `CreateCheqdDIDSpec.assertShape` mandatory
  // (steno #313 follow-up): this was the role that fell through the gap. The
  // success case here is the one that matters most — a required assertion that
  // rejects everything, including the correct shape, would pass a suite made
  // only of refusal tests.

  it('accepts the self-controlled, single-VM shape', () => {
    expect(() => assertRecoveryControllerShape(recoveryController())).not.toThrow();
  });

  it('REFUSES a foreign controller on the document', () => {
    expect(() =>
      assertRecoveryControllerShape(recoveryController({ controller: [OTHER] })),
    ).toThrowError(/must be self-controlled/);
  });

  it('REFUSES more than one verification method', () => {
    const wrong = recoveryController({
      verificationMethod: [
        slot(`${RCK}#key-1`, RCK, KEY_A),
        slot(`${RCK}#key-2`, RCK, KEY_B),
      ],
    });
    expect(() => assertRecoveryControllerShape(wrong)).toThrowError(
      /exactly one verification method/,
    );
  });

  it('REFUSES a verification method controlled by another DID', () => {
    const wrong = recoveryController({
      verificationMethod: [slot(`${RCK}#key-1`, OTHER, KEY_A)],
    });
    expect(() => assertRecoveryControllerShape(wrong)).toThrowError(
      /not the.*recovery-controller DID.*itself/,
    );
  });

  it('REFUSES a slot outside its own namespace', () => {
    const wrong = recoveryController({
      verificationMethod: [slot(`${OTHER}#key-1`, RCK, KEY_A)],
    });
    expect(() => assertRecoveryControllerShape(wrong)).toThrowError(/not under the/);
  });

  it('REFUSES a verification method absent from the authentication relationship', () => {
    const wrong = recoveryController({ authentication: [] });
    expect(() => assertRecoveryControllerShape(wrong)).toThrowError(
      /not in the authentication relationship/,
    );
  });
});

// ---------------------------------------------------------------------------

describe('the signer set is the chain predicate, not an approximation', () => {
  it('create = controllers ∪ ALL verification-method controllers', () => {
    expect(signerDidsForCreate(patient())).toEqual([INST, RCK].sort());
  });

  it('an omitted controller list means the SUBJECT, not "uncontrolled"', () => {
    expect(signerDidsForCreate({ id: PATIENT })).toEqual([PATIENT]);
    expect(signerDidsForCreate({ id: PATIENT, controller: [] })).toEqual([PATIENT]);
  });

  it('update over a changed slot appends BOTH the old and the new VM controller', () => {
    const before = { id: PATIENT, controller: [RCK, INST], verificationMethod: [slot(`${PATIENT}#key-1`, RCK, KEY_A)] };
    const after = { id: PATIENT, controller: [RCK, INST], verificationMethod: [slot(`${PATIENT}#key-1`, OTHER, KEY_B)] };
    expect(signerDidsForUpdate(before, after)).toEqual([INST, OTHER, RCK].sort());
  });

  it('an UNCHANGED slot contributes no signer — this is what makes 1-of-N work', () => {
    // S-4 M1: rotating one slot of a multi-VM DID does not conscript the others.
    const before = {
      id: INST,
      controller: [INST],
      verificationMethod: [slot(`${INST}#key-officer-1`, INST, KEY_A), slot(`${INST}#key-officer-2`, INST, KEY_B)],
    };
    const after = {
      id: INST,
      controller: [INST],
      verificationMethod: [slot(`${INST}#key-officer-1`, INST, KEY_A), slot(`${INST}#key-officer-2`, INST, KEY_C)],
    };
    expect(signerDidsForUpdate(before, after)).toEqual([INST]);
    expect(verificationMethodDelta(before, after)).toEqual({
      added: [],
      changed: [`${INST}#key-officer-2`],
      removed: [],
    });
  });

  it('a REMOVED slot contributes its own controller', () => {
    const before = {
      id: INST,
      controller: [INST],
      verificationMethod: [slot(`${INST}#key-officer-1`, INST, KEY_A), slot(`${INST}#key-officer-2`, OTHER, KEY_B)],
    };
    const after = { id: INST, controller: [INST], verificationMethod: [slot(`${INST}#key-officer-1`, INST, KEY_A)] };
    expect(signerDidsForUpdate(before, after)).toEqual([INST, OTHER].sort());
  });
});

// ---------------------------------------------------------------------------

describe('the X1 bulk-rotation trap is refused locally', () => {
  const before = {
    id: INST,
    controller: [INST],
    verificationMethod: [slot(`${INST}#key-officer-1`, INST, KEY_A), slot(`${INST}#key-officer-2`, INST, KEY_B)],
  };

  it('refuses to change two slots in one transaction', () => {
    // S-4 X1 at height 86330: rejected `code 1100` ErrInvalidSignature, not the
    // 1101 a reader would expect, because the signing key was verified against
    // the `<did>-updated` twin and no longer matched there.
    const after = {
      id: INST,
      controller: [INST],
      verificationMethod: [slot(`${INST}#key-officer-1`, INST, KEY_C), slot(`${INST}#key-officer-2`, INST, KEY_C)],
    };
    expect(() => assertRotationIsSurvivable(before, after, [INST])).toThrowError(
      /Rotate one slot per transaction/,
    );
  });

  it('refuses a single-slot rotation that leaves the self-signer nothing unchanged', () => {
    const single = { id: INST, controller: [INST], verificationMethod: [slot(`${INST}#key-officer-1`, INST, KEY_A)] };
    const rotated = { id: INST, controller: [INST], verificationMethod: [slot(`${INST}#key-officer-1`, INST, KEY_B)] };
    expect(() => assertRotationIsSurvivable(single, rotated, [INST])).toThrowError(
      /no verification\s+method survives|survives this transaction unchanged/,
    );
  });

  it('allows a single-slot rotation with a surviving sibling', () => {
    const after = {
      id: INST,
      controller: [INST],
      verificationMethod: [slot(`${INST}#key-officer-1`, INST, KEY_A), slot(`${INST}#key-officer-2`, INST, KEY_C)],
    };
    expect(() => assertRotationIsSurvivable(before, after, [INST])).not.toThrow();
  });
});

// ---------------------------------------------------------------------------

describe('the audit classifier separates re-issue from repair', () => {
  it('single self-controlled VM is UNRECOVERABLE — S-4 NC2, not rescued by anything', () => {
    const result = classifyPatientDid({
      id: PATIENT,
      controller: [RCK, INST],
      verificationMethod: [{ id: `${PATIENT}#key-1`, controller: PATIENT }],
    });
    expect(result.verdict).toBe('unrecoverable');
  });

  it('an external VM controller is recoverable', () => {
    const result = classifyPatientDid({
      id: PATIENT,
      controller: [RCK, INST],
      verificationMethod: [{ id: `${PATIENT}#key-1`, controller: RCK }],
    });
    expect(result.verdict).toBe('recoverable');
  });

  it('self-controlled but multi-VM and self-governed is recoverable by a sibling (S-4 M1)', () => {
    const result = classifyPatientDid({
      id: INST,
      controller: [INST],
      verificationMethod: [
        { id: `${INST}#key-officer-1`, controller: INST },
        { id: `${INST}#key-officer-2`, controller: INST },
      ],
    });
    expect(result.verdict).toBe('recoverable');
  });

  it('self-controlled multi-VM BEHIND an external controller is only conditionally recoverable', () => {
    // S-4 U2: the sibling does not excuse the missing controller.
    const result = classifyPatientDid({
      id: PATIENT,
      controller: [INST],
      verificationMethod: [
        { id: `${PATIENT}#key-1`, controller: PATIENT },
        { id: `${PATIENT}#key-2`, controller: PATIENT },
      ],
    });
    expect(result.verdict).toBe('indeterminate');
  });
});
