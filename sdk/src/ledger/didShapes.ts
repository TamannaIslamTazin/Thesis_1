/**
 * did:cheqd document SHAPES — the refusals that stand between a call site and a
 * DID it can never repair.
 *
 * ===========================================================================
 * WHY THESE ARE IN THE SDK
 * ===========================================================================
 * Every predicate here was established by execution against `bd-health-trust-1`
 * rather than by reading a spec:
 *
 *   S1-DID-CONTROLLER-SEMANTICS.md  — AND over controllers; the VM `controller`
 *                                     field decides who may replace a VM
 *   S4-MULTI-VM-RECOVERY.md         — OR within one controller DID; attribution
 *                                     by id prefix; the X1 bulk-rotation trap
 *
 * They moved out of the backend because the party who most needs them is the
 * one furthest from it. A handset about to rotate its own key has to predict
 * what the chain will demand BEFORE it broadcasts; an integrator assembling a
 * document needs the same answer without standing up our server. Leaving these
 * in the backend meant every one of those callers either guessed or duplicated
 * them, and a duplicated refusal is one that drifts (#341).
 *
 * NO I/O, NO LEDGER, NO KMS. That is what lets the properties deciding whether
 * an identity is recoverable be covered by fast tests, and therefore stops them
 * being silently un-covered by a stopped validator.
 *
 * ===========================================================================
 * TWO FIELDS NAMED `controller`, FAILING IN OPPOSITE DIRECTIONS
 * ===========================================================================
 * A document's `controller` ARRAY says who may update the document (AND, no
 * threshold). A verification method's `controller` FIELD says who may replace
 * that one method — and by S-4 V2 it does NOT decide whose signature that
 * method's key counts as; the id prefix does. Read every mention below with the
 * qualifier attached.
 */

import { ERROR_CODES, SsiError } from '@ssi-healthcare/shared';

import {
  ED25519_VERIFICATION_KEY_2020,
  isCheqdDid,
  didPartOf,
  fragmentOf,
  uniqueSorted,
  controllersOrSubject,
  verificationMethodDelta,
  verificationMethodChanged,
} from './didDocument';
import type {
  VerificationMethodSlot,
  CheqdDidDocumentShape,
  SignerSetInputDocument,
} from './didDocument';

export function assertIsCheqdDid(value: string, role: string): void {
  if (!isCheqdDid(value)) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `${role} is not a did:cheqd identifier: '${value}'`,
      400,
    );
  }
}

/**
 * Refuse a transaction that would leave the subject with no unchanged key of
 * its own to sign with.
 *
 * S-4 §3.4: `msg_server_update_diddoc.go:47` registers the incoming document
 * under a `<did>-updated` pseudo-DID and `DuplicateSignatures` clones every
 * signature under `<did>` into a twin under `<did>-updated`. The twin is
 * verified against the NEW key material. So a signature by a slot that is
 * itself being rotated verifies against the replacement key and fails —
 * `code 1100` `ErrInvalidSignature`, X1 at height 86330, NOT the
 * `1101 ErrSignatureNotFound` a reader would expect.
 *
 * The remedy X2 demonstrated (the incoming key co-signs under the same VM id)
 * is deliberately NOT the default. Rotating one slot at a time is always
 * available, always survivable, and does not require the tooling to hold both
 * halves of the new key at broadcast time.
 */
export function assertRotationIsSurvivable(
  existing: SignerSetInputDocument,
  updated: SignerSetInputDocument,
  requiredSigners: readonly string[],
): void {
  const delta = verificationMethodDelta(existing, updated);
  const touched = [...delta.added, ...delta.changed, ...delta.removed];

  if (touched.length > 1) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Refusing to change ${touched.length} verification methods of '${existing.id}' in one ` +
        `transaction (${touched.join(', ')}). Rotate one slot per transaction: the chain ` +
        `verifies the signing key against the NEW document as well as the old, so a bulk ` +
        `rotation signed by outgoing keys is rejected with code 1100 (S-4 X1, height 86330).`,
      400,
    );
  }

  // The subject only needs a surviving key of its own when the subject is
  // itself a required signer — a self-controlled DID, or one whose changed slot
  // names the subject as its controller.
  if (!requiredSigners.includes(existing.id)) return;

  const existingByFragment = new Map(
    (existing.verificationMethod ?? []).map((vm) => [fragmentOf(vm.id), vm]),
  );
  const survivesUnchanged = (updated.verificationMethod ?? []).some((vm) => {
    const previous = existingByFragment.get(fragmentOf(vm.id));
    return (
      previous !== undefined &&
      !verificationMethodChanged(previous, vm, existing.id, updated.id)
    );
  });

  if (!survivesUnchanged) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Refusing to update '${existing.id}': it must sign for itself, but no verification ` +
        `method survives this transaction unchanged. Its signature would be verified a ` +
        `second time against the updated document and fail there (code 1100, S-4 §3.4).`,
      400,
    );
  }
}

// ---------------------------------------------------------------------------
// Shape assertions — the last gate before broadcast
// ---------------------------------------------------------------------------

/**
 * The institutional shape (S-4 §6.2, steno #292).
 *
 * SELF-CONTROLLED DOCUMENT, and EVERY slot's `controller` is the institution's
 * own DID. If any slot names another DID, `GetSignerDIDsForDIDUpdate:152`
 * requires THAT DID's signature to rotate that slot — so 1-of-N silently
 * becomes 1-of-(N−1) plus one slot the institution can never recover, and the
 * discovery happens on the day it matters.
 *
 * This runs on the ASSEMBLED DOCUMENT, after every constructor path, so it
 * cannot be bypassed by a new call site that forgets a check.
 */
export function assertInstitutionalShape(document: CheqdDidDocumentShape): void {
  const { id, controller, verificationMethod, authentication } = document;

  assertIsCheqdDid(id, 'institutional DID');

  if (controller.length !== 1 || controller[0] !== id) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `An institutional DID must be self-controlled: controller must be exactly ['${id}'], ` +
        `not [${controller.join(', ')}]. A foreign controller makes every future update of ` +
        `this institution conditional on that DID's availability (AND, S-1 §2) and is the ` +
        `availability trap #278 rejected for the ministry-over-hospital hierarchy.`,
      400,
    );
  }

  if (verificationMethod.length < 1) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      'An institutional DID needs at least one verification method; without one it can ' +
        'never sign anything and is inert on arrival.',
      400,
    );
  }

  for (const vm of verificationMethod) {
    if (vm.controller !== id) {
      throw new SsiError(
        ERROR_CODES.DID_CREATION_FAILED,
        `Verification method '${vm.id}' declares controller '${vm.controller}', not the ` +
          `institution '${id}'. Rotating that slot would then require a signature from ` +
          `'${vm.controller}', so 1-of-N custody degrades to 1-of-${verificationMethod.length - 1} ` +
          `plus one unrecoverable slot (S-4 §6.1). This shape is not constructible here.`,
        400,
      );
    }

    if (didPartOf(vm.id) !== id) {
      throw new SsiError(
        ERROR_CODES.DID_CREATION_FAILED,
        `Verification method '${vm.id}' is not under the institution's namespace '${id}'. ` +
          'Attribution is by id prefix and never by the controller field (S-4 V2), so this ' +
          'would be scored as a signature by some other DID.',
        400,
      );
    }

    if (vm.type !== ED25519_VERIFICATION_KEY_2020 || !vm.publicKeyMultibase) {
      throw new SsiError(
        ERROR_CODES.DID_CREATION_FAILED,
        `Verification method '${vm.id}' is not a well-formed ${ED25519_VERIFICATION_KEY_2020}.`,
        400,
      );
    }
  }

  const fragments = verificationMethod.map((vm) => fragmentOf(vm.id));
  if (new Set(fragments).size !== fragments.length) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Duplicate verification-method fragments in '${id}': ${fragments.join(', ')}. The ` +
        'chain maps slots by fragment, so a duplicate silently shadows a key.',
      400,
    );
  }

  const known = new Set(verificationMethod.map((vm) => vm.id));
  for (const reference of [...authentication, ...(document.assertionMethod ?? [])]) {
    if (!known.has(reference)) {
      throw new SsiError(
        ERROR_CODES.DID_CREATION_FAILED,
        `'${reference}' is referenced by a verification relationship of '${id}' but is not ` +
          'one of its verification methods.',
        400,
      );
    }
  }
}

export interface PatientShapeExpectation {
  readonly recoveryControllerDid: string;
  readonly institutionalDid: string;
}

/**
 * The patient shape (S-1 §8.1, amended by S-4 §6.3).
 *
 *   controller:          [ RCK-DID, institutional-DID ]   — 2-of-2 AND
 *   verificationMethod:  exactly one, `controller` = RCK-DID  (NOT the patient)
 *   authentication:      [ <patient>#key-device ]
 *
 * Three refusals carry the whole design:
 *
 *  1. `vm.controller` must not be the patient DID. That default — emitted by
 *     `@cheqd/sdk` and by Credo's `CheqdDidRegistrar` — makes replacing a lost
 *     device key require the lost device key (S-1 R0, `1101` at height 46229).
 *  2. The patient DID must not appear in its own controller ARRAY. S-4's V2
 *     amendment: the device key's id is `<patient>#key-device`, so by
 *     attribution-by-prefix it counts as a signature BY the patient DID. That is
 *     inert only while the patient DID is outside its own controller array; the
 *     moment it is added, the stolen phone regains full authority.
 *  3. Exactly one verification method. Multi-VM for patients was measured
 *     strictly worse on three counts (S-4 §6.3) — it conscripts a second
 *     mandatory signer, forces the patient to hold two secrets, and hands a
 *     stolen phone the power to evict the backup key and deactivate the DID.
 */
export function assertPatientRecoverableShape(
  document: CheqdDidDocumentShape,
  expectation: PatientShapeExpectation,
): void {
  const { id, controller, verificationMethod, authentication } = document;
  const { recoveryControllerDid, institutionalDid } = expectation;

  assertIsCheqdDid(id, 'patient DID');
  assertIsCheqdDid(recoveryControllerDid, 'recovery controller DID');
  assertIsCheqdDid(institutionalDid, 'institutional DID');

  if (recoveryControllerDid === institutionalDid) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      'The recovery controller and the institution are the same DID, so the 2-of-2 AND ' +
        'collapses to 1-of-1 and the institution alone can move the patient identity. That ' +
        'is the custodial outcome the controller set exists to prevent.',
      400,
    );
  }

  if (controller.includes(id)) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Patient DID '${id}' appears in its own controller array. The device key's id lives ` +
        'under this DID, and attribution is by id prefix (S-4 V2), so this silently grants a ' +
        'stolen phone full authority over the identity. S-1 §8.1 as amended by S-4 §6.3.',
      400,
    );
  }

  const expectedControllers = uniqueSorted([recoveryControllerDid, institutionalDid]);
  if (
    controller.length !== 2 ||
    uniqueSorted([...controller]).join('|') !== expectedControllers.join('|')
  ) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Patient DID '${id}' must be controlled by exactly [recovery controller, institution] ` +
        `= [${expectedControllers.join(', ')}], not [${controller.join(', ')}]. The controller ` +
        'set is mutable only with the unanimous consent of old ∪ new (S-1 §5.4), so it must ' +
        'be right at creation.',
      400,
    );
  }

  if (verificationMethod.length !== 1) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Patient DID '${id}' must carry exactly one verification method, not ` +
        `${verificationMethod.length}. Multi-VM was measured strictly worse for patients on ` +
        'three counts (S-4 §6.3).',
      400,
    );
  }

  const vm = verificationMethod[0] as VerificationMethodSlot;

  if (vm.controller === id) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Patient DID '${id}' has a SELF-CONTROLLED verification method. Replacing that key ` +
        'would require a signature from the key being replaced, so a lost phone is a lost ' +
        'identity even with unanimous controller consent (S-1 R0). There is no retrofit.',
      400,
    );
  }

  if (vm.controller !== recoveryControllerDid) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Verification method '${vm.id}' names '${vm.controller}' as the DID that may replace ` +
        `it; it must be the patient's own recovery controller '${recoveryControllerDid}'. ` +
        'Anything else moves the power of recovery away from the patient.',
      400,
    );
  }

  if (didPartOf(vm.id) !== id) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Verification method '${vm.id}' is not under the patient's namespace '${id}'.`,
      400,
    );
  }

  if (!authentication.includes(vm.id)) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Verification method '${vm.id}' is not in the authentication relationship, so the ` +
        'wallet cannot present with it. Authorisation on chain would still work (S-4 M4) — ' +
        'this refusal is about DIDComm and VP verification, not about x/did.',
      400,
    );
  }
}

/**
 * The recovery-controller shape (R5 Phase B, #240).
 *
 * SELF-CONTROLLED DOCUMENT with EXACTLY ONE self-controlled verification
 * method. Structurally identical, today, to a one-officer institutional DID —
 * but kept as its OWN named predicate rather than reusing
 * `assertInstitutionalShape`, because the two roles are expected to diverge:
 * an institution is meant to GROW past one verification method (S-4 §6.2,
 * sibling rescue), while a recovery-controller DID never does — its
 * availability comes from the off-chain SLIP-39 guardian split (#240), not
 * from an on-chain sibling. Sharing one assertion between them would mean a
 * future tightening of one predicate (e.g. "institutions must have N >= 2")
 * silently starts rejecting RCK DIDs too, or vice versa.
 *
 * THIS WAS THE GAP steno #313's brief actually found, once inventoried: patient
 * and institutional DIDs already had shape-locked constructors
 * (`createPatientDid`, `provisionInstitutionalDid`) that always ran their
 * assertion. The recovery-controller DID — minted by both
 * `agentHeldRecoveryController` and `deviceHeldRecoveryController` in
 * patientEnrolment.ts / deviceRecoveryKey.ts — went through the generic
 * `createCheqdDID` with `assertShape` OPTIONAL and never supplied. Nothing
 * stood between that call site and a wrong-shaped DID except the fact that its
 * two inline literals happened to be typed correctly.
 */
export function assertRecoveryControllerShape(document: CheqdDidDocumentShape): void {
  const { id, controller, verificationMethod, authentication } = document;

  assertIsCheqdDid(id, 'recovery-controller DID');

  if (controller.length !== 1 || controller[0] !== id) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `A recovery-controller DID must be self-controlled: controller must be exactly ['${id}'], ` +
        `not [${controller.join(', ')}]. It is its own custodian by definition (#240); naming ` +
        'another DID as controller here only moves the availability question one hop.',
      400,
    );
  }

  if (verificationMethod.length !== 1) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `A recovery-controller DID must carry exactly one verification method, not ` +
        `${verificationMethod.length}. It never grows past one (#240): availability comes from ` +
        'the SLIP-39 guardian split, not from an on-chain sibling rescue.',
      400,
    );
  }

  const vm = verificationMethod[0] as VerificationMethodSlot;

  if (vm.controller !== id) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Verification method '${vm.id}' declares controller '${vm.controller}', not the ` +
        `recovery-controller DID '${id}' itself. A recovery controller is its own custodian; an ` +
        'external VM controller here would need that external DID to co-sign every future ' +
        'rotation of the very key that secures the patient identity.',
      400,
    );
  }

  if (didPartOf(vm.id) !== id) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Verification method '${vm.id}' is not under the recovery-controller's namespace '${id}'. ` +
        'Attribution is by id prefix and never by the controller field (S-4 V2).',
      400,
    );
  }

  if (vm.type !== ED25519_VERIFICATION_KEY_2020 || !vm.publicKeyMultibase) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Verification method '${vm.id}' is not a well-formed ${ED25519_VERIFICATION_KEY_2020}.`,
      400,
    );
  }

  if (!authentication.includes(vm.id)) {
    throw new SsiError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Verification method '${vm.id}' is not in the authentication relationship of '${id}', so ` +
        'it cannot sign the patient DID creation it exists to co-sign.',
      400,
    );
  }
}

/**
 * The escape hatch for negative-control fixtures that must mint a
 * KNOWINGLY-BROKEN document — reproducing a legacy defect, or proving that a
 * refusal actually fires.
 *
 * `CreateCheqdDIDSpec.assertShape` is mandatory precisely so a production call
 * site cannot omit the check by forgetting it. This constant is how a test or a
 * `scripts/verify-*.ts` diagnostic states the omission ON PURPOSE, as one
 * greppable name, instead of an inline `() => {}` that would read as
 * unremarkable at every site it got copied to next.
 *
 * `rg SHAPE_ASSERTION_DELIBERATELY_OMITTED` must return the complete, finite
 * list of every unchecked mint in this repository. Any use outside a test file
 * or a `scripts/verify-*.ts` diagnostic is a defect — file it, do not extend
 * this list to cover it.
 */
export const SHAPE_ASSERTION_DELIBERATELY_OMITTED = (_document: CheqdDidDocumentShape): void => {
  // Intentionally empty — see docblock above.
};

/**
 * Classify a RESOLVED document for the audit in S-1 §8.4.
 *
 * `unrecoverable` is the finding that matters: a single verification method
 * that controls itself. S-4's sibling rescue does not save it — that case is
 * exactly NC2 — so it must be re-issued rather than repaired.
 */
export type PatientDidRecoverability =
  | { readonly verdict: 'recoverable'; readonly verificationMethodController: string }
  | { readonly verdict: 'unrecoverable'; readonly reason: string }
  | { readonly verdict: 'indeterminate'; readonly reason: string };

export function classifyPatientDid(document: {
  id: string;
  controller?: readonly string[];
  verificationMethod?: readonly { id: string; controller: string }[];
}): PatientDidRecoverability {
  const vms = document.verificationMethod ?? [];

  if (vms.length === 0) {
    return {
      verdict: 'indeterminate',
      reason: 'resolved with no verification method; nothing to rotate and nothing to lose',
    };
  }

  const selfControlled = vms.filter((vm) => vm.controller === document.id);

  if (selfControlled.length === 0) {
    return {
      verdict: 'recoverable',
      verificationMethodController: (vms[0] as { controller: string }).controller,
    };
  }

  // S-4 M1: a sibling slot rescues a lost one, but only when the sibling exists
  // AND the subject is not gated behind a controller it cannot satisfy.
  if (vms.length > 1) {
    const controllers = controllersOrSubject(document.controller, document.id);
    const gatedBy = controllers.filter((c) => c !== document.id);
    if (gatedBy.length === 0) {
      return {
        verdict: 'recoverable',
        verificationMethodController: document.id,
      };
    }
    return {
      verdict: 'indeterminate',
      reason:
        `has ${vms.length} verification methods so a sibling can rotate a lost slot (S-4 M1), ` +
        `but every rotation also needs ${gatedBy.join(', ')} to co-sign (S-4 U2). Recoverable ` +
        'only while those controllers are available.',
    };
  }

  return {
    verdict: 'unrecoverable',
    reason:
      `single self-controlled verification method '${(vms[0] as { id: string }).id}'. ` +
      'Replacing it requires a signature from the key being replaced (S-1 R0, S-4 NC2). ' +
      'Must be RE-ISSUED, not repaired.',
  };
}
