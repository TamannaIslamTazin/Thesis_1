/**
 * SSI Healthcare Backend — patient enrolment, atomic, emitting the S-1 §8.1 shape.
 *
 * ===========================================================================
 * WHAT THIS PROVISIONS, AND WHY IT CANNOT BE DONE IN TWO STEPS
 * ===========================================================================
 *   controller:          [ recovery-controller-DID, institutional-DID ]  (2-of-2 AND)
 *   verificationMethod:  exactly one, `controller` = the RECOVERY CONTROLLER
 *                        — deliberately NOT the patient DID
 *   authentication:      [ <patient>#key-1 ]
 *
 * S-1 §8.4: "a DID created first and secured afterwards cannot be secured
 * afterwards." The controller set is mutable only with the unanimous consent of
 * old ∪ new (§5.4), and the verification method's `controller` can only be
 * changed by a transaction that the lost key would have to sign (R0). Both
 * corrections therefore require exactly the thing whose loss they exist to
 * survive. There is no retrofit; only re-issuance.
 *
 * So enrolment is all-or-nothing, in the same sense as `assertHolderBound`: if
 * it cannot complete, it persists NOTHING. See §"Atomicity" below for the one
 * residue that is unavoidable and why it is inert.
 *
 * ===========================================================================
 * WHY NOT MULTI-VM FOR THE PATIENT
 * ===========================================================================
 * S-4 measured the tempting inference — "give the patient two keys and let a
 * sibling rescue a lost one" — as strictly worse on three counts (§6.3): it
 * conscripts a third mandatory signer into every rotation (U2), it forces the
 * patient to safeguard two independent secrets, and it hands a stolen phone the
 * power to evict the backup key (H1) and deactivate the identity irreversibly
 * (G2 + T1). Under §8.1 the device key has NO update authority at all (S-1 E3):
 * a stolen phone cannot move the DID.
 *
 * ===========================================================================
 * WHOSE KEY THE RECOVERY CONTROLLER IS — SETTLED IN PHASE B
 * ===========================================================================
 * Creation needs the recovery controller's SIGNATURE — controllers ∪
 * VM-controllers, `msg_server_create_diddoc.go:58-59` — so enrolment cannot
 * proceed without a recovery controller that can sign at that moment. That is
 * why custody is an INJECTED DEPENDENCY ({@link RecoveryControllerProvider})
 * rather than something this module decides.
 *
 * TWO IMPLEMENTATIONS NOW EXIST, and the seam did its job: neither of them
 * changed a line of the enrolment below.
 *
 *   `deviceHeldRecoveryController` (deviceRecoveryKey.ts)  — R5 PHASE B, the
 *      real one. A random Ed25519 RCK generated per enrolment, split to SLIP-39
 *      guardians, never written to this backend's key store.
 *
 *   {@link agentHeldRecoveryController}                    — R5 PHASE A, and
 *      honestly custodial: the key lives in the Askar store, so both halves of
 *      the 2-of-2 sit in one building. DEVELOPMENT ONLY as of Phase B — the
 *      config refuses `backend-held-phase-a` when `NODE_ENV=production`.
 *
 * The DOCUMENT is identical either way, which was the point of fixing the shape
 * first: nothing minted under Phase A needs re-issuing.
 */

import type { Agent } from '@credo-ts/core';

import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import {
  ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL,
  createCheqdDID,
  rotateVerificationMethod,
  type CheqdDIDResult,
} from './cheqdDid.js';
import {
  assertPatientRecoverableShape,
  assertRecoveryControllerShape,
} from '@ssi-healthcare/sdk/ledger';
import type { CheqdDidDocumentShape } from '@ssi-healthcare/sdk/ledger';
import {
  agentSigner,
  didRepositoryOf,
  requireLiveDidOnChain,
  resolveOnChain,
  type CheqdSigner,
} from './cheqdLedger.js';
import { LEDGER_SIGNING_FRAGMENT } from './institutionalDid.js';

// ---------------------------------------------------------------------------
// The recovery controller, as a contract rather than an implementation
// ---------------------------------------------------------------------------

export interface RecoveryController {
  readonly did: string;
  readonly signer: CheqdSigner;
  /** Recorded in the log so an audit can tell Phase-A custody from Phase-B custody. */
  readonly custody: string;
}

/**
 * Where the patient's recovery controller comes from.
 *
 * A narrow interface on purpose. Phase B's device-held, SLIP-39-split RCK is a
 * different implementation of exactly this contract — it must produce a DID
 * that already resolves on chain and a signer that can sign the patient's
 * create payload — and nothing else about enrolment changes when it lands.
 */
export interface RecoveryControllerProvider {
  readonly custody: string;
  provision(agent: Agent, context: { readonly userId: string }): Promise<RecoveryController>;
}

/**
 * PHASE-A CUSTODY — SUPERSEDED, AND DEVELOPMENT ONLY.
 *
 * The recovery controller is a self-controlled did:cheqd whose single key lives
 * in this backend's key store. Read that plainly: the backend can co-sign a
 * rotation of the patient's device key together with the institution. The
 * 2-of-2 AND is cryptographically real but both halves are in the same
 * building, so the sovereignty claim is false under this provider.
 *
 * USE `deviceHeldRecoveryController` INSTEAD. This is retained because DIDs
 * minted under it exist and must remain reasonable-about, and because the fast
 * suite uses it to assert shape properties without a guardian ceremony. The
 * config refuses `backend-held-phase-a` outright when `NODE_ENV=production`, so
 * it cannot be selected where it would matter.
 *
 * SELF-CONTROL IS CORRECT HERE and is not the R0 defect. A controller DID is
 * its own custodian — the S-1 experiment used exactly this shape for A, B and C
 * — and the RCK's *availability* is protected off-chain by the guardian split
 * (#240), not by an on-chain controller.
 */
export const agentHeldRecoveryController: RecoveryControllerProvider = {
  custody: 'backend-agent-key-store (Phase A; moves to the device in Phase B, #240)',

  async provision(agent, context) {
    const created = await createCheqdDID(agent, {
      controllers: {
        kind: 'self',
        acknowledgement: ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL,
        reason:
          'Recovery controller DID for a patient enrolment. A controller DID is its own ' +
          'custodian by definition; its availability is protected by the guardian split ' +
          '(#240), not by naming another on-chain controller.',
      },
      verificationMethodControl: {
        kind: 'self',
        acknowledgement: ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL,
        reason:
          'Same DID, same reason. Naming an external VM controller here would only move the ' +
          'question one hop and add a mandatory co-signer to every recovery.',
      },
      signers: [],
      assertShape: assertRecoveryControllerShape,
    });

    logger.info('patient_recovery_controller_provisioned', {
      userId: context.userId,
      recoveryControllerDid: created.did,
      custody: agentHeldRecoveryController.custody,
      transactionHash: created.transactionHash,
      height: created.height,
    });

    return {
      did: created.did,
      signer: await agentSigner(agent, created.did),
      custody: agentHeldRecoveryController.custody,
    };
  },
};

/** Mirrors `config.patientRecoveryCustody`'s enum without importing `config/index.ts` here. */
export type PatientRecoveryCustody = 'device-held-guardian-split' | 'backend-held-phase-a';

/**
 * Map a deployment's declared custody policy to the provider that implements
 * it — the ONE place this decision is made, so every caller re-derives it from
 * the same configuration instead of copying the refusal logic.
 *
 * THIS FUNCTION EXISTS BECAUSE OF AN ASYMMETRY THAT SHIPPED (steno #313
 * follow-up, R5). `routes/auth.ts` `mintPatientDid` checked
 * `config.patientRecoveryCustody` and refused for `device-held-guardian-split`
 * rather than falling back to the custodial provider.
 * `scripts/reissue-identity.ts` — the OPERATOR'S TOOL FOR THE DOCUMENTED
 * PRODUCTION RE-ISSUANCE PROCEDURE — did not: it imported
 * `agentHeldRecoveryController` directly and used it unconditionally,
 * regardless of what the deployment had configured. Running that script
 * against a `device-held-guardian-split` deployment would have silently
 * minted a custodial recovery key and reported success. The guarantee held
 * only on the path that happened to defend it (#315: per-step failsafes do
 * not compose) — so the guarantee is now this one function, called at the
 * point of use by both callers, rather than two hand-copies of the same
 * refusal that can drift.
 *
 * Takes `custody` as a PARAMETER rather than reading `config` itself: a caller
 * must re-derive it from its OWN observable configuration at the point of
 * use, not receive it as an assumption. It also makes the function trivially
 * testable without mocking a module-level singleton.
 */
export function selectRecoveryControllerProvider(
  custody: PatientRecoveryCustody | undefined,
): RecoveryControllerProvider {
  if (!custody) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      'PATIENT_RECOVERY_CUSTODY is not set. A patient recovery-controller DID needs a custody ' +
        'provider, and there is no default — an absent value must refuse rather than guess, ' +
        'the same as an absent controller set (S1-DID-CONTROLLER-SEMANTICS.md §8.1).',
      503,
    );
  }

  if (custody === 'device-held-guardian-split') {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      'This deployment holds patient recovery keys on the device ' +
        '(PATIENT_RECOVERY_CUSTODY=device-held-guardian-split), so a recovery-controller DID ' +
        'cannot be minted in a single call. The key must be generated, split to the guardians ' +
        'the patient nominates, and READ BACK by at least the threshold of them before any ' +
        'identity is anchored to it — guardian shares cannot be added afterwards (S-2 §8). ' +
        'Refusing rather than falling back to backend-held custody, which would silently make ' +
        'this patient custodial.',
      409,
    );
  }

  // The only remaining enum value is `backend-held-phase-a`. Selecting it in
  // production already fails at config load time
  // (`assertCustodyIsPermitted` in config/index.ts), so reaching this line at
  // all means the calling process is permitted to use it.
  return agentHeldRecoveryController;
}

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

export interface EnrolPatientSpec {
  readonly userId: string;
  readonly institutionalDid: string;
  readonly recoveryControllerProvider: RecoveryControllerProvider;
  /**
   * The patient's own public key, generated on their handset.
   *
   * WHY THIS IS THE POINT OF THE WHOLE FILE. Without it `#key-1` is generated
   * in this backend's key store, so the patient holds no key appearing in their
   * own DID document and cannot sign a login challenge — which is why email/OTP
   * remained load-bearing long after it was ruled out.
   *
   * IT IS APPLIED BY ROTATION, NOT AT CREATION, and that is not a workaround.
   * The SDK refuses to construct a create message without a signature from the
   * subject's own `#key-1` (cheqdDid.ts, `creationSignerDids`), which the device
   * cannot supply without a round trip mid-enrolment. Rotation needs only the
   * verification method's controller — the recovery controller and the
   * institution, both already signing here — so the key can be replaced
   * immediately after birth with no extra party and no extra call.
   *
   * The key stays ROTATABLE: `#key-1`'s `controller` is the recovery controller,
   * and a verification method's key material is independent of who may change
   * it. A lost device is recoverable; a device-held key is not sovereignty over
   * the identifier. Do NOT respond to device loss by adding a second
   * verification method — S-4 §6.3 measured that as strictly worse (see the
   * header of this file).
   *
   * Optional only so that server-held identities and the fast suite's shape
   * assertions keep working. A patient enrolment that omits it produces a DID
   * the patient cannot authenticate with.
   */
  readonly devicePublicKeyMultibase?: string;
  /**
   * Called ONLY after the patient DID has been read back from the chain and its
   * shape re-verified there. Anything this throws aborts the enrolment, and the
   * on-chain artifacts are abandoned rather than half-recorded.
   */
  readonly persist: (result: PatientEnrolmentChainResult) => Promise<void>;
}

export interface PatientEnrolmentChainResult {
  readonly patientDid: string;
  readonly recoveryControllerDid: string;
  readonly institutionalDid: string;
  readonly recoveryControllerCustody: string;
  readonly transactionHash: string;
  readonly height: number;
}

export async function enrolPatient(
  agent: Agent,
  spec: EnrolPatientSpec,
): Promise<PatientEnrolmentChainResult> {
  // ---- 1. Everything that can fail without writing anything, first. --------
  const institution = await requireLiveDidOnChain(
    agent,
    spec.institutionalDid,
    `enrol a patient under '${spec.institutionalDid}'`,
  );

  assertInstitutionCanCoSign(institution);

  const institutionSigner = await agentSigner(
    agent,
    spec.institutionalDid,
    LEDGER_SIGNING_FRAGMENT,
  ).catch(() => agentSigner(agent, spec.institutionalDid));

  // ---- 2. Chain writes, in order, each undone by abandonment. --------------
  const abandonable: string[] = [];

  try {
    const recovery = await spec.recoveryControllerProvider.provision(agent, {
      userId: spec.userId,
    });
    abandonable.push(recovery.did);

    if (recovery.did === spec.institutionalDid) {
      throw new AppError(
        ERROR_CODES.DID_CREATION_FAILED,
        'The recovery controller provider returned the institutional DID. The 2-of-2 AND ' +
          'would collapse to 1-of-1 and the institution alone could move the patient identity.',
        500,
      );
    }

    const patient = await createPatientDid(agent, {
      recoveryControllerDid: recovery.did,
      institutionalDid: spec.institutionalDid,
      signers: [recovery.signer, institutionSigner],
    });
    abandonable.push(patient.did);

    // Hand `#key-1` to the device before anything is persisted.
    //
    // Ordering is the failsafe: a rotation that throws leaves the whole
    // enrolment to be abandoned by the catch below, so no user row is ever
    // written against a DID whose key the holder does not have. The alternative
    // — persist, then rotate — would produce an account that believes it can
    // sign and cannot.
    if (spec.devicePublicKeyMultibase) {
      await rotateVerificationMethod(agent, {
        did: patient.did,
        nextPublicKeyMultibase: spec.devicePublicKeyMultibase,
        // Exactly the pair that already authorised creation. Rotation requires
        // the verification method's controller, never the subject itself.
        signers: [recovery.signer, institutionSigner],
      });

      logger.info('patient_device_key_installed', {
        userId: spec.userId,
        patientDid: patient.did,
        custody: 'patient-device (private half never sent to this process)',
      });
    }

    // THE PROOF, NOT THE CACHE. Credo returns a well-formed document from its
    // own store for a DID that never changed on chain, which is exactly what a
    // failed write looks like from inside this process.
    await assertShapeOnChain(agent, patient.did, {
      recoveryControllerDid: recovery.did,
      institutionalDid: spec.institutionalDid,
    });

    const result: PatientEnrolmentChainResult = {
      patientDid: patient.did,
      recoveryControllerDid: recovery.did,
      institutionalDid: spec.institutionalDid,
      recoveryControllerCustody: recovery.custody,
      transactionHash: patient.transactionHash,
      height: patient.height,
    };

    await spec.persist(result);

    logger.info('patient_enrolled', {
      userId: spec.userId,
      ...result,
      deviceKeySignedCreationOnly: true,
    });

    return result;
  } catch (error) {
    await abandon(agent, spec.userId, abandonable, error);
    throw error;
  }
}

async function createPatientDid(
  agent: Agent,
  args: {
    readonly recoveryControllerDid: string;
    readonly institutionalDid: string;
    readonly signers: readonly CheqdSigner[];
  },
): Promise<CheqdDIDResult> {
  return createCheqdDID(agent, {
    controllers: {
      kind: 'dids',
      controllerDids: [args.recoveryControllerDid, args.institutionalDid],
    },
    // The whole design, in one field. `external` is the only variant this call
    // site can reach: `self` needs an acknowledgement token that appears
    // nowhere in this module.
    verificationMethodControl: {
      kind: 'external',
      controllerDid: args.recoveryControllerDid,
    },
    signers: args.signers,
    assertShape: (document) =>
      assertPatientRecoverableShape(document, {
        recoveryControllerDid: args.recoveryControllerDid,
        institutionalDid: args.institutionalDid,
      }),
  });
}

/**
 * The institution must be able to supply the second signature of the 2-of-2,
 * and must still be able to supply it later — a deactivated institution can
 * still authorise updates to the DIDs it controls (S-4 K1/K2), but one whose
 * document we cannot read is one we cannot reason about.
 */
function assertInstitutionCanCoSign(institution: {
  did: string;
  controller: string[];
  verificationMethod: { id: string }[];
}): void {
  if (institution.verificationMethod.length === 0) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Institutional DID '${institution.did}' has no verification method, so it cannot ` +
        'co-sign the patient DID it is about to control. Every patient enrolled under it ' +
        'would be frozen from birth.',
      503,
    );
  }

  const controllers =
    institution.controller.length > 0 ? institution.controller : [institution.did];
  if (controllers.length !== 1 || controllers[0] !== institution.did) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Institutional DID '${institution.did}' is controlled by [${controllers.join(', ')}], ` +
        'not by itself. Every future institutional key change would then need those DIDs to ' +
        'co-sign (AND), and the controller set can never be repaired (S-1 §5.4). Refusing to ' +
        'anchor patients to it.',
      503,
    );
  }
}

async function assertShapeOnChain(
  agent: Agent,
  patientDid: string,
  expectation: { recoveryControllerDid: string; institutionalDid: string },
): Promise<void> {
  const resolved = await resolveOnChain(agent, patientDid);

  if (!resolved || resolved.deactivated) {
    throw new AppError(
      ERROR_CODES.DID_RESOLUTION_FAILED,
      `Patient DID '${patientDid}' was reported written but does not resolve on chain as a ` +
        'live document. Refusing to record an identity that is not there.',
      502,
    );
  }

  assertPatientRecoverableShape(
    {
      '@context': [],
      id: resolved.did,
      controller: resolved.controller,
      verificationMethod: resolved.verificationMethod as CheqdDidDocumentShape['verificationMethod'],
      authentication: resolved.authentication,
      assertionMethod: resolved.assertionMethod,
    },
    expectation,
  );
}

/**
 * Abandon everything this enrolment wrote.
 *
 * TWO KINDS OF RESIDUE, AND THE DIFFERENCE MATTERS.
 *
 * LOCAL state — the agent's `DidRecord`s and their key mappings — is deleted,
 * so a failed enrolment leaves this process holding nothing that looks like a
 * provisioned wallet.
 *
 * LEDGER state cannot be deleted. Cosmos has no cross-transaction atomicity and
 * `x/did` has no delete; the only on-chain "removal" is deactivation, which is
 * itself a transaction that can fail and is terminal (S-4 T1). An abandoned
 * recovery-controller or patient DID is therefore left on chain. It is INERT:
 * it controls nothing, nothing controls it, no credential references it, and no
 * row points at it. It is logged at ERROR with its identifier so the residue is
 * countable rather than invisible.
 */
async function abandon(
  agent: Agent,
  userId: string,
  dids: readonly string[],
  cause: unknown,
): Promise<void> {
  const repository = didRepositoryOf(agent);

  for (const did of dids) {
    try {
      const record = await repository.findCreatedDid(agent.context, did);
      if (record) await repository.delete(agent.context, record);
    } catch (cleanupError) {
      logger.error('patient_enrolment_local_cleanup_failed', {
        userId,
        did,
        error: cleanupError instanceof Error ? cleanupError.message : String(cleanupError),
      });
    }
  }

  logger.error('patient_enrolment_aborted', {
    userId,
    abandonedOnChain: dids,
    localRecordsDeleted: dids.length,
    persisted: 'nothing',
    residue:
      dids.length > 0
        ? 'These DIDs exist on chain and are abandoned. They are inert: nothing controls ' +
          'them, they control nothing, and no row references them.'
        : 'none',
    error: cause instanceof Error ? cause.message : String(cause),
  });
}
