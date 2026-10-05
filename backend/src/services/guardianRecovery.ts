/**
 * R5 PHASE B — guardian recovery. The patient lost the phone; the identity survives.
 *
 * ===========================================================================
 * THE FAILURE MODE THIS EXISTS TO PREVENT
 * ===========================================================================
 * A patient DID's controller set is `[RCK, institution]` with AND semantics and
 * NO threshold (S-1 §3.1). If the RCK is lost and cannot be reconstructed, the
 * DID is frozen forever — the controller set is mutable only by unanimous
 * consent of old ∪ new (§5.4), which requires the very key that is missing.
 *
 * So this path is not a convenience. It is the reason the RCK is split at all,
 * and "implemented" is not the bar — it has to be PROVEN against the chain.
 *
 * ===========================================================================
 * WHY THIS IS FOUR PHASES AND EACH RE-CHECKS ITS OWN PRECONDITION (#315)
 * ===========================================================================
 * "Per-step failsafes do not compose." Re-issuance was individually correct at
 * every step and still revoked 79 credentials while re-issuing none, because a
 * later phase INHERITED a precondition instead of checking it.
 *
 * Recovery is multi-phase and destructive — it replaces a key — so each phase
 * below re-establishes its own precondition from observable state:
 *
 *   1. RESOLVE      Read the patient DID from the CHAIN. Not from a cache, not
 *                   from a row: the chain is the only thing that knows the
 *                   current controller set.
 *   2. RECONSTRUCT  Combine guardian shares. SLIP-39 refuses corrupt, mixed and
 *                   below-threshold sets, but a VALID set for a DIFFERENT
 *                   patient reconstructs perfectly — so this phase does not
 *                   trust its own success.
 *   3. PROVE        Check the reconstructed key against the RCK's public key AS
 *                   PUBLISHED ON CHAIN. This is the join that phase 2 cannot
 *                   make safe on its own, and it is checked before anything is
 *                   signed.
 *   4. ROTATE       Plan the signer set locally, refuse if incomplete, then
 *                   broadcast ONE verification method (S-4 §4.7 `code 1100`:
 *                   never rotate every VM in one transaction).
 *
 * Nothing is persisted at any point. A failure leaves the DID exactly as it
 * was, which is the correct outcome — the old device key still works, and the
 * patient is no worse off than before they tried.
 */

import type { Agent } from '@credo-ts/core';

import { combineGuardianShares, zeroise } from '@ssi-healthcare/shared';

import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import { DeviceRecoveryKeySession } from './deviceRecoveryKey.js';
import { resolveOnChain, requireLiveDidOnChain, type CheqdSigner } from './cheqdLedger.js';
import { executeRotation, planRotation } from './didRotationClient.js';

export interface GuardianRecoverySpec {
  readonly patientDid: string;
  /** SLIP-39 mnemonics collected from guardians. At least the threshold. */
  readonly guardianShares: readonly string[];
  /**
   * The replacement device key, generated on the NEW handset and never
   * exported. Required: letting the backend mint it here would re-introduce the
   * custody problem this phase exists to remove.
   */
  readonly nextDevicePublicKeyMultibase: string;
  /** The institution's half of the 2-of-2. */
  readonly institutionSigner: CheqdSigner;
}

export interface GuardianRecoveryResult {
  readonly patientDid: string;
  readonly recoveryControllerDid: string;
  readonly previousDevicePublicKeyMultibase: string;
  readonly nextDevicePublicKeyMultibase: string;
  readonly requiredSigners: readonly string[];
  /** THE ASSERTION. False means the lost key authorised nothing. */
  readonly deviceKeyParticipated: boolean;
  readonly guardianSharesUsed: number;
  readonly transactionHash: string;
  readonly height: number;
}

/**
 * Recover a patient's identity onto a new device using guardian shares.
 *
 * The device key being replaced is NEVER consulted. That is the property S-1
 * §8.1's shape buys and the one this function has to demonstrate: the
 * verification method's `controller` is the RCK, so `GetSignerDIDsForDIDUpdate`
 * asks for the RCK and the institution and never for the patient.
 */
export async function recoverWithGuardianShares(
  agent: Agent,
  spec: GuardianRecoverySpec,
): Promise<GuardianRecoveryResult> {
  // ---- PHASE 1: RESOLVE. The chain, not a cache. --------------------------
  const patient = await requireLiveDidOnChain(
    agent,
    spec.patientDid,
    `recover '${spec.patientDid}' with guardian shares`,
  );

  const deviceSlot = patient.verificationMethod[0];
  if (!deviceSlot) {
    throw new AppError(
      ERROR_CODES.DID_RESOLUTION_FAILED,
      `Patient DID '${spec.patientDid}' has no verification method to recover.`,
      409,
    );
  }

  const recoveryControllerDid = deviceSlot.controller as string;
  if (recoveryControllerDid === spec.patientDid) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Patient DID '${spec.patientDid}' has a SELF-CONTROLLED verification method, so the ` +
        'chain requires the lost key to authorise its own replacement. This identity is ' +
        'unrecoverable (S-1 R0) and must be re-issued, not recovered. Refusing before any ' +
        'share is combined.',
      409,
    );
  }

  // The RCK DID must itself still be readable, or we cannot learn which public
  // key the shares are supposed to reproduce.
  const recoveryController = await resolveOnChain(agent, recoveryControllerDid);
  const recoveryKeySlot = recoveryController?.verificationMethod?.[0];
  if (!recoveryController || recoveryController.deactivated || !recoveryKeySlot) {
    throw new AppError(
      ERROR_CODES.DID_RESOLUTION_FAILED,
      `The recovery controller '${recoveryControllerDid}' does not resolve as a live document ` +
        'with a verification method, so there is nothing to check the reconstructed key ' +
        'against. Refusing to sign on the strength of the shares alone.',
      502,
    );
  }

  // ---- PHASE 2: RECONSTRUCT. Does not trust its own success. --------------
  const attempt = combineGuardianShares(spec.guardianShares);
  const session = DeviceRecoveryKeySession.fromRecoveredSeed(attempt.seed);

  try {
    // ---- PHASE 3: PROVE, against the ledger, BEFORE signing anything. -----
    // This is the join #315 is about. Phase 2 succeeding means the shares were
    // internally consistent; it does NOT mean they were this patient's.
    session.assertMatchesOnChainKey(
      recoveryKeySlot.publicKeyMultibase as string,
      `recovery controller '${recoveryControllerDid}' of patient '${spec.patientDid}'`,
    );

    // ---- PHASE 4: ROTATE. Plan locally, refuse loudly, then broadcast. ----
    const signers = [
      session.controllerSigner(recoveryControllerDid),
      spec.institutionSigner,
    ];

    const plan = await planRotation(agent, {
      did: spec.patientDid,
      signers,
      nextPublicKeyMultibase: spec.nextDevicePublicKeyMultibase,
    });

    // The chain names only ONE missing signer per rejection (S-1 §8.4), so a
    // local completeness check is the only way to see the whole picture before
    // a block is consumed.
    if (!plan.complete) {
      throw new AppError(
        ERROR_CODES.DID_CREATION_FAILED,
        `Cannot recover '${spec.patientDid}': missing signatures from ` +
          `[${plan.missingSigners.join(', ')}]. Nothing was broadcast.`,
        409,
      );
    }

    // If the patient DID were in this set, the LOST key would be required to
    // authorise its own replacement and the identity would be unrecoverable.
    // Asserting it here rather than trusting the shape means a regression in
    // enrolment surfaces as a refusal, not as a frozen patient.
    if (plan.requiredSigners.includes(spec.patientDid)) {
      throw new AppError(
        ERROR_CODES.DID_CREATION_FAILED,
        `The chain requires '${spec.patientDid}' to sign its own recovery, which means the ` +
          'lost device key is conscripted. This DID does not have the S-1 §8.1 shape and ' +
          'cannot be recovered. Nothing was broadcast.',
        409,
      );
    }

    const { result } = await executeRotation(agent, {
      did: spec.patientDid,
      signers,
      nextPublicKeyMultibase: spec.nextDevicePublicKeyMultibase,
    });

    const outcome: GuardianRecoveryResult = {
      patientDid: spec.patientDid,
      recoveryControllerDid,
      previousDevicePublicKeyMultibase: result.previousPublicKeyMultibase,
      nextDevicePublicKeyMultibase: result.nextPublicKeyMultibase,
      requiredSigners: plan.requiredSigners,
      deviceKeyParticipated: plan.requiredSigners.includes(spec.patientDid),
      guardianSharesUsed: attempt.sharesUsed,
      transactionHash: result.transactionHash,
      height: result.height,
    };

    logger.info('patient_recovered_with_guardian_shares', {
      ...outcome,
      recoveryPath: 'GUARDIAN_SLIP39',
      backendHeldRecoveryKey: false,
    });

    return outcome;
  } finally {
    // The seed's lifetime ends here whatever happened, including on the failure
    // paths above where it was reconstructed but never used.
    session.close();
    zeroise(attempt.seed);
  }
}
