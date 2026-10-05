/**
 * R5 PHASE B — the RCK, held where it is supposed to be held.
 *
 * ===========================================================================
 * WHAT THIS CHANGES, AND WHAT IT DELIBERATELY DOES NOT
 * ===========================================================================
 * Phase A shipped `agentHeldRecoveryController`, which was honestly custodial:
 * the RCK lived in this backend's Askar store, so the 2-of-2 AND was
 * cryptographically real with both halves in the same building.
 *
 * This module swaps THE KEY HOLDER. It does not touch the document. The
 * controller set, the verification-method controller and the authentication
 * relationship that `enrolPatient` writes are byte-for-byte what Phase A wrote —
 * S-1 §8.1 and S-4 §6.3 settled that shape and it is a one-way door. Anything
 * minted under Phase A therefore needs no re-issuance.
 *
 * ===========================================================================
 * THE CONSTRAINT THAT SHAPES EVERYTHING HERE
 * ===========================================================================
 * `msg_server_create_diddoc.go:58-59` requires signatures from controllers ∪
 * VM-controllers AT CREATION. The RCK is one of those controllers. So the RCK
 * must be able to SIGN DURING ENROLMENT — it cannot be a key that only comes
 * into existence later, and it cannot be a key only the guardians can assemble.
 *
 * That is why the seed is generated first, split second, and only then used to
 * sign: {@link DeviceRecoveryKeySession} holds it in memory for the length of
 * the enrolment and zeroises it after. The seed is necessarily a software key —
 * it signs cheqd transactions — so the mitigation is LIFETIME, not avoidance
 * (S-2 §8).
 *
 * ===========================================================================
 * WHERE THE PRIVATE HALF ACTUALLY IS
 * ===========================================================================
 * Nowhere durable. It is never written to the Askar store, never persisted, and
 * never returned across a process boundary. `createCheqdDID` records a
 * `DidRecord` with NO key mapping for these DIDs, so `agentSigner` refuses for
 * them — the backend being unable to sign is the property being bought.
 *
 * The honest limit, stated plainly: in this build the session object lives in
 * the backend process during enrolment because that is where the ceremony is
 * driven from. {@link RemoteDeviceSigner} is the seam for moving it to the
 * handset — the signer is already an async `sign(payload)` call, which is a
 * network round trip in everything but transport. Nothing else in the enrolment
 * path needs to change when that lands.
 */

import type { Agent } from '@credo-ts/core';

import {
  GuardianCeremony,
  DEFAULT_GUARDIAN_POLICY,
  generateRecoveryKeySeed,
  recoveryKeyPublicKey,
  signWithRecoveryKey,
  zeroise,
  type GuardianPolicy,
  type GuardianShare,
} from '@ssi-healthcare/shared';

import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import { depositInstitutionShare } from './backupVaultClient.js';
import {
  ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL,
  DEVICE_KEY_FRAGMENT,
  createCheqdDID,
  type CheqdSigner,
  type ExternalSubjectKey,
} from './cheqdDid.js';

import {
  ed25519PublicKeyToMultibase,
  ed25519PublicKeyFromMultibase,
  assertRecoveryControllerShape,
} from '@ssi-healthcare/sdk/ledger';
import type { RecoveryController, RecoveryControllerProvider } from './patientEnrolment.js';

/**
 * The encoding `toMultibaseRaw` produces, restated so this module can produce it
 * too. Now one line over `sdk/ledger`, which also removed the second copy of
 * ED25519_MULTICODEC_PREFIX that used to sit here — and added the length check
 * this function never had. A wrong-length key is now refused rather than encoded
 * into an identifier that cannot be repaired.
 */
export function ed25519MultibaseFromRawPublicKey(publicKey: Uint8Array): string {
  return ed25519PublicKeyToMultibase(publicKey);
}

/**
 * The transport seam. An in-process session implements this today; an HTTP
 * client to the handset implements it tomorrow, and no caller changes.
 */
export interface RemoteDeviceSigner {
  readonly publicKeyMultibase: string;
  sign(payload: Uint8Array): Promise<Uint8Array>;
}

export type SessionState = 'ARMED' | 'SPENT';

/**
 * One enrolment's worth of RCK custody.
 *
 * SINGLE USE. Once {@link close} runs the seed is gone and every signer this
 * session produced starts refusing. A session that could be reused would be a
 * seed with an unbounded lifetime, which is the thing S-2 §8 asks us to avoid.
 */
export class DeviceRecoveryKeySession {
  private seed: Uint8Array | null;
  private state: SessionState = 'ARMED';
  /** Null on the recovery path, where the split already exists and must not be redone. */
  private readonly ceremony: GuardianCeremony | null;

  private constructor(seed: Uint8Array, ceremony: GuardianCeremony | null) {
    this.seed = seed;
    this.ceremony = ceremony;
  }

  /**
   * Generate a fresh RCK and open its guardian ceremony.
   *
   * Order matters and is not arbitrary: the split is produced and VERIFIED (see
   * `splitRecoveryKey`, which reconstructs from its own output) before the key
   * is ever used to sign anything. A key that has signed a DID creation but
   * whose shares do not reconstruct is precisely the unrecoverable identity
   * this phase exists to prevent.
   */
  static begin(policy: GuardianPolicy = DEFAULT_GUARDIAN_POLICY): DeviceRecoveryKeySession {
    const seed = generateRecoveryKeySeed();
    try {
      const ceremony = GuardianCeremony.begin(seed, policy);
      return new DeviceRecoveryKeySession(seed, ceremony);
    } catch (error) {
      zeroise(seed);
      throw error;
    }
  }

  /**
   * Adopt a seed reconstructed from guardian shares.
   *
   * Used by RECOVERY, where the key already exists and the guardian split is
   * not being re-created. No ceremony is opened: re-splitting here would issue
   * shares nobody asked for and silently invalidate nothing, leaving two live
   * share sets for one key.
   */
  static fromRecoveredSeed(seed: Uint8Array): DeviceRecoveryKeySession {
    return new DeviceRecoveryKeySession(seed, null);
  }

  get guardianCeremony(): GuardianCeremony {
    if (!this.ceremony) {
      throw new AppError(
        ERROR_CODES.VALIDATION_ERROR,
        'This session was opened from a recovered seed and has no guardian ceremony. ' +
          'Re-splitting an existing key would leave two live share sets for one identity.',
        500,
      );
    }
    return this.ceremony;
  }

  get shares(): readonly GuardianShare[] {
    return this.guardianCeremony.shares;
  }

  publicKeyMultibase(): string {
    return ed25519MultibaseFromRawPublicKey(recoveryKeyPublicKey(this.requireSeed()));
  }

  /**
   * A signer for the RCK's OWN DID, used to create it.
   *
   * The RCK DID is self-controlled, which is correct and is NOT the S-1 R0
   * defect: a controller DID is its own custodian, and the RCK's availability
   * is protected off-chain by the guardian split rather than by naming another
   * on-chain controller (#240).
   */
  subjectKey(): ExternalSubjectKey {
    return {
      publicKeyMultibase: this.publicKeyMultibase(),
      custody: 'device-held (RCK, SLIP-39 guardian split, #240)',
      sign: async (payload) => signWithRecoveryKey(this.requireSeed(), payload),
    };
  }

  /** A signer attributable to the RCK DID once that DID exists. */
  controllerSigner(recoveryControllerDid: string): CheqdSigner {
    return {
      did: recoveryControllerDid,
      verificationMethodId: `${recoveryControllerDid}${DEVICE_KEY_FRAGMENT}`,
      sign: async (payload) => signWithRecoveryKey(this.requireSeed(), payload),
    };
  }

  /**
   * Prove this session's key is the one a DID document names.
   *
   * #315 IN ONE METHOD, and the reason recovery is trustworthy at all. A seed
   * reconstructed from guardian shares is only *probably* the right one:
   * SLIP-39 detects corrupt, mixed and below-threshold sets, but a valid share
   * set for a DIFFERENT patient reconstructs perfectly well. So recovery must
   * re-establish its precondition from OBSERVABLE STATE — the public key on
   * chain — rather than inherit it from "the shares combined without error".
   */
  assertMatchesOnChainKey(publicKeyMultibase: string, context: string): void {
    const expected = ed25519PublicKeyFromMultibase(publicKeyMultibase);
    const actual = recoveryKeyPublicKey(this.requireSeed());

    const same =
      expected.length === actual.length && expected.every((byte, i) => byte === actual[i]);

    if (!same) {
      throw new AppError(
        ERROR_CODES.VALIDATION_ERROR,
        `The reconstructed recovery key does not match the key recorded on chain for ` +
          `${context}. These guardian shares belong to a different identity. Nothing has ` +
          'been signed and nothing has been written.',
        403,
      );
    }
  }

  /** Zeroise. Idempotent, so it is safe in a `finally`. */
  close(): void {
    if (this.seed) zeroise(this.seed);
    this.seed = null;
    this.state = 'SPENT';
  }

  private requireSeed(): Uint8Array {
    if (!this.seed || this.state === 'SPENT') {
      throw new AppError(
        ERROR_CODES.VALIDATION_ERROR,
        'This recovery key session is spent. Its seed was zeroised, so it can no longer ' +
          'sign. Open a new session rather than extending the lifetime of a key that ' +
          'should not have one.',
        500,
      );
    }
    return this.seed;
  }
}

/**
 * PHASE-B CUSTODY. The recovery controller's key is generated for this
 * enrolment, split to guardians, and never enters the backend's key store.
 *
 * REFUSES TO PROVISION UNTIL THE CEREMONY IS COMPLETE. That ordering is the
 * whole safety property: guardian shares cannot be retrofitted (S-2 §8), so an
 * identity anchored to an RCK whose shares were never delivered is
 * unrecoverable from birth — and would look completely healthy until the day it
 * was needed.
 */
export function deviceHeldRecoveryController(
  session: DeviceRecoveryKeySession,
): RecoveryControllerProvider {
  return {
    custody: 'device-held RCK, SLIP-39 guardian split (#240, R5 Phase B)',

    async provision(agent: Agent, context: { readonly userId: string }): Promise<RecoveryController> {
      // Re-established from observable state, not inherited from the fact that
      // a ceremony object exists: ask the ceremony what it actually recorded.
      const status = session.guardianCeremony.status();
      if (!status.canComplete) {
        throw new AppError(
          ERROR_CODES.DID_CREATION_FAILED,
          `Refusing to enrol: the guardian ceremony is not complete. ` +
            `${status.confirmedCount} of ${status.threshold} required guardians have proved ` +
            `possession${status.outstanding.length > 0 ? `; outstanding: ${status.outstanding.join(', ')}` : ''}. ` +
            'Guardian shares cannot be added after enrolment, so an identity created now ' +
            'would have no recovery path and would look healthy until the day it was needed.',
          409,
        );
      }

      const created = await createCheqdDID(agent, {
        controllers: {
          kind: 'self',
          acknowledgement: ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL,
          reason:
            'Recovery controller DID for a patient enrolment. A controller DID is its own ' +
            'custodian by definition; its availability is protected by the SLIP-39 guardian ' +
            'split (#240), not by naming another on-chain controller.',
        },
        verificationMethodControl: {
          kind: 'self',
          acknowledgement: ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL,
          reason:
            'Same DID, same reason. Naming an external VM controller here would only move ' +
            'the question one hop and add a mandatory co-signer to every recovery.',
        },
        signers: [],
        subjectKey: session.subjectKey(),
        assertShape: assertRecoveryControllerShape,
      });

      logger.info('patient_recovery_controller_provisioned', {
        userId: context.userId,
        recoveryControllerDid: created.did,
        custody: 'device-held RCK, SLIP-39 guardian split (#240, R5 Phase B)',
        guardianThreshold: status.threshold,
        guardianCount: status.guardianCount,
        guardiansConfirmed: status.confirmedCount,
        recoveryRehearsed: true,
        backendHoldsRecoveryPrivateKey: false,
        transactionHash: created.transactionHash,
        height: created.height,
      });

      // R5 PHASE C. Durability copy of the INSTITUTION guardian's share only
      // — never any other guardian's, never the seed. Runs AFTER the DID is
      // live on chain, so a deposit is never attempted for a DID that was
      // never actually created. Best-effort by design (backupVaultClient.ts
      // never throws): the ceremony's guardian shares already exist with
      // their guardians regardless of whether this copy lands.
      const institutionShare = session.shares.find((s) => s.guardian.role === 'INSTITUTION');
      if (institutionShare) {
        await depositInstitutionShare(created.did, institutionShare, status.threshold);
      } else {
        logger.info('institution_share_backup_skipped_no_institution_guardian', {
          recoveryControllerDid: created.did,
        });
      }

      return {
        did: created.did,
        signer: session.controllerSigner(created.did),
        custody: 'device-held RCK, SLIP-39 guardian split (#240, R5 Phase B)',
      };
    },
  };
}
