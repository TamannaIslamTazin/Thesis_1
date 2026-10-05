/**
 * SSI Healthcare Backend — the rotation client: plan first, broadcast second.
 *
 * ===========================================================================
 * WHY PLANNING IS A SEPARATE, CALLABLE STEP
 * ===========================================================================
 * S-1 §8.4, last bullet: "the error surface only ever names one missing signer
 * — rotation tooling should compute the expected signer set locally and
 * validate completeness before broadcast, rather than iterating on chain
 * errors."
 *
 * The mechanism: `msg_server.go:136` iterates a `utils.UniqueSorted` list and
 * returns on the FIRST unsatisfied signer, so a rejection names exactly one
 * missing signature however many are missing — and names it in DID sort order,
 * which has nothing to do with which one you forgot. S-1 E3 named `A` when both
 * `A` and `B` were missing, purely because `16359cb2…` sorts before
 * `8d45847d…`; S-4 U2 did the same. Discovering the required set by iterating
 * costs one consumed block per gap and misleads at every step.
 *
 * So {@link planRotation} answers "who must sign, and can I?" with NO
 * transaction, and {@link executeRotation} refuses to broadcast unless the plan
 * is complete. A partial submission is not a partial success — it is a consumed
 * block and a `1101`.
 */

import type { Agent } from '@credo-ts/core';

import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import {
  ED25519_VERIFICATION_KEY_2020,
  controllersOrSubject,
  signerDidsForUpdate,
  verificationMethodDelta,
} from '@ssi-healthcare/sdk/ledger';
import { assertSignerIsWellFormed, requireLiveDidOnChain, type CheqdSigner } from './cheqdLedger.js';
import { rotateVerificationMethod, type RotationResult } from './cheqdDid.js';

export interface RotationPlan {
  readonly did: string;
  /** The slot whose key material changes. */
  readonly verificationMethodId: string;
  /** Exactly what `GetSignerDIDsForDIDUpdate` will compute, in the chain's own order. */
  readonly requiredSigners: readonly string[];
  readonly availableSigners: readonly string[];
  /** ALL of them, not the first in sort order. */
  readonly missingSigners: readonly string[];
  readonly complete: boolean;
  /** Non-fatal observations a human should read before authorising a broadcast. */
  readonly warnings: readonly string[];
}

export interface PlanRotationSpec {
  readonly did: string;
  /** Which slot to rotate. Defaults to the only one, and refuses if there are several. */
  readonly fragment?: string;
  readonly signers: readonly CheqdSigner[];
  /**
   * The replacement key, if it is already known. Only affects whether the plan
   * can detect a no-op rotation; the signer set does not depend on key material.
   */
  readonly nextPublicKeyMultibase?: string;
}

/**
 * Compute the signer set for a verification-method rotation WITHOUT touching
 * the ledger beyond a read.
 */
export async function planRotation(
  agent: Agent,
  spec: PlanRotationSpec,
): Promise<RotationPlan> {
  const current = await requireLiveDidOnChain(agent, spec.did, `plan a rotation of '${spec.did}'`);

  const slot = selectSlot(current.verificationMethod, spec.did, spec.fragment);
  const warnings: string[] = [];

  const updated = {
    id: spec.did,
    controller: controllersOrSubject(current.controller, spec.did),
    verificationMethod: current.verificationMethod.map((vm) =>
      vm.id === slot.id
        ? {
            ...vm,
            type: ED25519_VERIFICATION_KEY_2020,
            publicKeyMultibase: spec.nextPublicKeyMultibase ?? `${vm.publicKeyMultibase}-planned`,
          }
        : { ...vm, type: ED25519_VERIFICATION_KEY_2020 },
    ),
  };

  const existing = {
    id: spec.did,
    controller: controllersOrSubject(current.controller, spec.did),
    verificationMethod: current.verificationMethod.map((vm) => ({
      ...vm,
      type: ED25519_VERIFICATION_KEY_2020,
    })),
  };

  const requiredSigners = signerDidsForUpdate(existing, updated);

  const available = new Set<string>();
  for (const signer of spec.signers) {
    assertSignerIsWellFormed(signer);
    available.add(signer.did);
  }

  const missingSigners = requiredSigners.filter((did) => !available.has(did));

  if (slot.controller === spec.did) {
    warnings.push(
      `'${slot.id}' declares its own subject as its controller, so the chain demands a ` +
        'signature from the key being replaced. If that key is lost this DID is ' +
        'UNRECOVERABLE and must be re-issued (S-1 R0, S-4 NC2) — unless a sibling ' +
        'verification method exists, which rescues it (S-4 M1).',
    );
  }

  if (current.verificationMethod.length > 1) {
    const delta = verificationMethodDelta(existing, updated);
    warnings.push(
      `This DID has ${current.verificationMethod.length} verification methods; this plan ` +
        `changes ${delta.changed.length}. Never rotate all of them in one transaction — the ` +
        'signing key is verified a second time against the updated document and fails there ' +
        '(code 1100, S-4 X1).',
    );
  }

  if (spec.nextPublicKeyMultibase && spec.nextPublicKeyMultibase === slot.publicKeyMultibase) {
    warnings.push(
      'The replacement key is the key already installed. A no-op update still consumes a ' +
        'block and leaves the lost key in place.',
    );
  }

  const excess = [...available].filter((did) => !requiredSigners.includes(did));
  if (excess.length > 0) {
    warnings.push(
      `Signers offered for [${excess.join(', ')}] are not in the required set. The chain ` +
        'attributes signatures by the DID part of the verification-method id and silently ' +
        'IGNORES ones it cannot attribute (S-1 §3.1), so these would count for nothing.',
    );
  }

  const plan: RotationPlan = {
    did: spec.did,
    verificationMethodId: slot.id,
    requiredSigners,
    availableSigners: [...available].sort(),
    missingSigners,
    complete: missingSigners.length === 0,
    warnings,
  };

  logger.info('did_rotation_planned', { ...plan });
  return plan;
}

/**
 * Broadcast a rotation, but only against a COMPLETE plan.
 *
 * The plan is recomputed here rather than trusted from the caller: between
 * planning and broadcasting, the document may have changed, and a stale plan is
 * a confidently wrong one.
 */
export async function executeRotation(
  agent: Agent,
  spec: PlanRotationSpec,
): Promise<{ plan: RotationPlan; result: RotationResult }> {
  const plan = await planRotation(agent, spec);

  if (!plan.complete) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Refusing to broadcast a rotation of '${spec.did}': ${plan.missingSigners.length} of ` +
        `${plan.requiredSigners.length} required signers cannot sign here — ` +
        `${plan.missingSigners.join(', ')}. cheqd is AND over the signer set with no ` +
        'threshold, and a rejection would have named only the first of these in DID sort ' +
        'order, which is not necessarily the one that matters.',
      400,
    );
  }

  for (const warning of plan.warnings) {
    logger.warn('did_rotation_warning', { did: spec.did, warning });
  }

  const result = await rotateVerificationMethod(agent, {
    did: spec.did,
    ...(spec.nextPublicKeyMultibase
      ? { nextPublicKeyMultibase: spec.nextPublicKeyMultibase }
      : {}),
    signers: spec.signers,
  });

  logger.info('did_rotation_executed', {
    did: spec.did,
    signedBy: plan.requiredSigners,
    deviceKeyParticipated: plan.requiredSigners.includes(spec.did),
    transactionHash: result.transactionHash,
    height: result.height,
  });

  return { plan, result };
}

function selectSlot(
  slots: readonly { id: string; controller: string; publicKeyMultibase: string }[],
  did: string,
  fragment: string | undefined,
): { id: string; controller: string; publicKeyMultibase: string } {
  if (slots.length === 0) {
    throw new AppError(
      ERROR_CODES.DID_RESOLUTION_FAILED,
      `DID '${did}' has no verification method to rotate.`,
      409,
    );
  }

  if (fragment) {
    const found = slots.find((slot) => slot.id.endsWith(fragment));
    if (!found) {
      throw new AppError(
        ERROR_CODES.DID_NOT_FOUND,
        `DID '${did}' has no slot '${fragment}'. It holds ` +
          `[${slots.map((slot) => slot.id).join(', ')}].`,
        404,
      );
    }
    return found;
  }

  if (slots.length > 1) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `DID '${did}' has ${slots.length} verification methods, so 'which one' is not a ` +
        'question this can answer by default. Name a fragment. Rotating all of them at once ' +
        'is rejected with code 1100 (S-4 X1).',
      400,
    );
  }

  return slots[0] as { id: string; controller: string; publicKeyMultibase: string };
}
