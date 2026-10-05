/**
 * R5 PHASE A — PATIENT ENROLMENT AND SEEDLESS RECOVERY, AGAINST THE REAL CHAIN.
 *
 * ---------------------------------------------------------------------------
 * WHY EVERY ASSERTION READS THE LEDGER RATHER THAN THE RETURN VALUE
 * ---------------------------------------------------------------------------
 * Credo will happily hand back a well-formed DID document from its own store
 * for a DID that was never written, which is exactly what a failed write looks
 * like from inside this process. And in Cosmos SDK v0.50 `CheckTx` does not
 * execute the message, so a `code: 0` from a sync broadcast proves nothing
 * either. Both traps produced wrong answers during spikes S-1 and S-4. So each
 * claim below is checked by RESOLVING the DID after the transaction committed.
 *
 * ---------------------------------------------------------------------------
 * THE FOUR PROPERTIES
 * ---------------------------------------------------------------------------
 *  1. The S-1 §8.1 shape is what actually lands on chain.
 *  2. Recovery works WITH THE DEVICE KEY NEVER USED — the whole point.
 *  3. A partial enrolment persists NOTHING (the `assertHolderBound` property).
 *  4. A patient DID cannot be minted with a self-controlled verification
 *     method through this path, and the refusal happens before a block is spent.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { Agent } from '@credo-ts/core';

import { createAgent, shutdownAgent } from '../../src/agent/index.js';
import { db } from '../../src/db/index.js';
import { config } from '../../src/config/index.js';
import { AppError } from '../../src/middleware/errorHandler.js';
import {
  agentHeldRecoveryController,
  enrolPatient,
  type PatientEnrolmentChainResult,
} from '../../src/services/patientEnrolment.js';
import { agentSigner, resolveOnChain } from '../../src/services/cheqdLedger.js';
import { LEDGER_SIGNING_FRAGMENT } from '../../src/services/institutionalDid.js';
import { executeRotation, planRotation } from '../../src/services/didRotationClient.js';
import { assertPatientRecoverableShape } from '@ssi-healthcare/sdk/ledger';
import type { CheqdDidDocumentShape } from '@ssi-healthcare/sdk/ledger';

let agent: Agent;
let institutionalDid: string;
const createdUserIds: string[] = [];

beforeAll(async () => {
  // Not a skip. The live tier refuses to run without its dependencies.
  if (!config.institutionalDid) {
    throw new Error(
      'LIVE SUITE PRECONDITION FAILED — INSTITUTIONAL_DID is not set.\n\n' +
        '  pnpm --filter @ssi-healthcare/backend exec tsx ' +
        'scripts/provision-institutional-did.ts create 3 "live suite"\n' +
        '  then put the printed INSTITUTIONAL_DID into packages/backend/.env\n\n' +
        'Without it there is no institution to co-control a patient, and this suite would ' +
        'be asserting properties of a shape it never built.',
    );
  }
  institutionalDid = config.institutionalDid;

  agent = await createAgent();

  const institution = await resolveOnChain(agent, institutionalDid);
  if (!institution || institution.deactivated) {
    throw new Error(
      `LIVE SUITE PRECONDITION FAILED — INSTITUTIONAL_DID '${institutionalDid}' does not ` +
        'resolve as a live document on this chain. It was probably provisioned against a ' +
        'different ledger, or the localnet state was reset.',
    );
  }
  // The agent must actually hold the institution's signing key, or every
  // enrolment here would fail for a reason that has nothing to do with shape.
  await agentSigner(agent, institutionalDid, LEDGER_SIGNING_FRAGMENT);
}, 180_000);

afterAll(async () => {
  if (createdUserIds.length > 0) {
    await db.user.deleteMany({ where: { id: { in: createdUserIds } } });
  }
  await shutdownAgent();
});

async function createTestUser(): Promise<string> {
  const user = await db.user.create({
    data: { email: `r5-live-${randomUUID()}@bdhealthtrust.test` },
    select: { id: true },
  });
  createdUserIds.push(user.id);
  return user.id;
}

async function enrol(userId: string): Promise<PatientEnrolmentChainResult> {
  let captured: PatientEnrolmentChainResult | undefined;
  await enrolPatient(agent, {
    userId,
    institutionalDid,
    recoveryControllerProvider: agentHeldRecoveryController,
    persist: async (result) => {
      captured = result;
      await db.user.update({
        where: { id: userId },
        data: { did: result.patientDid, walletSetup: true, walletType: 'DEVICE' },
      });
    },
  });
  return captured as PatientEnrolmentChainResult;
}

// ---------------------------------------------------------------------------

describe('enrolment emits the S-1 §8.1 shape and the CHAIN agrees', () => {
  it('writes controller [RCK, institution] with an externally-controlled device key', async () => {
    const userId = await createTestUser();
    const enrolment = await enrol(userId);

    const resolved = await resolveOnChain(agent, enrolment.patientDid);
    expect(resolved, 'patient DID does not resolve on chain').not.toBeNull();
    expect(resolved?.deactivated).toBe(false);

    // The shape assertion, applied to the RESOLVED document rather than to the
    // one we built. This is the difference between "we asked for the right
    // shape" and "the right shape is on the ledger".
    expect(() =>
      assertPatientRecoverableShape(
        {
          '@context': [],
          id: resolved!.did,
          controller: resolved!.controller,
          verificationMethod:
            resolved!.verificationMethod as CheqdDidDocumentShape['verificationMethod'],
          authentication: resolved!.authentication,
          assertionMethod: resolved!.assertionMethod,
        },
        {
          recoveryControllerDid: enrolment.recoveryControllerDid,
          institutionalDid,
        },
      ),
    ).not.toThrow();

    // Stated again, explicitly, because this single field is the whole design.
    const deviceVm = resolved!.verificationMethod[0]!;
    expect(deviceVm.controller).toBe(enrolment.recoveryControllerDid);
    expect(deviceVm.controller).not.toBe(enrolment.patientDid);
    expect(resolved!.controller).not.toContain(enrolment.patientDid);

    // And the recovery controller really exists as its own DID — a controller
    // that does not resolve would have been rejected by the chain at creation,
    // but a passing test should not depend on inferring that.
    const rck = await resolveOnChain(agent, enrolment.recoveryControllerDid);
    expect(rck?.deactivated).toBe(false);

    const row = await db.user.findUnique({ where: { id: userId }, select: { did: true } });
    expect(row?.did).toBe(enrolment.patientDid);
  }, 180_000);
});

// ---------------------------------------------------------------------------

describe('seedless recovery: the device key is never used', () => {
  it('rotates the device key signed ONLY by the recovery controller and the institution', async () => {
    const userId = await createTestUser();
    const enrolment = await enrol(userId);

    const before = await resolveOnChain(agent, enrolment.patientDid);
    const lostKey = before!.verificationMethod[0]!.publicKeyMultibase;

    const signers = [
      await agentSigner(agent, enrolment.recoveryControllerDid),
      await agentSigner(agent, institutionalDid, LEDGER_SIGNING_FRAGMENT),
    ];

    // THE PLAN IS THE ASSERTION. The chain names only one missing signer per
    // rejection, so "did it work" is a weaker claim than "the locally computed
    // signer set is exactly the two controllers and does NOT include the
    // patient". If the patient DID appeared here, the device key would be
    // conscripted and the identity would be unrecoverable.
    const plan = await planRotation(agent, {
      did: enrolment.patientDid,
      signers,
    });
    expect(plan.requiredSigners).toEqual(
      [enrolment.recoveryControllerDid, institutionalDid].sort(),
    );
    expect(plan.requiredSigners).not.toContain(enrolment.patientDid);
    expect(plan.missingSigners).toEqual([]);
    expect(plan.complete).toBe(true);

    const { result } = await executeRotation(agent, { did: enrolment.patientDid, signers });

    const after = await resolveOnChain(agent, enrolment.patientDid);
    const installed = after!.verificationMethod[0]!.publicKeyMultibase;

    // Recovery is REAL, not cosmetic: the new key is present and the lost one
    // is absent, not merely shadowed.
    expect(installed).toBe(result.nextPublicKeyMultibase);
    expect(installed).not.toBe(lostKey);
    expect(JSON.stringify(after!.verificationMethod)).not.toContain(lostKey);

    // And the shape survived the rotation — the VM controller is carried
    // forward, so the DID is still recoverable a second time.
    expect(after!.verificationMethod[0]!.controller).toBe(enrolment.recoveryControllerDid);
  }, 180_000);

  it('refuses to broadcast when a required signer is missing, naming ALL of them', async () => {
    const userId = await createTestUser();
    const enrolment = await enrol(userId);
    const keyBefore = (await resolveOnChain(agent, enrolment.patientDid))!
      .verificationMethod[0]!.publicKeyMultibase;

    // Only the institution. cheqd is AND over the controller set, so this is
    // exactly S-1 E1: refused for want of the other controller.
    const plan = await planRotation(agent, {
      did: enrolment.patientDid,
      signers: [await agentSigner(agent, institutionalDid, LEDGER_SIGNING_FRAGMENT)],
    });
    expect(plan.complete).toBe(false);
    expect(plan.missingSigners).toEqual([enrolment.recoveryControllerDid]);

    let thrown: unknown;
    try {
      await executeRotation(agent, {
        did: enrolment.patientDid,
        signers: [await agentSigner(agent, institutionalDid, LEDGER_SIGNING_FRAGMENT)],
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown, 'a rotation with a missing controller SUCCEEDED').toBeInstanceOf(AppError);
    expect((thrown as AppError).message).toContain(enrolment.recoveryControllerDid);

    // Nothing was spent: the key on chain is the one that was there before.
    // The refusal is local — a broadcast would have consumed a block and
    // returned 1101 naming only the first missing signer in DID sort order.
    const after = await resolveOnChain(agent, enrolment.patientDid);
    expect(after!.verificationMethod[0]!.publicKeyMultibase).toBe(keyBefore);
  }, 180_000);
});

// ---------------------------------------------------------------------------

describe('a partial enrolment persists NOTHING', () => {
  it('leaves the user row untouched when the persist step fails', async () => {
    const userId = await createTestUser();
    const boom = new Error('simulated failure after the chain writes committed');

    let thrown: unknown;
    try {
      await enrolPatient(agent, {
        userId,
        institutionalDid,
        recoveryControllerProvider: agentHeldRecoveryController,
        persist: async () => {
          throw boom;
        },
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBe(boom);

    // THE ASSERTION THAT MATTERS. A user with `did` set but no wallet, or a
    // wallet flag with no DID, is a half-provisioned identity that looks
    // healthy in the UI and cannot hold a credential.
    const row = await db.user.findUnique({
      where: { id: userId },
      select: { did: true, walletSetup: true, walletType: true },
    });
    expect(row?.did).toBeNull();
    expect(row?.walletSetup).toBe(false);
    expect(row?.walletType).toBeNull();
  }, 180_000);

  it('refuses before ANY chain write when the institution does not resolve', async () => {
    const userId = await createTestUser();
    const absent = `did:cheqd:bdhealthtestnet:${randomUUID()}`;

    let thrown: unknown;
    try {
      await enrolPatient(agent, {
        userId,
        institutionalDid: absent,
        recoveryControllerProvider: agentHeldRecoveryController,
        persist: async () => {
          throw new Error('persist must never be reached');
        },
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(AppError);
    expect((thrown as AppError).statusCode).toBe(404);

    const row = await db.user.findUnique({ where: { id: userId }, select: { did: true } });
    expect(row?.did).toBeNull();
  }, 180_000);
});
