/**
 * R5 PHASE B — DEVICE-HELD RCK AND GUARDIAN RECOVERY, AGAINST THE REAL CHAIN.
 *
 * ===========================================================================
 * THE ONE ASSERTION THIS FILE EXISTS FOR
 * ===========================================================================
 * Phone lost. RCK reconstructed from SLIP-39 guardian shares. Device key
 * rotated on chain. `deviceKeyParticipated: false`.
 *
 * Everything else here is scaffolding for that. It has to run against a real
 * ledger because the property is "the CHAIN did not require the lost key", and
 * the chain is the only thing that can answer it — Credo will hand back a
 * well-formed document from its own store for a DID that was never written, and
 * Cosmos v0.50 does not execute the message in `CheckTx`, so a `code 0` from a
 * sync broadcast proves nothing either. Both traps produced wrong answers
 * during S-1 and S-4.
 *
 * ===========================================================================
 * WHAT PHASE B CHANGES, RESTATED SO A FAILURE HERE IS LEGIBLE
 * ===========================================================================
 * The DOCUMENT is identical to Phase A: controller `[RCK, institution]`,
 * verification method controlled by the RCK. What changed is WHO HOLDS THE RCK.
 * If a test in this file fails on shape, the regression is in enrolment; if it
 * fails on custody, the regression is in `deviceRecoveryKey.ts`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { Agent } from '@credo-ts/core';

import {
  DEFAULT_GUARDIAN_POLICY,
  generateRecoveryKeySeed,
  recoveryKeyPublicKey,
} from '@ssi-healthcare/shared';

import { createAgent, shutdownAgent } from '../../src/agent/index.js';
import { db } from '../../src/db/index.js';
import { config } from '../../src/config/index.js';
import { enrolPatient } from '../../src/services/patientEnrolment.js';
import {
  DeviceRecoveryKeySession,
  deviceHeldRecoveryController,
  ed25519MultibaseFromRawPublicKey,
} from '../../src/services/deviceRecoveryKey.js';
import { recoverWithGuardianShares } from '../../src/services/guardianRecovery.js';
import { agentSigner, resolveOnChain } from '../../src/services/cheqdLedger.js';
import { LEDGER_SIGNING_FRAGMENT } from '../../src/services/institutionalDid.js';
import { assertPatientRecoverableShape } from '@ssi-healthcare/sdk/ledger';

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
        'resolve as a live document on this chain.',
    );
  }
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
    data: { email: `r5b-live-${randomUUID()}@bdhealthtrust.test` },
    select: { id: true },
  });
  createdUserIds.push(user.id);
  return user.id;
}

/** Run a full guardian ceremony and enrol against the resulting device-held RCK. */
async function enrolWithGuardians(userId: string) {
  const session = DeviceRecoveryKeySession.begin(DEFAULT_GUARDIAN_POLICY);
  const ceremony = session.guardianCeremony;

  // The ceremony, as a real one would run: each guardian reads their share back.
  const mnemonics = ceremony.shares.map((share) => share.mnemonic);
  for (const share of ceremony.shares.slice(0, DEFAULT_GUARDIAN_POLICY.threshold)) {
    ceremony.confirm(share.index, share.mnemonic);
  }
  ceremony.rehearse();

  const recoveryPublicKeyMultibase = session.publicKeyMultibase();

  let enrolment!: Awaited<ReturnType<typeof enrolPatient>>;
  try {
    enrolment = await enrolPatient(agent, {
      userId,
      institutionalDid,
      recoveryControllerProvider: deviceHeldRecoveryController(session),
      persist: async () => {},
    });
  } finally {
    // The seed's lifetime ends with enrolment. From here the ONLY way back to
    // this key is the guardian shares, which is the property under test.
    session.close();
  }

  return { enrolment, mnemonics, recoveryPublicKeyMultibase };
}

describe('enrolment anchors to a key the backend does not hold', () => {
  it('writes the S-1 §8.1 shape with a device-generated recovery key', async () => {
    const userId = await createTestUser();
    const { enrolment, recoveryPublicKeyMultibase } = await enrolWithGuardians(userId);

    const patient = await resolveOnChain(agent, enrolment.patientDid);
    expect(patient).not.toBeNull();

    // The shape is UNCHANGED from Phase A. This is the regression guard on the
    // claim that Phase B swaps the holder and not the document.
    assertPatientRecoverableShape(
      {
        '@context': [],
        id: patient!.did,
        controller: patient!.controller,
        verificationMethod: patient!.verificationMethod as never,
        authentication: patient!.authentication,
        assertionMethod: patient!.assertionMethod,
      },
      {
        recoveryControllerDid: enrolment.recoveryControllerDid,
        institutionalDid,
      },
    );

    expect(enrolment.recoveryControllerCustody).toMatch(/device-held/i);

    // The RCK published on chain is the key the DEVICE generated.
    const controller = await resolveOnChain(agent, enrolment.recoveryControllerDid);
    expect(controller!.verificationMethod[0]!.publicKeyMultibase).toBe(
      recoveryPublicKeyMultibase,
    );
  }, 180_000);

  it('leaves the backend UNABLE to sign for the recovery controller', async () => {
    const userId = await createTestUser();
    const { enrolment } = await enrolWithGuardians(userId);

    // THE CUSTODY ASSERTION. Under Phase A this call succeeded, which is what
    // made the 2-of-2 hollow. The DidRecord carries no key mapping now, so the
    // backend cannot produce the patient's half of the controller set at all.
    await expect(agentSigner(agent, enrolment.recoveryControllerDid)).rejects.toThrow(
      /carries no key mapping/i,
    );
  }, 180_000);

  it('REFUSES to enrol when the guardian ceremony is incomplete', async () => {
    const userId = await createTestUser();
    const session = DeviceRecoveryKeySession.begin(DEFAULT_GUARDIAN_POLICY);

    // Two of three guardians, and no rehearsal: shares cannot be retrofitted,
    // so enrolling here would mint an identity with no recovery path.
    const ceremony = session.guardianCeremony;
    ceremony.confirm(0, ceremony.shares[0]!.mnemonic);
    ceremony.confirm(1, ceremony.shares[1]!.mnemonic);

    let persisted = false;
    await expect(
      enrolPatient(agent, {
        userId,
        institutionalDid,
        recoveryControllerProvider: deviceHeldRecoveryController(session),
        persist: async () => {
          persisted = true;
        },
      }),
    ).rejects.toThrow(/guardian ceremony is not complete/i);

    expect(persisted).toBe(false);
    session.close();
  }, 180_000);
});

describe('GUARDIAN RECOVERY, END TO END, AGAINST THE CHAIN', () => {
  it('rebuilds the RCK from shares and rotates the lost device key', async () => {
    const userId = await createTestUser();
    const { enrolment, mnemonics } = await enrolWithGuardians(userId);

    const before = await resolveOnChain(agent, enrolment.patientDid);
    const lostKey = before!.verificationMethod[0]!.publicKeyMultibase;

    // The new handset generates its own key. The backend never sees the private
    // half — same property as at enrolment.
    const nextDeviceKey = ed25519MultibaseFromRawPublicKey(
      recoveryKeyPublicKey(generateRecoveryKeySeed()),
    );

    // Exactly the threshold, and NOT the first three, so the test proves a
    // threshold rather than an ordering.
    const collected = [mnemonics[1]!, mnemonics[3]!, mnemonics[4]!];

    const result = await recoverWithGuardianShares(agent, {
      patientDid: enrolment.patientDid,
      guardianShares: collected,
      nextDevicePublicKeyMultibase: nextDeviceKey,
      institutionSigner: await agentSigner(
        agent,
        institutionalDid,
        LEDGER_SIGNING_FRAGMENT,
      ),
    });

    // ---- THE ASSERTION THIS WHOLE PHASE EXISTS FOR ----------------------
    expect(result.deviceKeyParticipated).toBe(false);
    expect(result.requiredSigners).not.toContain(enrolment.patientDid);
    expect(result.requiredSigners).toEqual(
      [enrolment.recoveryControllerDid, institutionalDid].sort(),
    );
    expect(result.guardianSharesUsed).toBe(3);
    expect(result.transactionHash).toMatch(/^[0-9A-F]{64}$/i);

    // ---- AND THE CHAIN AGREES -------------------------------------------
    const after = await resolveOnChain(agent, enrolment.patientDid);
    const installed = after!.verificationMethod[0]!.publicKeyMultibase;

    expect(installed).toBe(nextDeviceKey);
    expect(installed).not.toBe(lostKey);
    // Replaced, not shadowed.
    expect(JSON.stringify(after!.verificationMethod)).not.toContain(lostKey);

    // Still recoverable a second time: the VM controller survived the rotation.
    expect(after!.verificationMethod[0]!.controller).toBe(enrolment.recoveryControllerDid);
  }, 180_000);

  it('refuses shares from a DIFFERENT patient, before signing anything', async () => {
    // #315's join, tested directly. SLIP-39 cannot tell that a perfectly valid
    // share set belongs to someone else — only the on-chain public key can, and
    // the check must happen BEFORE the rotation is signed.
    const victimId = await createTestUser();
    const strangerId = await createTestUser();

    const victim = await enrolWithGuardians(victimId);
    const stranger = await enrolWithGuardians(strangerId);

    const before = await resolveOnChain(agent, victim.enrolment.patientDid);

    await expect(
      recoverWithGuardianShares(agent, {
        patientDid: victim.enrolment.patientDid,
        guardianShares: [stranger.mnemonics[0]!, stranger.mnemonics[1]!, stranger.mnemonics[2]!],
        nextDevicePublicKeyMultibase: ed25519MultibaseFromRawPublicKey(
          recoveryKeyPublicKey(generateRecoveryKeySeed()),
        ),
        institutionSigner: await agentSigner(agent, institutionalDid, LEDGER_SIGNING_FRAGMENT),
      }),
    ).rejects.toThrow(/belong to a different identity/i);

    // Nothing was written: the victim's key is untouched.
    const after = await resolveOnChain(agent, victim.enrolment.patientDid);
    expect(after!.verificationMethod[0]!.publicKeyMultibase).toBe(
      before!.verificationMethod[0]!.publicKeyMultibase,
    );
  }, 180_000);

  it('refuses below the threshold, and the DID is untouched', async () => {
    const userId = await createTestUser();
    const { enrolment, mnemonics } = await enrolWithGuardians(userId);
    const before = await resolveOnChain(agent, enrolment.patientDid);

    await expect(
      recoverWithGuardianShares(agent, {
        patientDid: enrolment.patientDid,
        guardianShares: [mnemonics[0]!, mnemonics[1]!],
        nextDevicePublicKeyMultibase: ed25519MultibaseFromRawPublicKey(
          recoveryKeyPublicKey(generateRecoveryKeySeed()),
        ),
        institutionSigner: await agentSigner(agent, institutionalDid, LEDGER_SIGNING_FRAGMENT),
      }),
    ).rejects.toThrow();

    const after = await resolveOnChain(agent, enrolment.patientDid);
    expect(after!.verificationMethod[0]!.publicKeyMultibase).toBe(
      before!.verificationMethod[0]!.publicKeyMultibase,
    );
  }, 180_000);

  it('recovers a SECOND time from the same shares — recovery is not single-use', async () => {
    // The shares survive a recovery: they encode the RCK, and the RCK is not
    // what rotated. A patient who loses two phones is not out of options.
    const userId = await createTestUser();
    const { enrolment, mnemonics } = await enrolWithGuardians(userId);

    const institutionSigner = await agentSigner(
      agent,
      institutionalDid,
      LEDGER_SIGNING_FRAGMENT,
    );

    const first = await recoverWithGuardianShares(agent, {
      patientDid: enrolment.patientDid,
      guardianShares: mnemonics.slice(0, 3),
      nextDevicePublicKeyMultibase: ed25519MultibaseFromRawPublicKey(
        recoveryKeyPublicKey(generateRecoveryKeySeed()),
      ),
      institutionSigner,
    });

    const second = await recoverWithGuardianShares(agent, {
      patientDid: enrolment.patientDid,
      guardianShares: mnemonics.slice(2, 5),
      nextDevicePublicKeyMultibase: ed25519MultibaseFromRawPublicKey(
        recoveryKeyPublicKey(generateRecoveryKeySeed()),
      ),
      institutionSigner,
    });

    expect(first.deviceKeyParticipated).toBe(false);
    expect(second.deviceKeyParticipated).toBe(false);
    expect(second.previousDevicePublicKeyMultibase).toBe(first.nextDevicePublicKeyMultibase);

    const after = await resolveOnChain(agent, enrolment.patientDid);
    expect(after!.verificationMethod[0]!.publicKeyMultibase).toBe(
      second.nextDevicePublicKeyMultibase,
    );
  }, 180_000);
});
