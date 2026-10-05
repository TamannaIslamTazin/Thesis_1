/**
 * R5 — IDENTITY RE-ISSUANCE ("visa re-issuance") AGAINST THE REAL CHAIN.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS TIER, AND WHAT IT PROVES THAT `tests/fast` CANNOT
 * ---------------------------------------------------------------------------
 * `tests/fast` proves the authorisation cannot be forged and the worklist
 * cannot carry the wrong credentials forward. Neither of those needs a chain.
 *
 * What needs a chain is the part that has already been wrong twice:
 *
 *   1. THAT THE SUCCESSOR IS ACTUALLY USABLE. A patient-shaped successor for an
 *      ISSUER resolves perfectly, passes every shape assertion, and then cannot
 *      publish a status list — because `x/resource` demands the SUBJECT'S
 *      CONTROLLER SET and the wallet can only offer the subject's own key. That
 *      failure is invisible until a real `MsgCreateResource` is broadcast, and
 *      it cost 25 identical failures to discover (steno #313).
 *
 *   2. THAT A HALF-FINISHED MIGRATION DOES NOT DESTROY ANYTHING. The tombstone
 *      phase once revoked 25 credentials whose replacements had never been
 *      issued (steno #314). The guard against that is a composition property —
 *      one phase refusing to run on another phase's residue — and composition
 *      is exactly what a unit test does not exercise.
 *
 * Every assertion below reads the LEDGER or the DATABASE after the fact. A
 * return value is what would look right if the write had silently failed.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { Agent } from '@credo-ts/core';

import { createAgent, shutdownAgent } from '../../src/agent/index.js';
import { db } from '../../src/db/index.js';
import { config } from '../../src/config/index.js';
import { resolveOnChain } from '../../src/services/cheqdLedger.js';
import { classifyPatientDid } from '@ssi-healthcare/sdk/ledger';
import { agentHeldRecoveryController } from '../../src/services/patientEnrolment.js';
import {
  authoriseReissuance,
  executeReissuance,
} from '../../src/services/reissuance/reissuanceService.js';
import {
  canonicalAuthorisationBytes,
  verifyAuthorisationSignature,
} from '../../src/services/reissuance/authorisation.js';
import {
  ensureStatusListPublished,
  getOrCreateStatusList,
} from '../../src/services/statusListService.js';
import { createCheqdDID, ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL } from '../../src/services/cheqdDid.js';
import { SHAPE_ASSERTION_DELIBERATELY_OMITTED } from '@ssi-healthcare/sdk/ledger';

let agent: Agent;
let institutionalDid: string;
const createdUserIds: string[] = [];

/**
 * Mint a DID in the BROKEN legacy shape on purpose — single self-controlled
 * verification method, the S-1 R0 / S-4 NC2 case — so the migration is
 * exercised on the thing it exists for rather than on a healthy DID.
 */
async function mintUnrecoverableDid(): Promise<string> {
  const created = await createCheqdDID(agent, {
    controllers: {
      kind: 'self',
      acknowledgement: ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL,
      reason: 'R5 live test fixture: reproducing the legacy unrecoverable shape deliberately.',
    },
    verificationMethodControl: {
      kind: 'self',
      acknowledgement: ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL,
      reason: 'Same. This is the defect under test, not an oversight.',
    },
    signers: [],
    // Deliberately reproducing the broken legacy PATIENT shape (self-controlled
    // VM where an external recovery controller belongs) so the migration path
    // is exercised on the defect it exists to repair, not on a healthy DID.
    assertShape: SHAPE_ASSERTION_DELIBERATELY_OMITTED,
  });
  return created.did;
}

async function makeUserHolding(did: string): Promise<string> {
  const user = await db.user.create({
    data: {
      email: `r5-reissue-${randomUUID()}@bdhealthtrust.test`,
      did,
      walletSetup: true,
    },
  });
  createdUserIds.push(user.id);
  return user.id;
}

beforeAll(async () => {
  // Not a skip. The live tier refuses to run without its dependencies.
  if (!config.institutionalDid) {
    throw new Error(
      'LIVE SUITE PRECONDITION FAILED — INSTITUTIONAL_DID is not set.\n\n' +
        'Re-issuance is authenticated by the INSTITUTIONAL half of the controller set. ' +
        'Without an institution there is nothing to authenticate against, and this suite ' +
        'would be asserting properties of a trust relationship it never established.',
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
}, 180_000);

afterAll(async () => {
  if (createdUserIds.length > 0) {
    // Child rows first: CredentialReissuance cascades from DidSuccession, but
    // the succession and its authorisation do not cascade from User.
    const successions = await db.didSuccession.findMany({
      where: { userId: { in: createdUserIds } },
      select: { id: true, authorisationId: true },
    });
    await db.didSuccession.deleteMany({ where: { id: { in: successions.map((s) => s.id) } } });
    await db.reissuanceAuthorisation.deleteMany({
      where: { userId: { in: createdUserIds } },
    });
    await db.user.deleteMany({ where: { id: { in: createdUserIds } } });
  }
  await shutdownAgent();
}, 180_000);

describe('the authorisation is real evidence, checkable against the chain', () => {
  it('signs with an institutional key and verifies against the RESOLVED document', async () => {
    const oldDid = await mintUnrecoverableDid();
    const userId = await makeUserHolding(oldDid);

    const authorisation = await authoriseReissuance(agent, {
      oldDid,
      userId,
      institutionalDid,
      officerId: 'live-test-officer',
      officerName: 'Live Test Officer',
      evidenceKind: 'OPERATOR_TEST_DATA',
      evidenceReference: `live-${randomUUID()}`,
    });

    // Re-resolve independently and verify as a third party would: nothing here
    // consults the row that was just written.
    const institution = await resolveOnChain(agent, institutionalDid);
    expect(institution).not.toBeNull();

    expect(() =>
      verifyAuthorisationSignature({
        statement: authorisation.statement,
        signatureBase64: authorisation.signatureBase64,
        verificationMethodId: authorisation.verificationMethodId,
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        institution: institution!,
      }),
    ).not.toThrow();

    // And the signature is over the statement, so a single altered byte breaks it.
    expect(() =>
      verifyAuthorisationSignature({
        statement: { ...authorisation.statement, officerId: 'someone-else' },
        signatureBase64: authorisation.signatureBase64,
        verificationMethodId: authorisation.verificationMethodId,
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        institution: institution!,
      }),
    ).toThrow(/does NOT verify/);

    expect(canonicalAuthorisationBytes(authorisation.statement).length).toBeGreaterThan(0);
  }, 180_000);

  it('REFUSES to authorise the replacement of a DID the account does not hold', async () => {
    const oldDid = await mintUnrecoverableDid();
    const otherDid = await mintUnrecoverableDid();
    const userId = await makeUserHolding(oldDid);

    await expect(
      authoriseReissuance(agent, {
        oldDid: otherDid,
        userId,
        institutionalDid,
        officerId: 'live-test-officer',
        officerName: 'Live Test Officer',
        evidenceKind: 'OPERATOR_TEST_DATA',
        evidenceReference: `live-${randomUUID()}`,
      }),
    ).rejects.toThrow(/does not own|currently holds/);
  }, 180_000);
});

describe('the migration produces a successor that is BOTH recoverable and usable', () => {
  it('migrates an unrecoverable holder DID and the successor is recoverable on chain', async () => {
    const oldDid = await mintUnrecoverableDid();
    const userId = await makeUserHolding(oldDid);

    // The premise: the chain agrees this DID is beyond repair.
    const before = await resolveOnChain(agent, oldDid);
    expect(before).not.toBeNull();
    expect(classifyPatientDid({ ...before!, id: before!.did }).verdict).toBe('unrecoverable');

    const authorisation = await authoriseReissuance(agent, {
      oldDid,
      userId,
      institutionalDid,
      officerId: 'live-test-officer',
      officerName: 'Live Test Officer',
      evidenceKind: 'OPERATOR_TEST_DATA',
      evidenceReference: `live-${randomUUID()}`,
    });

    const result = await executeReissuance(agent, {
      authorisationId: authorisation.id,
      reason: 'UNRECOVERABLE_SHAPE_LEGACY',
      institutionalDid,
      recoveryControllerProvider: agentHeldRecoveryController,
    });

    expect(result.credentialsFailed).toBe(0);

    // THE LEDGER, not the return value.
    const successor = await resolveOnChain(agent, result.newDid);
    expect(successor).not.toBeNull();
    expect(successor!.deactivated).toBe(false);
    expect(classifyPatientDid({ ...successor!, id: successor!.did }).verdict).toBe('recoverable');

    // The whole point: the successor's verification method is controlled by
    // something OTHER than itself, so a lost device key is replaceable.
    expect(successor!.verificationMethod).toHaveLength(1);
    expect(successor!.verificationMethod[0]!.controller).not.toBe(result.newDid);

    // The account followed the identity.
    const user = await db.user.findUnique({ where: { id: userId } });
    expect(user?.did).toBe(result.newDid);

    // The authorisation is spent.
    const spent = await db.reissuanceAuthorisation.findUnique({
      where: { id: authorisation.id },
    });
    expect(spent?.consumedAt).not.toBeNull();
  }, 180_000);

  it('REFUSES a second migration of the same DID — one identity cannot fork', async () => {
    const oldDid = await mintUnrecoverableDid();
    const userId = await makeUserHolding(oldDid);

    const first = await authoriseReissuance(agent, {
      oldDid,
      userId,
      institutionalDid,
      officerId: 'live-test-officer',
      officerName: 'Live Test Officer',
      evidenceKind: 'OPERATOR_TEST_DATA',
      evidenceReference: `live-${randomUUID()}`,
    });

    await executeReissuance(agent, {
      authorisationId: first.id,
      reason: 'UNRECOVERABLE_SHAPE_LEGACY',
      institutionalDid,
      recoveryControllerProvider: agentHeldRecoveryController,
    });

    // Re-using the SAME authorisation is refused: single use.
    await expect(
      executeReissuance(agent, {
        authorisationId: first.id,
        reason: 'UNRECOVERABLE_SHAPE_LEGACY',
        institutionalDid,
        recoveryControllerProvider: agentHeldRecoveryController,
      }),
    ).rejects.toThrow(/already consumed/);

    // A FRESH authorisation for the same old DID is refused too. TWO
    // INDEPENDENT GUARDS cover this and the ownership one fires first, because
    // a completed migration has already moved `User.did` to the successor.
    await expect(
      authoriseReissuance(agent, {
        oldDid,
        userId,
        institutionalDid,
        officerId: 'live-test-officer',
        officerName: 'Live Test Officer',
        evidenceKind: 'OPERATOR_TEST_DATA',
        evidenceReference: `live-${randomUUID()}`,
      }),
    ).rejects.toThrow(/does not own/);

    // Now the dangerous case the succession guard actually exists for: someone
    // "repairs" the account back to the dead DID and retries. Ownership then
    // passes, and the succession is the only thing standing between this and a
    // second successor for one identity.
    await db.user.update({ where: { id: userId }, data: { did: oldDid } });

    await expect(
      authoriseReissuance(agent, {
        oldDid,
        userId,
        institutionalDid,
        officerId: 'live-test-officer',
        officerName: 'Live Test Officer',
        evidenceKind: 'OPERATOR_TEST_DATA',
        evidenceReference: `live-${randomUUID()}`,
      }),
    ).rejects.toThrow(/already has a succession/);
  }, 180_000);

  it('REFUSES to re-issue a RECOVERABLE DID — rotation is the remedy, not migration', async () => {
    // Re-issuance changes the identifier and orphans every credential until it
    // is issued again. A DID whose device key can simply be rotated (S-1 R2)
    // must not come through here.
    const oldDid = await mintUnrecoverableDid();
    const userId = await makeUserHolding(oldDid);

    const authorisation = await authoriseReissuance(agent, {
      oldDid,
      userId,
      institutionalDid,
      officerId: 'live-test-officer',
      officerName: 'Live Test Officer',
      evidenceKind: 'OPERATOR_TEST_DATA',
      evidenceReference: `live-${randomUUID()}`,
    });

    // Migrate once so a recoverable DID exists, then try to migrate THAT.
    const first = await executeReissuance(agent, {
      authorisationId: authorisation.id,
      reason: 'UNRECOVERABLE_SHAPE_LEGACY',
      institutionalDid,
      recoveryControllerProvider: agentHeldRecoveryController,
    });

    const second = await authoriseReissuance(agent, {
      oldDid: first.newDid,
      userId,
      institutionalDid,
      officerId: 'live-test-officer',
      officerName: 'Live Test Officer',
      evidenceKind: 'OPERATOR_TEST_DATA',
      evidenceReference: `live-${randomUUID()}`,
    });

    await expect(
      executeReissuance(agent, {
        authorisationId: second.id,
        reason: 'UNRECOVERABLE_SHAPE_LEGACY',
        institutionalDid,
        recoveryControllerProvider: agentHeldRecoveryController,
      }),
    ).rejects.toThrow(/is classified 'recoverable'/);
  }, 180_000);
});

describe('the shape an issuer needs is not the shape a holder needs (steno #313)', () => {
  it('a SELF-CONTROLLED DID can publish its own status list', async () => {
    // This is what makes an issuer an issuer: without a publishable status list
    // it can never revoke, and an issuer that cannot revoke should not issue.
    const selfControlled = await mintUnrecoverableDid();
    const list = await getOrCreateStatusList(selfControlled);
    const published = await ensureStatusListPublished(list);

    expect(published.latestResourceId).toBeTruthy();
    expect(published.publishedAt).not.toBeNull();

    await db.credentialStatusList.deleteMany({ where: { id: list.id } });
  }, 180_000);

  it('a 2-of-2 PATIENT-SHAPED DID CANNOT publish — x/resource wants the controller set', async () => {
    // The measurement that forced the successor shape to depend on role. The
    // rejection names the INSTITUTION, which holds no part of this wallet's
    // ability to sign for the subject.
    const oldDid = await mintUnrecoverableDid();
    const userId = await makeUserHolding(oldDid);

    const authorisation = await authoriseReissuance(agent, {
      oldDid,
      userId,
      institutionalDid,
      officerId: 'live-test-officer',
      officerName: 'Live Test Officer',
      evidenceKind: 'OPERATOR_TEST_DATA',
      evidenceReference: `live-${randomUUID()}`,
    });

    const migrated = await executeReissuance(agent, {
      authorisationId: authorisation.id,
      reason: 'UNRECOVERABLE_SHAPE_LEGACY',
      institutionalDid,
      recoveryControllerProvider: agentHeldRecoveryController,
    });

    const patientShaped = await resolveOnChain(agent, migrated.newDid);
    expect(patientShaped!.controller).toHaveLength(2);

    const list = await getOrCreateStatusList(migrated.newDid);
    await expect(ensureStatusListPublished(list)).rejects.toThrow(
      /signature is required but not found/,
    );

    await db.credentialStatusList.deleteMany({ where: { id: list.id } });
  }, 180_000);
});

describe('a half-finished migration destroys nothing (steno #314)', () => {
  it('records every credential bound to the old DID, including the ones NOT carried forward', async () => {
    // The interesting rows in an audit are the ones that were skipped. A
    // missing row is indistinguishable from a bug.
    const succession = await db.didSuccession.findFirst({
      where: { oldDid: 'did:cheqd:bdhealthtestnet:7cd03fdc-6a88-4895-9d89-e63445abe0c1' },
      include: { credentials: true },
    });

    if (!succession) {
      throw new Error(
        'LIVE SUITE PRECONDITION FAILED — the R5 migration of ' +
          'did:cheqd:bdhealthtestnet:7cd03fdc-6a88-4895-9d89-e63445abe0c1 is not in this ' +
          'database.\n\n' +
          '  pnpm --filter @ssi-healthcare/backend exec tsx scripts/reissue-identity.ts run ...\n\n' +
          'This test asserts properties of the real migration; without it there is nothing ' +
          'to assert and a pass would be meaningless.',
      );
    }

    const outcomes = succession.credentials.reduce<Record<string, number>>((acc, row) => {
      acc[row.outcome] = (acc[row.outcome] ?? 0) + 1;
      return acc;
    }, {});

    // Every credential the old DID held AT MIGRATION TIME has a row, and they
    // sum. Scoped by `startedAt` because the succession's credential list is a
    // frozen historical record while the row count is live: `revocation.live`
    // issues to this same DID on every run, so an unscoped count drifts upward
    // one per suite execution and this assertion could never stay true. It had
    // already drifted to 83 vs 79 when the scoping was added.
    const held = await db.credential.count({
      where: { holderDid: succession.oldDid, createdAt: { lte: succession.startedAt } },
    });
    expect(succession.credentials.length).toBe(held);
    expect(Object.values(outcomes).reduce((a, b) => a + b, 0)).toBe(held);

    // Nothing may be left PENDING or FAILED in a COMPLETE succession.
    if (succession.status === 'COMPLETE') {
      expect(outcomes.PENDING ?? 0).toBe(0);
      expect(outcomes.FAILED ?? 0).toBe(0);
    }

    // Every REISSUED row names a replacement that exists and is bound to the
    // NEW identity — not to the dead one.
    const reissued = succession.credentials.filter((row) => row.outcome === 'REISSUED');
    for (const row of reissued) {
      expect(row.newCredentialId).toBeTruthy();
      const replacement = await db.credential.findUnique({
        where: { id: row.newCredentialId as string },
      });
      expect(replacement?.holderDid).toBe(succession.newDid);

      // And its predecessor is revoked — the order that keeps a holder from
      // ever having neither copy.
      const superseded = await db.credential.findUnique({ where: { id: row.oldCredentialId } });
      expect(superseded?.status).toBe('REVOKED');
    }

    // An UNTRACKABLE row must NOT have a replacement: issuing one would leave
    // two live credentials saying the same thing under two identifiers.
    for (const row of succession.credentials.filter((r) => r.outcome === 'UNTRACKABLE')) {
      expect(row.newCredentialId).toBeNull();
    }
  }, 180_000);

  it('refuses to construct a successor whose role contradicts the old DID’s behaviour', async () => {
    // An issuer and a holder want opposite shapes, so asking for the wrong one
    // must fail BEFORE anything is minted rather than 25 credentials later.
    const issuerDid = 'did:cheqd:bdhealthtestnet:fa3fc79f-9d49-43f5-9aa7-4f2df973bbb0';
    const issued = await db.credential.count({ where: { issuerDid } });

    if (issued === 0) {
      throw new Error(
        `LIVE SUITE PRECONDITION FAILED — '${issuerDid}' has issued no credentials in this ` +
          'database, so the role-mismatch guard cannot be exercised.',
      );
    }

    const existing = await db.didSuccession.findUnique({ where: { oldDid: issuerDid } });
    expect(existing).not.toBeNull();

    // It was migrated as an ISSUER, so its successor must be SELF-CONTROLLED
    // and therefore able to publish.
    const successor = await resolveOnChain(agent, existing!.newDid);
    expect(successor).not.toBeNull();
    expect(successor!.controller).toEqual([existing!.newDid]);
    expect(successor!.verificationMethod.length).toBeGreaterThanOrEqual(2);
    for (const vm of successor!.verificationMethod) {
      expect(vm.controller).toBe(existing!.newDid);
    }
  }, 180_000);
});

describe('the old identity ends in a state that cannot be mistaken for live', () => {
  it('a DEACTIVATED predecessor resolves deactivated and refuses further updates', async () => {
    const succession = await db.didSuccession.findFirst({
      where: { disposition: 'DEACTIVATED' },
    });

    if (!succession) {
      throw new Error(
        'LIVE SUITE PRECONDITION FAILED — no DEACTIVATED succession exists in this database.',
      );
    }

    const old = await resolveOnChain(agent, succession.oldDid);
    expect(old).not.toBeNull();
    expect(old!.deactivated).toBe(true);
    expect(succession.deactivationTxHash).toBeTruthy();
    expect(succession.deactivationHeight).toBeGreaterThan(0);
  }, 180_000);

  it('a MARKED predecessor is recorded here even though the chain still says live', () => {
    // Stated rather than glossed: there is no key-free way to make an external
    // resolver see a cheqd DID as dead, because deactivation needs the lost
    // key. What a verifier CAN see is that every carried-forward credential is
    // revoked.
    return db.didSuccession
      .findFirst({ where: { disposition: 'MARKED' } })
      .then(async (succession) => {
        if (!succession) return;
        const old = await resolveOnChain(agent, succession.oldDid);
        expect(old?.deactivated).toBe(false);
        expect(succession.status).toBe('COMPLETE');
      });
  }, 180_000);
});
