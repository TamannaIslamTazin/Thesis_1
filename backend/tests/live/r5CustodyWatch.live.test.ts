/**
 * R5 — THE SIGNING AUDIT LOG AND THE CHAIN SILENT ALARM, AGAINST THE REAL CHAIN.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS CANNOT BE MOCKED, IN ONE SENTENCE
 * ---------------------------------------------------------------------------
 * The claim under test is "an officer key acting against the institutional DID
 * is DETECTED", and the only thing that can produce the evidence is a chain
 * that actually accepted the transaction. A stubbed RPC returning a canned
 * `MsgUpdateDidDoc` would prove that the stub returned what the stub was told
 * to return — the exact class of false pass this project keeps finding in its
 * own code (see the header of `vitest.live.config.ts`).
 *
 * The adversary case in `an officer key acting OUTSIDE this backend` is the
 * centrepiece. It signs and broadcasts with a real officer key WITHOUT going
 * through `institutionalDid.ts`, which is precisely what an attacker holding
 * that key would do: they do not need our backend, and nothing in our signing
 * path would ever see them. If the watcher only observed our own outbound
 * calls, that test would pass with no alarm and the whole component would be
 * theatre.
 *
 * The taxonomy itself (severity rules, change classification, hash-chain
 * tamper detection over synthetic entries) is in `tests/fast`, where a stopped
 * validator cannot stop it from running.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Agent } from '@credo-ts/core';
import { utils } from '@credo-ts/core';
import {
  createMsgDeactivateDidDocPayloadToSign,
  createMsgUpdateDidDocPayloadToSign,
} from '@cheqd/sdk/utils';

import { createAgent, shutdownAgent } from '../../src/agent/index.js';
import { db } from '../../src/db/index.js';
import { config } from '../../src/config/index.js';
import {
  agentSigner,
  assertDelivered,
  ledgerServiceOf,
  resolveOnChain,
} from '../../src/services/cheqdLedger.js';
import {
  addInstitutionalOfficerKey,
  LEDGER_SIGNING_FRAGMENT,
  provisionInstitutionalDid,
  retireInstitutionalOfficerKey,
  rotateInstitutionalOfficerKey,
} from '../../src/services/institutionalDid.js';
import { ChainWatch } from '../../src/services/custody/chainWatch.js';
import { CometBftClient } from '../../src/services/custody/cometBftClient.js';
import {
  recordSigningAttempt,
  verifySigningLog,
} from '../../src/services/custody/signingAuditLog.js';
import { reconcileLogAgainstChain } from '../../src/services/custody/reconciliation.js';
import {
  DID_V1_CONTEXT,
  ED25519_2020_CONTEXT,
  ED25519_VERIFICATION_KEY_2020,
  fragmentOf,
} from '@ssi-healthcare/sdk/ledger';

let agent: Agent;
let watch: ChainWatch;
let comet: CometBftClient;

/** Drive the watcher to the chain tip rather than sleeping and hoping. */
async function catchUp(): Promise<void> {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const report = await watch.scanOnce();
    if (report.caughtUp) return;
  }
  throw new Error('the chain watch never caught up within 40 bounded scans');
}

async function alarmsFor(txHash: string) {
  return db.custodyAlarm.findMany({ where: { txHash }, orderBy: { raisedAt: 'asc' } });
}

beforeAll(async () => {
  agent = await createAgent();
  comet = new CometBftClient(config.cheqdRpcUrl);

  // A fresh cursor at the current tip. The cursor is a resume point, not
  // evidence, so resetting it between suite runs is legitimate — unlike the
  // signing log, which no test is permitted to reset.
  const status = await comet.status();
  await db.chainWatchCursor.deleteMany({ where: { id: 'default' } });
  await db.chainWatchCursor.create({
    data: {
      id: 'default',
      lastScannedHeight: status.latestHeight,
      chainId: status.chainId,
      startedFromHeight: status.latestHeight,
    },
  });

  // NEVER started as a timer. Every scan in this file is explicit, so a
  // failure means the watcher did not detect something rather than that the
  // test did not wait long enough.
  watch = new ChainWatch({ pollIntervalMs: 2_000 });
}, 180_000);

afterAll(async () => {
  watch?.stop();
  await shutdownAgent();
});

// ---------------------------------------------------------------------------

describe('the eviction case — S-4 H1, through this codebase, on this chain', () => {
  it('detects an officer eviction and attributes it to the signing key', async () => {
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: eviction detection',
    });
    await catchUp();

    const doomed = `${created.did}#key-officer-2`;
    const evicted = await retireInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      fragment: '#key-officer-2',
      reason: 'live suite: the eviction the alarm exists for',
    });

    // The chain really lost the slot. Everything below is about DETECTION, so
    // establish the fact first rather than inferring it from our own alarm.
    const onChain = await resolveOnChain(agent, created.did);
    expect(onChain!.verificationMethod.map((vm) => vm.id)).not.toContain(doomed);

    await catchUp();

    const alarms = await alarmsFor(evicted.transactionHash);
    expect(alarms, 'no alarm was raised for the eviction').toHaveLength(1);
    const [alarm] = alarms;

    expect(alarm.kind).toBe('OFFICER_EVICTED');
    // CRITICAL even though we authorised it: attributable is not the same as
    // safe. Each eviction narrows the set toward the state where rotation —
    // the only remedy 1-of-N has — is impossible (#291).
    expect(alarm.severity).toBe('CRITICAL');
    expect(alarm.attribution).toBe('MATCHED');
    expect(alarm.subjectDid).toBe(created.did);
    expect(alarm.height).toBe(evicted.height);

    // WHICH KEY SIGNED, read out of the chain's own bytes rather than out of
    // anything this backend recorded about itself. Under 1-of-N that is the
    // whole of attribution.
    expect(alarm.signerVerificationMethodIds).toEqual([
      `${created.did}${LEDGER_SIGNING_FRAGMENT}`,
    ]);

    const detail = alarm.detail as Record<string, unknown>;
    expect(detail.change).toBe('eviction');
    expect(detail.removedVerificationMethodIds).toEqual([doomed]);
    expect(detail.deliveryCode).toBe(0);

    // And the audit log holds the intent that made it attributable, with the
    // payload needed to reconstruct what was authorised.
    const intent = await db.signingAuditEntry.findFirst({
      where: { subjectDid: created.did, kind: 'SIGNING_INTENT', operation: 'retire-officer-slot' },
      orderBy: { seq: 'desc' },
    });
    expect(intent).not.toBeNull();
    expect(alarm.matchedAuditSeq).toBe(intent!.seq);
    expect(intent!.signedByVerificationMethodId).toBe(`${created.did}${LEDGER_SIGNING_FRAGMENT}`);
    expect((intent!.payload as Record<string, unknown>).removed).toEqual([doomed]);
    expect((intent!.payload as Record<string, unknown>).reason).toContain('live suite');

    const result = await db.signingAuditEntry.findFirst({
      where: { correlationId: intent!.correlationId, kind: 'SIGNING_RESULT' },
    });
    expect(result!.txHash).toBe(evicted.transactionHash);
    expect(result!.height).toBe(evicted.height);
  }, 180_000);

  it('files a routine rotation below an eviction', async () => {
    // The operation 1-of-N exists to make possible must not page anybody, or
    // nothing else in the alarm list will get read.
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: routine rotation severity',
    });
    await catchUp();

    const rotated = await rotateInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      fragment: '#key-officer-2',
      reason: 'live suite: routine officer rotation',
    });
    await catchUp();

    const [alarm] = await alarmsFor(rotated.transactionHash);
    expect(alarm.kind).toBe('OFFICER_ROTATED');
    expect(alarm.severity).toBe('INFO');
    expect(alarm.attribution).toBe('MATCHED');
  }, 180_000);
});

// ---------------------------------------------------------------------------

describe('an officer key acting OUTSIDE this backend — the threat #291 names', () => {
  it('raises an UNMATCHED CRITICAL for a chain event no audit entry explains', async () => {
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: bypassed signing path',
    });
    await catchUp();

    const doomed = `${created.did}#key-officer-2`;

    // THE ADVERSARY PATH. This assembles and broadcasts `MsgUpdateDidDoc`
    // itself, with a real officer key, and never touches `institutionalDid.ts`
    // — so no SIGNING_INTENT is written. Anyone holding an officer key can do
    // exactly this from anywhere, which is why watching our own outbound calls
    // would have been worthless.
    const survivor = `${created.did}${LEDGER_SIGNING_FRAGMENT}`;
    const before = await resolveOnChain(agent, created.did);
    const document = {
      '@context': [DID_V1_CONTEXT, ED25519_2020_CONTEXT],
      id: created.did,
      controller: [created.did],
      verificationMethod: before!.verificationMethod
        .filter((vm) => vm.id !== doomed)
        .map((vm) => ({
          id: vm.id,
          type: ED25519_VERIFICATION_KEY_2020,
          controller: created.did,
          publicKeyMultibase: vm.publicKeyMultibase,
        })),
      authentication: [survivor],
      assertionMethod: before!.verificationMethod
        .filter((vm) => vm.id !== doomed)
        .map((vm) => vm.id),
    };

    const versionId = utils.uuid();
    const payload = await createMsgUpdateDidDocPayloadToSign(document as never, versionId);
    const signer = await agentSigner(agent, created.did, LEDGER_SIGNING_FRAGMENT);
    const write = assertDelivered(
      await ledgerServiceOf(agent).update(
        document as never,
        [
          {
            verificationMethodId: signer.verificationMethodId,
            signature: await signer.sign(payload),
          },
        ] as never,
        versionId,
      ),
      'adversarial direct eviction',
    );

    // Nothing in the signing log knows about this versionId. That is the point.
    const intent = await db.signingAuditEntry.findFirst({ where: { versionId } });
    expect(intent, 'the bypass wrote an audit entry, so it did not bypass anything').toBeNull();

    await catchUp();

    const [alarm] = await alarmsFor(write.transactionHash);
    expect(alarm, 'the watcher missed a direct broadcast').toBeDefined();
    expect(alarm.kind).toBe('OFFICER_EVICTED');
    expect(alarm.attribution).toBe('UNMATCHED');
    expect(alarm.severity).toBe('CRITICAL');
    expect(alarm.matchedAuditSeq).toBeNull();
    // The operator must learn this from the one line they read, not from a
    // field they have to expand.
    expect(alarm.headline).toContain('NO SIGNING AUDIT ENTRY ACCOUNTS FOR THIS');
    expect(alarm.signerVerificationMethodIds).toEqual([survivor]);
    expect((alarm.detail as Record<string, unknown>).removedVerificationMethodIds).toEqual([
      doomed,
    ]);
  }, 180_000);

  it('raises DID_DEACTIVATED for an irreversible deactivation', async () => {
    // There is no deactivate function in `institutionalDid.ts` — deliberately,
    // since code 1207 has no remedy — so this is necessarily the bypass path,
    // and necessarily UNMATCHED. It is also the worst thing one officer key can
    // do, so the watcher must survive it being the FIRST thing it ever sees for
    // that DID.
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }],
      purpose: 'live suite: deactivation detection',
    });
    await catchUp();

    const signer = await agentSigner(agent, created.did, LEDGER_SIGNING_FRAGMENT);
    const versionId = utils.uuid();
    // @cheqd/sdk validates the signature set against the document's
    // `authentication` array even for a deactivation, so the WHOLE document has
    // to be supplied — `{ id }` alone is rejected client-side before any
    // broadcast happens.
    const live = await resolveOnChain(agent, created.did);
    const document = {
      '@context': [DID_V1_CONTEXT, ED25519_2020_CONTEXT],
      id: created.did,
      controller: [created.did],
      verificationMethod: live!.verificationMethod.map((vm) => ({
        id: vm.id,
        type: ED25519_VERIFICATION_KEY_2020,
        controller: created.did,
        publicKeyMultibase: vm.publicKeyMultibase,
      })),
      authentication: live!.authentication,
      assertionMethod: live!.assertionMethod,
    };
    const payload = createMsgDeactivateDidDocPayloadToSign(document as never, versionId);

    const write = assertDelivered(
      await ledgerServiceOf(agent).deactivate(
        document as never,
        [
          {
            verificationMethodId: signer.verificationMethodId,
            signature: await signer.sign(payload),
          },
        ] as never,
        versionId,
      ),
      'adversarial deactivation',
    );

    await catchUp();

    const [alarm] = await alarmsFor(write.transactionHash);
    expect(alarm.kind).toBe('DID_DEACTIVATED');
    expect(alarm.severity).toBe('CRITICAL');
    expect(alarm.headline).toMatch(/irreversible/i);
    expect(alarm.headline).toContain('1207');

    // And the running picture records that this DID is gone, so a later message
    // against it is not compared against a document that no longer exists.
    const watched = await db.watchedInstitutionalDid.findUnique({ where: { did: created.did } });
    expect(watched!.deactivated).toBe(true);
  }, 180_000);
});

// ---------------------------------------------------------------------------

describe('downtime — the gap the watcher was not there for', () => {
  it('covers the blocks it missed, and is idempotent when it re-covers them', async () => {
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: downtime gap',
    });
    await catchUp();

    const cursorBefore = (await db.chainWatchCursor.findUnique({ where: { id: 'default' } }))!;

    // ---- the watcher is now "down". No scan happens below this line. -------
    const rotated = await rotateInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      fragment: '#key-officer-2',
      reason: 'live suite: change #1 during downtime',
    });
    const evicted = await retireInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      fragment: '#key-officer-2',
      reason: 'live suite: change #2 during downtime — the one that matters',
    });

    // Nothing was observed while it was down. If the watcher were somehow still
    // running, this assertion is what catches it and invalidates the test.
    expect(await alarmsFor(evicted.transactionHash)).toHaveLength(0);
    const cursorDuring = (await db.chainWatchCursor.findUnique({ where: { id: 'default' } }))!;
    expect(cursorDuring.lastScannedHeight).toBe(cursorBefore.lastScannedHeight);

    const tip = await comet.status();
    expect(
      tip.latestHeight,
      'the chain did not advance past the cursor, so there is no gap to test',
    ).toBeGreaterThan(cursorBefore.lastScannedHeight);

    // ---- the watcher comes back up ----------------------------------------
    await catchUp();

    // Both changes found, including the one that is now several blocks in the
    // past. A watcher that resumed at "now" would have found neither.
    const rotationAlarms = await alarmsFor(rotated.transactionHash);
    const evictionAlarms = await alarmsFor(evicted.transactionHash);
    expect(rotationAlarms, 'the rotation inside the gap was skipped').toHaveLength(1);
    expect(evictionAlarms, 'the EVICTION inside the gap was skipped').toHaveLength(1);
    expect(evictionAlarms[0].kind).toBe('OFFICER_EVICTED');
    expect(evictionAlarms[0].height).toBeLessThanOrEqual(
      (await db.chainWatchCursor.findUnique({ where: { id: 'default' } }))!.lastScannedHeight,
    );
    // Order preserved: the rotation was classified against the pre-rotation
    // document, which is only true if the heights were replayed in sequence.
    expect(rotationAlarms[0].kind).toBe('OFFICER_ROTATED');
    expect(rotationAlarms[0].height).toBeLessThan(evictionAlarms[0].height!);

    // ---- re-covering the same blocks must not re-alarm ---------------------
    // A crash mid-height re-scans it. If that produced a second alarm, every
    // restart would manufacture duplicates and the channel would become noise.
    await db.chainWatchCursor.update({
      where: { id: 'default' },
      data: { lastScannedHeight: cursorBefore.lastScannedHeight },
    });
    await catchUp();

    expect(await alarmsFor(rotated.transactionHash)).toHaveLength(1);
    expect(await alarmsFor(evicted.transactionHash)).toHaveLength(1);
  }, 300_000);
});

// ---------------------------------------------------------------------------

describe('append-only is enforced by the database, not by politeness', () => {
  it('refuses UPDATE, DELETE and TRUNCATE on the signing log', async () => {
    const entry = await db.signingAuditEntry.findFirst({ orderBy: { seq: 'desc' } });
    expect(entry, 'the suite has written no audit entries, so this proves nothing').not.toBeNull();

    // Through Prisma...
    await expect(
      db.signingAuditEntry.update({
        where: { seq: entry!.seq },
        data: { operation: 'tampered' },
      }),
    ).rejects.toThrow(/append-only/i);
    await expect(
      db.signingAuditEntry.delete({ where: { seq: entry!.seq } }),
    ).rejects.toThrow(/append-only/i);

    // ...and through raw SQL, which is the path a convention in TypeScript
    // would not survive.
    await expect(
      db.$executeRawUnsafe(`UPDATE "SigningAuditEntry" SET "operation" = 'tampered'`),
    ).rejects.toThrow(/append-only/i);
    await expect(db.$executeRawUnsafe(`DELETE FROM "SigningAuditEntry"`)).rejects.toThrow(
      /append-only/i,
    );
    await expect(db.$executeRawUnsafe(`TRUNCATE "SigningAuditEntry"`)).rejects.toThrow(
      /append-only/i,
    );

    const after = await db.signingAuditEntry.findUnique({ where: { seq: entry!.seq } });
    expect(after!.operation).toBe(entry!.operation);
  }, 60_000);

  it('detects tampering that got past the triggers, and names the entry', async () => {
    // The triggers stop a writer; they do not stop a role with DDL rights. This
    // reproduces exactly that: drop the trigger, edit one row, and check that
    // the hash chain still gives the game away. The row is restored afterwards.
    expect((await verifySigningLog()).intact).toBe(true);

    const victim = await db.signingAuditEntry.findFirst({
      where: { kind: 'SIGNING_INTENT' },
      orderBy: { seq: 'asc' },
    });
    const original = victim!.signedByVerificationMethodId;

    await db.$executeRawUnsafe(
      `ALTER TABLE "SigningAuditEntry" DISABLE TRIGGER "signingAuditEntry_noUpdate"`,
    );
    try {
      // The forgery an insider would attempt: re-attribute the signature.
      await db.$executeRawUnsafe(
        `UPDATE "SigningAuditEntry" SET "signedByVerificationMethodId" = $1 WHERE seq = $2`,
        'did:cheqd:bdhealthtestnet:someone-else#key-officer-9',
        victim!.seq,
      );

      const verdict = await verifySigningLog();
      expect(verdict.intact).toBe(false);
      expect(
        verdict.breaks.some((b) => b.seq === victim!.seq && b.reason === 'entry-hash-mismatch'),
      ).toBe(true);

      // Verifying is not a quiet read: it raises the alarm itself, so nobody
      // can discover tampering without the system also recording that it was
      // discovered.
      const alarm = await db.custodyAlarm.findFirst({
        where: { kind: 'AUDIT_CHAIN_TAMPERED' },
        orderBy: { raisedAt: 'desc' },
      });
      expect(alarm).not.toBeNull();
      expect(alarm!.severity).toBe('CRITICAL');
    } finally {
      await db.$executeRawUnsafe(
        `UPDATE "SigningAuditEntry" SET "signedByVerificationMethodId" = $1 WHERE seq = $2`,
        original,
        victim!.seq,
      );
      await db.$executeRawUnsafe(
        `ALTER TABLE "SigningAuditEntry" ENABLE TRIGGER "signingAuditEntry_noUpdate"`,
      );
    }

    // Restored byte for byte, so the chain verifies again — which also proves
    // the break above was caused by the edit and not by the verifier drifting.
    expect((await verifySigningLog()).intact).toBe(true);
  }, 120_000);
});

// ---------------------------------------------------------------------------

describe('reconciliation — a broadcast we believe in that the chain never had', () => {
  it('raises BROADCAST_NOT_ON_CHAIN for a result with no observed transaction', async () => {
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }],
      purpose: 'live suite: log-without-chain',
    });
    // A second real write, so the phantom below sits at a height STRICTLY above
    // the DID's arming height. The reconciler deliberately says nothing about
    // the arming height itself — the create transaction lives there and the
    // watch was not yet armed when it landed — and a provision alone can leave
    // the cursor sitting exactly on it.
    await addInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      key: { kind: 'agent-generated' },
      reason: 'live suite: put a block between the create and the phantom',
    });
    await catchUp();

    const cursor = (await db.chainWatchCursor.findUnique({ where: { id: 'default' } }))!;
    expect(cursor.lastScannedHeight).toBeGreaterThan(created.height);
    // Unique per run. The signing log is append-only, so a previous run's
    // phantom is still in it and a fixed hash would match that one instead —
    // the test would then assert against an alarm it did not cause.
    const phantomTxHash = utils.uuid().replace(/-/g, '').toUpperCase().repeat(2);

    // A completed signing attempt whose broadcast never reached the chain. Not
    // hand-inserted: it goes through the real append path, so the hash chain
    // stays valid and the reconciler sees exactly the state a silently-failed
    // write would leave behind.
    await recordSigningAttempt(
      {
        subjectDid: created.did,
        operation: 'rotate-officer-slot',
        versionId: utils.uuid(),
        signedByVerificationMethodId: `${created.did}${LEDGER_SIGNING_FRAGMENT}`,
        payload: { reason: 'live suite: a broadcast that never happened' },
      },
      async () => ({ transactionHash: phantomTxHash, height: cursor.lastScannedHeight }),
    );

    const report = await reconcileLogAgainstChain();
    expect(report.broadcastsNotOnChain).toContain(phantomTxHash);

    const alarm = await db.custodyAlarm.findFirst({
      where: { kind: 'BROADCAST_NOT_ON_CHAIN', txHash: phantomTxHash },
    });
    expect(alarm).not.toBeNull();
    expect(alarm!.severity).toBe('CRITICAL');
    expect(alarm!.subjectDid).toBe(created.did);
    // The identity de-duplication keys on. It was absent once, which made the
    // txhash-less branch unmatchable and re-raised such findings every sweep.
    expect(alarm!.matchedAuditSeq).not.toBeNull();

    // The log is still sound — this is a disagreement between two sources, not
    // tampering, and the two must not be conflated.
    expect((await verifySigningLog()).intact).toBe(true);
  }, 180_000);

  it('does not accuse a provisioning write that plainly succeeded', async () => {
    // The regression this exists for: `MsgCreateDidDoc` was not in the observed
    // set, so EVERY institution provisioned raised a CRITICAL
    // BROADCAST_NOT_ON_CHAIN for a write that had obviously worked. An alarm
    // channel that cries wolf on the happy path is worse than no channel.
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }],
      purpose: 'live suite: provisioning must not false-positive',
    });
    await catchUp();

    // The create really was observed — the fix is that it is RECORDED, not that
    // reconciliation was taught to look away.
    const observed = await db.observedDidTx.findFirst({
      where: { txHash: created.transactionHash },
    });
    expect(observed, 'the create transaction was never observed').not.toBeNull();
    expect(observed!.typeUrl).toBe('/cheqd.did.v2.MsgCreateDidDoc');

    // ...and it raised no alarm, because a DID coming into existence cannot
    // harm one that already exists.
    expect(await alarmsFor(created.transactionHash)).toHaveLength(0);

    await reconcileLogAgainstChain();
    const falsePositive = await db.custodyAlarm.findFirst({
      where: { kind: 'BROADCAST_NOT_ON_CHAIN', subjectDid: created.did },
    });
    expect(falsePositive).toBeNull();
  }, 180_000);

  it('reports an incomplete sweep as incomplete, not as clean (#302)', async () => {
    // Failsafe-first: "found nothing in the part I could see" and "found
    // nothing" must be different values. If they collapse, an operator reads an
    // empty findings list as an all-clear while part of the ledger was never
    // examined at all.
    const report = await reconcileLogAgainstChain();
    const residue =
      report.checksFailed +
      report.skippedOutsideWatchWindow +
      report.skippedBecauseWatchIsBehind +
      report.suppressedAsAlreadyOpen;

    expect(residue, 'this suite should have left residue to count').toBeGreaterThan(0);
    expect(report.complete).toBe(false);
    // Every bucket is countable rather than merely absent.
    expect(typeof report.checksFailed).toBe('number');
    expect(typeof report.skippedOutsideWatchWindow).toBe('number');
  }, 120_000);

  it('does not re-raise a finding that is already open', async () => {
    // A sweep that re-raises what an operator is already looking at turns a
    // standing finding into a stream, and a stream gets scrolled past.
    const before = await db.custodyAlarm.count({
      where: { kind: 'BROADCAST_NOT_ON_CHAIN', acknowledgedAt: null },
    });
    const report = await reconcileLogAgainstChain();
    const after = await db.custodyAlarm.count({
      where: { kind: 'BROADCAST_NOT_ON_CHAIN', acknowledgedAt: null },
    });

    expect(after).toBe(before);
    expect(report.suppressedAsAlreadyOpen).toBeGreaterThan(0);
  }, 120_000);

  it('does not accuse a write the watcher simply has not reached yet', async () => {
    // The reconciler examines only heights the cursor has passed. Without that,
    // every write made during a catch-up would raise a CRITICAL alarm — wrong,
    // and the fastest way to make the channel worthless.
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }],
      purpose: 'live suite: watch-is-behind guard',
    });

    const cursor = (await db.chainWatchCursor.findUnique({ where: { id: 'default' } }))!;
    await db.chainWatchCursor.update({
      where: { id: 'default' },
      data: { lastScannedHeight: Math.max(cursor.lastScannedHeight - 50, 1) },
    });

    const report = await reconcileLogAgainstChain();
    expect(report.skippedBecauseWatchIsBehind).toBeGreaterThan(0);
    expect(report.broadcastsNotOnChain).not.toContain(created.transactionHash);

    await catchUp();
  }, 180_000);
});

// ---------------------------------------------------------------------------

describe('the running picture the classification depends on', () => {
  it('tracks the document across a provision, an addition and an eviction', async () => {
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: watch state tracking',
    });
    await catchUp();

    const armed = await db.watchedInstitutionalDid.findUnique({ where: { did: created.did } });
    expect(armed, 'provisioning did not arm the watch').not.toBeNull();
    // Armed from the DID's own creation height, so the window the system claims
    // to have covered really is the whole lifetime of this DID.
    expect(armed!.watchedFromHeight).toBe(created.height);
    expect(armed!.lastSeenVerificationMethodIds.map(fragmentOf).sort()).toEqual([
      '#key-officer-1',
      '#key-officer-2',
    ]);

    await retireInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      fragment: '#key-officer-2',
      reason: 'live suite: advance the running picture',
    });
    await catchUp();

    const after = await db.watchedInstitutionalDid.findUnique({ where: { did: created.did } });
    expect(after!.lastSeenVerificationMethodIds).toEqual([
      `${created.did}${LEDGER_SIGNING_FRAGMENT}`,
    ]);
    expect(after!.lastSeenHeight).toBeGreaterThan(created.height);
  }, 180_000);
});
