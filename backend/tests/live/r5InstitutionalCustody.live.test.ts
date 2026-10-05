/**
 * R5 PHASE A — 1-of-N INSTITUTIONAL CUSTODY, AGAINST THE REAL CHAIN.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS BEING PROVEN, AND WHY IT NEEDS A LEDGER
 * ---------------------------------------------------------------------------
 * The 1-of-N ruling (#276) rests on one property of `x/did`: AND across
 * controller DIDs, OR across the keys of ONE controller DID. S-4 measured that
 * property directly (M1 at height 86320, with NC2 as the control whose only
 * difference was VM count). This suite proves OUR module produces documents
 * that inherit it — that a sibling officer key really can rotate and retire
 * another, through this codebase, on this chain.
 *
 * A mocked ledger would decide the outcome by fiat. The whole claim is "the
 * chain accepted a signature from a key that is not the one being changed",
 * and only the chain can say that.
 *
 * The pre-broadcast refusals — the shapes that must be unconstructable — are in
 * `tests/fast/didShapes.test.ts`, where a stopped validator cannot stop them
 * from running.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Agent } from '@credo-ts/core';

import { createAgent, shutdownAgent } from '../../src/agent/index.js';
import { AppError } from '../../src/middleware/errorHandler.js';
import { resolveOnChain } from '../../src/services/cheqdLedger.js';
import {
  ACKNOWLEDGE_FOREIGN_HELD_INSTITUTIONAL_KEY,
  addInstitutionalOfficerKey,
  describeInstitutionalCustody,
  LEDGER_SIGNING_FRAGMENT,
  provisionInstitutionalDid,
  retireInstitutionalOfficerKey,
  rotateInstitutionalOfficerKey,
} from '../../src/services/institutionalDid.js';
import { fragmentOf } from '@ssi-healthcare/sdk/ledger';

let agent: Agent;

beforeAll(async () => {
  agent = await createAgent();
}, 180_000);

afterAll(async () => {
  await shutdownAgent();
});

// ---------------------------------------------------------------------------

describe('provisioning writes the #292 shape and the chain agrees', () => {
  it('creates N self-controlled slots, every one controlled by the institution itself', async () => {
    const result = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: the 1-of-N shape',
    });

    const onChain = await resolveOnChain(agent, result.did);
    expect(onChain, 'institutional DID does not resolve').not.toBeNull();
    expect(onChain!.deactivated).toBe(false);

    // Self-controlled document. A foreign controller would make every future
    // institutional key change conditional on that DID (AND), and the
    // controller set can never be repaired (S-1 §5.4).
    expect(onChain!.controller).toEqual([result.did]);

    expect(onChain!.verificationMethod).toHaveLength(3);
    for (const vm of onChain!.verificationMethod) {
      // THE CONDITION 1-of-N DEPENDS ON. Any other value here and rotating that
      // slot needs a foreign signature: 1-of-3 becomes 1-of-2 plus one slot the
      // institution can never recover (S-4 §6.1).
      expect(vm.controller).toBe(result.did);
      expect(vm.id.startsWith(`${result.did}#`)).toBe(true);
    }

    // Exactly one authentication slot — forced by @cheqd/sdk, not chosen. All N
    // in `authentication` would make every patient enrolment N-of-N, which is
    // precisely the availability failure #276 picked 1-of-N to avoid.
    expect(onChain!.authentication).toEqual([`${result.did}${LEDGER_SIGNING_FRAGMENT}`]);
    // But every officer can ISSUE. Relationship membership is irrelevant to
    // x/did authorisation anyway (S-4 M4/M5).
    expect(onChain!.assertionMethod).toHaveLength(3);
  }, 180_000);
});

// ---------------------------------------------------------------------------

describe('the VM set is repairable in place — S-4 R1, and this is the migration path', () => {
  it('grows a 1-of-1 institution into 1-of-2 without re-issuing it', async () => {
    // This is the case that matters for institutions already issued: unlike the
    // controller set, the verification-method set can be repaired while at
    // least one key still lives (R1, height 86534).
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }],
      purpose: 'live suite: a deliberately 1-of-1 institution, to be grown',
    });
    expect((await resolveOnChain(agent, created.did))!.verificationMethod).toHaveLength(1);

    const grown = await addInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      key: { kind: 'agent-generated' },
      reason: 'live suite: grow 1-of-1 to 1-of-2 (S-4 R1)',
    });

    const onChain = await resolveOnChain(agent, created.did);
    expect(onChain!.verificationMethod).toHaveLength(2);
    expect(onChain!.did).toBe(created.did); // Same identifier. Nothing was re-issued.
    expect(grown.signedBy).toBe(`${created.did}${LEDGER_SIGNING_FRAGMENT}`);
    for (const vm of onChain!.verificationMethod) expect(vm.controller).toBe(created.did);
  }, 180_000);
});

// ---------------------------------------------------------------------------

describe('1-of-N: any surviving officer acts alone', () => {
  it('rotates one officer key signed by a SIBLING — the key being replaced signs nothing', async () => {
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: sibling rotation',
    });

    const before = await resolveOnChain(agent, created.did);
    const doomed = before!.verificationMethod.find(
      (vm) => fragmentOf(vm.id) === '#key-officer-2',
    )!;

    const rotated = await rotateInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      fragment: '#key-officer-2',
      reason: 'live suite: simulate a lost officer key',
    });

    // The signature came from officer-1, not from the key being replaced. That
    // is the entire content of S-4 M1 and of the 1-of-N ruling.
    expect(rotated.signedBy).toBe(`${created.did}${LEDGER_SIGNING_FRAGMENT}`);

    const after = await resolveOnChain(agent, created.did);
    const replaced = after!.verificationMethod.find(
      (vm) => fragmentOf(vm.id) === '#key-officer-2',
    )!;
    expect(replaced.publicKeyMultibase).not.toBe(doomed.publicKeyMultibase);
    expect(JSON.stringify(after!.verificationMethod)).not.toContain(doomed.publicKeyMultibase);
    expect(replaced.controller).toBe(created.did);
  }, 180_000);

  it('rotates the LEDGER SIGNING SLOT itself via the X2 co-signature', async () => {
    // The one slot a sibling cannot rescue, and the reason is the client
    // library rather than the chain: @cheqd/sdk's key-rotation validator
    // computes its required set from `authentication` on BOTH document
    // versions, so rotating that slot demands a signature under the same VM id
    // from the outgoing AND the incoming key. That is S-4 X2 (height 86331),
    // and it is only possible while the outgoing key still lives — which is why
    // this slot is always agent-held and can never be retired, only rotated.
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: signing-slot rotation',
    });
    const before = await resolveOnChain(agent, created.did);
    const outgoing = before!.verificationMethod.find(
      (vm) => fragmentOf(vm.id) === LEDGER_SIGNING_FRAGMENT,
    )!;

    await rotateInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      fragment: LEDGER_SIGNING_FRAGMENT,
      reason: 'live suite: rotate the signing officer while their key still works',
    });

    const after = await resolveOnChain(agent, created.did);
    const incoming = after!.verificationMethod.find(
      (vm) => fragmentOf(vm.id) === LEDGER_SIGNING_FRAGMENT,
    )!;
    expect(incoming.publicKeyMultibase).not.toBe(outgoing.publicKeyMultibase);
    expect(incoming.controller).toBe(created.did);
    expect(after!.authentication).toEqual([`${created.did}${LEDGER_SIGNING_FRAGMENT}`]);

    // The new key must actually be usable, or the rotation swapped the document
    // into a state this agent can no longer act on.
    const grown = await addInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      key: { kind: 'agent-generated' },
      reason: 'live suite: prove the rotated signing key still signs',
    });
    expect(grown.slots).toHaveLength(3);
  }, 180_000);

  it('refuses to rotate the signing slot to a key it does not hold', async () => {
    // A hardware-token replacement cannot co-sign from this process, and a
    // rotation missing the incoming signature is rejected by the SDK before
    // broadcast — better to say so than to consume a block finding out.
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: signing-slot rotation guard',
    });

    await expect(
      rotateInstitutionalOfficerKey(agent, {
        institutionalDid: created.did,
        fragment: LEDGER_SIGNING_FRAGMENT,
        nextPublicKeyMultibase: 'z6MkgX7vfgjbBdY6YTnxMX2hwk3oThMKP5qT6Seg8bUwq3HC',
        reason: 'live suite: this must be refused',
      }),
    ).rejects.toBeInstanceOf(AppError);
  }, 180_000);

  it('retires a dead slot outright — it is gone, not shadowed (S-4 D2)', async () => {
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: retirement',
    });
    const before = await resolveOnChain(agent, created.did);
    const doomed = before!.verificationMethod.find(
      (vm) => fragmentOf(vm.id) === '#key-officer-2',
    )!;

    await retireInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      fragment: '#key-officer-2',
      reason: 'live suite: retire a compromised officer',
    });

    const after = await resolveOnChain(agent, created.did);
    expect(after!.verificationMethod).toHaveLength(1);
    expect(JSON.stringify(after!.verificationMethod)).not.toContain(doomed.publicKeyMultibase);
  }, 180_000);

  it('refuses to retire the last remaining key', async () => {
    // #291: after such an eviction the institution holds no key at all, and
    // "remediable by rotation" is unavailable because rotation needs a key.
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }],
      purpose: 'live suite: last-key guard',
    });

    await expect(
      retireInstitutionalOfficerKey(agent, {
        institutionalDid: created.did,
        fragment: LEDGER_SIGNING_FRAGMENT,
        reason: 'live suite: this must be refused',
      }),
    ).rejects.toBeInstanceOf(AppError);

    expect((await resolveOnChain(agent, created.did))!.verificationMethod).toHaveLength(1);
  }, 180_000);
});

// ---------------------------------------------------------------------------

describe('the wrong shape cannot be reached through this API', () => {
  it('offers no way to name a foreign controller for a slot', async () => {
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
      purpose: 'live suite: shape is not a parameter',
    });

    // There is no `controller` argument on any function in the module, so the
    // only thing to assert is the outcome: every slot, however it got there,
    // names the institution. This is the runtime half of the property; the
    // compile-time half is that `assertInstitutionalShape` would refuse.
    const onChain = await resolveOnChain(agent, created.did);
    for (const vm of onChain!.verificationMethod) expect(vm.controller).toBe(created.did);

    const audit = await describeInstitutionalCustody(agent, created.did);
    expect(audit.selfControlled).toBe(true);
    expect(audit.foreignControlledSlots).toEqual([]);
    expect(audit.slotsOutsideNamespace).toEqual([]);
    expect(audit.n).toBe(2);
    // Every slot is held here, so no "this key is the whole institution" finding.
    expect(audit.findings).toEqual([]);
  }, 180_000);

  it('refuses an imported key without the acknowledgement, and flags it when given', async () => {
    const created = await provisionInstitutionalDid(agent, {
      officers: [{ kind: 'agent-generated' }],
      purpose: 'live suite: foreign key import',
    });

    await expect(
      addInstitutionalOfficerKey(agent, {
        institutionalDid: created.did,
        key: {
          kind: 'imported',
          publicKeyMultibase: 'z6MkgX7vfgjbBdY6YTnxMX2hwk3oThMKP5qT6Seg8bUwq3HC',
          acknowledgement: 'nope' as never,
          custodian: 'Officer Two',
        },
        reason: 'live suite: this must be refused',
      }),
    ).rejects.toBeInstanceOf(AppError);

    // With the acknowledgement it is permitted — the point is that it is
    // deliberate and attributed, not that it is forbidden. #277's hardware
    // tokens are exactly this shape.
    await addInstitutionalOfficerKey(agent, {
      institutionalDid: created.did,
      key: {
        kind: 'imported',
        publicKeyMultibase: 'z6MkgX7vfgjbBdY6YTnxMX2hwk3oThMKP5qT6Seg8bUwq3HC',
        acknowledgement: ACKNOWLEDGE_FOREIGN_HELD_INSTITUTIONAL_KEY,
        custodian: 'Officer Two (hardware token, live suite)',
      },
      reason: 'live suite: import a foreign-held officer key',
    });

    const audit = await describeInstitutionalCustody(agent, created.did);
    expect(audit.n).toBe(2);
    // Still self-controlled: importing key MATERIAL never changes the
    // `controller` field. But the custody finding must be raised, because by
    // S-4 V2 that key is authorised as the whole institution.
    expect(audit.foreignControlledSlots).toEqual([]);
    expect(audit.slotsThisAgentHolds).toHaveLength(1);
    expect(audit.findings.join(' ')).toMatch(/slots are keys this agent does not hold/);
  }, 180_000);
});
