/**
 * R5 — CLASSIFYING WHAT A `MsgUpdateDidDoc` ACTUALLY DID.
 *
 * The message states the document AFTER the change and says nothing about what
 * was there before, so "an officer was evicted" is only visible by comparing
 * against the watcher's running picture. Two ways to get this wrong, both
 * tested here:
 *
 *   - A transaction that removes one slot and adds another is an EVICTION. Any
 *     classifier that checks additions first files it as growth, and the
 *     alarm that mattered never fires.
 *
 *   - A DID whose prior state was never observed cannot be said to have lost
 *     anything. Guessing there would manufacture evictions out of every first
 *     sighting and train an operator to ignore the channel.
 *
 * The transaction-hash property is checked against a real, historical block:
 * S-4's H1 eviction at height 86424. If the hash function drifts, the watcher
 * silently stops being able to read delivery codes.
 */
import { describe, expect, it } from 'vitest';

import {
  classifyDidChange,
  cometTxHash,
  decodeDidMessagesInTx,
  MSG_DEACTIVATE_DID_DOC,
  MSG_UPDATE_DID_DOC,
  verificationMethodDigestOf,
  type DecodedDidMessage,
  type KnownDidState,
} from '../../src/services/custody/didTxDecode.js';

const DID = 'did:cheqd:bdhealthtestnet:07ec2e82-832f-4708-a44c-c703441830c1';

function slot(fragment: string, key: string) {
  return {
    id: `${DID}${fragment}`,
    controller: DID,
    publicKeyMultibase: key,
    type: 'Ed25519VerificationKey2020',
  };
}

function stateOf(slots: readonly { id: string; publicKeyMultibase: string }[]): KnownDidState {
  return {
    verificationMethodIds: slots.map((s) => s.id),
    verificationMethodDigest: verificationMethodDigestOf(slots),
    controllers: [DID],
  };
}

function update(slots: readonly ReturnType<typeof slot>[]): DecodedDidMessage {
  return {
    txHash: 'DEADBEEF',
    msgIndex: 0,
    typeUrl: MSG_UPDATE_DID_DOC,
    subjectDid: DID,
    versionId: 'version-1',
    signerVerificationMethodIds: [`${DID}#key-officer-1`],
    controllers: [DID],
    verificationMethods: slots,
    authentication: [`${DID}#key-officer-1`],
    assertionMethod: slots.map((s) => s.id),
  };
}

const ONE = slot('#key-officer-1', 'zOne');
const TWO = slot('#key-officer-2', 'zTwo');
const THREE = slot('#key-officer-3', 'zThree');

// ---------------------------------------------------------------------------

describe('eviction — the case the alarm exists for (S-4 H1)', () => {
  it('reads a removed slot as an eviction and names it', () => {
    const change = classifyDidChange(update([ONE]), stateOf([ONE, TWO]));
    expect(change.kind).toBe('eviction');
    expect(change.removedVerificationMethodIds).toEqual([TWO.id]);
  });

  it('reads remove-plus-add as an EVICTION, not as an addition', () => {
    // The precedence that matters. An attacker swapping a sibling for their own
    // key in one transaction must not be filed as the institution growing.
    const change = classifyDidChange(update([ONE, THREE]), stateOf([ONE, TWO]));
    expect(change.kind).toBe('eviction');
    expect(change.removedVerificationMethodIds).toEqual([TWO.id]);
    expect(change.addedVerificationMethodIds).toEqual([THREE.id]);
  });

  it('reads a deactivation as a deactivation whatever the payload carries', () => {
    const message: DecodedDidMessage = {
      ...update([]),
      typeUrl: MSG_DEACTIVATE_DID_DOC,
    };
    const change = classifyDidChange(message, stateOf([ONE, TWO]));
    expect(change.kind).toBe('deactivation');
    // Everything is gone, and the alarm should say which keys that was.
    expect(change.removedVerificationMethodIds).toEqual([ONE.id, TWO.id]);
  });
});

describe('routine change', () => {
  it('reads a same-slot key swap as a rotation', () => {
    const rotated = slot('#key-officer-2', 'zTwoRotated');
    const change = classifyDidChange(update([ONE, rotated]), stateOf([ONE, TWO]));
    expect(change.kind).toBe('rotation');
    expect(change.removedVerificationMethodIds).toEqual([]);
    expect(change.rotatedVerificationMethodIds).toContain(ONE.id);
  });

  it('reads a new slot as an addition', () => {
    const change = classifyDidChange(update([ONE, TWO, THREE]), stateOf([ONE, TWO]));
    expect(change.kind).toBe('addition');
    expect(change.addedVerificationMethodIds).toEqual([THREE.id]);
  });

  it('reads an unchanged key set as no key change', () => {
    const change = classifyDidChange(update([ONE, TWO]), stateOf([ONE, TWO]));
    expect(change.kind).toBe('no-key-change');
  });
});

describe('controller changes outrank everything except removal', () => {
  it('flags a controller change even when the keys are untouched', () => {
    const message = { ...update([ONE, TWO]), controllers: ['did:cheqd:bdhealthtestnet:someone'] };
    const change = classifyDidChange(message, stateOf([ONE, TWO]));
    expect(change.kind).toBe('controller-change');
    expect(change.controllersAfter).toEqual(['did:cheqd:bdhealthtestnet:someone']);
  });

  it('still reports eviction when a controller change accompanies a removal', () => {
    const message = { ...update([ONE]), controllers: ['did:cheqd:bdhealthtestnet:someone'] };
    expect(classifyDidChange(message, stateOf([ONE, TWO])).kind).toBe('eviction');
  });
});

describe('a DID whose prior state was never observed', () => {
  it('degrades honestly instead of inventing a removal', () => {
    // The watcher has no picture, so it cannot know what was there. Reporting
    // "eviction" here would manufacture a CRITICAL alarm from ignorance.
    const change = classifyDidChange(update([ONE]), null);
    expect(change.kind).toBe('no-key-change');
    expect(change.removedVerificationMethodIds).toEqual([]);
  });
});

describe('the transaction hash the watcher uses to read delivery codes', () => {
  it('reproduces S-4 H1 at height 86424', () => {
    // Not a synthetic vector: this is the eviction S-4 measured. The watcher
    // computes this hash itself so it works with the tx indexer off, and
    // computing it wrong means every delivery-code lookup silently misses.
    const rawTx = Buffer.from(
      // The block's single transaction, as CometBFT serves it under
      // /block?height=86424 -> block.data.txs[0]. Hash is over these bytes.
      H1_TX_BASE64,
      'base64',
    );
    expect(cometTxHash(rawTx)).toBe(
      '67D682DEC77D7DF7ED5E1592E51B13F7FAA6B3F8DE9A6B7186AB07EF21A79DC0',
    );
  });

  it('decodes S-4 H1 out of the real bytes and calls it an eviction', () => {
    // End to end over a genuine adversarial transaction: one officer key alone
    // removing its sibling. Everything the alarm needs — the subject DID, the
    // surviving slot, and WHICH key signed — comes out of the chain's own
    // bytes rather than out of anything this backend recorded about itself.
    const { messages, decodeError } = decodeDidMessagesInTx(H1_TX_BASE64);
    expect(decodeError).toBeNull();
    expect(messages).toHaveLength(1);

    const [message] = messages;
    expect(message.typeUrl).toBe(MSG_UPDATE_DID_DOC);
    expect(message.subjectDid).toBe(DID);
    expect(message.signerVerificationMethodIds).toEqual([`${DID}#key-1`]);
    expect(message.verificationMethods.map((vm) => vm.id)).toEqual([`${DID}#key-1`]);

    const before = stateOf([
      { id: `${DID}#key-1`, publicKeyMultibase: 'zWhatever' },
      { id: `${DID}#key-2`, publicKeyMultibase: 'zSibling' },
    ]);
    const change = classifyDidChange(message, before);
    expect(change.kind).toBe('eviction');
    expect(change.removedVerificationMethodIds).toEqual([`${DID}#key-2`]);
  });

  it('digests the id→key map order-independently', () => {
    expect(verificationMethodDigestOf([ONE, TWO])).toBe(verificationMethodDigestOf([TWO, ONE]));
    expect(verificationMethodDigestOf([ONE, TWO])).not.toBe(
      verificationMethodDigestOf([ONE, slot('#key-officer-2', 'zDifferent')]),
    );
  });
});

/** Captured from bd-health-trust-1 block 86424 (S-4 H1). See the test above. */
const H1_TX_BASE64 =
  'CpQFCpEFCh0vY2hlcWQuZGlkLnYyLk1zZ1VwZGF0ZURpZERvYxLvBArhAwocaHR0cHM6Ly93d3cudzMub3JnL25zL2Rp' +
  'ZC92MRI+ZGlkOmNoZXFkOmJkaGVhbHRodGVzdG5ldDowN2VjMmU4Mi04MzJmLTQ3MDgtYTQ0Yy1jNzAzNDQxODMwYzEa' +
  'PmRpZDpjaGVxZDpiZGhlYWx0aHRlc3RuZXQ6MDdlYzJlODItODMyZi00NzA4LWE0NGMtYzcwMzQ0MTgzMGMxItQBCkRk' +
  'aWQ6Y2hlcWQ6YmRoZWFsdGh0ZXN0bmV0OjA3ZWMyZTgyLTgzMmYtNDcwOC1hNDRjLWM3MDM0NDE4MzBjMSNrZXktMRIa' +
  'RWQyNTUxOVZlcmlmaWNhdGlvbktleTIwMjAaPmRpZDpjaGVxZDpiZGhlYWx0aHRlc3RuZXQ6MDdlYzJlODItODMyZi00' +
  'NzA4LWE0NGMtYzcwMzQ0MTgzMGMxIjB6Nk1rblllZndDQmVRTVRMQXhGSmE3a0V4YnpmWG1ua1ZTMjc5MVRXVUZUcWRi' +
  'ZFAqRGRpZDpjaGVxZDpiZGhlYWx0aHRlc3RuZXQ6MDdlYzJlODItODMyZi00NzA4LWE0NGMtYzcwMzQ0MTgzMGMxI2tl' +
  'eS0xYiRiODM4ZTMxOS03NzQwLTQ1M2MtYjkzMy05M2M1N2I2OWNjNTESiAEKRGRpZDpjaGVxZDpiZGhlYWx0aHRlc3Ru' +
  'ZXQ6MDdlYzJlODItODMyZi00NzA4LWE0NGMtYzcwMzQ0MTgzMGMxI2tleS0xEkAPREPCenpMzH8aksxCd5Fn+rOIr3Yo' +
  'eSx/6mpq/35s/QDVPMNRK49FQQjBBcMeaJeTfIiZn2+Octi9mOREUKUIEoYBClAKRgofL2Nvc21vcy5jcnlwdG8uc2Vj' +
  'cDI1NmsxLlB1YktleRIjCiECY2jQYm0iDn+1pGN/2HKqUpWNVI5g1igZjyflvy/3JXoSBAoCCAEYNxIyEMDPJBosY2hl' +
  'cWQxZXF0NzVrODBzaDN3Y3F6a3IwN2sweW55eWRjNTA5MzI3NnR1ZGMaQJ3qB12aSub13EN4IUpZhQsHHmL4KC1UAOKa' +
  'PtFlrkF6eqBVvYFAYgRDTgOMk97UF+ZBE5FdrgQqkRK2D9FeUF8=';
