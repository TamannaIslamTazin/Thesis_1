/**
 * Tests the load-bearing invariants at the SQLite layer directly. Per the
 * brief: every refusal here is paired with a test proving the adjacent
 * success path is still reachable -- a store that always errors would pass
 * a suite made only of negative tests.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  VaultError,
  depositShare,
  erasePatient,
  eraseShare,
  getShare,
  listShares,
  openDatabase,
  registerPolicy,
} from './db.js';

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function freshDb() {
  return openDatabase(':memory:');
}

function shareInput(did: string, index: number, ciphertext = `ct-${index}`) {
  return { recoveryControllerDid: did, index, nonce: `nonce-${index}`, ciphertext, contentHash: sha256Hex(ciphertext) };
}

// --- policy -----------------------------------------------------------------

test('registerPolicy: success path stores the threshold', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:rck-1', 3);
  // No direct getter for policy; proven indirectly via a share deposit succeeding.
  const result = depositShare(db, shareInput('did:cheqd:test:rck-1', 0));
  assert.equal(result.rewrapped, false);
});

test('registerPolicy: refuses threshold < 2', () => {
  const db = freshDb();
  assert.throws(() => registerPolicy(db, 'did:cheqd:test:rck-2', 1), (err) => {
    assert.ok(err instanceof VaultError);
    assert.equal(err.code, 'INVALID_THRESHOLD');
    return true;
  });
});

test('registerPolicy: idempotent re-registration with the SAME threshold succeeds', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:rck-3', 3);
  registerPolicy(db, 'did:cheqd:test:rck-3', 3); // must not throw
  assert.ok(true);
});

test('registerPolicy: refuses to change an already-registered threshold', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:rck-4', 3);
  assert.throws(() => registerPolicy(db, 'did:cheqd:test:rck-4', 5), (err) => {
    assert.ok(err instanceof VaultError);
    assert.equal(err.code, 'POLICY_IMMUTABLE');
    return true;
  });
});

// --- deposit: cap enforcement (amendment 1: ONE share, not threshold - 1) ---

test('depositShare: refuses without a registered policy (fail closed)', () => {
  const db = freshDb();
  assert.throws(() => depositShare(db, shareInput('did:cheqd:test:no-policy', 0)), (err) => {
    assert.ok(err instanceof VaultError);
    assert.equal(err.code, 'NO_POLICY');
    return true;
  });
});

test('depositShare: SUCCESS PATH -- first share for a patient is accepted', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:cap-1', 3);
  const result = depositShare(db, shareInput('did:cheqd:test:cap-1', 4)); // institution is index 4 in DEFAULT_GUARDIAN_POLICY
  assert.equal(result.rewrapped, false);
  const stored = getShare(db, 'did:cheqd:test:cap-1', 4);
  assert.equal(stored?.ciphertext, 'ct-4');
});

test('depositShare: a SECOND distinct slot is refused even though threshold=3 would allow two under the old (wrong) formula', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:cap-2', 3);
  depositShare(db, shareInput('did:cheqd:test:cap-2', 4));
  assert.throws(() => depositShare(db, shareInput('did:cheqd:test:cap-2', 0)), (err) => {
    assert.ok(err instanceof VaultError);
    assert.equal(err.code, 'SHARE_CAP_EXCEEDED');
    return true;
  });
  // Prove the cap is truly ONE regardless of threshold, not threshold - 1 = 2.
  assert.equal(listShares(db, 'did:cheqd:test:cap-2').length, 1);
});

test('depositShare: SUCCESS PATH -- rewrapping the EXISTING slot does not count against the cap', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:cap-3', 3);
  depositShare(db, shareInput('did:cheqd:test:cap-3', 4, 'ct-v1'));
  const result = depositShare(db, shareInput('did:cheqd:test:cap-3', 4, 'ct-v2'));
  assert.equal(result.rewrapped, true);
  assert.equal(listShares(db, 'did:cheqd:test:cap-3').length, 1);
  assert.equal(getShare(db, 'did:cheqd:test:cap-3', 4)?.ciphertext, 'ct-v2');
});

test('depositShare: a different patient is unaffected by another patient being at cap', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:cap-4a', 3);
  registerPolicy(db, 'did:cheqd:test:cap-4b', 3);
  depositShare(db, shareInput('did:cheqd:test:cap-4a', 4));
  const result = depositShare(db, shareInput('did:cheqd:test:cap-4b', 4)); // SUCCESS PATH
  assert.equal(result.rewrapped, false);
});

// --- deposit: content hash integrity (amendment 4) ---------------------------

test('depositShare: refuses a contentHash that does not match the ciphertext', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:hash-1', 3);
  assert.throws(
    () =>
      depositShare(db, {
        recoveryControllerDid: 'did:cheqd:test:hash-1',
        index: 4,
        nonce: 'n',
        ciphertext: 'real-ciphertext',
        contentHash: sha256Hex('a-different-string'),
      }),
    (err) => {
      assert.ok(err instanceof VaultError);
      assert.equal(err.code, 'CONTENT_HASH_MISMATCH');
      return true;
    },
  );
});

// --- erasure: single share ----------------------------------------------------

test('eraseShare: SUCCESS PATH -- deletes the row and returns a receipt', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:erase-1', 3);
  depositShare(db, shareInput('did:cheqd:test:erase-1', 4));

  const receipt = eraseShare(db, {
    recoveryControllerDid: 'did:cheqd:test:erase-1',
    index: 4,
    deletedByActorRef: 'test-actor',
    reason: 'PATIENT_REQUEST',
    pepperKey: 'pepper',
  });

  assert.equal(receipt.index, 4);
  assert.equal(getShare(db, 'did:cheqd:test:erase-1', 4), undefined);
});

test('eraseShare: 404s on a slot that was never stored', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:erase-2', 3);
  assert.throws(
    () =>
      eraseShare(db, {
        recoveryControllerDid: 'did:cheqd:test:erase-2',
        index: 4,
        deletedByActorRef: 'test-actor',
        reason: 'x',
        pepperKey: 'pepper',
      }),
    (err) => {
      assert.ok(err instanceof VaultError);
      assert.equal(err.code, 'SHARE_NOT_FOUND');
      return true;
    },
  );
});

test('eraseShare: after erasure, the slot is deposit-able again (cap freed, not permanently exhausted)', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:erase-3', 3);
  depositShare(db, shareInput('did:cheqd:test:erase-3', 4));
  eraseShare(db, {
    recoveryControllerDid: 'did:cheqd:test:erase-3',
    index: 4,
    deletedByActorRef: 'a',
    reason: 'r',
    pepperKey: 'pepper',
  });
  const result = depositShare(db, shareInput('did:cheqd:test:erase-3', 4, 'ct-new')); // SUCCESS PATH
  assert.equal(result.rewrapped, false);
});

// --- erasure receipts: immutability and pseudonymisation (amendment 3) -------

test('erasure_receipts: raw DID is NOT stored -- subject_ref is an HMAC, not the plaintext DID', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:pseudo-1', 3);
  depositShare(db, shareInput('did:cheqd:test:pseudo-1', 4));
  eraseShare(db, {
    recoveryControllerDid: 'did:cheqd:test:pseudo-1',
    index: 4,
    deletedByActorRef: 'a',
    reason: 'r',
    pepperKey: 'pepper-key-value',
  });
  const row = db.prepare('SELECT subject_ref FROM erasure_receipts').get() as { subject_ref: string };
  assert.notEqual(row.subject_ref, 'did:cheqd:test:pseudo-1');
  assert.equal(row.subject_ref.length, 64); // hex sha256/hmac-sha256 digest
});

test('erasure_receipts: the SAME DID with a DIFFERENT pepper key produces a DIFFERENT subject_ref (proves it is keyed, not a bare hash)', () => {
  const dbA = freshDb();
  registerPolicy(dbA, 'did:cheqd:test:pseudo-2', 3);
  depositShare(dbA, shareInput('did:cheqd:test:pseudo-2', 4));
  eraseShare(dbA, { recoveryControllerDid: 'did:cheqd:test:pseudo-2', index: 4, deletedByActorRef: 'a', reason: 'r', pepperKey: 'pepper-A' });
  const refA = (dbA.prepare('SELECT subject_ref FROM erasure_receipts').get() as { subject_ref: string }).subject_ref;

  const dbB = freshDb();
  registerPolicy(dbB, 'did:cheqd:test:pseudo-2', 3);
  depositShare(dbB, shareInput('did:cheqd:test:pseudo-2', 4));
  eraseShare(dbB, { recoveryControllerDid: 'did:cheqd:test:pseudo-2', index: 4, deletedByActorRef: 'a', reason: 'r', pepperKey: 'pepper-B' });
  const refB = (dbB.prepare('SELECT subject_ref FROM erasure_receipts').get() as { subject_ref: string }).subject_ref;

  assert.notEqual(refA, refB);
});

test('erasure_receipts: UPDATE is refused -- the residue record is truly immutable', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:immut-1', 3);
  depositShare(db, shareInput('did:cheqd:test:immut-1', 4));
  eraseShare(db, { recoveryControllerDid: 'did:cheqd:test:immut-1', index: 4, deletedByActorRef: 'a', reason: 'r', pepperKey: 'p' });

  assert.throws(() => db.exec("UPDATE erasure_receipts SET reason = 'tampered'"));
});

test('erasure_receipts: DELETE is refused -- cannot be erased even by the operator', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:immut-2', 3);
  depositShare(db, shareInput('did:cheqd:test:immut-2', 4));
  eraseShare(db, { recoveryControllerDid: 'did:cheqd:test:immut-2', index: 4, deletedByActorRef: 'a', reason: 'r', pepperKey: 'p' });

  assert.throws(() => db.exec('DELETE FROM erasure_receipts'));
  // SUCCESS PATH proof this isn't just "the table is broken": SELECT still works.
  const count = db.prepare('SELECT COUNT(*) as c FROM erasure_receipts').get() as { c: number };
  assert.equal(count.c, 1);
});

// --- full-patient erasure ------------------------------------------------------

test('erasePatient: SUCCESS PATH -- removes the share and the policy row, one receipt per share', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:full-1', 3);
  depositShare(db, shareInput('did:cheqd:test:full-1', 4));

  const receipts = erasePatient(db, {
    recoveryControllerDid: 'did:cheqd:test:full-1',
    deletedByActorRef: 'admin',
    reason: 'ACCOUNT_DELETION',
    pepperKey: 'p',
  });

  assert.equal(receipts.length, 1);
  assert.equal(listShares(db, 'did:cheqd:test:full-1').length, 0);
  // Policy gone too -- depositing again requires a fresh policy registration.
  assert.throws(() => depositShare(db, shareInput('did:cheqd:test:full-1', 4)), (err) => {
    assert.ok(err instanceof VaultError);
    assert.equal(err.code, 'NO_POLICY');
    return true;
  });
});

test('erasePatient: on a patient with no shares stored, returns an empty list without error (SUCCESS PATH, not a refusal)', () => {
  const db = freshDb();
  registerPolicy(db, 'did:cheqd:test:full-2', 3);
  const receipts = erasePatient(db, {
    recoveryControllerDid: 'did:cheqd:test:full-2',
    deletedByActorRef: 'admin',
    reason: 'ACCOUNT_DELETION',
    pepperKey: 'p',
  });
  assert.deepEqual(receipts, []);
});
