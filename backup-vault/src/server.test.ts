/**
 * HTTP-layer tests: the wire contract, auth, and that a real request round
 * trip exercises store -> retrieve -> erase, not just the db.ts functions
 * directly. Each refusal is paired with the adjacent success path.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { openDatabase } from './db.js';
import { createVaultServer } from './server.js';

const SECRET = 'test-shared-secret';
const PEPPER = 'test-pepper-key';

async function withServer(fn: (baseUrl: string) => Promise<void>): Promise<void> {
  const db = openDatabase(':memory:');
  const server = createVaultServer(db, SECRET, PEPPER);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
  }
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

async function asJson<T = Record<string, any>>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

const AUTH = { Authorization: `Bearer ${SECRET}` };

test('GET /healthz requires no auth and reports ok (SUCCESS PATH)', async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/healthz`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { status: 'ok' });
  });
});

test('requests without a bearer token are refused with 401', async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/v1/patients/did:cheqd:test:x/shares`);
    assert.equal(res.status, 401);
  });
});

test('requests with the WRONG bearer token are refused with 401', async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/v1/patients/did:cheqd:test:x/shares`, {
      headers: { Authorization: 'Bearer not-the-secret' },
    });
    assert.equal(res.status, 401);
  });
});

test('SUCCESS PATH: full round trip -- register policy, deposit, retrieve, list, erase', async () => {
  await withServer(async (base) => {
    const did = 'did:cheqd:test:roundtrip';

    const policyRes = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/policy`, {
      method: 'POST',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ threshold: 3 }),
    });
    assert.equal(policyRes.status, 204);

    const ciphertext = 'ciphertext-bytes-base64url';
    const depositRes = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares/4`, {
      method: 'PUT',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce: 'abc', ciphertext, contentHash: sha256Hex(ciphertext) }),
    });
    assert.equal(depositRes.status, 201);
    assert.deepEqual(await depositRes.json(), { rewrapped: false });

    const getRes = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares/4`, { headers: AUTH });
    assert.equal(getRes.status, 200);
    const got = await asJson<{ ciphertext: string; nonce: string }>(getRes);
    assert.equal(got.ciphertext, ciphertext);
    assert.equal(got.nonce, 'abc');

    const listRes = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares`, { headers: AUTH });
    assert.equal(listRes.status, 200);
    const listed = await asJson<{ shares: Array<{ index: number }> }>(listRes);
    assert.equal(listed.shares.length, 1);
    assert.equal(listed.shares[0].index, 4);

    const eraseRes = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares/4`, {
      method: 'DELETE',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ deletedByActorRef: 'test-suite', reason: 'PATIENT_REQUEST' }),
    });
    assert.equal(eraseRes.status, 200);
    const receipt = await asJson<{ index: number; id: string }>(eraseRes);
    assert.equal(receipt.index, 4);
    assert.ok(receipt.id);

    const getAfterErase = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares/4`, { headers: AUTH });
    assert.equal(getAfterErase.status, 404);
  });
});

test('below-threshold cap refuses a second slot over HTTP, and the first slot is unaffected', async () => {
  await withServer(async (base) => {
    const did = 'did:cheqd:test:http-cap';
    await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/policy`, {
      method: 'POST',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ threshold: 3 }),
    });
    const ct0 = 'ct-0';
    await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares/4`, {
      method: 'PUT',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce: 'n', ciphertext: ct0, contentHash: sha256Hex(ct0) }),
    });

    const ct1 = 'ct-1';
    const second = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares/0`, {
      method: 'PUT',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce: 'n', ciphertext: ct1, contentHash: sha256Hex(ct1) }),
    });
    assert.equal(second.status, 409);
    const body = await asJson<{ code: string }>(second);
    assert.equal(body.code, 'SHARE_CAP_EXCEEDED');

    // SUCCESS PATH still reachable: the original slot is still there and gettable.
    const stillThere = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares/4`, { headers: AUTH });
    assert.equal(stillThere.status, 200);
  });
});

test('contentHash mismatch is refused with 400 over HTTP', async () => {
  await withServer(async (base) => {
    const did = 'did:cheqd:test:http-hash';
    await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/policy`, {
      method: 'POST',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ threshold: 3 }),
    });
    const res = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares/4`, {
      method: 'PUT',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce: 'n', ciphertext: 'real', contentHash: sha256Hex('wrong') }),
    });
    assert.equal(res.status, 400);
    assert.equal((await asJson<{ code: string }>(res)).code, 'CONTENT_HASH_MISMATCH');
  });
});

test('full-patient DELETE erases every slot and returns receipts (SUCCESS PATH)', async () => {
  await withServer(async (base) => {
    const did = 'did:cheqd:test:http-full';
    await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/policy`, {
      method: 'POST',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ threshold: 3 }),
    });
    const ct = 'ct';
    await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares/4`, {
      method: 'PUT',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce: 'n', ciphertext: ct, contentHash: sha256Hex(ct) }),
    });

    const res = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}`, {
      method: 'DELETE',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ deletedByActorRef: 'test-suite', reason: 'ACCOUNT_DELETION' }),
    });
    assert.equal(res.status, 200);
    const body = await asJson<{ receipts: unknown[] }>(res);
    assert.equal(body.receipts.length, 1);

    const list = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/shares`, { headers: AUTH });
    assert.deepEqual(await list.json(), { shares: [] });
  });
});

test('an oversized body is refused with 413', async () => {
  await withServer(async (base) => {
    const did = 'did:cheqd:test:http-big';
    const res = await fetch(`${base}/v1/patients/${encodeURIComponent(did)}/policy`, {
      method: 'POST',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ threshold: 3, padding: 'x'.repeat(100_000) }),
    });
    assert.equal(res.status, 413);
  });
});
