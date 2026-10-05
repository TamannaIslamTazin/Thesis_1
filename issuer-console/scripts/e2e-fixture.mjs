/**
 * Live end-to-end wiring for the L1 issuer console, against RUNNING
 * containers and the running backend — not a unit test. Modelled on
 * packages/locker/scripts/verify-locker.mjs (same stub-resolver technique,
 * same "real Ed25519 keys against a controllable resolver" approach).
 *
 * What this proves for real:
 *   - a holder DID and an authority (institution) DID both resolve through
 *     the stub resolver with real Ed25519 keys
 *   - the holder authenticates to the locker datastore via DID
 *     challenge-response and stores a real AES-256-GCM-encrypted object
 *   - the holder mints a locker capability the same way the wallet will
 *     (packages/shared/src/capability, mintLockerCapability — not
 *     reimplemented here)
 *   - a real issuance request is filed through POST /api/issuance/requests
 *     carrying that object's real locker reference and a placeholder
 *     wrappedContentKey (see __docs__/backend/CONTENT-KEY-ENVELOPE-GAP.md
 *     for why it is a placeholder, not a real wrap)
 *   - an officer session is attached to the L1 ministry institution's
 *     roster and can see the request in GET /api/authority/queue
 *
 * What it deliberately bypasses, and why:
 *   - Officer/holder sessions are inserted directly into Postgres rather
 *     than completed through the real email/OTP screens. SMTP in this
 *     deployment's .env points at a real Gmail account this agent cannot
 *     read; the login SCREEN and the two endpoints it calls are exercised
 *     separately (see the round report). This script only needs a valid
 *     session to reach the endpoints past that gate.
 *   - The holder's wallet does not exist yet (round 5), so this script
 *     plays the wallet's part for minting the capability and wrapping the
 *     content key, exactly as the round brief asks for.
 *
 * Usage: node scripts/e2e-fixture.mjs
 * Requires: the chain+backend (../../../scripts/awaken.sh up) and the
 * locker stack (packages/locker: docker compose up -d, plus
 * `docker start bdht-stub-resolver`) already running.
 */

import { execSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';
import {
  mintLockerCapability,
  encryptLockerObject,
  wrapContentKey,
  bytesToBase64Url,
  base64UrlToBytes,
  MINISTRY_OF_HEALTH,
} from '@ssi-healthcare/shared';

const BACKEND = 'http://localhost:3001';
const DATASTORE = 'http://127.0.0.1:4540';
const STUB_RESOLVER = 'http://127.0.0.1:4599';
const BACKEND_ENV_PATH = new URL('../../backend/.env', import.meta.url).pathname;

const MOHFW_DID = 'did:cheqd:bdhealthtestnet:00000000-0000-4000-8000-000000000000';
const MOHFW_INSTITUTION_ID = 'l1-mohfw';

const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

function sh(cmd) {
  return execSync(cmd, { encoding: 'utf8' }).trim();
}

function psql(sql) {
  return sh(`PGPASSWORD=postgres psql -h localhost -U postgres -d ssi_healthcare -t -A -c ${JSON.stringify(sql)}`);
}

function keypairFor(did, privateKey, publicKey) {
  const vmId = `${did}#key-1`;
  const multicodec = new Uint8Array([0xed, 0x01, ...publicKey]);
  const publicKeyMultibase = `z${base58.encode(multicodec)}`;
  return { did, vmId, privateKey, publicKey, publicKeyMultibase };
}

function newSubject() {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  const did = `did:cheqd:bdhealthtestnet:${randomUUID()}`;
  return keypairFor(did, privateKey, publicKey);
}

async function pushSubject(subject) {
  // Real cheqd Cosmos LCD REST shape (round 5's packages/locker/src/didResolver.ts
  // fix, found while verifying the wallet-custody broker against a real
  // on-chain DID) — snake_case, wrapped in `value`, not the W3C `didDocument`
  // shape this fixture used to send to the stub resolver.
  const document = {
    value: {
      did_doc: {
        id: subject.did,
        verification_method: [
          { id: subject.vmId, verification_method_type: 'Ed25519VerificationKey2020', controller: subject.did, verification_material: subject.publicKeyMultibase },
        ],
        authentication: [subject.vmId],
      },
      metadata: { deactivated: false },
    },
  };
  await fetch(`${STUB_RESOLVER}/_control/subjects`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did: subject.did, document }),
  });
}

function signAuth(subject, { audience, nonce, iat }) {
  const canonical = `bdhealthtrust/locker-auth/v1\naud:${audience}\ndid:${subject.did}\nnonce:${nonce}\niat:${iat}\n`;
  const signature = ed25519.sign(new TextEncoder().encode(canonical), subject.privateKey);
  return Buffer.from(signature).toString('base64url');
}

async function authenticateToLocker(subject) {
  const challengeRes = await fetch(`${DATASTORE}/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did: subject.did }),
  });
  const challenge = await challengeRes.json();
  const iat = Math.floor(Date.now() / 1000);
  const signature = signAuth(subject, { audience: challenge.audience, nonce: challenge.nonce, iat });
  const tokenRes = await fetch(`${DATASTORE}/v1/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nonce: challenge.nonce, signature, verificationMethodId: subject.vmId, iat }),
  });
  if (!tokenRes.ok) throw new Error(`locker auth failed: ${tokenRes.status} ${await tokenRes.text()}`);
  const { token } = await tokenRes.json();
  return token;
}

function provisionSession(email, { did, walletSetup } = {}) {
  const existing = psql(`SELECT id FROM "User" WHERE email = '${email}'`);
  let userId = existing;
  if (!userId) {
    userId = `usr${randomUUID().replace(/-/g, '').slice(0, 20)}`;
    const didClause = did ? `'${did}'` : 'NULL';
    psql(
      `INSERT INTO "User" (id, email, "firstName", "lastName", did, "walletSetup", "updatedAt") ` +
        `VALUES ('${userId}', '${email}', 'Fixture', 'User', ${didClause}, ${walletSetup ? 'true' : 'false'}, now())`,
    );
  } else if (did) {
    psql(`UPDATE "User" SET did = '${did}', "walletSetup" = true WHERE id = '${userId}'`);
  }

  const tokenBytes = new Uint8Array(32);
  crypto.getRandomValues(tokenBytes);
  const token = bytesToBase64Url(tokenBytes);
  const tokenHash = sha256Hex(Buffer.from(token, 'utf8'));
  const sessionId = `ses${randomUUID().replace(/-/g, '').slice(0, 20)}`;
  psql(
    `INSERT INTO "Session" (id, "userId", token, status, "expiresAt") ` +
      `VALUES ('${sessionId}', '${userId}', '${tokenHash}', 'ACTIVE', now() + interval '2 hours')`,
  );
  return { userId, token };
}

async function api(path, { token, method = 'GET', body, headers = {} } = {}) {
  const res = await fetch(`${BACKEND}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, json };
}

async function main() {
  console.log('== 1. holder + authority DIDs, registered in the stub resolver ==');
  const holder = newSubject();
  await pushSubject(holder);
  console.log('holder DID:', holder.did);

  // Fixed, not random: every rerun of this script must re-register the SAME
  // authority key with the stub resolver, or a console already running with
  // ISSUER_LOCKER_SIGNING_SEED from an earlier run would sign with a key the
  // resolver no longer has on file for this DID.
  const authorityPrivateKey = Buffer.from(
    '4h4QUsGqMyzvqJV2t5MGvorNBl-0_kJcJe0fjfe10ME',
    'base64url',
  );
  const authorityPublicKey = ed25519.getPublicKey(authorityPrivateKey);
  const authority = keypairFor(MOHFW_DID, authorityPrivateKey, authorityPublicKey);
  await pushSubject(authority);
  console.log('authority DID (MOHFW, pinned):', authority.did);

  console.log('\n== 2. holder stores a real encrypted document in the locker ==');
  const holderLockerToken = await authenticateToLocker(holder);
  const objectId = `health-card-nid-scan-${randomUUID()}`;
  const contentKey = new Uint8Array(32);
  crypto.getRandomValues(contentKey);
  const plaintext = new TextEncoder().encode('NID SCAN — fixture bytes standing in for a real document image.');
  // Round 5's real framing (@ssi-healthcare/shared crypto/lockerObjectCipher.ts),
  // not the round-4 placeholder this script used to call directly.
  const objectBytes = encryptLockerObject(objectId, contentKey, plaintext);

  const put = await fetch(`${DATASTORE}/v1/objects/${objectId}`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${holderLockerToken}`, 'X-Locker-Object-Hash': sha256Hex(objectBytes) },
    body: objectBytes,
  });
  console.log('object stored:', put.status);
  if (put.status !== 201) throw new Error(`object store failed: ${put.status} ${await put.text()}`);

  // Round 5: the request id is minted BY THE WALLET, before the request
  // exists server-side, because both the capability's `sub` and the wrapped
  // key's AAD need something to bind to. 16 random bytes, same construction
  // as the capability's own `jti` (mintLockerCapability's generateJti).
  const requestId = `req_${Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url')}`;

  console.log('\n== 3. holder mints a locker capability the same way the wallet will ==');
  const capability = await mintLockerCapability({
    holderDid: holder.did,
    authorityDid: authority.did,
    objectIds: [objectId],
    issuanceRequestId: requestId,
    verificationMethodId: holder.vmId,
    validitySeconds: 3600,
    sign: (payload) => ed25519.sign(payload, holder.privateKey),
  });
  console.log('capability minted, jti:', capability.claims.jti);

  console.log('\n== 3b. holder wraps the content key to the authority\'s REAL X25519 public key ==');
  // MINISTRY_OF_HEALTH.contentKeyPublicKey is the pinned public half of
  // ISSUER_CONTENT_KEY_X25519_SEED (packages/issuer-console/.env.local) —
  // round 5's decided ECIES scheme, not the round-4 raw pass-through.
  const wrappedContentKey = wrapContentKey({
    recipientPublicKey: base64UrlToBytes(MINISTRY_OF_HEALTH.contentKeyPublicKey),
    contentKey,
    wrappedToVerificationMethodId: authority.vmId,
    issuanceRequestId: requestId,
  });

  console.log('\n== 4. holder + officer sessions, provisioned directly (see script header) ==');
  const holderSession = provisionSession('fixture-holder@bdhealthtrust.test', { did: holder.did, walletSetup: true });
  const officerSession = provisionSession('fixture-officer@bdhealthtrust.test');
  console.log('holder session token:', holderSession.token);
  console.log('officer session token:', officerSession.token);

  console.log('\n== 5. put the officer on the MOHFW roster ==');
  const activeAdminCount = Number(
    psql(`SELECT count(*) FROM "InstitutionMember" WHERE "institutionId"='${MOHFW_INSTITUTION_ID}' AND "isActive"=true`),
  );
  let officerAddResult;
  if (activeAdminCount === 0) {
    const bootstrapSecret = sh(`grep '^AUTHORITY_BOOTSTRAP_SECRET=' ${BACKEND_ENV_PATH} | cut -d= -f2`);
    officerAddResult = await api('/api/authority/bootstrap', {
      token: officerSession.token,
      method: 'POST',
      headers: { 'X-Authority-Bootstrap-Secret': bootstrapSecret },
      body: { institutionId: MOHFW_INSTITUTION_ID },
    });
    console.log('bootstrap (roster was empty):', officerAddResult.status, JSON.stringify(officerAddResult.json));
  } else {
    // The roster already has an ADMIN from a prior round. Provision a
    // session for that existing ADMIN and add the fixture officer through
    // the REAL POST /api/authority/members path, rather than bypassing it —
    // this is the one part of roster management step 4's earlier bootstrap
    // shortcut does not exercise.
    const existingAdminEmail = psql(
      `SELECT email FROM "InstitutionMember" WHERE "institutionId"='${MOHFW_INSTITUTION_ID}' AND role='ADMIN' AND "isActive"=true LIMIT 1`,
    );
    const adminSession = provisionSession(existingAdminEmail);
    officerAddResult = await api('/api/authority/members', {
      token: adminSession.token,
      method: 'POST',
      body: { email: 'fixture-officer@bdhealthtrust.test', name: 'Fixture Officer', role: 'OFFICER' },
    });
    console.log('add member (existing ADMIN adds the fixture officer):', officerAddResult.status, JSON.stringify(officerAddResult.json));
  }

  console.log('\n== 6. holder submits the issuance request for real ==');
  const submit = await api('/api/issuance/requests', {
    token: holderSession.token,
    method: 'POST',
    body: {
      requestId,
      documentType: 'health-card',
      documents: [{ lockerObjectId: objectId, contentHash: sha256Hex(objectBytes), mediaType: 'image/jpeg' }],
      wrappedContentKey,
      capability,
    },
  });
  console.log('submit:', submit.status, JSON.stringify(submit.json));
  if (submit.status !== 201) throw new Error('submission failed, aborting');

  console.log('\n== 7. officer sees it in the queue ==');
  const queue = await api('/api/authority/queue', { token: officerSession.token });
  console.log('queue:', queue.status, JSON.stringify(queue.json?.data?.requests?.map((r) => r.id)));

  console.log('\n== 8. officer releases the single-use key (capability travels on the SAME response) ==');
  const detail = await api(`/api/authority/requests/${requestId}`, { token: officerSession.token });
  console.log('detail:', detail.status, 'keyReleased:', detail.json?.data?.keyReleased, 'capability present:', !!detail.json?.data?.lockerCapability);
  if (!detail.json?.data?.wrappedContentKey) throw new Error('expected the wrapped key on first release');
  if (!detail.json?.data?.lockerCapability) throw new Error('expected the capability to travel with the release');

  console.log('\n== 9. officer console unwraps the content key server-side (real ECIES, not the placeholder) ==');
  const unwrapRes = await fetch('http://localhost:3100/console/content-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ wrappedContentKey: detail.json.data.wrappedContentKey, issuanceRequestId: requestId }),
  }).catch((err) => ({ ok: false, status: 0, json: async () => ({ error: String(err) }) }));
  const unwrapBody = unwrapRes.ok === undefined ? null : await unwrapRes.json().catch(() => null);
  console.log('content-key unwrap (requires `npm run dev` in packages/issuer-console on :3100):', unwrapRes.status ?? 'n/a', JSON.stringify(unwrapBody));

  console.log('\n== 10. officer console fetches + decrypts the object under the released capability ==');
  const objectFetchRes = await fetch('http://localhost:3100/console/locker/object', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ objectId, capability: detail.json.data.lockerCapability }),
  }).catch((err) => ({ ok: false, status: 0, json: async () => ({ error: String(err) }) }));
  const objectFetchBody = objectFetchRes.ok === undefined ? null : await objectFetchRes.json().catch(() => null);
  let decryptedText = null;
  if (unwrapBody?.contentKeyBase64Url && objectFetchBody?.objectBase64) {
    const { decryptLockerObject } = await import('@ssi-healthcare/shared');
    const contentKeyBack = Buffer.from(unwrapBody.contentKeyBase64Url, 'base64url');
    const objBytesBack = Buffer.from(objectFetchBody.objectBase64, 'base64');
    try {
      const plaintextBack = decryptLockerObject(objectId, contentKeyBack, objBytesBack);
      decryptedText = new TextDecoder().decode(plaintextBack);
    } catch (e) {
      decryptedText = `DECRYPT FAILED: ${e.message}`;
    }
  }
  console.log('fetch+decrypt result:', decryptedText, '(expected:', new TextDecoder().decode(plaintext), ')');

  console.log('\n== 11. officer approves ==');
  const approve = await api(`/api/authority/requests/${requestId}/approve`, { token: officerSession.token, method: 'POST', body: {} });
  console.log('approve:', approve.status, JSON.stringify(approve.json));

  console.log('\n== 12. holder\'s verified badge (GET /api/users/me identityVerified) ==');
  // identityVerified is computed from a HELD credential (services/identityVerification.ts),
  // not from the offer this approve just created — the holder still has to
  // redeem the OID4VCI offer. This step reports what it is BEFORE that
  // redemption; the round report states plainly whether it was exercised.
  const meBefore = await api('/api/users/me', { token: holderSession.token });
  console.log('holder identityVerified (before credential redemption):', meBefore.json?.data?.identityVerified);

  console.log('\n== FIXTURE STATE ==');
  console.log(
    JSON.stringify(
      {
        requestId,
        objectId,
        holderDid: holder.did,
        authorityDid: authority.did,
        authorityVerificationMethodId: authority.vmId,
        issuerLockerSigningSeed: Buffer.from(authorityPrivateKey).toString('base64url'),
        officerSessionToken: officerSession.token,
        holderSessionToken: holderSession.token,
        offerId: approve.json?.data?.offerId,
        expectedPlaintext: new TextDecoder().decode(plaintext),
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  console.error('FIXTURE FAILED:', error);
  process.exit(1);
});
