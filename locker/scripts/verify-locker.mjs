/**
 * Live verification of the locker, against RUNNING containers.
 *
 * Not a unit test. Every assertion below goes over a real socket to a real
 * locker process talking to a real MinIO, in the spirit of
 * scripts/verify-backup-vault.ts.
 *
 * EVERY REFUSAL IS PAIRED WITH THE SUCCESS PATH IT REFUSES AGAINST. A suite
 * that only proved the locker says no would pass perfectly against a locker
 * that says no to everything, which is the failure this project has already
 * shipped once.
 *
 * THE DID RESOLVER HERE IS A LOCAL STUB serving cheqd-shaped documents with
 * REAL Ed25519 keys. That makes the signature check, the multibase decode, the
 * authentication-relationship check and the replay CAS genuinely exercised.
 * What it does NOT prove is our parsing of a real cheqd node's REST response
 * shape — that stays explicitly unverified. See the report.
 *
 * Usage: node scripts/verify-locker.mjs
 */

import { execSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';
import { gcm } from '@noble/ciphers/aes';
import { mintLockerCapability } from '@ssi-healthcare/shared/capability';


/**
 * Retry once on a dropped keep-alive socket.
 *
 * Node's HTTP server closes idle connections after 5s; undici pools them and
 * can hand back one the server has just closed, surfacing as UND_ERR_SOCKET
 * "other side closed". That is a client-side race in this harness, not a
 * locker defect, and retrying the single affected request keeps the harness
 * from reporting a transport artefact as a failed assertion. It deliberately
 * does NOT retry on HTTP status codes -- a refusal must stay a refusal.
 */
const bareFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  try {
    return await bareFetch(input, init);
  } catch (error) {
    const code = error?.cause?.code ?? error?.code;
    if (code !== 'UND_ERR_SOCKET' && code !== 'ECONNRESET') throw error;
    await new Promise((r) => setTimeout(r, 250));
    return bareFetch(input, init);
  }
};

const DATASTORE = 'http://127.0.0.1:4540';
const KEYSTORE = 'http://127.0.0.1:4541';

let passed = 0;
let failed = 0;

function check(label, condition, detail = '') {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${label}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function section(title) {
  console.log(`\n=== ${title} ===`);
}

// --------------------------------------------------------------------------
// The DID resolver runs as a CONTAINER on the compose network.
//
// The host firewall on this machine drops bridge-to-host traffic (measured:
// both 172.24.0.1 and 172.17.0.1 time out from inside a container), so a
// resolver listening on the host is unreachable from the locker. Running it
// inside the network sidesteps the firewall entirely and makes this run
// reproducible on a machine with different rules.
// --------------------------------------------------------------------------
const STUB = 'http://127.0.0.1:4599';

/**
 * Every subject we have registered, so a resolver RESTART can replay them.
 *
 * The stub holds its subjects in memory, so `docker start` comes back with an
 * empty map. Without this replay, the unreachability test silently deletes
 * every previously registered DID and the failures land several sections
 * later, looking like a locker defect rather than a harness one. (It did
 * exactly that on the first run.)
 */
const registeredSubjects = new Map();

async function pushSubject(did, document) {
  await fetch(`${STUB}/_control/subjects`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did, document }),
  });
}

async function registerSubject({ deactivated = false, keyInAuthentication = true } = {}) {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  const did = `did:cheqd:bdhealthtestnet:${randomUUID()}`;
  const vmId = `${did}#key-1`;
  const multicodec = new Uint8Array([0xed, 0x01, ...publicKey]);
  const publicKeyMultibase = `z${base58.encode(multicodec)}`;

  // Real cheqd Cosmos LCD REST shape (round 5's didResolver.ts fix) —
  // snake_case, wrapped in `value`, verified live against a running node.
  // See didResolver.ts's docblock: this was NEVER the shape this script (or
  // the resolver it feeds) used before round 5, and the mismatch meant every
  // real DID resolved NOT_FOUND regardless of whether it actually existed.
  const document = {
    value: {
      did_doc: {
        id: did,
        verification_method: [
          { id: vmId, verification_method_type: 'Ed25519VerificationKey2020', controller: did, verification_material: publicKeyMultibase },
        ],
        authentication: keyInAuthentication ? [vmId] : [],
      },
      metadata: { deactivated },
    },
  };

  registeredSubjects.set(did, document);
  await pushSubject(did, document);

  return { did, vmId, privateKey };
}

async function stopResolver() {
  execSync('docker --context default stop bdht-stub-resolver', { stdio: 'ignore' });
}
async function startResolver() {
  execSync('docker --context default start bdht-stub-resolver', { stdio: 'ignore' });
  for (let i = 0; i < 20; i += 1) {
    try {
      const res = await fetch(`${STUB}/_control/health`);
      if (res.ok) return;
    } catch { /* still coming up */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('stub resolver did not come back');
}

/** Bring the stub back AND restore everything it forgot while it was down. */
async function restartResolver() {
  await startResolver();
  for (const [did, document] of registeredSubjects) {
    await pushSubject(did, document);
  }
}

// --------------------------------------------------------------------------
// Auth helpers
// --------------------------------------------------------------------------
function signAuth(subject, { audience, nonce, iat, overrideAudience }) {
  const canonical =
    `bdhealthtrust/locker-auth/v1\n` +
    `aud:${overrideAudience ?? audience}\n` +
    `did:${subject.did}\n` +
    `nonce:${nonce}\n` +
    `iat:${iat}\n`;
  const signature = ed25519.sign(new TextEncoder().encode(canonical), subject.privateKey);
  return Buffer.from(signature).toString('base64url');
}

async function getChallenge(base, did) {
  const res = await fetch(`${base}/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did }),
  });
  return { status: res.status, body: await res.json() };
}

async function exchange(base, { nonce, signature, vmId, iat }) {
  const res = await fetch(`${base}/v1/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nonce, signature, verificationMethodId: vmId, iat }),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function authenticate(base, subject) {
  const challenge = await getChallenge(base, subject.did);
  const iat = Math.floor(Date.now() / 1000);
  const signature = signAuth(subject, {
    audience: challenge.body.audience,
    nonce: challenge.body.nonce,
    iat,
  });
  const token = await exchange(base, {
    nonce: challenge.body.nonce,
    signature,
    vmId: subject.vmId,
    iat,
  });
  return { challenge, token };
}

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

async function main() {
  await startResolver();
  console.log('stub DID resolver container is up');

  // ------------------------------------------------------------------ auth
  section('DID challenge-response: the SUCCESS path');
  const alice = await registerSubject();
  const { challenge, token } = await authenticate(DATASTORE, alice);
  check('challenge issued', challenge.status === 201 && !!challenge.body.nonce);
  check('challenge echoes the canonical payload template', typeof challenge.body.payloadTemplate === 'string');
  check('a valid signature yields a session token', token.status === 200 && !!token.body.token, JSON.stringify(token.body));
  const aliceToken = token.body.token;

  section('DID challenge-response: the refusals');

  // Replay: reuse a spent nonce.
  const replayIat = Math.floor(Date.now() / 1000);
  const replaySig = signAuth(alice, {
    audience: challenge.body.audience,
    nonce: challenge.body.nonce,
    iat: replayIat,
  });
  const replay = await exchange(DATASTORE, {
    nonce: challenge.body.nonce,
    signature: replaySig,
    vmId: alice.vmId,
    iat: replayIat,
  });
  check('a SPENT nonce is refused (single-use CAS)', replay.status === 401, `got ${replay.status}`);

  // Wrong audience: a signature harvested by another locker.
  const wrongAudChallenge = await getChallenge(DATASTORE, alice.did);
  const wrongAudIat = Math.floor(Date.now() / 1000);
  const wrongAudSig = signAuth(alice, {
    audience: wrongAudChallenge.body.audience,
    nonce: wrongAudChallenge.body.nonce,
    iat: wrongAudIat,
    overrideAudience: 'bdhealthtrust:locker:datastore:SOMEONE-ELSES-BUCKET',
  });
  const wrongAud = await exchange(DATASTORE, {
    nonce: wrongAudChallenge.body.nonce,
    signature: wrongAudSig,
    vmId: alice.vmId,
    iat: wrongAudIat,
  });
  check('a signature bound to ANOTHER audience is refused', wrongAud.status === 401, `got ${wrongAud.status}`);

  // Key present in the document but not in `authentication`.
  const mallory = await registerSubject({ keyInAuthentication: false });
  const malloryChallenge = await getChallenge(DATASTORE, mallory.did);
  const malloryIat = Math.floor(Date.now() / 1000);
  const malloryAuth = await exchange(DATASTORE, {
    nonce: malloryChallenge.body.nonce,
    signature: signAuth(mallory, {
      audience: malloryChallenge.body.audience,
      nonce: malloryChallenge.body.nonce,
      iat: malloryIat,
    }),
    vmId: mallory.vmId,
    iat: malloryIat,
  });
  check(
    'a key NOT in `authentication` is refused with 403, not accepted',
    malloryAuth.status === 403,
    `got ${malloryAuth.status} ${JSON.stringify(malloryAuth.body)}`,
  );

  // Deactivated DID.
  const zombie = await registerSubject({ deactivated: true });
  const zombieChallenge = await getChallenge(DATASTORE, zombie.did);
  const zombieIat = Math.floor(Date.now() / 1000);
  const zombieAuth = await exchange(DATASTORE, {
    nonce: zombieChallenge.body.nonce,
    signature: signAuth(zombie, {
      audience: zombieChallenge.body.audience,
      nonce: zombieChallenge.body.nonce,
      iat: zombieIat,
    }),
    vmId: zombie.vmId,
    iat: zombieIat,
  });
  check('a DEACTIVATED DID is refused with 409 (terminal)', zombieAuth.status === 409, `got ${zombieAuth.status}`);

  // Unknown DID: the resolver ANSWERS, so this is a definitive 404.
  const ghostChallenge = await getChallenge(DATASTORE, `did:cheqd:bdhealthtestnet:${randomUUID()}`);
  const ghostIat = Math.floor(Date.now() / 1000);
  const ghost = await exchange(DATASTORE, {
    nonce: ghostChallenge.body.nonce,
    signature: signAuth(alice, {
      audience: ghostChallenge.body.audience,
      nonce: ghostChallenge.body.nonce,
      iat: ghostIat,
    }),
    vmId: alice.vmId,
    iat: ghostIat,
  });
  check('an ABSENT DID is 404 (the resolver answered)', ghost.status === 404, `got ${ghost.status}`);

  section('ABSENCE and UNREACHABILITY do not collapse (the cheqdLedger.ts lesson)');
  await stopResolver();
  const outageChallenge = await getChallenge(DATASTORE, alice.did);
  const outageIat = Math.floor(Date.now() / 1000);
  const outage = await exchange(DATASTORE, {
    nonce: outageChallenge.body.nonce,
    signature: signAuth(alice, {
      audience: outageChallenge.body.audience,
      nonce: outageChallenge.body.nonce,
      iat: outageIat,
    }),
    vmId: alice.vmId,
    iat: outageIat,
  });
  check(
    'a DOWN resolver gives 503 UNREACHABLE, NOT 404 "your DID does not exist"',
    outage.status === 503 && outage.body.code === 'RESOLVER_UNREACHABLE',
    `got ${outage.status} ${JSON.stringify(outage.body)}`,
  );
  await restartResolver();

  // -------------------------------------------------------------- storage
  section('Store -> read back -> verify the GCM tag -> erase -> confirm gone');

  // The wallet's side: encrypt locally. The locker never sees this key.
  const dek = new Uint8Array(32);
  crypto.getRandomValues(dek);
  const nonceBytes = new Uint8Array(12);
  crypto.getRandomValues(nonceBytes);
  const plaintext = new TextEncoder().encode(
    'DISCHARGE SUMMARY: patient stable, follow up in 6 weeks. ' + 'x'.repeat(2000),
  );
  const objectId = 'discharge-summary-2026-08';
  const aad = new TextEncoder().encode(`bdhealthtrust/locker-object/v1|${objectId}|0`);
  const ciphertext = Buffer.from(gcm(dek, nonceBytes, aad).encrypt(plaintext));

  const put = await fetch(`${DATASTORE}/v1/objects/${objectId}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${aliceToken}`,
      'X-Locker-Object-Hash': sha256(ciphertext),
      'Content-Type': 'application/octet-stream',
    },
    body: ciphertext,
  });
  check('SUCCESS: the object stores', put.status === 201, `got ${put.status} ${await put.clone().text()}`);

  const listed = await (
    await fetch(`${DATASTORE}/v1/objects`, { headers: { Authorization: `Bearer ${aliceToken}` } })
  ).json();
  check('it appears in the subject listing', listed.objects?.some((o) => o.key.includes(objectId)));

  const readBack = await fetch(`${DATASTORE}/v1/objects/${objectId}`, {
    headers: { Authorization: `Bearer ${aliceToken}` },
  });
  const returned = Buffer.from(await readBack.arrayBuffer());
  check('read-back returns byte-identical ciphertext', returned.equals(ciphertext));

  // THE PROOF THAT MATTERS: the returned bytes decrypt under the wallet's key.
  // A 200 with the right length proves nothing; the GCM tag proves the backup
  // is USABLE, which is what "backed up" has to mean (#328).
  let decrypted = null;
  try {
    decrypted = Buffer.from(gcm(dek, nonceBytes, aad).decrypt(returned));
  } catch {
    decrypted = null;
  }
  check(
    'the read-back bytes DECRYPT under the wallet key (GCM tag verifies)',
    decrypted !== null && decrypted.equals(Buffer.from(plaintext)),
  );

  // ...and the tamper case, so the check above is discriminating.
  const tampered = Buffer.from(returned);
  tampered[0] ^= 0xff;
  let tamperOpened = true;
  try {
    gcm(dek, nonceBytes, aad).decrypt(tampered);
  } catch {
    tamperOpened = false;
  }
  check('a single flipped byte fails the tag (so the check above is real)', !tamperOpened);

  section('The operator is blind, and cross-subject access is unconstructable');
  const bob = await registerSubject();
  const bobAuth = await authenticate(DATASTORE, bob);
  const bobToken = bobAuth.token.body.token;
  check('SUCCESS: a second subject can authenticate', !!bobToken);

  const bobList = await (
    await fetch(`${DATASTORE}/v1/objects`, { headers: { Authorization: `Bearer ${bobToken}` } })
  ).json();
  check(
    "a second subject cannot see the first's objects",
    Array.isArray(bobList.objects) && bobList.objects.length === 0,
    JSON.stringify(bobList),
  );

  const bobSteal = await fetch(`${DATASTORE}/v1/objects/${objectId}`, {
    headers: { Authorization: `Bearer ${bobToken}` },
  });
  check("a second subject cannot read the first's object by name", bobSteal.status === 404);

  const noAuth = await fetch(`${DATASTORE}/v1/objects/${objectId}`);
  check('no token at all is refused', noAuth.status === 401);

  section('Role policy: the keystore refuses multipart, the datastore offers it');
  const aliceKeystore = await authenticate(KEYSTORE, alice);
  const ksToken = aliceKeystore.token.body.token;
  const kekEnvelope = Buffer.from(JSON.stringify({ version: 1, salt: 'x', nonce: 'y', ciphertext: 'z' }));
  const ksPut = await fetch(`${KEYSTORE}/v1/objects/kek-device`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${ksToken}`, 'X-Locker-Object-Hash': sha256(kekEnvelope) },
    body: kekEnvelope,
  });
  check('SUCCESS: the keystore stores a KEK envelope', ksPut.status === 201, `got ${ksPut.status}`);

  const ksMultipart = await fetch(`${KEYSTORE}/v1/objects/kek-device/multipart`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${ksToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ contentHash: 'a'.repeat(64) }),
  });
  check('the keystore REFUSES multipart', ksMultipart.status === 409, `got ${ksMultipart.status}`);

  section('Transport integrity: a mis-declared hash is refused');
  const good = Buffer.from('some ciphertext bytes');
  const liar = await fetch(`${DATASTORE}/v1/objects/liar`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${aliceToken}`, 'X-Locker-Object-Hash': 'f'.repeat(64) },
    body: good,
  });
  check('a body that does not match its declared hash is refused', liar.status === 400);

  const missing = await fetch(`${DATASTORE}/v1/objects/nohash`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${aliceToken}` },
    body: good,
  });
  check('a write with no declared hash at all is refused', missing.status === 400);

  section('Erasure leaves a receipt, and the object is gone');
  const residueBefore = await (
    await fetch(`${DATASTORE}/v1/residue`, { headers: { Authorization: `Bearer ${aliceToken}` } })
  ).json();

  const erase = await fetch(`${DATASTORE}/v1/objects/${objectId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${aliceToken}` },
  });
  const receipt = await erase.json();
  check('erasure returns a receipt', erase.status === 200 && !!receipt.id, JSON.stringify(receipt));
  check('the receipt records the byte count', receipt.byteCount === ciphertext.length);

  const afterErase = await fetch(`${DATASTORE}/v1/objects/${objectId}`, {
    headers: { Authorization: `Bearer ${aliceToken}` },
  });
  check('CONFIRMED GONE: reading it back now 404s', afterErase.status === 404);

  const residueAfter = await (
    await fetch(`${DATASTORE}/v1/residue`, { headers: { Authorization: `Bearer ${aliceToken}` } })
  ).json();
  check(
    'the erasure is counted in the append-only log',
    residueAfter.erasures === residueBefore.erasures + 1,
    `${residueBefore.erasures} -> ${residueAfter.erasures}`,
  );

  // ------------------------------------------------------ officer capability
  section('Officer capability: mint, read, and the six refusals (OFFICER-DOCUMENT-ACCESS.md §3)');

  const holder = await registerSubject();
  const officer = await registerSubject();
  const strangerHolder = await registerSubject(); // owns nothing; plays the cross-subject attacker

  const holderAuth = await authenticate(DATASTORE, holder);
  const holderToken = holderAuth.token.body.token;
  const officerAuth = await authenticate(DATASTORE, officer);
  const officerToken = officerAuth.token.body.token;

  const capObjectId = 'health-card-application-2026-09';
  const capPlaintext = Buffer.from('NID scan bytes, standing in for a real document image.');
  const capCiphertext = capPlaintext; // no encryption needed to exercise the capability path itself
  const capPut = await fetch(`${DATASTORE}/v1/objects/${capObjectId}`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${holderToken}`, 'X-Locker-Object-Hash': sha256(capCiphertext) },
    body: capCiphertext,
  });
  check('SUCCESS: the holder stores the object the capability will cover', capPut.status === 201, `got ${capPut.status}`);

  function b64urlToken(token) {
    return Buffer.from(JSON.stringify(token), 'utf8').toString('base64url');
  }

  async function mint({ signer = holder, iss = holder.did, aud = officer.did, obj = [capObjectId], sub = 'req-cap-1', validitySeconds, now } = {}) {
    return mintLockerCapability({
      holderDid: iss,
      authorityDid: aud,
      objectIds: obj,
      issuanceRequestId: sub,
      verificationMethodId: signer.vmId,
      validitySeconds,
      now,
      sign: (payload) => ed25519.sign(payload, signer.privateKey),
    });
  }

  async function readWithCapability(token, { asToken = officerToken, objectId = capObjectId } = {}) {
    const res = await fetch(`${DATASTORE}/v1/objects/${objectId}/capability`, {
      headers: { Authorization: `Bearer ${asToken}`, 'X-Locker-Capability': b64urlToken(token) },
    });
    return { status: res.status, body: await res.json().catch(() => null), raw: res };
  }

  // ---- the success path ---------------------------------------------------
  const validCap = await mint();
  const goodRead = await fetch(`${DATASTORE}/v1/objects/${capObjectId}/capability`, {
    headers: { Authorization: `Bearer ${officerToken}`, 'X-Locker-Capability': b64urlToken(validCap) },
  });
  const goodBytes = Buffer.from(await goodRead.arrayBuffer());
  check('SUCCESS: a valid capability reads the holder\'s object', goodRead.status === 200, `got ${goodRead.status}`);
  check('the bytes returned are byte-identical to what the holder stored', goodBytes.equals(capCiphertext));

  // ---- step 0: malformed -----------------------------------------------
  const malformedRead = await fetch(`${DATASTORE}/v1/objects/${capObjectId}/capability`, {
    headers: { Authorization: `Bearer ${officerToken}`, 'X-Locker-Capability': Buffer.from('not json').toString('base64url') },
  });
  check('a MALFORMED capability is refused with 400, not 403', malformedRead.status === 400, `got ${malformedRead.status}`);

  // ---- step 1: bad signature ---------------------------------------------
  const tamperedSig = { ...validCap, signature: validCap.signature.slice(0, -4) + (validCap.signature.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA') };
  const badSigResult = await readWithCapability(tamperedSig);
  check('step 1: a TAMPERED SIGNATURE is refused', badSigResult.status === 403 && badSigResult.body?.code === 'CAPABILITY_REFUSED', JSON.stringify(badSigResult));

  // ---- step 2: wrong audience ---------------------------------------------
  const wrongAudCap = await mint({ aud: strangerHolder.did }); // signed for a DIFFERENT authority than the one authenticating
  const wrongAudResult = await readWithCapability(wrongAudCap);
  check('step 2: a capability audienced to ANOTHER authority is refused', wrongAudResult.status === 403, JSON.stringify(wrongAudResult));

  // ---- step 3: window not current (already expired) -----------------------
  const expiredCap = await mint({ now: new Date(Date.now() - 2 * 60 * 60 * 1000), validitySeconds: 60 });
  const expiredResult = await readWithCapability(expiredCap);
  check('step 3: an EXPIRED capability is refused', expiredResult.status === 403, JSON.stringify(expiredResult));

  // ---- step 4: revoked jti -------------------------------------------------
  const revocableCap = await mint({ sub: 'req-cap-revoke' });
  const preRevokeRead = await readWithCapability(revocableCap);
  check('a capability reads successfully BEFORE it is revoked (so revocation below is discriminating)', preRevokeRead.status === 200, JSON.stringify(preRevokeRead));
  const revokeCall = await fetch(`${DATASTORE}/v1/capabilities/revoke`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${holderToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ jti: revocableCap.claims.jti }),
  });
  check('the holder can revoke their own capability', revokeCall.status === 204, `got ${revokeCall.status}`);
  const postRevokeRead = await readWithCapability(revocableCap);
  check('step 4: the SAME capability is refused AFTER revocation', postRevokeRead.status === 403, JSON.stringify(postRevokeRead));
  const stillValidRead = await readWithCapability(validCap);
  check('revocation is scoped to ONE jti: an unrelated capability from the same holder still reads', stillValidRead.status === 200, JSON.stringify(stillValidRead));

  // ---- step 5: requested object id not in scope ----------------------------
  const otherObjectId = 'unrelated-object-id';
  const narrowCap = await mint({ obj: [otherObjectId] });
  const outOfScopeResult = await readWithCapability(narrowCap, { objectId: capObjectId });
  check('step 5: a capability naming a DIFFERENT object id is refused for this object', outOfScopeResult.status === 403, JSON.stringify(outOfScopeResult));

  // ---- step 6: THE CROSS-SUBJECT TEST -------------------------------------
  // strangerHolder signs a perfectly well-formed, correctly audienced,
  // currently-valid, unrevoked capability -- naming the HOLDER's real object
  // id in `obj`. Every check up to and including step 5 passes. Step 6 is
  // what stops it: the object is looked up under HMAC(pepper, iss=stranger),
  // and the holder's object was never stored there.
  const crossSubjectCap = await mint({ signer: strangerHolder, iss: strangerHolder.did, obj: [capObjectId] });
  const crossSubjectResult = await readWithCapability(crossSubjectCap);
  check(
    'step 6: an otherwise-VALID capability naming ANOTHER subject\'s object id is refused',
    crossSubjectResult.status === 403 && crossSubjectResult.body?.code === 'CAPABILITY_REFUSED',
    JSON.stringify(crossSubjectResult),
  );
  check(
    'the cross-subject refusal has the IDENTICAL shape as a bad-signature refusal (no oracle)',
    crossSubjectResult.status === badSigResult.status && crossSubjectResult.body?.code === badSigResult.body?.code,
  );

  // ---- missing header, and no session at all -------------------------------
  const noHeaderRead = await fetch(`${DATASTORE}/v1/objects/${capObjectId}/capability`, {
    headers: { Authorization: `Bearer ${officerToken}` },
  });
  check('a request with NO capability header at all is refused with 400', noHeaderRead.status === 400, `got ${noHeaderRead.status}`);

  const noSessionRead = await fetch(`${DATASTORE}/v1/objects/${capObjectId}/capability`, {
    headers: { 'X-Locker-Capability': b64urlToken(validCap) },
  });
  check('a request with NO session token at all is refused with 401', noSessionRead.status === 401, `got ${noSessionRead.status}`);

  console.log(`\n${'='.repeat(60)}`);
  console.log(`PASSED ${passed}   FAILED ${failed}`);
  console.log('='.repeat(60));

  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error('verification crashed:', error);
  process.exit(1);
});
