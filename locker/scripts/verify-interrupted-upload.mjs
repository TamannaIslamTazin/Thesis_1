/**
 * The interrupted-large-upload proof, against running containers.
 *
 * Two claims, and they are the heart of why this design is safe against the
 * failure mode the project fears most (#328, a wallet that says "Last backup:
 * today" when no usable backup exists):
 *
 *   1. AN INTERRUPTED UPLOAD IS NOT AN OBJECT. Parts land, the upload is
 *      abandoned, and the object namespace is UNCHANGED — a read returns 404,
 *      a listing does not mention it. There is no half-object for a user to
 *      believe in, because S3 materialises the object only on
 *      CompleteMultipartUpload. We get this from the substrate, not from our
 *      own carefulness, which is the strongest place to get it from.
 *
 *   2. THE RESIDUE IS REAPED AND COUNTED. The bytes those parts occupy are
 *      real and must not accumulate invisibly on a disk that is 85% full. The
 *      reaper aborts them through the S3 API and writes an append-only
 *      receipt, so "how much residue have we produced" is a query rather than
 *      an unknown.
 *
 * Requires the datastore locker to be running with a short
 * LOCKER_ABANDONED_UPLOAD_TTL_MS and LOCKER_HOUSEKEEPING_INTERVAL_MS.
 *
 * Usage: node scripts/verify-interrupted-upload.mjs
 */

import { createHash, randomUUID } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';

const DATASTORE = 'http://127.0.0.1:4540';
const STUB = 'http://127.0.0.1:4599';
const PART_BYTES = 5 * 1024 * 1024; // S3's minimum for a non-final part

let passed = 0;
let failed = 0;
const check = (label, ok, detail = '') => {
  if (ok) {
    passed += 1;
    console.log(`  PASS  ${label}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${label}${detail ? ` -- ${detail}` : ''}`);
  }
};

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

async function registerSubject() {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  const did = `did:cheqd:bdhealthtestnet:${randomUUID()}`;
  const vmId = `${did}#key-1`;
  const publicKeyMultibase = `z${base58.encode(new Uint8Array([0xed, 0x01, ...publicKey]))}`;
  await fetch(`${STUB}/_control/subjects`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      did,
      // Real cheqd Cosmos LCD REST shape (round 5's didResolver.ts fix) —
      // snake_case, wrapped in `value`, NOT the W3C `didDocument` shape this
      // used to send.
      document: {
        value: {
          did_doc: {
            id: did,
            verification_method: [
              { id: vmId, verification_method_type: 'Ed25519VerificationKey2020', controller: did, verification_material: publicKeyMultibase },
            ],
            authentication: [vmId],
          },
          metadata: { deactivated: false },
        },
      },
    }),
  });
  return { did, vmId, privateKey };
}

async function authenticate(subject) {
  const challenge = await (
    await fetch(`${DATASTORE}/v1/auth/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: subject.did }),
    })
  ).json();
  const iat = Math.floor(Date.now() / 1000);
  const canonical =
    `bdhealthtrust/locker-auth/v1\naud:${challenge.audience}\ndid:${subject.did}\n` +
    `nonce:${challenge.nonce}\niat:${iat}\n`;
  const signature = Buffer.from(
    ed25519.sign(new TextEncoder().encode(canonical), subject.privateKey),
  ).toString('base64url');
  const token = await (
    await fetch(`${DATASTORE}/v1/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nonce: challenge.nonce,
        signature,
        verificationMethodId: subject.vmId,
        iat,
      }),
    })
  ).json();
  return token.token;
}

async function residue(token) {
  return (
    await fetch(`${DATASTORE}/v1/residue`, { headers: { Authorization: `Bearer ${token}` } })
  ).json();
}

async function main() {
  const subject = await registerSubject();
  const token = await authenticate(subject);
  check('SUCCESS: authenticated (so the refusals below are meaningful)', !!token);

  const objectId = 'large-scan-2026-08';
  const before = await residue(token);

  console.log('\n=== A large multipart upload, interrupted after two parts ===');
  const begin = await (
    await fetch(`${DATASTORE}/v1/objects/${objectId}/multipart`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ contentHash: 'b'.repeat(64) }),
    })
  ).json();
  check('multipart upload begins', !!begin.uploadId, JSON.stringify(begin));

  // Two real 5MiB parts land, then we simply stop — the way a phone losing
  // signal mid-backup stops.
  let uploaded = 0;
  for (const partNumber of [1, 2]) {
    const part = Buffer.alloc(PART_BYTES, partNumber);
    const res = await fetch(
      `${DATASTORE}/v1/objects/${objectId}/multipart/${begin.uploadId}/parts/${partNumber}`,
      {
        method: 'PUT',
        headers: { Authorization: `Bearer ${token}` },
        body: part,
      },
    );
    if (res.ok) uploaded += PART_BYTES;
  }
  check(`two 5MiB parts landed (${(uploaded / 1024 / 1024).toFixed(0)}MiB in flight)`, uploaded === 2 * PART_BYTES);

  console.log('\n=== CLAIM 1: a partial upload is NOT an object ===');
  const read = await fetch(`${DATASTORE}/v1/objects/${objectId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  check(
    'reading the key 404s — there is no half-object to believe in',
    read.status === 404,
    `got ${read.status}`,
  );

  const listed = await (
    await fetch(`${DATASTORE}/v1/objects`, { headers: { Authorization: `Bearer ${token}` } })
  ).json();
  check(
    'the listing does not mention it either',
    !(listed.objects ?? []).some((o) => o.key.includes(objectId)),
    JSON.stringify(listed.objects),
  );

  console.log('\n=== CLAIM 2: the reaper aborts the residue and COUNTS it ===');
  console.log('  waiting for the housekeeping sweep...');
  let after = before;
  for (let i = 0; i < 24; i += 1) {
    await new Promise((r) => setTimeout(r, 2000));
    after = await residue(token);
    if (after.reapedUploads > before.reapedUploads) break;
  }

  check(
    'the reaper recorded an abandoned upload',
    after.reapedUploads > before.reapedUploads,
    `${before.reapedUploads} -> ${after.reapedUploads}`,
  );

  const stillGone = await fetch(`${DATASTORE}/v1/objects/${objectId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  check('and the object still does not exist afterwards', stillGone.status === 404);

  console.log(`\n${'='.repeat(60)}`);
  console.log(`PASSED ${passed}   FAILED ${failed}`);
  console.log('='.repeat(60));
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error('verification crashed:', error);
  process.exit(1);
});
