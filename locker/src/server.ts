/**
 * The locker's HTTP surface. Hand-rolled on `node:http` for the same reason as
 * the Phase C vault: a handful of routes over one resource does not need a
 * router dependency, and this process should be the smallest thing that
 * satisfies the brief.
 *
 * Routes:
 *   GET    /healthz                          liveness, no auth
 *   GET    /readyz                           readiness — proves the BUCKET is reachable
 *   POST   /v1/auth/challenge                { did } -> nonce
 *   POST   /v1/auth/token                    signed challenge -> session token
 *   GET    /v1/objects                       list this subject's objects
 *   PUT    /v1/objects/:objectId             single-shot write
 *   POST   /v1/objects/:objectId/multipart   begin
 *   PUT    /v1/objects/:objectId/multipart/:uploadId/parts/:n
 *   POST   /v1/objects/:objectId/multipart/:uploadId/complete
 *   DELETE /v1/objects/:objectId/multipart/:uploadId
 *   GET    /v1/objects/:objectId             read back
 *   DELETE /v1/objects/:objectId             erase, with a receipt
 *   GET    /v1/objects/:objectId/capability  read a HOLDER's object under a
 *                                             capability they signed
 *                                             (OFFICER-DOCUMENT-ACCESS.md §3),
 *                                             carried in X-Locker-Capability
 *   POST   /v1/capabilities/revoke           the holder revokes one of their
 *                                             own capabilities by jti (§5)
 *   GET    /v1/residue                       what the reaper has aborted
 *
 * ===========================================================================
 * A SESSION AUTHORISES READS. EVERY WRITE IS SEPARATELY BOUND.
 * ===========================================================================
 * The session token is a bearer credential and a stolen one is replayable for
 * its lifetime. So it grants listing and reading, and any request that CREATES
 * or DESTROYS bytes must also carry the subject's own `X-Locker-Object-Hash`
 * matching the body — cheap, and it means a stolen token alone cannot forge a
 * write whose content the thief chooses. The wallet-side signature over that
 * hash is the next increment; mobile is deferred by #331, so the header is
 * checked but the signature is not yet demanded.
 *
 * ===========================================================================
 * A SUBJECT CAN ONLY EVER ADDRESS ITS OWN PREFIX
 * ===========================================================================
 * Every object key is built HERE from the session's DID, never from anything
 * the client sends. There is no request field that can influence which
 * subjectRef a key lands under, so cross-subject access is not "checked" — it
 * is unconstructable, which is the stronger of the two.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { S3Client } from '@aws-sdk/client-s3';

import { abandonedUploadTtlMs, type LockerConfig } from './config.js';
import {
  CHALLENGE_TTL_MS,
  SessionStore,
  authPayload,
  generateNonce,
  verifySignedChallenge,
} from './didAuth.js';
import {
  LockerError,
  consumeChallenge,
  countReceipts,
  issueChallenge,
  recordReceipt,
  recordUploadIntent,
  revokeCapability,
  settleUploadIntent,
  subjectRef as computeSubjectRef,
  findRecoveryIndex,
  handleRef,
  putRecoveryIndex,
} from './db.js';
import { verifyLockerCapability } from './capability.js';
import {
  MIN_PART_BYTES,
  abortMultipart,
  assertBucketReachable,
  assertWithinQuota,
  beginMultipart,
  completeMultipart,
  deleteObject,
  getObject,
  headObject,
  listObjects,
  objectKey,
  objectPrefix,
  putObject,
  uploadPart,
} from './objectStore.js';
import { reapAbandonedUploads } from './reaper.js';

export interface ServerDeps {
  readonly config: LockerConfig;
  readonly db: DatabaseSync;
  readonly s3: S3Client;
  readonly sessions: SessionStore;
  /** The `aud` this locker requires in a signed challenge. Its own identity. */
  readonly audience: string;
}

async function readBody(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > maxBytes) {
      throw new LockerError(`request body exceeds ${maxBytes} bytes`, 413, 'BODY_TOO_LARGE');
    }
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const raw = await readBody(req, 64 * 1024);
  if (raw.length === 0) return {};
  try {
    return JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
  } catch {
    throw new LockerError('request body is not valid JSON', 400, 'INVALID_JSON');
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  if (body === undefined) {
    res.writeHead(status);
    res.end();
    return;
  }
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function bearerToken(req: IncomingMessage): string | undefined {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return undefined;
  return header.slice('Bearer '.length);
}

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function createLockerServer(deps: ServerDeps) {
  return createServer((req, res) => {
    void handle(deps, req, res).catch((error) => {
      // A handler bug must still fail closed with a response rather than
      // hanging the socket on a client that is waiting to know whether its
      // backup landed.
      console.error(
        JSON.stringify({
          level: 'error',
          event: 'locker_unhandled_error',
          role: deps.config.policy.role,
          message: error instanceof Error ? error.message : String(error),
        }),
      );
      if (!res.headersSent) sendJson(res, 500, { error: 'internal error', code: 'INTERNAL' });
    });
  });
}

async function handle(
  deps: ServerDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://internal');
  const method = req.method ?? 'GET';
  const parts = url.pathname.split('/').filter(Boolean);

  try {
    if (method === 'GET' && url.pathname === '/healthz') {
      sendJson(res, 200, { status: 'ok', role: deps.config.policy.role });
      return;
    }

    // Readiness is distinct from liveness: the process can be alive and unable
    // to reach its bucket, and routing traffic to it then produces failed
    // backups that look like the user's fault.
    if (method === 'GET' && url.pathname === '/readyz') {
      try {
        await assertBucketReachable(deps.s3, deps.config.s3Bucket);
        sendJson(res, 200, { status: 'ready', bucket: deps.config.s3Bucket });
      } catch (error) {
        sendJson(res, 503, {
          status: 'not-ready',
          code: 'BUCKET_UNREACHABLE',
          error: error instanceof Error ? error.message : String(error),
        });
      }
      return;
    }

    if (parts[0] !== 'v1') {
      sendJson(res, 404, { error: 'not found', code: 'NOT_FOUND' });
      return;
    }

    // ---- recovery (unauthenticated BY NECESSITY) --------------------------
    //
    // A device that has just been unboxed knows a phone number and a passphrase.
    // It cannot prove control of the DID, because the key that would prove it is
    // the thing it is trying to recover. So this read cannot be authenticated
    // without making restore impossible, and it is not.
    //
    // What it returns is already sealed: the envelope opens only under a
    // scrypt-derived key from the user's passphrase, and this service never sees
    // either. The residual exposure — someone who knows a phone number may fetch
    // an envelope and attempt to crack it offline — is the cost of choosing the
    // phone number as the handle, recorded and accepted (#380). It is bounded
    // here by answering in constant time, so the endpoint cannot also be used to
    // enumerate which numbers are enrolled.
    if (parts[1] === 'recovery' && parts[2] === 'envelope' && method === 'POST') {
      if (deps.config.policy.role !== 'keystore') {
        throw new LockerError('recovery envelopes live in the keystore', 404, 'NOT_FOUND');
      }
      const started = Date.now();
      const body = await readJson(req);
      const handle = typeof body.handle === 'string' ? body.handle.trim() : '';

      let found: { envelope: string; did: string } | null = null;
      if (handle.length > 0) {
        const entry = findRecoveryIndex(deps.db, handleRef(handle, deps.config.subjectPepper));
        if (entry) {
          const stored = await getObject(
            deps.s3,
            deps.config.s3Bucket,
            objectKey(entry.subjectRef, entry.objectId, entry.generation),
          );
          if (stored) {
            found = { envelope: new TextDecoder().decode(stored), did: entry.did };
          }
        }
      }

      // Constant-ish floor. A hit costs a bucket read and a miss costs nothing,
      // and that difference alone would answer "is this number enrolled".
      const FLOOR_MS = 250;
      const elapsed = Date.now() - started;
      if (elapsed < FLOOR_MS) await new Promise((r) => setTimeout(r, FLOOR_MS - elapsed));

      if (!found) {
        sendJson(res, 404, { error: 'no envelope for that handle', code: 'ENVELOPE_NOT_FOUND' });
        return;
      }
      sendJson(res, 200, found);
      return;
    }

    // ---- auth (unauthenticated by definition) ----------------------------
    if (parts[1] === 'auth' && parts[2] === 'challenge' && method === 'POST') {
      const body = await readJson(req);
      const did = typeof body.did === 'string' ? body.did.trim() : '';
      if (!did.startsWith('did:')) {
        throw new LockerError('body.did must be a DID', 400, 'INVALID_DID');
      }
      const challenge = issueChallenge(deps.db, {
        did,
        audience: deps.audience,
        nonce: generateNonce(),
        ttlMs: CHALLENGE_TTL_MS,
      });
      sendJson(res, 201, {
        nonce: challenge.nonce,
        audience: challenge.audience,
        expiresAt: challenge.expiresAt,
        // Echo the exact template so a wallet cannot guess the canonical form
        // wrong and spend three days debugging a valid signature.
        payloadTemplate: new TextDecoder().decode(
          authPayload({
            audience: challenge.audience,
            did,
            nonce: challenge.nonce,
            issuedAtSeconds: 0,
          }),
        ),
      });
      return;
    }

    if (parts[1] === 'auth' && parts[2] === 'token' && method === 'POST') {
      const body = await readJson(req);
      const nonce = typeof body.nonce === 'string' ? body.nonce : '';
      const signature = typeof body.signature === 'string' ? body.signature : '';
      const verificationMethodId =
        typeof body.verificationMethodId === 'string' ? body.verificationMethodId : '';
      const issuedAtSeconds = typeof body.iat === 'number' ? body.iat : NaN;

      if (!nonce || !signature || !verificationMethodId || !Number.isFinite(issuedAtSeconds)) {
        throw new LockerError(
          'body must carry nonce, signature, verificationMethodId and iat',
          400,
          'INVALID_BODY',
        );
      }

      // SPEND FIRST. The challenge is consumed before the (slower, network-
      // bound) signature check, so a flood of replays cannot each get a free
      // DID resolution out of us, and two concurrent replays cannot both pass.
      const consumption = consumeChallenge(deps.db, nonce);
      if (!consumption.ok) {
        sendJson(res, 401, { error: 'challenge refused', code: 'CHALLENGE_REFUSED' });
        return;
      }

      const outcome = await verifySignedChallenge({
        did: consumption.did,
        audience: consumption.audience,
        nonce,
        issuedAtSeconds,
        verificationMethodId,
        signatureBase64Url: signature,
        resolverUrl: deps.config.didResolverUrl,
        resolverTimeoutMs: deps.config.didResolverTimeoutMs,
      });

      if (!outcome.ok) {
        // The challenge stays spent. A failed attempt does not get to retry
        // against the same nonce.
        sendJson(res, outcome.httpStatus, { error: outcome.reason, code: outcome.code });
        return;
      }

      const session = deps.sessions.issue(outcome.did);
      sendJson(res, 200, { token: session.token, expiresAt: session.expiresAt });
      return;
    }

    // ---- everything below needs a session --------------------------------
    const did = deps.sessions.resolve(bearerToken(req));
    if (!did) {
      sendJson(res, 401, { error: 'unauthorised', code: 'UNAUTHORISED' });
      return;
    }
    const subjectRef = computeSubjectRef(did, deps.config.subjectPepper);

    if (parts[1] === 'residue' && method === 'GET') {
      sendJson(res, 200, {
        reapedUploads: countReceipts(deps.db, 'ABANDONED_UPLOAD_REAPED'),
        erasures: countReceipts(deps.db, 'ERASURE'),
      });
      return;
    }

    // POST /v1/capabilities/revoke — the holder revokes one of their own
    // capabilities (OFFICER-DOCUMENT-ACCESS.md §5). Authenticated the same
    // way as everything else past this point: the session already proves
    // `did`, and `subjectRef` here is THIS caller's own — a subject can only
    // ever revoke a jti under their own prefix, the same unconstructable-by-
    // construction property the rest of this file relies on for reads.
    if (parts[1] === 'capabilities' && parts[2] === 'revoke' && method === 'POST') {
      const body = await readJson(req);
      const jti = typeof body.jti === 'string' ? body.jti.trim() : '';
      if (!jti) {
        throw new LockerError('body.jti is required', 400, 'INVALID_JTI');
      }
      revokeCapability(deps.db, { subjectRef, jti });
      sendJson(res, 204, undefined);
      return;
    }

    // GET /v1/objects/:objectId/capability — an authority reads a HOLDER's
    // object under a capability the holder signed (OFFICER-DOCUMENT-ACCESS.md
    // §3). Handled before the `objects`-only routes below because it is the
    // one route under `objects/` whose result depends on a DIFFERENT
    // subjectRef than the caller's own session — see capability.ts step 6.
    if (method === 'GET' && parts[1] === 'objects' && parts[3] === 'capability' && parts.length === 4) {
      const requestedObjectId = parts[2] ? decodeURIComponent(parts[2]) : '';
      if (!requestedObjectId || requestedObjectId.includes('/') || requestedObjectId.includes('..')) {
        throw new LockerError(
          `invalid object id '${requestedObjectId}'`,
          400,
          'INVALID_OBJECT_ID',
        );
      }
      const capGeneration = Number(url.searchParams.get('generation') ?? '0');
      if (!Number.isInteger(capGeneration) || capGeneration < 0) {
        throw new LockerError('generation must be a non-negative integer', 400, 'INVALID_GENERATION');
      }

      const capabilityHeader = req.headers['x-locker-capability'];
      if (typeof capabilityHeader !== 'string' || capabilityHeader.length === 0) {
        throw new LockerError(
          'X-Locker-Capability header is required for a capability read',
          400,
          'MISSING_CAPABILITY',
        );
      }
      let tokenJson: unknown;
      try {
        tokenJson = JSON.parse(Buffer.from(capabilityHeader, 'base64url').toString('utf8'));
      } catch (error) {
        throw new LockerError(
          `X-Locker-Capability header is not valid base64url JSON: ${
            error instanceof Error ? error.message : String(error)
          }`,
          400,
          'MALFORMED_CAPABILITY',
        );
      }

      const outcome = await verifyLockerCapability({
        token: tokenJson,
        callerDid: did,
        requestedObjectId,
        resolverUrl: deps.config.didResolverUrl,
        resolverTimeoutMs: deps.config.didResolverTimeoutMs,
        db: deps.db,
        subjectPepper: deps.config.subjectPepper,
      });

      if (!outcome.ok) {
        console.error(
          JSON.stringify({
            level: 'warn',
            event: 'locker_capability_refused',
            step: outcome.step,
            reason: outcome.internalReason,
          }),
        );
        sendJson(res, outcome.httpStatus, { error: 'capability refused', code: outcome.publicCode });
        return;
      }

      const holderKey = objectKey(outcome.holderSubjectRef, requestedObjectId, capGeneration);
      const stored = await getObject(deps.s3, deps.config.s3Bucket, holderKey);
      if (!stored) {
        // SAME SHAPE as any of the six checks failing (§6): an officer must
        // not be able to tell "your capability is bad" apart from "that
        // object doesn't exist under this subject", which is exactly the
        // distinction step 6 exists to make unconstructable.
        sendJson(res, 403, { error: 'capability refused', code: 'CAPABILITY_REFUSED' });
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': stored.length,
        'X-Locker-Object-Hash': sha256Hex(stored),
      });
      res.end(stored);
      return;
    }

    if (parts[1] !== 'objects') {
      sendJson(res, 404, { error: 'not found', code: 'NOT_FOUND' });
      return;
    }

    // GET /v1/objects — list
    if (method === 'GET' && parts.length === 2) {
      const objects = await listObjects(deps.s3, deps.config.s3Bucket, objectPrefix(subjectRef));
      sendJson(res, 200, {
        // The subjectRef prefix is stripped: it is our bookkeeping, not the
        // caller's business, and echoing it invites clients to depend on it.
        objects: objects.map((item) => ({
          key: item.key.slice(`${subjectRef}/objects/`.length),
          size: item.size,
          lastModified: item.lastModified,
        })),
      });
      return;
    }

    const objectId = parts[2] ? decodeURIComponent(parts[2]) : '';
    if (!objectId || objectId.includes('/') || objectId.includes('..')) {
      throw new LockerError(
        `invalid object id '${objectId}'. Refusing anything that could traverse out of the ` +
          "subject's own prefix.",
        400,
        'INVALID_OBJECT_ID',
      );
    }
    const generation = Number(url.searchParams.get('generation') ?? '0');
    if (!Number.isInteger(generation) || generation < 0) {
      throw new LockerError('generation must be a non-negative integer', 400, 'INVALID_GENERATION');
    }
    const key = objectKey(subjectRef, objectId, generation);

    // PUT /v1/objects/:objectId — single shot
    if (method === 'PUT' && parts.length === 3) {
      const body = await readBody(req, deps.config.policy.maxObjectBytes);
      if (body.length === 0) {
        throw new LockerError('refusing to store a zero-byte object', 400, 'EMPTY_BODY');
      }
      assertDeclaredHash(req, body);
      await assertWithinQuota(
        deps.s3,
        deps.config.s3Bucket,
        subjectRef,
        body.length,
        deps.config.policy.quotaBytesPerSubject,
      );
      await putObject(deps.s3, deps.config.s3Bucket, key, body);

      // The holder may file a handle pointer at their OWN object, so a future
      // handset can find it with a phone number and a passphrase. Written here,
      // inside an authenticated write, so only the subject can create a pointer
      // and only to something they own. Keystore only: the datastore has no
      // recovery role and a pointer there would be an invitation.
      const recoveryHandle = req.headers['x-locker-recovery-handle'];
      if (typeof recoveryHandle === 'string' && recoveryHandle.length > 0) {
        if (deps.config.policy.role !== 'keystore') {
          throw new LockerError(
            'a recovery handle may only be filed against the keystore',
            400,
            'RECOVERY_HANDLE_WRONG_ROLE',
          );
        }
        putRecoveryIndex(deps.db, {
          handleRef: handleRef(recoveryHandle, deps.config.subjectPepper),
          subjectRef,
          did,
          objectId,
          // Record the generation this landed at. Reconstructing the key with a
          // fixed `/v1` missed every FIRST write, because generations start at 0.
          generation,
        });
      }

      sendJson(res, 201, { objectId, generation, size: body.length, contentHash: sha256Hex(body) });
      return;
    }

    // GET /v1/objects/:objectId — read back
    if (method === 'GET' && parts.length === 3) {
      const stored = await getObject(deps.s3, deps.config.s3Bucket, key);
      if (!stored) {
        sendJson(res, 404, { error: 'object not found', code: 'OBJECT_NOT_FOUND' });
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': stored.length,
        // The caller re-verifies this against its own AES-GCM tag. Ours is a
        // transport check, never the security boundary.
        'X-Locker-Object-Hash': sha256Hex(stored),
      });
      res.end(stored);
      return;
    }

    // DELETE /v1/objects/:objectId — erase with a receipt
    if (method === 'DELETE' && parts.length === 3) {
      const head = await headObject(deps.s3, deps.config.s3Bucket, key);
      if (!head) {
        sendJson(res, 404, { error: 'object not found', code: 'OBJECT_NOT_FOUND' });
        return;
      }
      await deleteObject(deps.s3, deps.config.s3Bucket, key);
      const receipt = recordReceipt(deps.db, {
        kind: 'ERASURE',
        subjectRef,
        objectKey: key,
        byteCount: head.size,
        actorRef: 'subject',
        reason: 'subject-requested erasure',
      });
      sendJson(res, 200, receipt);
      return;
    }

    // ---- multipart -------------------------------------------------------
    if (parts[3] === 'multipart') {
      if (!deps.config.policy.allowsMultipart) {
        throw new LockerError(
          `the ${deps.config.policy.role} role does not offer multipart upload: its objects are ` +
            'orders of magnitude below any sane part size, so a multipart write here is a ' +
            'caller bug, and accepting it would mean carrying interrupted-upload residue in ' +
            'the one store a recovery cannot do without.',
          409,
          'MULTIPART_NOT_ALLOWED',
        );
      }

      // POST .../multipart — begin
      if (method === 'POST' && parts.length === 4) {
        const body = await readJson(req);
        const declaredHash = typeof body.contentHash === 'string' ? body.contentHash : '';
        if (!/^[0-9a-f]{64}$/.test(declaredHash)) {
          throw new LockerError(
            'body.contentHash must be the sha256 hex of the complete plaintext-side ciphertext. ' +
              'It is recorded now so completion can be checked against an intent formed BEFORE ' +
              'any part was sent.',
            400,
            'INVALID_CONTENT_HASH',
          );
        }
        const handle = await beginMultipart(deps.s3, deps.config.s3Bucket, key);
        // INTENT BEFORE ACTION. Written before a single part is sent, so an
        // interrupted upload leaves a countable record rather than an orphan
        // only object storage knows about.
        recordUploadIntent(deps.db, {
          uploadId: handle.uploadId,
          subjectRef,
          objectKey: key,
          declaredHash,
        });
        sendJson(res, 201, {
          uploadId: handle.uploadId,
          minPartBytes: MIN_PART_BYTES,
          objectId,
          generation,
        });
        return;
      }

      const uploadId = parts[4] ? decodeURIComponent(parts[4]) : '';
      if (!uploadId) {
        throw new LockerError('missing upload id', 400, 'INVALID_UPLOAD_ID');
      }

      // PUT .../multipart/:uploadId/parts/:n
      if (method === 'PUT' && parts[5] === 'parts' && parts[6]) {
        const partNumber = Number(parts[6]);
        if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
          throw new LockerError('part number must be 1..10000', 400, 'INVALID_PART_NUMBER');
        }
        const body = await readBody(req, deps.config.policy.maxObjectBytes);
        if (body.length === 0) {
          throw new LockerError('refusing an empty part', 400, 'EMPTY_PART');
        }
        const uploaded = await uploadPart(
          deps.s3,
          deps.config.s3Bucket,
          { uploadId, key },
          partNumber,
          body,
        );
        sendJson(res, 200, uploaded);
        return;
      }

      // POST .../multipart/:uploadId/complete
      if (method === 'POST' && parts[5] === 'complete') {
        const body = await readJson(req);
        const claimed = Array.isArray(body.parts) ? body.parts : null;
        if (!claimed) {
          throw new LockerError('body.parts must be an array', 400, 'INVALID_BODY');
        }
        const expectedParts = claimed.map((entry) => {
          const part = entry as { partNumber?: unknown; etag?: unknown };
          if (typeof part.partNumber !== 'number' || typeof part.etag !== 'string') {
            throw new LockerError(
              'each part needs a numeric partNumber and a string etag',
              400,
              'INVALID_PART',
            );
          }
          return { partNumber: part.partNumber, etag: part.etag };
        });

        try {
          // Re-establishes its precondition from observable state (#315):
          // asks storage which parts actually landed rather than trusting
          // that the upload phase did what it said.
          await completeMultipart(deps.s3, deps.config.s3Bucket, { uploadId, key }, expectedParts);
        } catch (error) {
          // PERSIST NOTHING ON PARTIAL FAILURE. A refused completion leaves no
          // object in the namespace at all — S3 only materialises it on
          // Complete — and the intent is marked ABANDONED so the reaper will
          // collect the parts and count them.
          settleUploadIntent(deps.db, uploadId, 'ABANDONED');
          throw error;
        }

        settleUploadIntent(deps.db, uploadId, 'COMMITTED');
        const head = await headObject(deps.s3, deps.config.s3Bucket, key);
        sendJson(res, 201, { objectId, generation, size: head?.size ?? 0 });
        return;
      }

      // DELETE .../multipart/:uploadId — caller-initiated abort
      if (method === 'DELETE' && parts.length === 5) {
        await abortMultipart(deps.s3, deps.config.s3Bucket, { uploadId, key });
        settleUploadIntent(deps.db, uploadId, 'ABANDONED');
        sendJson(res, 204, undefined);
        return;
      }
    }

    sendJson(res, 404, { error: 'not found', code: 'NOT_FOUND' });
  } catch (error) {
    if (error instanceof LockerError) {
      sendJson(res, error.httpStatus, { error: error.message, code: error.code });
      return;
    }
    throw error;
  }
}

/**
 * The caller declares what it is sending and we check it.
 *
 * This is a TRANSPORT integrity check, not the security boundary — AES-GCM's
 * own tag is that, and it is verified on the wallet where the key lives. What
 * this buys is a loud failure at write time instead of a silent one discovered
 * at restore, which is the same reasoning as the Phase C vault's server-side
 * hash recomputation.
 */
function assertDeclaredHash(req: IncomingMessage, body: Buffer): void {
  const declared = req.headers['x-locker-object-hash'];
  if (typeof declared !== 'string') {
    throw new LockerError(
      'X-Locker-Object-Hash header is required on writes. A write whose content nobody ' +
        'declared cannot be checked, and an unchecked write is discovered wrong at restore.',
      400,
      'MISSING_CONTENT_HASH',
    );
  }
  const actual = sha256Hex(body);
  if (declared.toLowerCase() !== actual) {
    throw new LockerError(
      `declared hash ${declared} does not match the ${actual} actually received. Refusing a ` +
        'write that does not match its own declaration.',
      400,
      'CONTENT_HASH_MISMATCH',
    );
  }
}

/**
 * Periodic housekeeping. Exported so the entrypoint owns the schedule, and it
 * RETURNS the reap summary so the caller can log what was reclaimed — residue
 * that is reaped but never reported is only half of "keep residue countable".
 */
export async function runHousekeeping(deps: ServerDeps) {
  const sessionsPruned = deps.sessions.prune();
  const reaped = await reapAbandonedUploads({
    client: deps.s3,
    db: deps.db,
    bucket: deps.config.s3Bucket,
    ttlMs: abandonedUploadTtlMs(deps.config),
  });
  return { sessionsPruned, ...reaped };
}
