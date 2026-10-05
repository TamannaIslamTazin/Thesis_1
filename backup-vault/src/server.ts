/**
 * R5 Phase C — the vault's HTTP surface. Deliberately hand-rolled on
 * `node:http` rather than a framework dependency: five routes over one
 * resource do not need a router library, and every added dependency is
 * another thing running inside the process that is supposed to be the
 * smallest thing that satisfies the brief's three properties.
 *
 * Routes (all require `Authorization: Bearer <VAULT_SHARED_SECRET>`):
 *   POST   /v1/patients/:did/policy
 *   PUT    /v1/patients/:did/shares/:index
 *   GET    /v1/patients/:did/shares/:index
 *   GET    /v1/patients/:did/shares
 *   DELETE /v1/patients/:did/shares/:index
 *   DELETE /v1/patients/:did
 *   GET    /healthz   (no auth — matches the localnet convention of a cheap,
 *                       unauthenticated liveness check)
 */

import type { DatabaseSync } from 'node:sqlite';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import { isAuthorised } from './auth.js';
import {
  VaultError,
  depositShare,
  erasePatient,
  eraseShare,
  getShare,
  listShares,
  registerPolicy,
} from './db.js';

const MAX_BODY_BYTES = 64 * 1024; // shares are a few hundred bytes; this is generous, not tight

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > MAX_BODY_BYTES) {
      throw new VaultError(`request body exceeds ${MAX_BODY_BYTES} bytes`, 413, 'BODY_TOO_LARGE');
    }
    chunks.push(chunk as Buffer);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new VaultError('request body is not valid JSON', 400, 'INVALID_JSON');
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  if (body === undefined) {
    // 204 and similar: HTTP forbids a body on these regardless of what the
    // caller passed, so this is not a special case worth a second code path.
    res.writeHead(status);
    res.end();
    return;
  }
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
  res.end(payload);
}

function parseIndex(raw: string | undefined): number {
  const index = Number(raw);
  if (!Number.isInteger(index) || index < 0) {
    throw new VaultError(`invalid share index '${raw}'`, 400, 'INVALID_INDEX');
  }
  return index;
}

export function createVaultServer(db: DatabaseSync, sharedSecret: string, pepperKey: string) {
  return createServer((req, res) => {
    void handle(db, sharedSecret, pepperKey, req, res).catch((error) => {
      // A handler bug must still fail closed with a response, not hang the socket.
      console.error('vault_unhandled_error', error);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal error', code: 'INTERNAL' });
    });
  });
}

async function handle(
  db: DatabaseSync,
  sharedSecret: string,
  pepperKey: string,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://internal');
  const method = req.method ?? 'GET';
  const parts = url.pathname.split('/').filter(Boolean); // ['v1','patients',':did', ...]

  if (method === 'GET' && url.pathname === '/healthz') {
    sendJson(res, 200, { status: 'ok' });
    return;
  }

  if (!isAuthorised(req.headers.authorization, sharedSecret)) {
    sendJson(res, 401, { error: 'unauthorised', code: 'UNAUTHORISED' });
    return;
  }

  try {
    if (parts[0] !== 'v1' || parts[1] !== 'patients' || !parts[2]) {
      sendJson(res, 404, { error: 'not found', code: 'NOT_FOUND' });
      return;
    }
    const recoveryControllerDid = decodeURIComponent(parts[2]);

    // POST /v1/patients/:did/policy
    if (method === 'POST' && parts[3] === 'policy' && parts.length === 4) {
      const body = (await readBody(req)) as { threshold?: unknown };
      if (typeof body.threshold !== 'number') {
        throw new VaultError('body.threshold must be a number', 400, 'INVALID_BODY');
      }
      registerPolicy(db, recoveryControllerDid, body.threshold);
      sendJson(res, 204, undefined);
      return;
    }

    // .../shares[/:index]
    if (parts[3] === 'shares') {
      // PUT /v1/patients/:did/shares/:index
      if (method === 'PUT' && parts[4]) {
        const index = parseIndex(parts[4]);
        const body = (await readBody(req)) as {
          nonce?: unknown;
          ciphertext?: unknown;
          contentHash?: unknown;
        };
        if (
          typeof body.nonce !== 'string' ||
          typeof body.ciphertext !== 'string' ||
          typeof body.contentHash !== 'string'
        ) {
          throw new VaultError('body must have string nonce, ciphertext, contentHash', 400, 'INVALID_BODY');
        }
        const result = depositShare(db, {
          recoveryControllerDid,
          index,
          nonce: body.nonce,
          ciphertext: body.ciphertext,
          contentHash: body.contentHash,
        });
        sendJson(res, result.rewrapped ? 200 : 201, result);
        return;
      }

      // GET /v1/patients/:did/shares/:index
      if (method === 'GET' && parts[4]) {
        const index = parseIndex(parts[4]);
        const share = getShare(db, recoveryControllerDid, index);
        if (!share) {
          sendJson(res, 404, { error: 'share not found', code: 'SHARE_NOT_FOUND' });
          return;
        }
        sendJson(res, 200, share);
        return;
      }

      // DELETE /v1/patients/:did/shares/:index
      if (method === 'DELETE' && parts[4]) {
        const index = parseIndex(parts[4]);
        const body = (await readBody(req)) as { deletedByActorRef?: unknown; reason?: unknown };
        const deletedByActorRef = typeof body.deletedByActorRef === 'string' ? body.deletedByActorRef : 'unknown';
        const reason = typeof body.reason === 'string' ? body.reason : 'unspecified';
        const receipt = eraseShare(db, {
          recoveryControllerDid,
          index,
          deletedByActorRef,
          reason,
          pepperKey,
        });
        sendJson(res, 200, receipt);
        return;
      }

      // GET /v1/patients/:did/shares
      if (method === 'GET' && parts.length === 4) {
        sendJson(res, 200, { shares: listShares(db, recoveryControllerDid) });
        return;
      }
    }

    // DELETE /v1/patients/:did  (full erasure)
    if (method === 'DELETE' && parts.length === 3) {
      const body = (await readBody(req)) as { deletedByActorRef?: unknown; reason?: unknown };
      const deletedByActorRef = typeof body.deletedByActorRef === 'string' ? body.deletedByActorRef : 'unknown';
      const reason = typeof body.reason === 'string' ? body.reason : 'unspecified';
      const receipts = erasePatient(db, {
        recoveryControllerDid,
        deletedByActorRef,
        reason,
        pepperKey,
      });
      sendJson(res, 200, { receipts });
      return;
    }

    sendJson(res, 404, { error: 'not found', code: 'NOT_FOUND' });
  } catch (error) {
    if (error instanceof VaultError) {
      sendJson(res, error.httpStatus, { error: error.message, code: error.code });
      return;
    }
    throw error;
  }
}
