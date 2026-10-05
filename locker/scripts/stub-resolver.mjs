/**
 * A controllable, cheqd-shaped DID resolver for the live verification run.
 *
 * ===========================================================================
 * WHY THIS RUNS IN A CONTAINER AND NOT IN THE TEST PROCESS
 * ===========================================================================
 * The obvious design — listen on the host, point the locker at
 * host.docker.internal — does not work on this machine. Measured: the compose
 * network's gateway (172.24.0.1) and docker0's (172.17.0.1) both time out from
 * inside a container, so the host firewall drops bridge-to-host traffic. (Host
 * networking is also in flux here; DNS and DHCP are not configured yet.)
 *
 * Running the stub as a container on the SAME compose network sidesteps all of
 * that: container-to-container traffic stays inside the bridge and never meets
 * the host firewall. It also makes the verification reproducible on a machine
 * with different firewall rules, which the host-gateway approach would not be.
 *
 * The test process still reaches this stub through a published port, exactly
 * the way it reaches the lockers.
 *
 * ===========================================================================
 * WHAT IT IS AND IS NOT EVIDENCE FOR
 * ===========================================================================
 * The keys are real Ed25519 keys and the documents carry real multibase
 * encodings, so the locker's signature verification, multicodec check,
 * authentication-relationship check and replay CAS are all genuinely
 * exercised.
 *
 * It is NOT evidence that we parse a real cheqd node's REST response shape
 * correctly. That remains unverified and is recorded as such — a stub cannot
 * prove agreement with a dependency it is impersonating.
 */

import { createServer } from 'node:http';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

const PORT = Number(process.env.STUB_PORT ?? '4599');

/**
 * Where registered subjects survive a restart.
 *
 * WHY THIS EXISTS. The map is in-memory, so any `docker start` emptied it and
 * every DID-authenticated locker session then failed until someone re-ran
 * packages/locker/scripts/bridge-did-to-stub.mjs — which needs the chain and
 * the backend up. That trap cost two sessions (#439, #474). A container's
 * writable layer outlives stop/start (only a recreate loses it), so a file
 * here makes bridging a per-DID cost instead of a per-restart one.
 */
const STATE_FILE = process.env.STUB_STATE_FILE ?? '/app/subjects.json';

/** did -> { didDocument, didDocumentMetadata } */
const subjects = new Map();

function loadSubjects() {
  try {
    if (!existsSync(STATE_FILE)) return;
    const stored = JSON.parse(readFileSync(STATE_FILE, 'utf8'));
    for (const [did, document] of Object.entries(stored)) subjects.set(did, document);
    console.log(`stub cheqd resolver restored ${subjects.size} subject(s) from ${STATE_FILE}`);
  } catch (error) {
    console.error(`stub cheqd resolver could not read ${STATE_FILE}: ${error.message}`);
  }
}

function saveSubjects() {
  try {
    writeFileSync(STATE_FILE, JSON.stringify(Object.fromEntries(subjects)));
  } catch (error) {
    console.error(`stub cheqd resolver could not write ${STATE_FILE}: ${error.message}`);
  }
}

loadSubjects();

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

createServer((req, res) => {
  void (async () => {
    const url = new URL(req.url ?? '/', 'http://stub');

    // Control plane, used by the verification script only.
    if (url.pathname === '/_control/subjects' && req.method === 'POST') {
      const body = await readJson(req);
      subjects.set(body.did, body.document);
      saveSubjects();
      send(res, 201, { registered: body.did, total: subjects.size });
      return;
    }
    if (url.pathname === '/_control/health') {
      send(res, 200, { status: 'ok', subjects: subjects.size });
      return;
    }

    // The cheqd Cosmos REST shape the locker's resolver expects.
    const match = /^\/cheqd\/did\/v2\/(.+)$/.exec(url.pathname);
    if (!match) {
      send(res, 404, {});
      return;
    }
    const did = decodeURIComponent(match[1]);
    const document = subjects.get(did);
    if (!document) {
      // A DID that was never written: the resolver ANSWERS, definitively.
      send(res, 404, {});
      return;
    }
    send(res, 200, document);
  })().catch(() => {
    if (!res.headersSent) send(res, 500, { error: 'stub failure' });
  });
}).listen(PORT, '0.0.0.0', () => {
  console.log(`stub cheqd resolver listening on 0.0.0.0:${PORT}`);
});
