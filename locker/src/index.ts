/**
 * Locker entrypoint.
 *
 * BIND ADDRESS — 0.0.0.0 INSIDE the container, deliberately (#333). Binding to
 * 127.0.0.1 inside a container makes the service unreachable through Docker's
 * port publishing, because publishing forwards from the host to the
 * container's BRIDGE interface, not into the container's loopback. The
 * container reports healthy and refuses everything. The container's network
 * namespace is already the isolation boundary; the compose file's
 * `127.0.0.1:<port>:<port>` mapping is the one place that decides whether the
 * HOST exposes this further.
 */

import { loadConfig } from './config.js';
import { openDatabase, pruneChallenges } from './db.js';
import { SessionStore } from './didAuth.js';
import { createS3Client } from './objectStore.js';
import { createLockerServer, runHousekeeping, type ServerDeps } from './server.js';

const CHALLENGE_RETENTION_MS = 24 * 60 * 60 * 1000;

function log(event: string, fields: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

const config = loadConfig();
const db = openDatabase(config.dbPath);
const s3 = createS3Client(config);
const sessions = new SessionStore();

const deps: ServerDeps = {
  config,
  db,
  s3,
  sessions,
  // This locker's identity, and what a wallet must name as `aud`. Defaults to
  // the role plus the bucket so that two deployments on one host are never
  // interchangeable audiences by accident.
  audience: process.env.LOCKER_AUDIENCE ?? `bdhealthtrust:locker:${config.policy.role}:${config.s3Bucket}`,
};

const server = createLockerServer(deps);

server.listen(config.port, '0.0.0.0', () => {
  log('locker_listening', {
    role: config.policy.role,
    port: config.port,
    bucket: config.s3Bucket,
    endpoint: config.s3Endpoint,
    audience: deps.audience,
    db: config.dbPath,
    housekeepingIntervalMs: config.housekeepingIntervalMs,
  });
});

const housekeeping = setInterval(() => {
  void runHousekeeping(deps)
    .then((summary) => {
      const pruned = pruneChallenges(db, CHALLENGE_RETENTION_MS);
      if (summary.inspected > 0 || summary.aborted > 0 || pruned > 0) {
        log('housekeeping', { ...summary, challengesPruned: pruned });
      }
    })
    .catch((error: unknown) => {
      // Housekeeping failure must never take the server down — a locker that
      // stops serving because its reaper hiccuped has converted a disk-space
      // concern into an outage.
      log('housekeeping_failed', {
        error: error instanceof Error ? error.message : String(error),
      });
    });
}, config.housekeepingIntervalMs);
housekeeping.unref();

function shutdown(signal: string): void {
  log('locker_shutting_down', { signal });
  clearInterval(housekeeping);
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
