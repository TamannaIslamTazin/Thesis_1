/**
 * R5 Phase C entrypoint.
 *
 * BIND ADDRESS, CORRECTED DURING PHASE 3. The first version of this file
 * bound to 127.0.0.1, on the reasoning that the process should enforce
 * loopback-only independently of the compose file. That reasoning is wrong
 * for a container: 127.0.0.1 inside a container is a private loopback
 * scoped to that container's own network namespace, and Docker's port
 * publishing forwards from the HOST's loopback to the container's BRIDGE
 * interface, not into the container's loopback. Binding to 127.0.0.1 here
 * made the service unreachable through `docker compose`'s port mapping at
 * all — confirmed by a `curl` that got "connection reset by peer" against a
 * container reporting itself healthy.
 *
 * The correct split (standard Docker practice, and what cheqd-localnet's own
 * validator container does): bind to every interface INSIDE the container,
 * because the container's network namespace is already the isolation
 * boundary — nothing else shares it. The docker-compose.yml port mapping
 * (`127.0.0.1:4530:4530`, not a bare `4530:4530`) is what actually decides
 * whether the HOST exposes this beyond its own loopback, and is the one
 * place that decision now lives. See the compose file's header comment.
 */

import { loadConfig } from './config.js';
import { openDatabase } from './db.js';
import { createVaultServer } from './server.js';

const config = loadConfig();
const db = openDatabase(config.dbPath);
const server = createVaultServer(db, config.sharedSecret, config.pepperKey);

server.listen(config.port, '0.0.0.0', () => {
  console.log(`backup-vault listening on 0.0.0.0:${config.port} (container-local), db=${config.dbPath}`);
});

function shutdown(signal: string): void {
  console.log(`backup-vault received ${signal}, closing`);
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
