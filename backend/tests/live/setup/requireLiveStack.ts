/**
 * Refuse to run the live suite against a stack that is not actually there.
 *
 * WHY THIS IS A HARD FAILURE AND NOT A SKIP. A skipped test reports green.
 * The entire reason this suite is split in two is so that "the fast half
 * passed" and "the properties that need a real chain were verified" are
 * DIFFERENT, VISIBLE statements. A live suite that silently self-skips when the
 * validator is stopped collapses them back into one, and would let someone
 * report a clean run having exercised nothing — which is precisely the class of
 * false pass this project keeps finding in its own code.
 *
 * So: no `describe.skipIf`, no environment sniffing that downgrades to a
 * no-op. If the stack is missing, the process exits non-zero with instructions.
 */
// Load packages/backend/.env exactly as the dev server and every probe do.
// NOT shell-sourceable: it contains unquoted values with `<` and `>`, so
// `set -a && . ./.env` fails. Loading it here means `pnpm test:live` works
// without the caller having to know that.
import 'dotenv/config';
import { beforeAll } from 'vitest';

const RPC_URL = process.env.CHEQD_RPC_URL ?? 'http://localhost:26657';
const EXPECTED_CHAIN_ID = process.env.LIVE_TEST_CHAIN_ID ?? 'bd-health-trust-1';

function fail(what: string, remedy: string): never {
  throw new Error(
    `LIVE SUITE PRECONDITION FAILED — ${what}\n\n` +
      `  ${remedy}\n\n` +
      'These tests are not skippable. They exist to prove things about a real ' +
      'chain and a real database; running them without one would report a pass ' +
      'for work that never happened. Start the stack or run `pnpm test:fast` ' +
      'instead and say so.',
  );
}

async function assertChainIsProducingBlocks(): Promise<void> {
  let status: {
    result?: {
      node_info?: { network?: string };
      sync_info?: { latest_block_height?: string; catching_up?: boolean };
    };
  };

  try {
    const response = await fetch(`${RPC_URL}/status`, {
      signal: AbortSignal.timeout(10_000),
    });
    status = (await response.json()) as typeof status;
  } catch (error) {
    fail(
      `the cheqd localnet is not reachable at ${RPC_URL} (${
        error instanceof Error ? error.message : String(error)
      })`,
      'cd /home/ahsan/Work/Project/BDHealthTrust/cheqd-localnet && docker compose up -d',
    );
  }

  const network = status.result?.node_info?.network;
  if (network !== EXPECTED_CHAIN_ID) {
    fail(
      `the chain at ${RPC_URL} identifies as '${network}', not '${EXPECTED_CHAIN_ID}'`,
      'You are pointed at the wrong chain. Check CHEQD_RPC_URL — verifying against ' +
        'public cheqd instead of our fork would make every assertion here meaningless.',
    );
  }

  if (status.result?.sync_info?.catching_up !== false) {
    fail('the chain is still catching up', 'Wait for `catching_up: false` and retry.');
  }

  // Blocks must be ADVANCING, not merely present. A halted validator still
  // answers /status with its last height.
  const first = Number(status.result?.sync_info?.latest_block_height ?? 0);
  await new Promise((resolve) => setTimeout(resolve, 6_000));
  const second = Number(
    (
      (await (await fetch(`${RPC_URL}/status`, { signal: AbortSignal.timeout(10_000) })).json()) as typeof status
    ).result?.sync_info?.latest_block_height ?? 0,
  );

  if (!(second > first)) {
    fail(
      `the chain is not producing blocks (height stuck at ${first})`,
      'docker logs bd-health-trust-validator-0 --tail 50',
    );
  }
}

async function assertDatabaseIsMigrated(): Promise<void> {
  if (!process.env.DATABASE_URL) {
    fail('DATABASE_URL is not set', 'Load packages/backend/.env before running the live suite.');
  }

  const { db } = await import('../../../src/db/index.js');
  try {
    // Touching a table the suite actually uses proves reachability AND that the
    // schema is applied, which a bare `SELECT 1` would not.
    await db.credential.count();
    await db.presentation.count();
  } catch (error) {
    fail(
      `Postgres is unreachable or unmigrated (${
        error instanceof Error ? error.message : String(error)
      })`,
      'cd packages/backend && pnpm prisma migrate deploy',
    );
  }
}

beforeAll(async () => {
  await assertChainIsProducingBlocks();
  await assertDatabaseIsMigrated();
}, 120_000);
