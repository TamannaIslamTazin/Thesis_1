/**
 * Reset an account whose DID predates device-held keys, so it enrols again.
 *
 * WHY THIS EXISTS. DIDs minted before `rotateVerificationMethod` cleared the
 * local key mapping left the agent still answering `agentSigner` for a key that
 * is no longer on chain — it would sign, and the signature would not verify.
 * Those accounts cannot authenticate by DID and cannot be repaired in place:
 * the key on chain is the device's, and this backend does not have it.
 *
 * So the account is returned to the pre-enrolment state and mints a fresh DID
 * through the gate. Nothing on chain is touched: the old DID is left where it
 * is, deactivating it would need signatures we do not hold, and an orphaned
 * identifier nobody references is inert.
 *
 * REFUSES if the account holds credentials, because those are stored against
 * the old DID and would be orphaned silently — the exact failure the
 * non-idempotent wallet setup produced. Move them first, or decide explicitly.
 *
 *   npx tsx tools/resetStaleEnrolment.ts <email|userId> [--apply]
 */
import { db, disconnectDatabase } from '../src/db/index.js';

async function main() {
  const target = process.argv[2];
  const apply = process.argv.includes('--apply');
  if (!target) throw new Error('usage: resetStaleEnrolment.ts <email|userId> [--apply]');

  try {
    const user = await db.user.findFirst({
      where: { OR: [{ email: target }, { id: target }] },
      select: { id: true, email: true, did: true, walletSetup: true },
    });
    if (!user) throw new Error(`No account matches '${target}'.`);

    const credentials = user.did
      ? await db.credential.count({ where: { holderDid: user.did } })
      : 0;

    console.log(JSON.stringify({ ...user, credentialsHeld: credentials }, null, 2));

    if (credentials > 0) {
      console.log(
        `\nREFUSING: ${credentials} credential(s) are stored against the old DID and would be ` +
          'orphaned. Reassign or withdraw them first.',
      );
      process.exit(2);
    }

    if (!apply) {
      console.log('\nDry run. Re-run with --apply to clear did/walletSetup.');
      process.exit(0);
    }

    await db.user.update({
      where: { id: user.id },
      data: { did: null, walletSetup: false },
    });
    console.log(`\nCleared. '${user.email ?? user.id}' will enrol again and mint a device-held key.`);
  } finally {
    await disconnectDatabase();
  }
}

main().catch((error) => {
  console.error('ERR', (error as Error)?.message ?? error);
  process.exit(1);
});
