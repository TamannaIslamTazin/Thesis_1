/**
 * What "verified" means (IDENTITY-VERIFICATION-API.md §6).
 *
 * A user is verified when they hold a valid, unrevoked health-card credential
 * from the ministry DID — computed from `Credential`, never from a
 * `User.identityVerified` column. A boolean column would recreate exactly the
 * defect this round exists to remove: a flag that can read "verified" without
 * anything having verified it. See `GET /api/users/me` in `routes/users.ts`
 * for the one place this is currently read.
 */

import { db } from '../db/index.js';
import { HEALTH_CARD_CREDENTIAL_TYPE, MINISTRY_OF_HEALTH } from '@ssi-healthcare/shared';

/**
 * Whether `holderDid` currently holds a valid, unrevoked health-card
 * credential issued by the ministry DID.
 *
 * Reads `Credential.status`, which is this system's OWN authoritative record
 * of revocation, not a cache of one. `CredentialStatusList`'s own schema
 * comment is explicit that the on-chain bitstring is regenerated FROM this
 * column on every publish — so checking `status` here is checking the source
 * the ledger copy is published from, not a value that could be stale relative
 * to it. This is the "server-side" checking IDENTITY-VERIFICATION-API.md §6
 * names as the interim answer until on-device revocation checking is
 * unblocked (SYSTEM_DESIGN.md §9's gzip floor).
 */
export async function isIdentityVerified(holderDid: string, at: Date = new Date()): Promise<boolean> {
  const healthCard = await db.credential.findFirst({
    where: {
      holderDid,
      issuerDid: MINISTRY_OF_HEALTH.did,
      type: { has: HEALTH_CARD_CREDENTIAL_TYPE },
      status: 'ACTIVE',
      OR: [{ expiresAt: null }, { expiresAt: { gt: at } }],
    },
    select: { id: true },
  });
  return healthCard !== null;
}
