/**
 * Raise a real break-glass grant against a patient, for observing the wallet.
 *
 * Deliberately a tool and not a test fixture: it writes a genuine record through
 * the same service a provider would, so what the handset shows is the real
 * thing rather than a seeded row that happens to look like one.
 *
 *   npx tsx tools/raiseEmergencyGrant.ts <patientDid>
 */
import { createAgent, shutdownAgent } from '../src/agent/index.js';
import { requestEmergencyAccess } from '../src/services/emergencyService.js';
import { db } from '../src/db/index.js';

async function main() {
  const patientDid = process.argv[2];
  if (!patientDid) throw new Error('usage: raiseEmergencyGrant.ts <patientDid>');
  await createAgent();

  const creds = await db.credential.findMany({
    where: { holderDid: patientDid },
    select: { id: true },
    orderBy: { issuedAt: 'desc' },
    take: 1,
  });
  if (creds.length === 0) throw new Error('patient holds no credentials');

  const record = await requestEmergencyAccess({
    providerDid: 'did:cheqd:bdhealthtestnet:e12e1111-0000-4000-8000-000000000001',
    providerName: 'Dhaka Medical College ER',
    patientDid,
    reason: 'Unconscious road traffic casualty, no identification, needs blood type before transfusion',
    credentialIds: creds.map((c) => c.id),
  });

  console.log(`grant ${record.id} — status ${record.status}, expires ${record.expiresAt}`);
  await shutdownAgent();
  process.exit(0);
}
void main();
