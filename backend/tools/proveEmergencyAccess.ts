/**
 * Prove break-glass emergency access grants, enforces, expires and revokes.
 *
 * The property under test is NOT "a record was written". Before today a grant
 * wrote a row and conferred no access at all — `checkEmergencyAccess` had one
 * caller, its own route, and no credential read path consulted it. So every
 * assertion below pairs a refusal with the success it refuses against; a suite
 * that only checks refusals passes perfectly against code that refuses
 * everything (#345, #347).
 *
 *   npx tsx tools/proveEmergencyAccess.ts <patientDid>
 */
import { createAgent, shutdownAgent } from '../src/agent/index.js';
import {
  requestEmergencyAccess,
  readEmergencyCredentials,
  revokeEmergencyAccess,
  checkEmergencyAccess,
} from '../src/services/emergencyService.js';
import { db } from '../src/db/index.js';

const PROVIDER = 'did:cheqd:bdhealthtestnet:e12e1111-0000-4000-8000-000000000001';
const OTHER_PROVIDER = 'did:cheqd:bdhealthtestnet:e12e2222-0000-4000-8000-000000000002';

let pass = 0;
let fail = 0;
const assert = (label: string, ok: boolean, detail = '') => {
  if (ok) { pass++; console.log(`  PASS  ${label}${detail ? ` — ${detail}` : ''}`); }
  else { fail++; console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`); }
};

async function refuses(label: string, fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    assert(label, false, 'it RETURNED DATA instead of refusing');
    return '';
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    assert(label, true, msg.slice(0, 70));
    return msg;
  }
}

async function main() {
  const patientDid = process.argv[2];
  if (!patientDid) throw new Error('usage: proveEmergencyAccess.ts <patientDid>');
  await createAgent();

  const all = await db.credential.findMany({
    where: { holderDid: patientDid },
    select: { id: true },
    orderBy: { issuedAt: 'desc' },
  });
  if (all.length < 2) throw new Error(`patient needs >= 2 credentials, has ${all.length}`);
  const granted = [all[0]!.id];
  const withheld = all.slice(1).map((c) => c.id);

  console.log('\n=== BEFORE ANY GRANT — a read must be refused ===\n');
  await refuses('reading with no grant at all is refused', () =>
    readEmergencyCredentials({ providerDid: PROVIDER, patientDid }));

  console.log('\n=== THE GRANT ===\n');
  const record = await requestEmergencyAccess({
    providerDid: PROVIDER,
    providerName: 'Dhaka Medical College ER',
    patientDid,
    reason: 'Unconscious patient, no ID, needs allergy and blood type before transfusion',
    credentialIds: granted,
  });
  assert('access is GRANTED without patient approval', record.status === 'granted', record.status);
  assert('it is time-boxed', Boolean(record.expiresAt),
    `expires ${new Date(record.expiresAt!).toISOString()}`);

  console.log('\n  --- the honesty fix ---');
  assert('familyNotifiedAt is NOT stamped, because nothing notifies anyone',
    record.familyNotifiedAt === undefined,
    'it used to be set to now() whenever a contact DID was supplied');

  const grantLog = await db.auditLog.findFirst({
    where: { actorDid: PROVIDER, targetDid: patientDid },
    orderBy: { timestamp: 'desc' },
  });
  const gd = (grantLog?.details ?? {}) as Record<string, unknown>;
  assert('the audit entry says notification was NOT delivered',
    gd.familyNotificationDelivered === false && gd.familyNotificationChannel === 'NOT_IMPLEMENTED');
  assert('and records the grant model plainly', gd.grantModel === 'AUTO_GRANT_ON_SIGNED_REQUEST');

  console.log('\n=== WITH THE GRANT — the read must now SUCCEED ===\n');
  const read = await readEmergencyCredentials({ providerDid: PROVIDER, patientDid });
  assert('the provider can now read', read.credentials.length > 0,
    `${read.credentials.length} credential(s)`);
  const readIds = (read.credentials as Array<{ id: string }>).map((c) => c.id);
  assert('...exactly the credentials the grant named',
    readIds.length === granted.length && readIds.every((id) => granted.includes(id)));
  assert('...and NOTHING outside the grant',
    !readIds.some((id) => withheld.includes(id)),
    `${withheld.length} other credential(s) were not returned`);

  console.log('\n=== THE READ IS LOGGED SEPARATELY FROM THE GRANT ===\n');
  const readLog = await db.auditLog.findFirst({
    where: { actorDid: PROVIDER, targetDid: patientDid, action: { contains: 'Emergency READ' } },
    orderBy: { timestamp: 'desc' },
  });
  assert('a per-READ audit entry exists', Boolean(readLog), readLog?.action ?? 'none');
  const rd = (readLog?.details ?? {}) as Record<string, unknown>;
  assert('it names what was actually read, not merely what was allowed',
    Array.isArray(rd.credentialIdsRead) && (rd.credentialIdsRead as string[]).length > 0);
  assert('and records that an emergency read is FULL disclosure', rd.disclosure === 'FULL');

  console.log('\n=== ANOTHER PROVIDER CANNOT SPEND THIS GRANT ===\n');
  await refuses('a different provider is refused the same patient', () =>
    readEmergencyCredentials({ providerDid: OTHER_PROVIDER, patientDid }));

  console.log('\n=== REVOCATION ACTUALLY STOPS THE READ ===\n');
  await revokeEmergencyAccess(record.id, patientDid);
  const afterRevoke = await checkEmergencyAccess(PROVIDER, patientDid);
  assert('the grant is no longer active', !afterRevoke.isActive);
  await refuses('the read is refused after revocation', () =>
    readEmergencyCredentials({ providerDid: PROVIDER, patientDid }));

  console.log('\n=== EXPIRY ALSO STOPS IT (a grant nobody revoked) ===\n');
  const second = await requestEmergencyAccess({
    providerDid: PROVIDER,
    providerName: 'Dhaka Medical College ER',
    patientDid,
    reason: 'Second admission, same night, checking expiry behaviour end to end',
    credentialIds: granted,
  });
  const beforeExpiry = await readEmergencyCredentials({ providerDid: PROVIDER, patientDid });
  assert('it reads while still valid', beforeExpiry.credentials.length > 0,
    'the success this expiry test refuses against');

  await db.emergencyAccessRecord.update({
    where: { id: second.id },
    data: { expiresAt: new Date(Date.now() - 60_000) },
  });
  await refuses('the read is refused once expired', () =>
    readEmergencyCredentials({ providerDid: PROVIDER, patientDid }));
  const expired = await db.emergencyAccessRecord.findUnique({ where: { id: second.id } });
  assert('and the record is marked EXPIRED, not left GRANTED',
    expired?.status === 'EXPIRED', String(expired?.status));

  console.log('\n=== THE REFUSAL IS ITSELF VISIBLE ===\n');
  const refusalLog = await db.auditLog.findFirst({
    where: { actorDid: PROVIDER, action: { contains: 'REFUSED' } },
    orderBy: { timestamp: 'desc' },
  });
  assert('a refused read is audited too', Boolean(refusalLog),
    'a probe for records you cannot reach must not be silent');

  console.log(`\n${'='.repeat(64)}`);
  console.log(`  ${pass} passed, ${fail} failed`);
  console.log(`${'='.repeat(64)}\n`);
  await shutdownAgent();
  process.exit(fail === 0 ? 0 : 1);
}

void main();
