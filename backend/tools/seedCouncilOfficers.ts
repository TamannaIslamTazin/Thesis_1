/**
 * Give each professional council its own reviewing officer.
 *
 * Until now only the ministry had one, so the issuer console was effectively a
 * single desk: whoever signed in saw the only queue that existed. The routing
 * was never the problem — `POST /api/issuance/requests` already resolves the
 * reviewing authority from the document type and files the request against that
 * institution, and `GET /api/authority/queue` already scopes to the officer's
 * own institution. What was missing was anyone to sign in AS a council.
 *
 * That separation is the point of the exercise: an officer who checks national
 * ID scans for the ministry has no business seeing a doctor's qualification
 * documents, and the medical, nursing and pharmacy registers are three
 * different statutory bodies. One officer reviewing all of them is a
 * convenience the design does not have.
 *
 *   npx tsx tools/seedCouncilOfficers.ts
 */
// FIRST, and not for style. `db/index.ts` constructs a PrismaClient at module
// load and throws without DATABASE_URL, so anything importing it before dotenv
// has run dies on import rather than on use (the #382 ordering trap).
import 'dotenv/config';
import { db } from '../src/db/index.js';

const OFFICERS = [
  { did: 'did:cheqd:bdhealthtestnet:cb977556-ce6e-413b-b8c6-1ba6e53eeb0f', short: 'bmdc' },
  { did: 'did:cheqd:bdhealthtestnet:2b86a5df-1a16-4609-abf3-b37bd82c16cd', short: 'bnmc' },
  { did: 'did:cheqd:bdhealthtestnet:5ec73178-7e8c-4f60-ad4b-9573a0362a39', short: 'pcb' },
];

async function main() {
  for (const officer of OFFICERS) {
    const institution = await db.institution.findUnique({ where: { did: officer.did } });
    if (!institution) {
      throw new Error(
        `No Institution row for ${officer.short} (${officer.did}). ` +
          'The registry and the database disagree — see migration 20260909083000.',
      );
    }

    const email = `officer@${officer.short}.bdhealthtrust.test`;

    // Idempotent by (institution, email): re-running must converge rather than
    // create a second officer with the same address.
    const existing = await db.institutionMember.findFirst({
      where: { institutionId: institution.id, email },
    });
    if (existing) {
      console.log(`  = ${institution.name.padEnd(42)} ${email} (already present)`);
      continue;
    }

    await db.institutionMember.create({
      data: {
        institutionId: institution.id,
        email,
        name: `${officer.short.toUpperCase()} registration officer`,
        // ADMIN so the desk can also invite its own colleagues. A council that
        // needs the ministry's help to add a second reviewer is a council with
        // one point of failure.
        role: 'ADMIN',
        isActive: true,
        acceptedAt: new Date(),
      },
    });
    console.log(`  + ${institution.name.padEnd(42)} ${email}`);
  }

  const rows = await db.institutionMember.findMany({
    include: { institution: { select: { name: true } } },
    orderBy: { email: 'asc' },
  });
  console.log('\n--- every reviewing desk that now exists ---');
  for (const r of rows) {
    console.log(`  ${r.institution.name.padEnd(42)} ${r.role.padEnd(7)} ${r.email}`);
  }
  process.exit(0);
}

void main();
