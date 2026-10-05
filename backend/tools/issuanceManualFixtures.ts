/**
 * One-off fixture script for manually exercising the R6 issuance endpoints
 * against a live backend. NOT part of the test suite — run with tsx and
 * discard. Prints bearer tokens for a holder and an L1 ministry officer.
 *
 * Follows the same "through the repository, not db.session.create" pattern
 * `tests/live/professionalGuardHttp.live.test.ts` uses, because the Session
 * row stores sha256(token), not the token itself.
 */
import { randomUUID } from 'node:crypto';
import { db } from '../src/db/index.js';
import { createSession } from '../src/db/userRepository.js';

async function main() {
  const holderDid = `did:cheqd:bdhealthtestnet:${randomUUID()}`;
  const holder = await db.user.create({
    data: {
      did: holderDid,
      email: `r6-manual-holder-${randomUUID()}@bd-health.example`,
      firstName: 'Test',
      lastName: 'Holder',
      walletSetup: true,
    },
  });
  const holderToken = `${randomUUID()}${randomUUID()}`.replace(/-/g, '');
  await createSession({
    user: { connect: { id: holder.id } },
    token: holderToken,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });

  const officerEmail = `r6-manual-officer-${randomUUID()}@bd-health.example`;
  const officer = await db.user.create({
    data: {
      email: officerEmail,
      firstName: 'Test',
      lastName: 'Officer',
      walletSetup: false,
    },
  });
  const officerToken = `${randomUUID()}${randomUUID()}`.replace(/-/g, '');
  await createSession({
    user: { connect: { id: officer.id } },
    token: officerToken,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });

  const ministry = await db.institution.findUniqueOrThrow({ where: { id: 'l1-mohfw' } });
  await db.institutionMember.create({
    data: { institutionId: ministry.id, email: officerEmail, name: 'Test Officer', role: 'OFFICER' },
  });

  const bmdcOfficerEmail = `r6-manual-bmdc-officer-${randomUUID()}@bd-health.example`;
  const bmdcOfficer = await db.user.create({
    data: { email: bmdcOfficerEmail, firstName: 'BMDC', lastName: 'Officer', walletSetup: false },
  });
  const bmdcOfficerToken = `${randomUUID()}${randomUUID()}`.replace(/-/g, '');
  await createSession({
    user: { connect: { id: bmdcOfficer.id } },
    token: bmdcOfficerToken,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });
  await db.institutionMember.create({
    data: { institutionId: 'l1-bmdc', email: bmdcOfficerEmail, name: 'BMDC Officer', role: 'OFFICER' },
  });

  // A second user, active but NOT a member of any L1 authority — to prove the
  // gate refuses someone merely logged in.
  const nonMemberEmail = `r6-manual-nonmember-${randomUUID()}@bd-health.example`;
  const nonMember = await db.user.create({
    data: { email: nonMemberEmail, firstName: 'Test', lastName: 'NonMember', walletSetup: false },
  });
  const nonMemberToken = `${randomUUID()}${randomUUID()}`.replace(/-/g, '');
  await createSession({
    user: { connect: { id: nonMember.id } },
    token: nonMemberToken,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });

  console.log(JSON.stringify({
    holderUserId: holder.id,
    holderDid,
    holderToken,
    officerUserId: officer.id,
    officerEmail,
    officerToken,
    nonMemberUserId: nonMember.id,
    nonMemberToken,
    ministryInstitutionId: ministry.id,
    ministryDid: ministry.did,
    bmdcOfficerEmail,
    bmdcOfficerToken,
  }, null, 2));

  await db.$disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
