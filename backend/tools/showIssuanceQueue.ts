import 'dotenv/config';
// Through the app's own client, not a fresh PrismaClient: Prisma 7 needs a
// driver adapter, and src/db already builds one from DATABASE_URL. Importing
// dotenv FIRST is required (#382) — db/index.ts constructs at module load.
import { db as prisma } from '../src/db/index.js';

/**
 * Read the issuance queue AS THE DATABASE HOLDS IT, not as the console renders
 * it. Used while proving a flow end to end: the console can only show what its
 * officer's institution is allowed to see, which is the property under test, so
 * confirming "the request reached the right desk" needs a view from outside it.
 *
 * Read-only. Prints holder, authority, status, whether the single-use key has
 * been spent, and the issued offer id once approval has run.
 */
async function main(): Promise<void> {
  const limit = Number(process.argv[2] ?? 10);
  const requests = await prisma.issuanceRequest.findMany({
    orderBy: { createdAt: 'desc' },
    take: limit,
    include: { documents: true, authority: true, holder: true },
  });

  if (requests.length === 0) {
    console.log('No issuance requests exist.');
    return;
  }

  for (const request of requests) {
    console.log('─'.repeat(96));
    console.log(`${request.id}  ${request.documentTypeId}  ${request.credentialType}  ${request.status}`);
    console.log(`  authority   ${request.authority?.name ?? '(none)'}  ${request.authority?.did ?? ''}`);
    console.log(`  holder      ${request.holder?.firstName ?? ''} ${request.holder?.lastName ?? ''}  ${request.holderDid ?? ''}`);
    console.log(`  created     ${request.createdAt.toISOString()}`);
    console.log(`  keySpent    ${request.keyReleasedAt ? request.keyReleasedAt.toISOString() : 'no'}`);
    console.log(`  offer       ${request.issuedCredentialOfferId ?? '(none)'}`);
    if (request.reviewNotes) console.log(`  notes       ${request.reviewNotes}`);
    for (const document of request.documents) {
      console.log(`  document    ${document.lockerObjectId}  ${document.mediaType}  ${document.fileName ?? ''}`);
    }
  }
}

main()
  .catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
