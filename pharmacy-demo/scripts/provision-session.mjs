/**
 * Mint a session for the demo pharmacy.
 *
 * Stands in for "Log in with SSI", which an L2 institution would really use and
 * which is not built. Session.token stores sha256(token), so the raw value
 * exists only here — print it, paste it into .env.local, and it is gone.
 */
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID, randomBytes } from 'node:crypto';

const EMAIL = process.argv[2] ?? 'pharmacy-demo@bdhealthtrust.test';
const psql = (sql) =>
  execFileSync('psql', ['-h', 'localhost', '-U', 'postgres', '-d', 'ssi_healthcare', '-At', '-c', sql], {
    env: { ...process.env, PGPASSWORD: process.env.PGPASSWORD ?? 'postgres' },
    encoding: 'utf8',
  }).trim();

let userId = psql(`SELECT id FROM "User" WHERE email = '${EMAIL}'`);
if (!userId) {
  userId = `usr${randomUUID().replace(/-/g, '').slice(0, 20)}`;
  psql(
    `INSERT INTO "User" (id, email, "firstName", "lastName", "walletSetup", "updatedAt") ` +
      `VALUES ('${userId}', '${EMAIL}', 'Dhaka Community', 'Pharmacy', false, now())`,
  );
  console.log(`created user ${userId}`);
}

const token = randomBytes(32).toString('base64url');
psql(
  `INSERT INTO "Session" (id, "userId", token, status, "expiresAt") ` +
    `VALUES ('ses${randomUUID().replace(/-/g, '').slice(0, 20)}', '${userId}', ` +
    `'${createHash('sha256').update(Buffer.from(token, 'utf8')).digest('hex')}', 'ACTIVE', now() + interval '30 days')`,
);

console.log('\nPut this in packages/pharmacy-demo/.env.local:\n');
console.log(`PHARMACY_SESSION_TOKEN=${token}`);
