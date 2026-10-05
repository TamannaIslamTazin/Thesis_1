/**
 * Give each reviewing authority its own console keys.
 *
 * The issuer console was single-tenant: one `ISSUER_CONTENT_KEY_X25519_SEED` and
 * one `ISSUER_LOCKER_DID`, both the ministry's. A council officer could sign in
 * and see their own queue — the scoping was always correct — and then fail to
 * open a single document, because the content key that sealed it belongs to an
 * authority whose private half this console does not hold:
 *
 *   KeyEnvelopeError: The key envelope did not authenticate.
 *
 * That is the honest failure, not a bug: the wallet seals each submission to the
 * PUBLIC key of the authority the document type names, so only that authority
 * can open it. Which is the property we want — it just means every authority
 * needs its own key, and three of them had a placeholder public half with no
 * private counterpart anywhere.
 *
 *   node tools/provisionAuthorityConsoleKeys.mjs
 */
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { x25519 } from '@noble/curves/ed25519';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = '1' + out; }
  return out;
}

const COUNCILS = [
  { short: 'BMDC', did: 'did:cheqd:bdhealthtestnet:cb977556-ce6e-413b-b8c6-1ba6e53eeb0f' },
  { short: 'BNMC', did: 'did:cheqd:bdhealthtestnet:2b86a5df-1a16-4609-abf3-b37bd82c16cd' },
  { short: 'PCB',  did: 'did:cheqd:bdhealthtestnet:5ec73178-7e8c-4f60-ad4b-9573a0362a39' },
];

console.log('--- registry: packages/shared/src/accreditation/index.ts ---\n');
const envLines = [];
const growLines = [];

for (const c of COUNCILS) {
  // CONTENT KEY (X25519): what the holder's wallet wraps the document key to.
  const contentSeed = randomBytes(32);
  const contentPublic = x25519.getPublicKey(contentSeed);

  // LOCKER SIGNING KEY (Ed25519): signs the capability call that fetches the
  // document. Its public half goes on the council's DID document as an imported
  // officer key, so the ledger can attribute the fetch to this console.
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const rawSeed = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
  const multibase = `z${base58(Buffer.concat([Buffer.from([0xed, 0x01]), rawPub]))}`;

  console.log(`  ${c.short} contentKeyPublicKey: '${Buffer.from(contentPublic).toString('base64url')}',`);

  envLines.push(
    `# ${c.short}`,
    `ISSUER_CONTENT_KEY_X25519_SEED__${c.short}=${contentSeed.toString('base64url')}`,
    `ISSUER_LOCKER_DID__${c.short}=${c.did}`,
    `ISSUER_LOCKER_VERIFICATION_METHOD_ID__${c.short}="${c.did}#key-console"`,
    `ISSUER_LOCKER_SIGNING_SEED__${c.short}=${rawSeed.toString('base64url')}`,
    '',
  );
  growLines.push(
    `npx tsx scripts/provision-institutional-did.ts grow ${c.did} "issuer console review key" ${multibase} "BDHealthTrust issuer console"`,
  );
}

console.log('\n--- append to packages/issuer-console/.env.local ---\n');
console.log(envLines.join('\n'));
console.log('--- then add each console key to its council DID on chain ---\n');
console.log(growLines.join('\n'));
