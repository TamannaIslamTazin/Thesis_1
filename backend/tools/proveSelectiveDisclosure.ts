/**
 * Issue a real `vc+sd-jwt` health card and prove the narrowing REMOVES claims.
 *
 * The property under test is not "the wallet sent fewer field names". It is that
 * a withheld claim is ABSENT FROM THE BYTES — that the verifier could not
 * recover it even if it tried. So this checks the produced artifact three
 * independent ways, the way #199 did: the decoded claims, the raw compact
 * string, and every disclosure segment taken apart individually.
 *
 *   npx tsx tools/proveSelectiveDisclosure.ts <holderDid>
 */
import { createAgent, shutdownAgent } from '../src/agent/index.js';
import { issueCredential } from '../src/services/credentialService.js';
import { db } from '../src/db/index.js';
import { presentSync } from '@ssi-healthcare/sdk/sd-jwt';
import { buildPresentationFrame, CREDENTIAL_FORMATS } from '@ssi-healthcare/shared';
import { sha256 } from '@noble/hashes/sha256';

const MOHFW = 'did:cheqd:bdhealthtestnet:5d3c6ffe-c151-4c30-9223-c86d24594753';
const hasher = (data: string, alg: string) => {
  if (alg.toLowerCase() !== 'sha-256') throw new Error(`unsupported alg ${alg}`);
  return sha256(new TextEncoder().encode(data));
};

let pass = 0;
let fail = 0;
const assert = (label: string, ok: boolean, detail = '') => {
  if (ok) { pass++; console.log(`  PASS  ${label}${detail ? ` — ${detail}` : ''}`); }
  else { fail++; console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`); }
};

const b64u = (v: string) => Buffer.from(v.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();

/**
 * Everything a verifier can READ out of a compact SD-JWT, decoded.
 *
 * Searching the compact string directly is worthless and looks fine: the
 * segments are base64url, so a literal `compact.includes('nidLastFour')` is
 * false whether the claim was disclosed or withheld. That check passed here for
 * the wrong reason until the mutation case below caught it — a test that cannot
 * fail is not evidence, and this one was defending the very property it claimed
 * to prove.
 */
function decodedSurface(compact: string): string {
  const [jwt, ...rest] = compact.split('~');
  const parts: string[] = [];
  try { parts.push(b64u(jwt!.split('.')[1]!)); } catch { /* unreadable payload */ }
  for (const seg of rest) {
    if (!seg) continue;
    try { parts.push(b64u(seg)); } catch { /* not a disclosure */ }
  }
  return parts.join('\n');
}

function disclosureNames(compact: string): string[] {
  const [, ...rest] = compact.split('~');
  return rest.filter(Boolean).flatMap((seg) => {
    try {
      const j = JSON.parse(b64u(seg));
      return Array.isArray(j) && typeof j[1] === 'string' ? [j[1] as string] : [];
    } catch { return []; }
  });
}

async function main() {
  const holderDid = process.argv[2];
  if (!holderDid) throw new Error('usage: proveSelectiveDisclosure.ts <holderDid>');

  await createAgent();

  console.log('\n=== ISSUE — the default must now be vc+sd-jwt ===\n');
  await issueCredential({
    issuerDid: MOHFW,
    subjectDid: holderDid,
    credentialType: 'HealthCardCredential',
    category: 'general' as never,
    claims: {
      verifiedAt: new Date().toISOString(),
      verificationMethod: 'nid-record-comparison',
      nidLastFour: '4417',
    },
  });

  // Read the ENVELOPE back off the row: `IssuedCredential` carries only the W3C
  // JSON, and the compact artifact is what a verifier actually receives.
  const row = await db.credential.findFirst({
    where: { holderDid, type: { has: 'HealthCardCredential' } },
    orderBy: { issuedAt: 'desc' },
    select: { id: true, credentialJwt: true, credentialFormat: true },
  });
  const compact = row?.credentialJwt ?? '';
  assert('a credential was issued and its envelope stored', Boolean(compact), row?.id ?? '');
  assert('issued as an SD-JWT (has ~ disclosure segments)', compact.includes('~'),
    `${compact.split('~').length - 1} segments`);
  assert('the default format is vc+sd-jwt, not vc+jwt',
    row?.credentialFormat === CREDENTIAL_FORMATS.SD_JWT_VC,
    String(row?.credentialFormat));

  const issuerPayload = JSON.parse(b64u(compact.split('~')[0]!.split('.')[1]!));
  const subject = issuerPayload.credentialSubject ?? {};
  console.log('\n--- the ISSUER-SIGNED payload (what travels even when nothing is disclosed) ---');
  console.log(`  credentialSubject keys : ${Object.keys(subject).join(', ')}`);
  console.log(`  _sd digests            : ${(subject._sd ?? []).length}`);
  console.log(`  disclosures available  : ${disclosureNames(compact).join(', ')}`);

  assert('credentialSubject.id is ALWAYS disclosed (never digested)', typeof subject.id === 'string',
    'withholding it lets a thief present a stolen credential as their own (#195)');
  assert('every other claim is a digest, not a value',
    !('verifiedAt' in subject) && !('nidLastFour' in subject));

  console.log('\n=== NARROW — the holder shares verifiedAt only ===\n');
  const narrowed = presentSync(compact, buildPresentationFrame(['verifiedAt']) as never, hasher);
  const revealed = disclosureNames(narrowed);
  assert('exactly one disclosure survives', revealed.length === 1, revealed.join(', '));
  assert('and it is verifiedAt', revealed[0] === 'verifiedAt');

  console.log('\n=== THE WITHHELD CLAIMS ARE ABSENT, CHECKED THREE WAYS ===\n');
  const narrowedSurface = decodedSurface(narrowed);
  for (const withheld of ['verificationMethod', 'nidLastFour']) {
    assert(`1. '${withheld}' is not among the surviving disclosure names`,
      !revealed.includes(withheld));
    assert(`2. '${withheld}' is absent from the DECODED issuer payload + disclosures`,
      !narrowedSurface.includes(withheld));
    const anySegmentCarriesIt = narrowed
      .split('~').slice(1).filter(Boolean)
      .some((seg) => { try { return b64u(seg).includes(withheld); } catch { return false; } });
    assert(`3. no individual disclosure segment decodes to '${withheld}'`, !anySegmentCarriesIt);
  }

  const nid = '4417';
  assert('the NID digits are unrecoverable from the narrowed artifact',
    !narrowedSurface.includes(nid));

  console.log('\n=== THE MUTATION CHECK — prove the test can FAIL ===\n');
  const wide = presentSync(
    compact,
    buildPresentationFrame(['verifiedAt', 'verificationMethod', 'nidLastFour']) as never,
    hasher,
  );
  const wideNames = disclosureNames(wide);
  assert('disclosing everything yields all three claims', wideNames.length === 3, wideNames.join(', '));
  // THE SAME SEARCH that asserted absence must find it here, or absence proved
  // nothing. This is the check that caught the vacuous version of check 2.
  const wideSurface = decodedSurface(wide);
  assert('...and THEN the same search DOES find the NID digits', wideSurface.includes(nid),
    'so the absence above is a real property, not a search that never matches');
  assert('...and DOES find the withheld claim names', wideSurface.includes('nidLastFour'));
  assert('the narrowed artifact is strictly shorter than the full one',
    narrowed.length < wide.length, `${narrowed.length} < ${wide.length} bytes`);

  console.log(`\n${'='.repeat(64)}`);
  console.log(`  ${pass} passed, ${fail} failed`);
  console.log(`${'='.repeat(64)}\n`);
  await shutdownAgent();
  process.exit(fail === 0 ? 0 : 1);
}

void main();
