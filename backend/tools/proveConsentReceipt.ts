/**
 * Prove the holder-signed consent receipt (steno #279) in BOTH directions.
 *
 * A fail-closed verifier passes perfectly against a verifier that refuses
 * everything, so a refusal-only run proves nothing (#345, #347). Every refusal
 * below is therefore paired with the success path it refuses against: the same
 * receipt, verified genuinely, then mutated in exactly one way.
 *
 *   npx tsx tools/proveConsentReceipt.ts
 */
import {
  buildConsentReceiptPayload,
  signConsentReceipt,
  verifyConsentReceipt,
  hashVpToken,
  CONSENT_RECEIPT_TYP,
} from '@ssi-healthcare/shared';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToBase64Url, base64UrlToBytes } from '@ssi-healthcare/shared';

const HOLDER = 'did:cheqd:bdhealthtestnet:f654bf75-b2f6-40ba-badb-d005e074c049';
const VERIFIER = 'did:cheqd:bdhealthtestnet:9f2b1c44-6d0e-4a7b-8c31-5e0a7d21b6f4';
const REQUEST_ID = 'e495199e-1d52-480c-ab93-33b8e150a2e2';
const NONCE = 'nonce-under-test';
const VP_TOKEN = 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZSJ9.c2ln';

const seed = ed25519.utils.randomPrivateKey();
const publicKey = ed25519.getPublicKey(seed);
const sign = async (input: Uint8Array) => bytesToBase64Url(ed25519.sign(input, seed));

let pass = 0;
let fail = 0;
function assert(label: string, condition: boolean, detail = '') {
  if (condition) { pass++; console.log(`  PASS  ${label}${detail ? ` — ${detail}` : ''}`); }
  else { fail++; console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`); }
}

/** Re-sign a payload after mutating it, so only the mutation is under test. */
async function resign(mutate: (p: any) => void): Promise<string> {
  const payload = buildConsentReceiptPayload(base);
  mutate(payload);
  return signConsentReceipt(payload as any, `${HOLDER}#key-1`, sign);
}

const base = {
  holderDid: HOLDER,
  verifierDid: VERIFIER,
  verifierName: 'Dhaka Community Pharmacy',
  purpose: 'Confirm this is your health identity before dispensing',
  purposeCategory: 'treatment',
  credentialTypes: ['HealthCardCredential'],
  // TRUTH, not intent: a vc+jwt health card carries all three of these
  // regardless of what the holder switched off (steno #360).
  disclosedClaims: ['verifiedAt', 'verificationMethod', 'id'],
  holderSelectedClaims: ['verifiedAt'],
  requestedClaims: ['verifiedAt'],
  minimisationEnforced: false,
  requestId: REQUEST_ID,
  nonce: NONCE,
  vpToken: VP_TOKEN,
  receiptId: 'urn:uuid:11111111-2222-3333-4444-555555555555',
};

const expected = {
  holderDid: HOLDER,
  verifierDid: VERIFIER,
  requestId: REQUEST_ID,
  nonce: NONCE,
  vpToken: VP_TOKEN,
};

async function main() {
  console.log('\n=== THE SUCCESS PATH — a genuine receipt must verify ===\n');
  const good = await signConsentReceipt(
    buildConsentReceiptPayload(base) as any,
    `${HOLDER}#key-1`,
    sign,
  );
  const ok = verifyConsentReceipt(good, publicKey, expected);
  assert('a genuine receipt verifies', ok.verified, ok.errors.join('; '));
  for (const [name, value] of Object.entries(ok.checks)) {
    assert(`  check ${name} is true`, value === true);
  }

  console.log('\n--- what the receipt actually says (read the artifact, not the exit code) ---');
  const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(good.split('.')[1]!)));
  console.log(`  typ                : ${CONSENT_RECEIPT_TYP}`);
  console.log(`  spec version       : ${payload.version}`);
  console.log(`  holder (iss/sub)   : ${payload.iss}`);
  console.log(`  verifier (aud)     : ${payload.aud}`);
  console.log(`  purpose, verbatim  : "${payload.services[0].purposes[0].purpose}"`);
  console.log(`  purposeCategory    : ${payload.services[0].purposes[0].purposeCategory}`);
  console.log(`  claims TRANSMITTED : ${payload.presentation.disclosedClaims.join(', ')}`);
  console.log(`  holder SELECTED    : ${payload.presentation.holderSelectedClaims.join(', ')}`);
  console.log(`  verifier REQUESTED : ${payload.presentation.requestedClaims.join(', ')}`);
  console.log(`  minimisation held  : ${payload.presentation.minimisationEnforced}  <-- the gap, recorded`);
  console.log(`  consent stands to  : ${payload.services[0].purposes[0].termination}`);
  console.log(`  bound to request   : ${payload.presentation.requestId}`);
  console.log(`  bound to vp_token  : ${payload.presentation.vpTokenHash}`);
  console.log(`  recomputes to      : ${hashVpToken(VP_TOKEN)}`);
  console.log(`  sensitive / spiCat : ${payload.sensitive} / ${payload.spiCat.join(', ')}`);

  console.log('\n=== THE REFUSALS — each is the SAME receipt with ONE thing changed ===\n');

  // 1. Forged signature. The bytes say the right things; the key is wrong.
  const otherSeed = ed25519.utils.randomPrivateKey();
  const forged = await signConsentReceipt(
    buildConsentReceiptPayload(base) as any,
    `${HOLDER}#key-1`,
    async (input) => bytesToBase64Url(ed25519.sign(input, otherSeed)),
  );
  const r1 = verifyConsentReceipt(forged, publicKey, expected);
  assert('a receipt signed by another key is refused', !r1.verified);
  assert('  ...and it is the SIGNATURE check that fails', r1.checks.signature === false);
  assert('  ...while attribution still passed, so the failure is attributable',
    r1.checks.holderAttribution === true);

  // 2. Replay onto a DIFFERENT disclosure. This is the binding that makes a
  //    receipt evidence about one act rather than a standing permission.
  const r2 = verifyConsentReceipt(good, publicKey, {
    ...expected,
    vpToken: VP_TOKEN.replace('c2ln', 'b3RoZXI'),
  });
  assert('a receipt replayed onto a different vp_token is refused', !r2.verified);
  assert('  ...on presentationBinding specifically', r2.checks.presentationBinding === false);
  assert('  ...and its signature is still valid, proving the binding did the work',
    r2.checks.signature === true);

  // 3. Replay into a different exchange between the same two parties.
  const r3 = verifyConsentReceipt(good, publicKey, { ...expected, nonce: 'a-different-nonce' });
  assert('a receipt replayed into another exchange is refused', !r3.verified);
  assert('  ...on exchangeBinding specifically', r3.checks.exchangeBinding === false);

  // 4. Addressed to a different verifier.
  const r4 = verifyConsentReceipt(good, publicKey, {
    ...expected,
    verifierDid: 'did:cheqd:bdhealthtestnet:00000000-0000-0000-0000-000000000000',
  });
  assert('a receipt addressed to another verifier is refused', !r4.verified);
  assert('  ...on verifierBinding specifically', r4.checks.verifierBinding === false);

  // 5. Signed under someone else's DID namespace. Attribution is by the VM ID
  //    PREFIX, so a foreign kid must be caught even with a valid signature.
  const foreignKid = await signConsentReceipt(
    buildConsentReceiptPayload(base) as any,
    'did:cheqd:bdhealthtestnet:deadbeef-0000-0000-0000-000000000000#key-1',
    sign,
  );
  const r5 = verifyConsentReceipt(foreignKid, publicKey, expected);
  assert('a receipt whose kid names another DID is refused', !r5.verified);
  assert('  ...on holderAttribution, not on the signature', r5.checks.holderAttribution === false);
  assert('  ...signature genuinely verified, so only attribution rejected it',
    r5.checks.signature === true);

  // 6. Stale. A receipt that is not fresh cannot belong to a live exchange.
  const stale = await resign((p) => { p.iat = p.iat - 3600; });
  const r6 = verifyConsentReceipt(stale, publicKey, expected);
  assert('a stale receipt is refused', !r6.verified);
  assert('  ...on freshness specifically', r6.checks.freshness === false);

  // 7. Future-dated beyond skew.
  const future = await resign((p) => { p.iat = p.iat + 3600; });
  const r7 = verifyConsentReceipt(future, publicKey, expected);
  assert('a future-dated receipt is refused', !r7.verified);
  assert('  ...on freshness specifically', r7.checks.freshness === false);

  // 8. Wrong typ — a presentation must never be readable as a consent receipt.
  const wrongTyp = (() => {
    const [, p, s] = good.split('.');
    const h = bytesToBase64Url(new TextEncoder().encode(
      JSON.stringify({ alg: 'EdDSA', typ: 'vp+jwt', kid: `${HOLDER}#key-1` })));
    return `${h}.${p}.${s}`;
  })();
  const r8 = verifyConsentReceipt(wrongTyp, publicKey, expected);
  assert('a vp+jwt cannot pass as a consent receipt', !r8.verified);
  assert('  ...on the header check', r8.checks.header === false);

  // 9. Absence is failure, not a skip — the #196 lesson made explicit.
  const gutted = await resign((p) => { delete p.presentation; });
  const r9 = verifyConsentReceipt(gutted, publicKey, expected);
  assert('a receipt with NO binding block is refused, not skipped', !r9.verified);
  assert('  ...exchangeBinding false on absence', r9.checks.exchangeBinding === false);
  assert('  ...presentationBinding false on absence', r9.checks.presentationBinding === false);

  // 10. Not a JWS at all.
  const r10 = verifyConsentReceipt('not-a-jws', publicKey, expected);
  assert('a malformed receipt is refused', !r10.verified);

  console.log(`\n${'='.repeat(64)}`);
  console.log(`  ${pass} passed, ${fail} failed`);
  console.log(`${'='.repeat(64)}\n`);
  process.exit(fail === 0 ? 0 : 1);
}

void main();
