/**
 * SD-JWT SELECTIVE DISCLOSURE — evidence probe.
 *
 * Every claim in the report for this round is produced here, by execution
 * against the live cheqd localnet and the real Postgres database. Nothing is
 * asserted from reading code.
 *
 * The negative controls are the centrepiece. Each exploit is demonstrated
 * SUCCEEDING against unmodified Credo and then FAILING at our verification
 * boundary, in the same run, so the fix is distinguishable from a fix that
 * never worked.
 */
import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import {
  W3cV2SdJwtVerifiableCredential,
  W3cV2SdJwtVerifiablePresentation,
  W3cV2Presentation,
  W3cV2Credential,
  W3cV2CredentialSubject,
  W3cV2EnvelopedVerifiableCredential,
  JsonTransformer,
  TypedArrayEncoder,
  Hasher,
  Kms,
} from '@credo-ts/core';
import { db } from './src/db/index.js';
import { createAgent, shutdownAgent, getAgent } from './src/agent/index.js';
import {
  issueCredential,
  verifyCredential,
  revokeCredential,
} from './src/services/credentialService.js';
import {
  presentSdJwtCredential,
  signSdJwtCredential,
  signSdJwtPresentation,
  verifySdJwtPresentation,
  sdJwtVcToW3cJson,
  toV2SdJwtVerifiableCredential,
  credentialEnvelopeFormat,
} from './src/services/sdJwtVc.js';
import { credentialEnvelopeJwt, jwtVcToW3cJson } from './src/services/jwtVc.js';
import { toWalletCredential } from './src/api/walletCredential.js';
import {
  buildDisclosureFrame,
  assertNothingDisclosableLeaked,
  CREDENTIAL_FORMATS,
} from '@ssi-healthcare/shared';

const ISSUER = 'did:cheqd:bdhealthtestnet:fa3fc79f-9d49-43f5-9aa7-4f2df973bbb0';
const HOLDER = 'did:cheqd:bdhealthtestnet:7cd03fdc-6a88-4895-9d89-e63445abe0c1';
const ATTACKER = 'did:cheqd:bdhealthtestnet:a697648c-7a8a-43b3-825b-7bb50725d764';
const VERIFIER_DOMAIN = 'https://pharmacy.bd-health.example';

/** The subject claims every part of this probe issues over. */
const claims = {
  patientName: 'Ahsan Rahman',
  hivStatus: 'negative',
  bloodType: 'O+',
  testDate: '2026-08-10',
  prescriber: { name: 'Dr Karim', licence: 'BMDC-4471' },
  medications: ['Metformin 500mg', 'Lisinopril 10mg', 'Sertraline 50mg'],
};

const failures: string[] = [];
function hr(t: string) { console.log(`\n${'='.repeat(74)}\n${t}\n${'='.repeat(74)}`); }
function check(label: string, ok: boolean, detail?: unknown) {
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${label}${detail === undefined ? '' : ` -> ${JSON.stringify(detail)}`}`);
  if (!ok) failures.push(label);
}

/** Sign an arbitrary VP payload with an arbitrary key — i.e. act as an attacker. */
async function forgePresentation(
  presentation: W3cV2Presentation,
  signerDid: string,
  nonce: string,
  aud: string,
): Promise<string> {
  const agent = getAgent();
  const { SDJwtInstance } = await import('@sd-jwt/core');
  const kms = agent.context.resolve(Kms.KeyManagementApi);
  const doc = await agent.dids.resolve(signerDid);
  const authn = doc.didDocument!.authentication![0];
  const kid = typeof authn === 'string' ? authn : (authn as { id: string }).id;
  const keyId = (await agent.dids.getCreatedDids({ did: signerDid }))[0]!.keys![0]!.kmsKeyId;

  const payload = JsonTransformer.toJSON(presentation) as Record<string, unknown>;
  payload.nonce = nonce;
  payload.aud = aud;

  return new SDJwtInstance({
    hasher: (d: string | ArrayBuffer, alg: string) =>
      Hasher.hash(typeof d === 'string' ? d : new Uint8Array(d), alg),
    saltGenerator: (len: number) =>
      TypedArrayEncoder.toBase64URL(kms.randomBytes({ length: len })).slice(0, len),
    signer: async (input: string) =>
      TypedArrayEncoder.toBase64URL(
        (await kms.sign({ keyId, data: TypedArrayEncoder.fromString(input), algorithm: 'EdDSA' })).signature,
      ),
    signAlg: 'EdDSA',
    hashAlg: 'sha-256',
  }).issue(payload, undefined, { header: { typ: 'vp+sd-jwt', alg: 'EdDSA', kid } });
}

/** A bare W3cV2Credential, for the tests that must bypass the shipped policy. */
function buildRawCredential(): W3cV2Credential {
  return new W3cV2Credential({
    context: ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
    id: `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', 'LabResultCredential'],
    issuer: ISSUER,
    validFrom: new Date().toISOString(),
    validUntil: new Date(Date.now() + 86400_000).toISOString(),
    credentialSubject: new W3cV2CredentialSubject({ id: HOLDER, ...claims }),
  });
}

async function main() {
  const agent = await createAgent();

  // =========================================================================
  hr('1. ISSUE a credential as vc+sd-jwt through the production issuance path');
  // =========================================================================
  const issued = await issueCredential({
    issuerDid: ISSUER,
    subjectDid: HOLDER,
    credentialType: 'LabResultCredential',
    category: 'lab_results',
    claims,
    format: CREDENTIAL_FORMATS.SD_JWT_VC,
  });

  const row = await db.credential.findFirst({
    where: { holderDid: HOLDER, issuerDid: ISSUER },
    orderBy: { createdAt: 'desc' },
  });
  const compact = row!.credentialJwt!;
  check('row persisted', row !== null);
  check('credentialFormat recorded EXPLICITLY as vc+sd-jwt',
    row!.credentialFormat === 'vc+sd-jwt', row!.credentialFormat);
  check('envelope is an SD-JWT (has disclosures)', compact.includes('~'));
  check('issued credential id matches the row', issued.credential.id === (row!.credentialData as { id: string }).id);

  const sdCred = toV2SdJwtVerifiableCredential(compact)!;
  const signedPayload = sdCred.sdJwt.payload as Record<string, unknown>;
  console.log('\n--- ISSUER-SIGNED payload (what a verifier sees with ZERO disclosures) ---');
  console.log(JSON.stringify(signedPayload, null, 2));
  console.log('\n--- DISCLOSURES carried alongside ---');
  for (const d of compact.split('~').slice(1)) {
    if (d) console.log('   ', Buffer.from(d, 'base64url').toString('utf8'));
  }

  const signedSubject = signedPayload.credentialSubject as Record<string, unknown>;
  check('cnf holder binding present', signedPayload.cnf !== undefined, signedPayload.cnf);
  check('cnf.kid is the holder\'s absolute DID URL',
    (signedPayload.cnf as { kid: string }).kid === `${HOLDER}#key-1`);
  check('credentialSubject.id remains in cleartext (policy carve-out)',
    signedSubject.id === HOLDER);
  check('credentialStatus survives (revocation stays checkable)',
    signedPayload.credentialStatus !== undefined);
  for (const key of ['patientName', 'hivStatus', 'bloodType', 'testDate', 'prescriber', 'medications']) {
    check(`'${key}' is a digest, NOT cleartext, in the signed payload`, !(key in signedSubject));
  }
  check('signed payload carries _sd digests', Array.isArray(signedSubject._sd),
    (signedSubject._sd as string[])?.length);

  // =========================================================================
  hr('2. THE CORE PROOF — present a STRICT SUBSET, then verify it');
  // =========================================================================
  // The holder reveals ONLY their HIV status and ONE of three medications.
  const disclosed = await presentSdJwtCredential(agent, compact, {
    credentialSubject: { hivStatus: true, medications: { 1: true } },
  });
  const disclosedCompact = disclosed.encoded;

  const seenByVerifier = sdJwtVcToW3cJson(disclosedCompact)!;
  console.log('\n--- EVERYTHING the verifier can see, decoded from the presented artifact ---');
  console.log(JSON.stringify(seenByVerifier, null, 2));

  const seenSubject = seenByVerifier.credentialSubject as Record<string, unknown>;

  console.log('\n(a) does it VERIFY?');
  const nonce = randomUUID();
  const vp = await signSdJwtPresentation(agent, {
    holderDid: HOLDER,
    credential: disclosed,
    challenge: nonce,
    domain: VERIFIER_DOMAIN,
  });
  const good = await verifySdJwtPresentation(agent, {
    presentation: vp,
    challenge: nonce,
    domain: VERIFIER_DOMAIN,
  });
  console.log('   checks:', JSON.stringify(good.checks));
  check('presentation VERIFIES', good.isValid, good.errors);
  check('all four checks green', Object.values(good.checks).every(Boolean));

  console.log('\n(b) are undisclosed claims GENUINELY ABSENT — not merely hidden from a display path?');
  // Three independent readings, because "absent from the object we built" is
  // not the same as "absent from the bytes the verifier received".
  const secrets: Array<[string, string]> = [
    ['patientName', 'Ahsan Rahman'],
    ['bloodType', 'O+'],
    ['testDate', '2026-08-10'],
    ['prescriber.name', 'Dr Karim'],
    ['prescriber.licence', 'BMDC-4471'],
    ['medications[0]', 'Metformin 500mg'],
    ['medications[2]', 'Sertraline 50mg'],
  ];
  for (const [label, value] of secrets) {
    const inDecoded = JSON.stringify(seenByVerifier).includes(value);
    const inRawBytes = disclosedCompact.includes(TypedArrayEncoder.toBase64URL(Buffer.from(value)));
    const inAnyDisclosure = disclosedCompact
      .split('~')
      .slice(1)
      .some((d) => d && Buffer.from(d, 'base64url').toString('utf8').includes(value));
    check(`'${label}' absent from decoded claims, raw bytes AND every disclosure`,
      !inDecoded && !inRawBytes && !inAnyDisclosure,
      { inDecoded, inRawBytes, inAnyDisclosure });
  }
  check('withheld keys are ABSENT, not present-and-empty',
    !('patientName' in seenSubject) && !('bloodType' in seenSubject) && !('prescriber' in seenSubject),
    Object.keys(seenSubject));
  console.log('   verifier sees exactly these subject keys:', JSON.stringify(Object.keys(seenSubject)));

  console.log('\n(c) are the DISCLOSED claims intact?');
  check('hivStatus intact', seenSubject.hivStatus === 'negative', seenSubject.hivStatus);
  check('medications[1] intact and ALONE',
    JSON.stringify(seenSubject.medications) === JSON.stringify(['Lisinopril 10mg']),
    seenSubject.medications);
  check('credentialSubject.id intact', seenSubject.id === HOLDER);
  check('issuer / type / validity / status intact',
    seenByVerifier.issuer === ISSUER
      && seenByVerifier.type.includes('LabResultCredential')
      && seenByVerifier.credentialStatus !== undefined);
  check('claims the verifier receives are a STRICT SUBSET of what was issued',
    Object.keys(seenSubject).length < Object.keys({ id: 1, ...claims }).length,
    { disclosed: Object.keys(seenSubject).length, issued: Object.keys({ id: 1, ...claims }).length });

  // =========================================================================
  hr('3. NEGATIVE CONTROL — TAMPERED DISCLOSURE');
  // =========================================================================
  const segments = disclosedCompact.split('~');
  const targetIndex = segments.findIndex(
    (s, i) => i > 0 && s && Buffer.from(s, 'base64url').toString('utf8').includes('negative'),
  );
  const original = JSON.parse(Buffer.from(segments[targetIndex]!, 'base64url').toString('utf8')) as unknown[];
  const forged = [original[0], original[1], 'positive'];
  console.log('  original disclosure:', JSON.stringify(original));
  console.log('  forged   disclosure:', JSON.stringify(forged), '  <- flips a negative HIV result to positive');
  const tamperedSegments = [...segments];
  tamperedSegments[targetIndex] = Buffer.from(JSON.stringify(forged)).toString('base64url');
  const tamperedCompact = tamperedSegments.join('~');

  const tamperedCred = toV2SdJwtVerifiableCredential(tamperedCompact);
  const tamperedClaims = tamperedCred
    ? (tamperedCred.sdJwt.prettyClaims.credentialSubject as Record<string, unknown>)
    : {};
  console.log('  claims resolved from the tampered artifact:', JSON.stringify(tamperedClaims));
  check('the forged value NEVER appears in resolved claims',
    JSON.stringify(tamperedClaims) !== undefined && tamperedClaims.hivStatus !== 'positive',
    tamperedClaims.hivStatus);
  check('the tampered claim is DROPPED entirely (digest no longer matches)',
    !('hivStatus' in tamperedClaims));

  const tamperedNonce = randomUUID();
  const tamperedVp = await signSdJwtPresentation(agent, {
    holderDid: HOLDER,
    credential: tamperedCred!,
    challenge: tamperedNonce,
    domain: VERIFIER_DOMAIN,
  });

  const credoTamper = await agent.w3cV2Credentials.verifyPresentation({
    presentation: W3cV2SdJwtVerifiablePresentation.fromCompact(tamperedVp.encoded),
    challenge: tamperedNonce,
    domain: VERIFIER_DOMAIN,
  });
  console.log(`  BEFORE (raw Credo isValid): ${credoTamper.isValid}`);
  check('BEFORE: unmodified Credo ACCEPTS the tampered presentation (hole 3 is real)',
    credoTamper.isValid === true);
  console.log('          ...while the claim it was asked about has silently vanished:',
    JSON.stringify(tamperedClaims));

  const tamperedResult = await verifySdJwtPresentation(agent, {
    presentation: tamperedVp,
    challenge: tamperedNonce,
    domain: VERIFIER_DOMAIN,
  });
  console.log(`  AFTER  (our boundary)     : ${tamperedResult.isValid} ${JSON.stringify(tamperedResult.errors)}`);
  check('AFTER: our boundary REJECTS the tampered disclosure', tamperedResult.isValid === false);
  check('AFTER: rejected specifically on disclosure integrity',
    tamperedResult.checks.disclosureIntegrity === false);
  check('the forged value is never reachable either way',
    !JSON.stringify(tamperedResult.credentials).includes('positive'));

  console.log('\n  --- an INJECTED extra disclosure is refused too ---');
  const injected = `${disclosedCompact}${Buffer.from(
    JSON.stringify(['aaaaaaaaaaaaaaaa', 'clearanceLevel', 'top-secret']),
  ).toString('base64url')}~`;
  const injectedVp = await signSdJwtPresentation(agent, {
    holderDid: HOLDER,
    credential: toV2SdJwtVerifiableCredential(injected)!,
    challenge: tamperedNonce,
    domain: VERIFIER_DOMAIN,
  });
  const injectedResult = await verifySdJwtPresentation(agent, {
    presentation: injectedVp,
    challenge: tamperedNonce,
    domain: VERIFIER_DOMAIN,
  });
  check('AFTER: an injected disclosure is REJECTED',
    injectedResult.isValid === false && injectedResult.checks.disclosureIntegrity === false,
    injectedResult.errors);

  console.log('\n  --- and the UNTAMPERED presentation still passes the same check ---');
  const cleanRecheck = await verifySdJwtPresentation(agent, {
    presentation: vp, challenge: nonce, domain: VERIFIER_DOMAIN,
  });
  check('the honest presentation is NOT caught by the integrity check',
    cleanRecheck.isValid && cleanRecheck.checks.disclosureIntegrity === true);

  // =========================================================================
  hr('4. NEGATIVE CONTROL — REPLAY (wrong challenge). BEFORE vs AFTER.');
  // =========================================================================
  const wrongNonce = randomUUID();
  const credoReplay = await agent.w3cV2Credentials.verifyPresentation({
    presentation: W3cV2SdJwtVerifiablePresentation.fromCompact(vp.encoded),
    challenge: wrongNonce,
    domain: VERIFIER_DOMAIN,
  });
  console.log(`  VP was signed over nonce  : ${nonce}`);
  console.log(`  verifier is asking for    : ${wrongNonce}`);
  console.log(`  BEFORE (raw Credo isValid): ${credoReplay.isValid}`);
  check('BEFORE: unmodified Credo ACCEPTS the replay (the hole is real)', credoReplay.isValid === true);

  const ourReplay = await verifySdJwtPresentation(agent, {
    presentation: vp.encoded,
    challenge: wrongNonce,
    domain: VERIFIER_DOMAIN,
  });
  console.log(`  AFTER  (our boundary)     : ${ourReplay.isValid} ${JSON.stringify(ourReplay.errors)}`);
  check('AFTER: our boundary REJECTS the replay', ourReplay.isValid === false);
  check('AFTER: rejected specifically on the challenge', ourReplay.checks.challenge === false);
  check('AFTER: signatures still verified — only the binding failed', ourReplay.checks.signatures === true);
  check('AFTER: no claims handed back from a failed verification', ourReplay.credentials.length === 0);

  console.log('\n  --- same VP, wrong AUDIENCE ---');
  const credoAud = await agent.w3cV2Credentials.verifyPresentation({
    presentation: W3cV2SdJwtVerifiablePresentation.fromCompact(vp.encoded),
    challenge: nonce,
    domain: 'https://attacker.example',
  });
  console.log(`  BEFORE (raw Credo isValid): ${credoAud.isValid}`);
  check('BEFORE: unmodified Credo ACCEPTS the wrong audience', credoAud.isValid === true);
  const ourAud = await verifySdJwtPresentation(agent, {
    presentation: vp.encoded,
    challenge: nonce,
    domain: 'https://attacker.example',
  });
  console.log(`  AFTER  (our boundary)     : ${ourAud.isValid} ${JSON.stringify(ourAud.errors)}`);
  check('AFTER: our boundary REJECTS the wrong audience', ourAud.isValid === false);
  check('AFTER: rejected specifically on the domain', ourAud.checks.domain === false);

  console.log('\n  --- a VP carrying NO nonce at all must not be treated as "nothing to check" ---');
  const noNoncePresentation = new W3cV2Presentation({
    holder: HOLDER,
    verifiableCredential: [W3cV2EnvelopedVerifiableCredential.fromVerifiableCredential(disclosed)],
  });
  const noNonceRaw = JsonTransformer.toJSON(noNoncePresentation) as Record<string, unknown>;
  void noNonceRaw;
  const noNonceCompact = await forgePresentation(noNoncePresentation, HOLDER, '', VERIFIER_DOMAIN);
  const noNonceResult = await verifySdJwtPresentation(agent, {
    presentation: noNonceCompact,
    challenge: randomUUID(),
    domain: VERIFIER_DOMAIN,
  });
  check('AFTER: an empty/absent nonce FAILS CLOSED', noNonceResult.isValid === false,
    noNonceResult.errors);

  // =========================================================================
  hr('5. NEGATIVE CONTROL — THEFT (holder binding). BEFORE vs AFTER.');
  // =========================================================================
  // The attacker wraps the victim's DISCLOSED credential in their own
  // presentation, under their own DID, signed with their own key.
  const stolenPresentation = new W3cV2Presentation({
    holder: ATTACKER,
    verifiableCredential: [W3cV2EnvelopedVerifiableCredential.fromVerifiableCredential(disclosed)],
  });
  const attackNonce = randomUUID();
  const stolenCompact = await forgePresentation(
    stolenPresentation, ATTACKER, attackNonce, VERIFIER_DOMAIN,
  );
  console.log(`  credential is bound to (cnf): ${HOLDER}#key-1`);
  console.log(`  presentation signed by      : ${ATTACKER}`);

  const credoTheft = await agent.w3cV2Credentials.verifyPresentation({
    presentation: W3cV2SdJwtVerifiablePresentation.fromCompact(stolenCompact),
    challenge: attackNonce,
    domain: VERIFIER_DOMAIN,
  });
  console.log(`  BEFORE (raw Credo isValid)  : ${credoTheft.isValid}`);
  const credoSubjAuth = (credoTheft.validations as { credentials?: Array<{ validations?: Record<string, { isValid: boolean }> }> })
    .credentials?.[0]?.validations?.credentialSubjectAuthentication;
  console.log('  Credo credentialSubjectAuthentication:', JSON.stringify(credoSubjAuth));

  const ourTheft = await verifySdJwtPresentation(agent, {
    presentation: stolenCompact,
    challenge: attackNonce,
    domain: VERIFIER_DOMAIN,
  });
  console.log(`  AFTER  (our boundary)       : ${ourTheft.isValid} ${JSON.stringify(ourTheft.errors)}`);
  check('AFTER: our boundary REJECTS the theft', ourTheft.isValid === false);
  check('AFTER: rejected specifically on holder binding', ourTheft.checks.holderBinding === false);
  check('AFTER: the error names both DIDs',
    ourTheft.errors.some((e) => e.includes(ATTACKER) && e.includes(HOLDER)), ourTheft.errors);
  check('AFTER: no claims handed back', ourTheft.credentials.length === 0);

  console.log('\n  --- the check must be UNCONDITIONAL, so isolate it from Credo\'s ---');
  console.log('  Above, the shipped policy keeps credentialSubject.id disclosed, so Credo\'s own');
  console.log('  credentialSubjectAuthentication fires too and Credo also said false. That makes');
  console.log('  the run above insufficient to show OUR check works. So: reissue under a');
  console.log('  deliberately UNSAFE policy that makes id disclosable, withhold it, and repeat.');
  console.log('  Credo must now ACCEPT the theft, and only our binding check may catch it.');

  const unsafePolicy = { alwaysDisclosed: [] as string[], maxDepth: 12 };
  const unsafeFrame = buildDisclosureFrame({ id: HOLDER, ...claims }, unsafePolicy)!;
  check('the unsafe policy really does make credentialSubject.id disclosable',
    (unsafeFrame.credentialSubject as { _sd: string[] })._sd.includes('id'));

  const unsafeSigned = await signSdJwtCredential(agent, {
    credential: buildRawCredential(),
    verificationMethod: `${ISSUER}#key-1`,
    holder: { method: 'did', didUrl: `${HOLDER}#key-1` },
    disclosureFrame: unsafeFrame,
  });
  const unsafeDisclosed = await presentSdJwtCredential(agent, unsafeSigned, {
    credentialSubject: { hivStatus: true }, // id deliberately WITHHELD
  });
  const unsafeSubject = unsafeDisclosed.sdJwt.prettyClaims.credentialSubject as Record<string, unknown>;
  console.log('  disclosed subject (note: no id):', JSON.stringify(unsafeSubject));
  check('credentialSubject.id really is withheld', !('id' in unsafeSubject));

  const isolatedNonce = randomUUID();
  const isolatedTheft = await forgePresentation(
    new W3cV2Presentation({
      holder: ATTACKER,
      verifiableCredential: [
        W3cV2EnvelopedVerifiableCredential.fromVerifiableCredential(unsafeDisclosed),
      ],
    }),
    ATTACKER,
    isolatedNonce,
    VERIFIER_DOMAIN,
  );

  const credoIsolated = await agent.w3cV2Credentials.verifyPresentation({
    presentation: W3cV2SdJwtVerifiablePresentation.fromCompact(isolatedTheft),
    challenge: isolatedNonce,
    domain: VERIFIER_DOMAIN,
  });
  console.log(`  BEFORE (raw Credo isValid): ${credoIsolated.isValid}`);
  check('BEFORE: Credo ACCEPTS the theft outright when no subject id is disclosed',
    credoIsolated.isValid === true);

  const ourIsolated = await verifySdJwtPresentation(agent, {
    presentation: isolatedTheft,
    challenge: isolatedNonce,
    domain: VERIFIER_DOMAIN,
  });
  console.log(`  AFTER  (our boundary)     : ${ourIsolated.isValid} ${JSON.stringify(ourIsolated.errors)}`);
  check('AFTER: our boundary REJECTS it', ourIsolated.isValid === false);
  check('AFTER: caught by holderBinding ALONE — every other check passed',
    ourIsolated.checks.holderBinding === false
      && ourIsolated.checks.signatures === true
      && ourIsolated.checks.disclosureIntegrity === true
      && ourIsolated.checks.challenge === true
      && ourIsolated.checks.domain === true,
    ourIsolated.checks);
  check('AFTER: no claims handed back', ourIsolated.credentials.length === 0);

  console.log('\n  --- the legitimate holder presenting the SAME credential still succeeds ---');
  const honestNonce = randomUUID();
  const honestVp = await signSdJwtPresentation(agent, {
    holderDid: HOLDER, credential: unsafeDisclosed,
    challenge: honestNonce, domain: VERIFIER_DOMAIN,
  });
  const honest = await verifySdJwtPresentation(agent, {
    presentation: honestVp, challenge: honestNonce, domain: VERIFIER_DOMAIN,
  });
  check('the binding check does NOT reject the genuine holder', honest.isValid, honest.errors);

  // =========================================================================
  hr('6. NEGATIVE CONTROL — REVOKED SD-JWT credential');
  // =========================================================================
  const beforeRevoke = await verifyCredential(seenByVerifier, {
    envelopeJwt: disclosedCompact,
    envelopeFormat: CREDENTIAL_FORMATS.SD_JWT_VC,
  });
  console.log('  before revocation:', JSON.stringify(beforeRevoke));
  check('a live SD-JWT credential verifies, revocation checked on-ledger',
    beforeRevoke.isValid && beforeRevoke.checks.revocation === true, beforeRevoke.errors);

  const revoked = await revokeCredential(row!.id, ISSUER, 'probe: revocation must bite an SD-JWT');
  console.log('  revoke:', JSON.stringify(revoked));
  check('revocation published to the ledger', revoked.statusListPublished === true, revoked.publishError);

  const afterRevoke = await verifyCredential(seenByVerifier, {
    envelopeJwt: disclosedCompact,
    envelopeFormat: CREDENTIAL_FORMATS.SD_JWT_VC,
  });
  console.log('  after revocation :', JSON.stringify(afterRevoke));
  check('the SAME selectively-disclosed credential is now REJECTED', afterRevoke.isValid === false);
  check('rejected for revocation specifically',
    afterRevoke.checks.revocation === false
      && afterRevoke.errors.some((e) => /revoked/i.test(e)), afterRevoke.errors);
  check('its signature still verifies — only the status changed',
    afterRevoke.checks.signature === true);

  // =========================================================================
  hr('7. PERSISTENCE — stored, retrievable, format explicit on the wire');
  // =========================================================================
  const reread = await db.credential.findUnique({ where: { id: row!.id } });
  const wallet = toWalletCredential({
    ...reread!,
    category: reread!.category as string,
    status: reread!.status as string,
  })!;
  check('envelope round-trips byte-identically from the DB',
    credentialEnvelopeJwt(reread!) === compact);
  check('format read back from the row, not sniffed',
    credentialEnvelopeFormat(reread!) === 'vc+sd-jwt');
  check('wire contract carries credentialFormat',
    wallet.credentialFormat === 'vc+sd-jwt', wallet.credentialFormat);
  check('wire contract carries the presentable artifact',
    wallet.credentialJwt === compact);
  check('stored credentialData is the FULL credential (holder keeps everything)',
    Object.keys(wallet.credential.credentialSubject as Record<string, unknown>).length
      === Object.keys({ id: 1, ...claims }).length,
    Object.keys(wallet.credential.credentialSubject as Record<string, unknown>));

  console.log('\n  --- the trap this guards against: a JWT reader on an SD-JWT ---');
  const viaJwtReader = jwtVcToW3cJson(compact);
  check('jwtVcToW3cJson on an SD-JWT routes correctly instead of returning a husk',
    viaJwtReader !== null
      && (viaJwtReader.credentialSubject as Record<string, unknown>).patientName === 'Ahsan Rahman',
    Object.keys((viaJwtReader?.credentialSubject ?? {}) as Record<string, unknown>));

  // =========================================================================
  hr('8. POLICY MODULE — behaviour, not inspection');
  // =========================================================================
  const frame = buildDisclosureFrame({ id: HOLDER, ...claims })!;
  console.log('  frame:', JSON.stringify(frame));
  const subjectFrame = frame.credentialSubject as Record<string, unknown>;
  check('id is NOT disclosable', !(subjectFrame._sd as string[]).includes('id'));
  check('every other subject key IS disclosable',
    Object.keys(claims).every((k) => (subjectFrame._sd as string[]).includes(k)));
  check('array element indices are NUMBERS (strings are silently ignored)',
    ((subjectFrame.medications as Record<string, unknown>)._sd as unknown[]).every(
      (i) => typeof i === 'number'),
    (subjectFrame.medications as Record<string, unknown>)._sd);
  check('nested containers get their own frame',
    Array.isArray((subjectFrame.prescriber as Record<string, unknown>)._sd));

  console.log('\n  --- the self-check refuses a frame that did not take effect ---');
  let leakCaught = false;
  try {
    assertNothingDisclosableLeaked(
      { id: HOLDER, hivStatus: 'negative' },
      { id: HOLDER, hivStatus: 'negative' }, // pretend the frame was ignored
    );
  } catch (e) {
    leakCaught = true;
    console.log('  refused:', (e as Error).message);
  }
  check('a leaked disclosable claim aborts issuance', leakCaught);
  let leakPasses = false;
  try {
    assertNothingDisclosableLeaked({ id: HOLDER, hivStatus: 'negative' }, { id: HOLDER, _sd: ['x'] });
    leakPasses = true;
  } catch { /* ignore */ }
  check('a correctly redacted payload passes the same check', leakPasses);

  // =========================================================================
  hr('9. REGRESSION — every pre-existing credential still verifies');
  // =========================================================================
  const corpus = await db.credential.findMany({ where: { id: { not: row!.id } } });
  console.log(`  corpus: ${corpus.length} rows`);
  const tally = { v1: 0, v2jwt: 0, sdjwt: 0, unreadable: 0, sigOk: 0, sigBad: 0 };

  for (const c of corpus) {
    const envelope = credentialEnvelopeJwt(c);
    const format = credentialEnvelopeFormat(c);
    const json = envelope
      ? (format === CREDENTIAL_FORMATS.SD_JWT_VC ? sdJwtVcToW3cJson(envelope) : jwtVcToW3cJson(envelope))
      : (c.credentialData as { '@context'?: unknown } | null)?.['@context']
        ? (c.credentialData as never)
        : null;

    if (!json) { tally.unreadable++; continue; }
    if (format === CREDENTIAL_FORMATS.SD_JWT_VC) tally.sdjwt++;
    else if (format === CREDENTIAL_FORMATS.VC_JWT) tally.v2jwt++;
    else tally.v1++;

    // Signature only: revocation state across a historical corpus is not the
    // property under test here, and several rows are deliberately revoked.
    const result = await verifyCredential(json, {
      envelopeJwt: envelope,
      envelopeFormat: format,
      checkRevocation: false,
      checkExpiration: false,
    });
    if (result.checks.signature) tally.sigOk++;
    else { tally.sigBad++; console.log(`    SIG FAIL ${c.id} format=${format}: ${result.errors.join('; ')}`); }
  }
  console.log('  tally:', JSON.stringify(tally));
  check('every pre-migration VC 1.1 row is still readable', tally.v1 > 0, tally.v1);
  check('every VC 2.0 vc+jwt row is still readable', tally.v2jwt > 0, tally.v2jwt);
  check('no row became unreadable', tally.unreadable === 0, tally.unreadable);
  check('EVERY corpus credential still passes signature verification',
    tally.sigBad === 0 && tally.sigOk === corpus.length, tally);

  // =========================================================================
  hr('10. REGRESSION — a vc+jwt credential still issues and presents');
  // =========================================================================
  const jwtIssued = await issueCredential({
    issuerDid: ISSUER,
    subjectDid: HOLDER,
    credentialType: 'VaccinationCredential',
    category: 'vaccinations',
    claims: { vaccine: 'Measles', doses: 2 },
  });
  const jwtRow = await db.credential.findFirst({
    where: { holderDid: HOLDER, type: { has: 'VaccinationCredential' } },
    orderBy: { createdAt: 'desc' },
  });
  check('default format is still vc+jwt (additive, not a cutover)',
    jwtRow!.credentialFormat === 'vc+jwt', jwtRow!.credentialFormat);
  check('its envelope is a plain JWT', !jwtRow!.credentialJwt!.includes('~'));
  check('it carries all claims in cleartext, as a JWT credential must',
    (jwtIssued.credential.credentialSubject as Record<string, unknown>).vaccine === 'Measles');
  const jwtVerify = await verifyCredential(jwtIssued.credential, {
    envelopeJwt: jwtRow!.credentialJwt,
    envelopeFormat: CREDENTIAL_FORMATS.VC_JWT,
  });
  check('a freshly issued vc+jwt credential still verifies end to end',
    jwtVerify.isValid, jwtVerify.errors);

  // =========================================================================
  hr('SUMMARY');
  // =========================================================================
  if (failures.length === 0) console.log('RESULT: PASS — all checks green');
  else {
    console.log(`RESULT: FAIL — ${failures.length} check(s) failed:`);
    for (const f of failures) console.log('  -', f);
  }

  await shutdownAgent();
  await db.$disconnect();
  process.exit(failures.length === 0 ? 0 : 1);
}

main().catch(async (e) => {
  console.error('PROBE THREW:', (e as Error)?.message ?? e);
  console.error((e as Error)?.stack?.split('\n').slice(0, 25).join('\n'));
  await shutdownAgent().catch(() => {});
  await db.$disconnect().catch(() => {});
  process.exit(1);
});
