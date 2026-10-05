/**
 * SD-JWT ROUND 2 — DISCLOSURE UX AND WIRE NEGOTIATION — evidence probe.
 *
 * Round 1 proved selective disclosure works in the backend. This probe proves
 * the part a holder can actually reach: that a verifier can STATE what it
 * needs, that the wallet's sheet DEFAULTS to the minimum satisfying that, and
 * that presenting at the default produces an artifact from which the withheld
 * claims are genuinely absent.
 *
 * The load-bearing assertions here are the DEFAULTS. A disclosure sheet whose
 * default is "everything" produces exactly as much disclosure as having no
 * sheet at all, plus a consent record saying the holder chose it — so the
 * default is the privacy property, and it is asserted rather than described.
 *
 * Companion to probe-sdjwt.mts, which is the round-1 regression suite and must
 * continue to pass unchanged.
 */
import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import {
  W3cV2Credential,
  W3cV2CredentialSubject,
  W3cV2Presentation,
  W3cV2EnvelopedVerifiableCredential,
  W3cV2SdJwtVerifiableCredential,
  JsonTransformer,
  TypedArrayEncoder,
  Hasher,
  Kms,
} from '@credo-ts/core';
import { createAgent, shutdownAgent, getAgent } from './src/agent/index.js';
import {
  presentSdJwtCredential,
  signSdJwtPresentation,
  verifySdJwtPresentation,
  sdJwtVcToW3cJson,
} from './src/services/sdJwtVc.js';
import { secureV2Credential } from './src/services/securing.js';
import {
  allocateStatusIndex,
  buildStatusEntry,
  ensureStatusListPublished,
  toCredoV2CredentialStatus,
} from './src/services/statusListService.js';
import {
  enumerateDisclosableClaims,
  buildPresentationFrame,
  buildDisclosureChoices,
  presentationFrameForChoices,
  volunteeredClaims,
  unsatisfiableRequirements,
  claimRequestsFromInputDescriptor,
  subjectClaimJsonPath,
  parseClaimPath,
  CREDENTIAL_FORMATS,
  type DisclosureChoice,
  type VerifierClaimRequest,
} from '@ssi-healthcare/shared';

const ISSUER = 'did:cheqd:bdhealthtestnet:fa3fc79f-9d49-43f5-9aa7-4f2df973bbb0';
const HOLDER = 'did:cheqd:bdhealthtestnet:7cd03fdc-6a88-4895-9d89-e63445abe0c1';
const ATTACKER = 'did:cheqd:bdhealthtestnet:a697648c-7a8a-43b3-825b-7bb50725d764';
const PHARMACY = 'https://pharmacy.bd-health.example';

/** The subject the whole probe issues over. */
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

async function main() {
  const agent = await createAgent();
  const subject = { id: HOLDER, ...claims };

  // =========================================================================
  hr('1. THE HOLDER SEES EVERY CLAIM THE ISSUER MADE DISCLOSABLE — AND ONLY THOSE');
  // =========================================================================
  const disclosable = enumerateDisclosableClaims(subject);
  const paths = disclosable.map((c) => c.path).sort();
  console.log('  disclosable leaf paths:', JSON.stringify(paths));

  check('every scalar claim is offered as a choice',
    ['bloodType', 'hivStatus', 'patientName', 'testDate'].every((p) => paths.includes(p)));
  check('nested container members are offered INDIVIDUALLY',
    paths.includes('prescriber.name') && paths.includes('prescriber.licence'));
  check('array elements are offered INDIVIDUALLY',
    paths.includes('medications[0]') && paths.includes('medications[1]') && paths.includes('medications[2]'));
  check('credentialSubject.id is NOT offered — it is outside the issuer frame and locked there',
    !paths.includes('id'));
  check('containers are not offered as bare toggles (naming one alone discloses it EMPTY)',
    !paths.includes('prescriber') && !paths.includes('medications'));

  // =========================================================================
  hr('2. THE DARK-PATTERN PROPERTY — WHAT THE SHEET IS PRE-SET TO');
  // =========================================================================
  // A pharmacy dispensing a prescription needs the medication and the
  // prescriber's licence. It does not need the patient's HIV status, and says
  // the patient's name is optional.
  const pharmacyRequests: VerifierClaimRequest[] = [
    { path: 'medications[1]', requirement: 'required', purpose: 'To dispense the correct medicine' },
    { path: 'prescriber.licence', requirement: 'required', purpose: 'To confirm the prescriber is registered' },
    { path: 'patientName', requirement: 'optional', purpose: 'To label the package' },
  ];

  const choices = buildDisclosureChoices(disclosable, pharmacyRequests);
  const selected = choices.filter((c) => c.disclosed).map((c) => c.path).sort();
  console.log('  pre-selected at open:', JSON.stringify(selected));

  check('THE DEFAULT IS EXACTLY THE REQUIRED SET — not everything',
    JSON.stringify(selected) === JSON.stringify(['medications[1]', 'prescriber.licence']),
    selected);
  check('an OPTIONAL claim starts UNSELECTED — "optional" is honoured, not treated as yes',
    choices.find((c) => c.path === 'patientName')!.disclosed === false);
  check('a claim the verifier never mentioned starts UNSELECTED',
    choices.filter((c) => c.requirement === null).every((c) => !c.disclosed));
  check('NOT ASKED and OPTIONAL stay distinguishable (never collapsed to one state)',
    choices.find((c) => c.path === 'patientName')!.requirement === 'optional'
      && choices.find((c) => c.path === 'hivStatus')!.requirement === null);
  check('required claims are locked; nothing else is',
    choices.every((c) => c.locked === (c.requirement === 'required')));
  check('the minimal disclosure costs ZERO taps — the confirm button is live at open',
    selected.length > 0);
  check('nothing volunteered at the default',
    volunteeredClaims(choices).length === 0, volunteeredClaims(choices));

  // The asymmetry that enforces it: over-disclosure is one deliberate tap each.
  const overDisclosed: DisclosureChoice[] = choices.map((c) =>
    c.path === 'hivStatus' ? { ...c, disclosed: true } : c);
  check('over-disclosure IS possible — the sheet is not paternalistic',
    volunteeredClaims(overDisclosed).includes('hivStatus'));
  check('...and it is NAMED the moment it happens, so it cannot pass unnoticed',
    volunteeredClaims(overDisclosed).length === 1, volunteeredClaims(overDisclosed));

  // A verifier can ask for something this credential does not carry.
  check('a required claim the credential cannot supply is detected BEFORE the holder consents',
    unsatisfiableRequirements(disclosable, [
      ...pharmacyRequests,
      { path: 'insurancePolicyNumber', requirement: 'required' },
    ]).includes('insurancePolicyNumber'));

  // =========================================================================
  hr('3. WIRE NEGOTIATION — the verifier states requirements, the wallet reads them back');
  // =========================================================================
  // Exactly the descriptor shape routes/oid4vp.ts builds.
  const inputDescriptor = {
    id: 'descriptor_0',
    name: 'LabResultCredential',
    constraints: {
      fields: [
        { path: ['$.type'], filter: { type: 'array', contains: { const: 'LabResultCredential' } } },
        ...pharmacyRequests.map((r) => ({
          path: [subjectClaimJsonPath(r.path)],
          optional: r.requirement === 'optional',
          ...(r.purpose ? { purpose: r.purpose } : {}),
        })),
      ],
    },
  };

  const parsed = claimRequestsFromInputDescriptor(inputDescriptor);
  check('every stated claim requirement survives the round trip',
    parsed.length === pharmacyRequests.length, parsed.length);
  check('required/optional polarity survives (PE says `optional`, we say `requirement`)',
    parsed.find((r) => r.path === 'medications[1]')!.requirement === 'required'
      && parsed.find((r) => r.path === 'patientName')!.requirement === 'optional');
  check('the purpose reaches the holder, so the ask is explainable',
    parsed.find((r) => r.path === 'prescriber.licence')!.purpose ===
      'To confirm the prescriber is registered');
  check('$.type is NOT read as a disclosure choice — it is a credential filter',
    !parsed.some((r) => r.path === 'type'));
  check('paths parse to segments, with array indices as NUMBERS',
    JSON.stringify(parseClaimPath('medications[1]')) === JSON.stringify(['medications', 1]));

  // The wallet rebuilds the same sheet from the wire alone.
  const choicesFromWire = buildDisclosureChoices(disclosable, parsed);
  check('the sheet built FROM THE WIRE is identical to the sheet built from intent',
    JSON.stringify(choicesFromWire) === JSON.stringify(choices));

  // =========================================================================
  hr('4. ISSUE as vc+sd-jwt through the shared securing step');
  // =========================================================================
  const doc = await agent.dids.resolve(ISSUER);
  const am = doc.didDocument!.assertionMethod![0];
  const vmId = typeof am === 'string' ? am : (am as { id: string }).id;

  // A REAL status entry, because one of the properties this probe asserts is
  // that revocation stays checkable on a REDACTED credential. Constructing the
  // credential without a status would make that assertion vacuous — it would
  // pass or fail on whether the probe remembered to set it up, not on whether
  // the disclosure frame leaves `credentialStatus` in the clear.
  const { list: statusList, index: statusIndex } = await allocateStatusIndex(ISSUER);
  const publishedList = await ensureStatusListPublished(statusList);
  const statusEntry = buildStatusEntry(publishedList, statusIndex);

  const credential = new W3cV2Credential({
    context: ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
    id: `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', 'LabResultCredential'],
    issuer: ISSUER,
    validFrom: new Date().toISOString(),
    validUntil: new Date(Date.now() + 86400_000).toISOString(),
    credentialSubject: new W3cV2CredentialSubject(subject),
    credentialStatus: toCredoV2CredentialStatus(statusEntry),
  });

  const secured = await secureV2Credential(agent, {
    credential,
    format: CREDENTIAL_FORMATS.SD_JWT_VC,
    verificationMethod: vmId,
    holder: { method: 'did', didUrl: `${HOLDER}#key-1` },
    subjectClaims: subject,
  });

  check('the shared securing step reports the format it produced',
    secured.format === CREDENTIAL_FORMATS.SD_JWT_VC, secured.format);
  check('the envelope is an SD-JWT', secured.envelope.includes('~'));
  check('the holder\'s own stored copy keeps EVERY claim (selection happens later)',
    Object.keys(secured.json.credentialSubject as Record<string, unknown>).length
      === Object.keys(subject).length);

  // =========================================================================
  hr('5. THE CORE PROOF — present at the SHEET DEFAULT and check the SIGNED ARTIFACT');
  // =========================================================================
  const frame = presentationFrameForChoices(choices);
  console.log('  presentation frame from the default sheet:', JSON.stringify(frame));

  const disclosedCredential = await presentSdJwtCredential(agent, secured.envelope, frame);
  const disclosedCompact = disclosedCredential.encoded;
  const seen = sdJwtVcToW3cJson(disclosedCompact)!;
  const seenSubject = seen.credentialSubject as Record<string, unknown>;
  console.log('  verifier sees subject keys:', JSON.stringify(Object.keys(seenSubject)));
  console.log('  full view:', JSON.stringify(seenSubject));

  const nonce = randomUUID();
  const vp = await signSdJwtPresentation(agent, {
    holderDid: HOLDER,
    credential: disclosedCredential,
    challenge: nonce,
    domain: PHARMACY,
  });
  const verified = await verifySdJwtPresentation(agent, {
    presentation: vp,
    challenge: nonce,
    domain: PHARMACY,
  });

  check('the minimal presentation VERIFIES — disclosing less is not disclosing wrong',
    verified.isValid, verified.errors);
  check('all five checks green', Object.values(verified.checks).every(Boolean), verified.checks);

  console.log('\n  (a) did the verifier get what it REQUIRED?');
  check('required medications[1] delivered',
    JSON.stringify(seenSubject.medications) === JSON.stringify(['Lisinopril 10mg']),
    seenSubject.medications);
  check('required prescriber.licence delivered',
    (seenSubject.prescriber as Record<string, unknown>)?.licence === 'BMDC-4471');

  console.log('\n  (b) is everything else ABSENT FROM THE SIGNED ARTIFACT, not merely unrendered?');
  // Three independent readings. "Absent from the object we built" is not the
  // same as "absent from the bytes the verifier received".
  const secrets: Array<[string, string]> = [
    ['patientName (optional, declined)', 'Ahsan Rahman'],
    ['hivStatus (never asked for)', 'negative'],
    ['bloodType (never asked for)', 'O+'],
    ['testDate (never asked for)', '2026-08-10'],
    ['prescriber.name (never asked for)', 'Dr Karim'],
    ['medications[0] (never asked for)', 'Metformin 500mg'],
    ['medications[2] — the psychiatric one', 'Sertraline 50mg'],
  ];
  for (const [label, value] of secrets) {
    const inDecoded = JSON.stringify(seen).includes(value);
    const inRawBytes = disclosedCompact.includes(TypedArrayEncoder.toBase64URL(Buffer.from(value)));
    const inAnyDisclosure = disclosedCompact
      .split('~')
      .slice(1)
      .some((d) => d && Buffer.from(d, 'base64url').toString('utf8').includes(value));
    check(`'${label}' absent from decoded claims, RAW BYTES and every disclosure`,
      !inDecoded && !inRawBytes && !inAnyDisclosure,
      { inDecoded, inRawBytes, inAnyDisclosure });
  }

  check('withheld claims are ABSENT, not present-and-empty',
    !('patientName' in seenSubject) && !('hivStatus' in seenSubject) && !('bloodType' in seenSubject),
    Object.keys(seenSubject));
  check('the prescriber container carries ONLY the disclosed member',
    JSON.stringify(seenSubject.prescriber) === JSON.stringify({ licence: 'BMDC-4471' }),
    seenSubject.prescriber);
  check('one medication disclosed, and the ARRAY LENGTH does not betray the other two',
    (seenSubject.medications as unknown[]).length === 1);
  check('what the verifier receives is a STRICT SUBSET of what was issued',
    Object.keys(seenSubject).length < Object.keys(subject).length,
    { disclosed: Object.keys(seenSubject).length, issued: Object.keys(subject).length });
  check('credentialSubject.id survives — holder binding stays checkable',
    seenSubject.id === HOLDER);
  check('credentialStatus survives — revocation stays checkable on a redacted credential',
    seen.credentialStatus !== undefined);

  // =========================================================================
  hr('6. THE CONTAINER FOOTGUN — a bare container toggle would disclose it EMPTY');
  // =========================================================================
  // Measured, and the reason buildPresentationFrame takes LEAF paths only.
  const bareContainer = await presentSdJwtCredential(agent, secured.envelope, {
    credentialSubject: { prescriber: true },
  });
  const bareSeen = (sdJwtVcToW3cJson(bareContainer.encoded)!.credentialSubject as Record<string, unknown>);
  check('naming a container ALONE yields an EMPTY object — existence without contents',
    JSON.stringify(bareSeen.prescriber) === '{}', bareSeen.prescriber);
  check('...whereas our builder, given a leaf, discloses the member itself',
    JSON.stringify(
      buildPresentationFrame(['prescriber.licence']),
    ) === JSON.stringify({ credentialSubject: { prescriber: { licence: true } } }));
  check('a container path can never reach the frame as a bare `true` from a sheet',
    !enumerateDisclosableClaims(subject).some((c) => c.path === 'prescriber'));

  // =========================================================================
  hr('7. NEGATIVE CONTROLS — still fail closed on the round-2 presentation path');
  // =========================================================================
  console.log('\n  (a) REPLAY — captured VP replayed at a different verifier/nonce');
  const replay = await verifySdJwtPresentation(agent, {
    presentation: vp,
    challenge: randomUUID(),
    domain: 'https://hospital-b.bd-health.example',
  });
  check('replay REJECTED', replay.isValid === false);
  check('...on the challenge', replay.checks.challenge === false);
  check('...and on the domain', replay.checks.domain === false);
  check('signatures still verified — only the binding failed', replay.checks.signatures === true);
  check('no claims handed back from a failed verification', replay.credentials.length === 0);

  console.log('\n  (b) THEFT — attacker wraps the captured credential in their own VP');
  const stolen = new W3cV2Presentation({
    holder: ATTACKER,
    verifiableCredential: [
      W3cV2EnvelopedVerifiableCredential.fromVerifiableCredential(disclosedCredential),
    ],
  });
  const theftNonce = randomUUID();
  const forged = await forgePresentation(stolen, ATTACKER, theftNonce, PHARMACY);
  const theft = await verifySdJwtPresentation(agent, {
    presentation: forged,
    challenge: theftNonce,
    domain: PHARMACY,
  });
  check('theft REJECTED', theft.isValid === false);
  check('...on holder binding', theft.checks.holderBinding === false);
  check('...and the error names both DIDs',
    theft.errors.some((e) => e.includes(ATTACKER) && e.includes(HOLDER)), theft.errors);
  check('no claims handed back', theft.credentials.length === 0);

  console.log('\n  (c) UNMATCHED DISCLOSURE — attacker injects a disclosure matching no digest');
  const segments = disclosedCompact.split('~');
  const injected = TypedArrayEncoder.toBase64URL(
    Buffer.from(JSON.stringify(['injectedsalt', 'hivStatus', 'positive'])),
  );
  const tamperedCompact = [...segments.slice(0, -1), injected, segments[segments.length - 1]].join('~');
  const tamperedCredential = W3cV2SdJwtVerifiableCredential.fromCompact(tamperedCompact);
  const tamperNonce = randomUUID();
  const tamperedVp = await signSdJwtPresentation(agent, {
    holderDid: HOLDER,
    credential: tamperedCredential,
    challenge: tamperNonce,
    domain: PHARMACY,
  });
  const tampered = await verifySdJwtPresentation(agent, {
    presentation: tamperedVp,
    challenge: tamperNonce,
    domain: PHARMACY,
  });
  check('injected disclosure REJECTED', tampered.isValid === false);
  check('...on disclosure integrity', tampered.checks.disclosureIntegrity === false);
  check('the injected value is never reachable as a claim',
    !JSON.stringify(tampered.credentials).includes('positive'));

  console.log('\n  (d) the HONEST minimal presentation is not caught by any of the above');
  const reNonce = randomUUID();
  const honestVp = await signSdJwtPresentation(agent, {
    holderDid: HOLDER,
    credential: disclosedCredential,
    challenge: reNonce,
    domain: PHARMACY,
  });
  const honest = await verifySdJwtPresentation(agent, {
    presentation: honestVp, challenge: reNonce, domain: PHARMACY,
  });
  check('the genuine holder disclosing the minimum still SUCCEEDS', honest.isValid, honest.errors);

  // =========================================================================
  hr('8. DISCLOSING NOTHING is a legal, meaningful level — not a crash');
  // =========================================================================
  const nothing = await presentSdJwtCredential(agent, secured.envelope, buildPresentationFrame([]));
  const nothingSeen = sdJwtVcToW3cJson(nothing.encoded)!.credentialSubject as Record<string, unknown>;
  check('a zero-claim presentation still carries id and nothing else',
    JSON.stringify(Object.keys(nothingSeen)) === JSON.stringify(['id']), Object.keys(nothingSeen));
  const nothingNonce = randomUUID();
  const nothingVp = await signSdJwtPresentation(agent, {
    holderDid: HOLDER, credential: nothing, challenge: nothingNonce, domain: PHARMACY,
  });
  const nothingResult = await verifySdJwtPresentation(agent, {
    presentation: nothingVp, challenge: nothingNonce, domain: PHARMACY,
  });
  check('...and it VERIFIES — proving genuineness without revealing any claim',
    nothingResult.isValid, nothingResult.errors);

  // =========================================================================
  hr('SUMMARY');
  // =========================================================================
  if (failures.length === 0) console.log('RESULT: PASS — all checks green');
  else {
    console.log(`RESULT: FAIL — ${failures.length} check(s) failed:`);
    for (const f of failures) console.log(`  - ${f}`);
  }

  await shutdownAgent();
  process.exit(failures.length === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
