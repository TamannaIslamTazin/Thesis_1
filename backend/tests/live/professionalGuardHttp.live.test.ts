/**
 * THE PROFESSIONAL-AUTHORITY GUARD, END TO END, OVER HTTP — CLOSES #263.
 *
 * Phase A verified the DECISION against a real chain (8 tests) but never a
 * REQUEST. `consumeChallenge`'s compare-and-swap and `recordChallengeOutcome`
 * compiled and were reasoned about; neither had ever executed, because the live
 * suite signed presentations in-process and nothing on the holder side ever
 * spoke HTTP. The header names, the 401-vs-403 split and the single-use
 * semantics were therefore PLANNED, not verified. This file drives all of them
 * through a running backend:
 *
 *   challenge -> present -> POST /api/pharmacy/dispense
 *
 * ---------------------------------------------------------------------------
 * WHY THE REPLAY ASSERTION IS THE ONE THAT MATTERS
 * ---------------------------------------------------------------------------
 * A presentation is a bearer artifact for as long as its challenge is open. The
 * single-use property is the ONLY thing standing between a captured
 * presentation and an attacker replaying it, and it is implemented as one
 * conditional UPDATE out of `REQUESTED`. A read-then-write in that position
 * would pass every sequential test ever written and still admit two concurrent
 * requests. So replay is asserted twice, and the second form is the one the
 * compare-and-swap actually exists for:
 *
 *   SEQUENTIAL — the same VP submitted twice; the second is refused.
 *   CONCURRENT — the same VP submitted twice AT THE SAME TIME against the same
 *                challenge; exactly one succeeds.
 *
 * Each replay targets a DIFFERENT, undispensed prescription, so "refused" is
 * distinguishable from "the guard let it through and the route refused a
 * duplicate dispense". The assertion is on the audit row, not just the status.
 *
 * ---------------------------------------------------------------------------
 * WHY MINIMAL DISCLOSURE IS ASSERTED ON THE WIRE AND NOT INFERRED
 * ---------------------------------------------------------------------------
 * The licence issued here carries a claim NOBODY ASKED FOR (`homeAddress`). The
 * holder client derives its frame from the verifier's own presentation
 * definition, so that claim must never leave the wallet. It is asserted by
 * decoding the disclosures out of the compact VP, not by trusting the client —
 * `presentSdJwtCredential(agent, x, true)` produced a well-formed, correctly
 * signed credential that asserted NOTHING until #259, which is exactly how much
 * a "it returned a string" assertion is worth here.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS NEEDS A RUNNING BACKEND, AND REFUSES TO SKIP
 * ---------------------------------------------------------------------------
 * The properties live in middleware and in the error middleware's status
 * mapping. There is no function to call: 401-vs-403 is a claim about what an
 * HTTP client observes. Same reasoning, and the same hard failure, as
 * `unsupportedFormat.live.test.ts` and `setup/requireLiveStack.ts` — a skipped
 * test reports green, and green here would mean #263 was closed by a run that
 * exercised nothing.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID, createHash } from 'node:crypto';
import {
  CREDENTIAL_FORMATS,
  HealthcareCredentialCategory,
  PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  buildDisclosureFrame,
} from '@ssi-healthcare/shared';
import { W3cV2Credential, W3cV2CredentialSubject, type Agent } from '@credo-ts/core';
import { createAgent, shutdownAgent } from '../../src/agent/index.js';
import { issueCredential } from '../../src/services/credentialService.js';
import { signSdJwtCredential } from '../../src/services/sdJwtVc.js';
import {
  callWithProfessionalAuthority,
  claimsRequestedBy,
  professionalPresentationHeaders,
  ProfessionalPresentationError,
  requestProfessionalChallenge,
  signProfessionalPresentation,
  type ProfessionalChallengeResponse,
} from '../../src/services/professionalPresentation.js';
import { db } from '../../src/db/index.js';
import { createSession } from '../../src/db/userRepository.js';
import { ISSUER, HOLDER } from './helpers/liveSdJwt.js';

const BASE_URL = process.env.LIVE_TEST_BASE_URL ?? `http://localhost:${process.env.PORT ?? 3001}`;

/**
 * The patient whose prescription is dispensed.
 *
 * A synthetic DID on our namespace, deliberately NOT one of the three audited
 * fixtures. Nothing in the dispense path resolves it — it is a column — and
 * reusing a fixture DID as "the patient" would make a later reader think the
 * choice was load bearing.
 */
const PATIENT = `did:cheqd:bdhealthtestnet:${randomUUID()}`;

/** What the guard on `POST /api/pharmacy/dispense` demands. */
const DISPENSE = { profession: 'pharmacist', scope: ['dispense'] } as const;

/**
 * The licence the pharmacist holds — plus one claim no verifier asks for.
 *
 * `homeAddress` is the minimal-disclosure canary. See the header.
 */
const PHARMACIST_LICENCE = {
  profession: 'pharmacist',
  licenceNumber: 'PCB-A-7742',
  register: 'Register of Pharmacists, Grade A',
  practiceScope: ['dispense', 'view-patient-record'],
  licenceValidFrom: '2026-02-01T00:00:00.000Z',
  licenceValidUntil: '2030-02-01T00:00:00.000Z',
  homeAddress: '14/B Kalabagan, Dhaka 1205',
};

/** A real, valid licence that simply does not authorise dispensing. */
const DOCTOR_LICENCE = {
  profession: 'doctor',
  licenceNumber: 'BMDC-A-1180',
  register: 'Register of Medical Practitioners',
  practiceScope: ['prescribe', 'view-patient-record'],
  licenceValidFrom: '2026-02-01T00:00:00.000Z',
  licenceValidUntil: '2030-02-01T00:00:00.000Z',
};

let agent: Agent;
let accessToken: string;
let pharmacistLicenceJwt: string;
let doctorLicenceJwt: string;

/** Everything this file wrote, torn down in reverse. */
const created = {
  userId: undefined as string | undefined,
  createdUser: false,
  consentId: undefined as string | undefined,
  prescriptionIds: [] as string[],
  licenceIds: [] as string[],
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** A fresh, undispensed prescription. One per dispense attempt, never shared. */
async function seedPrescription(label: string): Promise<string> {
  const id = `urn:uuid:${randomUUID()}`;
  const row = await db.credential.create({
    data: {
      holderDid: PATIENT,
      issuerDid: ISSUER,
      type: ['VerifiableCredential', 'PrescriptionCredential'],
      category: 'PRESCRIPTIONS',
      name: `R4 Phase B prescription (${label})`,
      // Seeded rather than issued: the dispense route reads this row and never
      // verifies it cryptographically, so signing one would add a ledger write
      // and a status-list allocation that no assertion in this file depends on.
      credentialData: {
        id,
        credentialSubject: { id: PATIENT, medicationName: 'Metformin 500mg' },
      },
      credentialHash: createHash('sha256').update(id).digest('hex'),
      issuedAt: new Date(),
    },
  });
  created.prescriptionIds.push(row.id);
  return row.id;
}

/** Whether the dispense actually happened, which is the real success signal. */
async function wasDispensed(prescriptionRowId: string): Promise<boolean> {
  const row = await db.auditLog.findFirst({
    where: { resourceId: prescriptionRowId, eventType: 'PRESCRIPTION_DISPENSED' },
  });
  return row !== null;
}

/**
 * The claim names a compact `vp+sd-jwt` actually reveals.
 *
 * Reads the disclosures out of the enveloped credential rather than asking the
 * client what it disclosed. An SD-JWT disclosure is a base64url JSON triple
 * `[salt, key, value]` for an object member (a pair for an array element, which
 * has no name and is skipped).
 */
function disclosedClaimNames(compactVp: string): string[] {
  const payload = JSON.parse(
    Buffer.from(compactVp.split('~')[0]!.split('.')[1]!, 'base64url').toString('utf8'),
  ) as { verifiableCredential?: Array<{ id?: string }> };

  const envelope = payload.verifiableCredential?.[0]?.id ?? '';
  const compactCredential = envelope.slice(envelope.indexOf(',') + 1);

  const names: string[] = [];
  for (const segment of compactCredential.split('~').slice(1)) {
    if (!segment) continue;
    try {
      const decoded = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as unknown[];
      if (decoded.length === 3 && typeof decoded[1] === 'string') names.push(decoded[1]);
    } catch {
      // The trailing segment of a presented SD-JWT is the key-binding JWT, not
      // a disclosure. Not an error; it simply has no claim name to contribute.
    }
  }
  return names;
}

async function issueLicence(claims: Record<string, unknown>): Promise<string> {
  await issueCredential({
    issuerDid: ISSUER,
    subjectDid: HOLDER,
    credentialType: PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
    category: HealthcareCredentialCategory.PROFESSIONAL,
    claims,
    format: CREDENTIAL_FORMATS.SD_JWT_VC,
  });

  const row = await db.credential.findFirst({
    where: {
      holderDid: HOLDER,
      issuerDid: ISSUER,
      type: { has: PROFESSIONAL_LICENCE_CREDENTIAL_TYPE },
    },
    orderBy: { createdAt: 'desc' },
  });

  created.licenceIds.push(row!.id);
  return row!.credentialJwt!;
}

beforeAll(async () => {
  // Scoped to THIS file, for the reason in unsupportedFormat.live.test.ts: the
  // other live files drive services directly and must not be made to depend on
  // a running HTTP server.
  let health: number;
  try {
    health = (await fetch(`${BASE_URL}/api/health`, { signal: AbortSignal.timeout(10_000) })).status;
  } catch (error) {
    throw new Error(
      `LIVE HTTP PRECONDITION FAILED — the backend is not reachable at ${BASE_URL} ` +
        `(${error instanceof Error ? error.message : String(error)}).\n\n` +
        '  cd /home/ahsan/Work/Project/BDHealthTrust/SSI_healthcare && pnpm dev:backend\n\n' +
        'Every property in this file is a claim about an HTTP status produced by ' +
        'middleware. There is nothing meaningful to assert without a server.',
    );
  }
  if (health !== 200) {
    throw new Error(`Backend at ${BASE_URL} answered /api/health with ${health}, expected 200`);
  }

  if (!process.env.VERIFIER_DID) {
    throw new Error(
      'LIVE PRECONDITION FAILED — VERIFIER_DID is not set.\n\n' +
        '  Set VERIFIER_DID in packages/backend/.env and restart the backend.\n\n' +
        'The guard refuses every request with 503 when it has no audience to bind ' +
        'presentations to, so without it this file would assert 503 everywhere and ' +
        'prove nothing about authorization.',
    );
  }

  agent = await createAgent();

  const user = await db.user.upsert({
    where: { did: HOLDER },
    update: { walletSetup: true },
    create: {
      did: HOLDER,
      email: `r4-phase-b-pharmacist-${randomUUID()}@bd-health.example`,
      firstName: 'Rokeya',
      lastName: 'Sultana',
      walletSetup: true,
    },
  });
  created.userId = user.id;
  // Non-null assertion: the `create` branch above always sets an email, so
  // `upsert` cannot return one without it here. `User.email` became optional
  // for the DID-only signup path added in the auth/keystore round; this
  // fixture does not exercise that path.
  created.createdUser = user.email!.startsWith('r4-phase-b-pharmacist-');

  // `requireAuth` refuses a token shorter than 32 characters before it reaches
  // the database, so the fixture has to be a realistic length.
  const token = `${randomUUID()}${randomUUID()}`.replace(/-/g, '');
  // THROUGH THE REPOSITORY, NOT `db.session.create`. The column stores
  // `sha256(token)`, not the token — a fixture that wrote the raw value
  // produced a row `findSessionByToken` could never match, and every test in
  // this file failed with "Invalid or expired session" for a reason that had
  // nothing to do with professional authority. Using the production path is
  // what stops the fixture drifting from the scheme again.
  await createSession({
    user: { connect: { id: user.id } },
    token,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });
  accessToken = token;

  const consent = await db.consent.create({
    data: {
      holderDid: PATIENT,
      verifierDid: HOLDER,
      verifierName: 'R4 Phase B pharmacy',
      credentialTypes: ['PrescriptionCredential'],
      credentialIds: [],
      attributes: [],
      purpose: 'TREATMENT',
      isActive: true,
    },
  });
  created.consentId = consent.id;

  pharmacistLicenceJwt = await issueLicence(PHARMACIST_LICENCE);
  doctorLicenceJwt = await issueLicence(DOCTOR_LICENCE);
});

afterAll(async () => {
  if (created.prescriptionIds.length > 0) {
    await db.auditLog.deleteMany({ where: { resourceId: { in: created.prescriptionIds } } });
  }
  if (created.consentId) await db.consent.delete({ where: { id: created.consentId } }).catch(() => undefined);
  // By user, not by token: the column holds the hash, not the value we kept.
  if (created.userId) await db.session.deleteMany({ where: { userId: created.userId } });
  await db.credential.deleteMany({
    where: { id: { in: [...created.prescriptionIds, ...created.licenceIds] } },
  });
  // The user is left in place unless this run created it: other live files and
  // fixtures key off HOLDER, and deleting a row they depend on would make this
  // file's cleanup a cause of their failures.
  if (created.createdUser && created.userId) {
    await db.user.delete({ where: { id: created.userId } }).catch(() => undefined);
  }
  await shutdownAgent();
});

/**
 * Turn the deployment's own rate limit into an actionable precondition rather
 * than a mystery assertion failure.
 *
 * MEASURED (R4 Phase B): `apiLimiter` allows 100 requests per 15 minutes PER IP
 * across `/api/pharmacy`, `/api/professional` and their siblings, and the whole
 * live suite shares one loopback address. One pass of this file costs roughly
 * thirty — comfortably inside the budget — but iterating on it, or running the
 * suite three times inside one window, exhausts it. Every request then returns
 * 429 and every assertion in the file fails for a reason that has nothing to do
 * with professional authority.
 *
 * Named here rather than worked around. Raising the limit for the convenience
 * of a test would be changing production-shaped security behaviour to suit the
 * harness, and silently retrying past a 429 would teach the suite to ignore the
 * one signal that says the server is shedding load.
 */
function assertNotRateLimited(status: number, what: string): void {
  if (status !== 429) return;
  throw new Error(
    `LIVE PRECONDITION FAILED — the backend rate-limited ${what} (429).\n\n` +
      '  Restart the backend; express-rate-limit keeps its counters in memory,\n' +
      '  so a restart clears the window immediately. Otherwise wait 15 minutes.\n\n' +
      'This is the deployment refusing, not the guard. Nothing about professional ' +
      'authority can be concluded from a run that was shed at the front door.',
  );
}

/** One challenge for the dispense requirement, via the holder client. */
async function newChallenge(): Promise<ProfessionalChallengeResponse> {
  try {
    return await requestProfessionalChallenge({
      baseUrl: BASE_URL,
      accessToken,
      requirement: DISPENSE,
    });
  } catch (error) {
    if (error instanceof ProfessionalPresentationError) {
      assertNotRateLimited(error.status, 'the challenge request');
    }
    throw error;
  }
}

/** Challenge, then sign — the two steps a wallet performs before it retries. */
async function challengeAndPresent(licence: string): Promise<{
  challenge: ProfessionalChallengeResponse;
  vp: string;
}> {
  const issued = await newChallenge();
  const vp = await signProfessionalPresentation(agent, {
    holderDid: HOLDER,
    licence,
    challenge: issued,
  });
  return { challenge: issued, vp };
}

async function dispense(
  requestId: string,
  presentation: string,
  prescriptionId: string,
): Promise<{ status: number; error?: { code?: string; message?: string } }> {
  const result = await callWithProfessionalAuthority({
    baseUrl: BASE_URL,
    path: '/api/pharmacy/dispense',
    accessToken,
    requestId,
    presentation,
    body: { prescriptionId, quantity: 30 },
  });
  assertNotRateLimited(result.status, 'the dispense request');
  return result;
}

// ---------------------------------------------------------------------------
// The exchange
// ---------------------------------------------------------------------------

describe('the challenge names an audience and a nonce this wallet did not choose', () => {
  it('asks for exactly the licence claims the schema requires, and no more', async () => {
    const challenge = await newChallenge();

    expect(challenge.requestId).toBeTruthy();
    expect(challenge.nonce).toBeTruthy();
    expect(challenge.audience).toBe(process.env.VERIFIER_DID);

    const asked = claimsRequestedBy(challenge.definition).map((request) => request.path).sort();
    expect(asked).toEqual([
      'licenceNumber',
      'licenceValidFrom',
      'licenceValidUntil',
      'practiceScope',
      'profession',
      'register',
    ]);

    // The canary is NOT in the ask. If it ever is, the minimal-disclosure
    // assertion below stops meaning anything and this line says so first.
    expect(asked).not.toContain('homeAddress');
  });
});

describe('HAPPY PATH — a pharmacist presents a licence and the dispense takes effect', () => {
  it('returns 200 and writes the dispense', async () => {
    const prescriptionId = await seedPrescription('happy path');
    const { challenge, vp } = await challengeAndPresent(pharmacistLicenceJwt);

    const result = await dispense(challenge.requestId, vp, prescriptionId);

    // Attribution before the assertion: a bare `toBe(200)` on a 403 tells the
    // next reader nothing about which of ten checks refused.
    expect(result.error?.message ?? '', 'guard refused a licence it should admit').toBe('');
    // 201: the route CREATES a dispense record. Asserting 200 here would have
    // been asserting a status this route has never returned.
    expect(result.status).toBe(201);

    // THE ASSERTION THAT MATTERS. A 200 from a route that did not act is a
    // route that returned success for nothing.
    expect(await wasDispensed(prescriptionId)).toBe(true);
  });

  it('revealed only the claims the verifier asked for', async () => {
    const { challenge, vp } = await challengeAndPresent(pharmacistLicenceJwt);

    const disclosed = disclosedClaimNames(vp);

    expect(disclosed.sort()).toEqual([
      'licenceNumber',
      'licenceValidFrom',
      'licenceValidUntil',
      'practiceScope',
      'profession',
      'register',
    ]);

    // The claim the pharmacy never asked for never left the wallet. This is the
    // difference between selective disclosure and a credential that merely
    // supports it.
    expect(disclosed).not.toContain('homeAddress');

    // And the presentation is still one the verifier accepts — minimal
    // disclosure that gets refused is not a privacy feature, it is a bug.
    const prescriptionId = await seedPrescription('minimal disclosure');
    expect((await dispense(challenge.requestId, vp, prescriptionId)).status).toBe(201);
  });
});

describe('REPLAY — a captured presentation is worth exactly one use', () => {
  it('the same presentation submitted twice is refused the second time', async () => {
    const first = await seedPrescription('replay first');
    const second = await seedPrescription('replay second');

    const { challenge, vp } = await challengeAndPresent(pharmacistLicenceJwt);

    expect((await dispense(challenge.requestId, vp, first)).status).toBe(201);
    expect(await wasDispensed(first)).toBe(true);

    // Byte-identical replay, against a DIFFERENT prescription so a refusal
    // cannot be the route's duplicate-dispense check standing in for the
    // guard's. Nothing about the presentation has changed — only that its
    // challenge has been spent.
    const replay = await dispense(challenge.requestId, vp, second);

    expect(replay.status).toBe(401);
    expect(replay.error?.code).toBe('PROFESSIONAL_PRESENTATION_REQUIRED');

    // The refusal happened AT THE GUARD, not downstream.
    expect(await wasDispensed(second)).toBe(false);
  });

  it('the challenge row was spent exactly once', async () => {
    const { challenge, vp } = await challengeAndPresent(pharmacistLicenceJwt);
    const prescriptionId = await seedPrescription('single spend');

    await dispense(challenge.requestId, vp, prescriptionId);

    const row = await db.presentation.findUnique({ where: { requestId: challenge.requestId } });
    // VERIFIED, not REQUESTED: `recordChallengeOutcome` ran. Phase A could only
    // reason that it would.
    expect(row?.status).toBe('VERIFIED');
    expect(row?.verifiedAt).toBeTruthy();
  });

  it('CONCURRENT replay: two simultaneous submissions, exactly one succeeds', async () => {
    // THE CONDITION THE COMPARE-AND-SWAP EXISTS FOR. A read-then-write in
    // `consumeChallenge` passes the sequential test above and fails this one:
    // both requests would read REQUESTED, both would write PRESENTED, and both
    // would dispense. Nothing else in the suite can distinguish the two
    // implementations.
    const left = await seedPrescription('concurrent left');
    const right = await seedPrescription('concurrent right');

    const { challenge, vp } = await challengeAndPresent(pharmacistLicenceJwt);

    const [a, b] = await Promise.all([
      dispense(challenge.requestId, vp, left),
      dispense(challenge.requestId, vp, right),
    ]);

    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([201, 401]);

    // Exactly one prescription moved. Asserting on the statuses alone would
    // pass a build where both requests dispensed and one then failed to
    // serialise its response.
    const dispensed = [await wasDispensed(left), await wasDispensed(right)].filter(Boolean);
    expect(dispensed).toHaveLength(1);
  });

  it('a fresh challenge does not rehabilitate an old presentation', async () => {
    // The other half of single use. If the guard compared the nonce loosely —
    // or not at all, which is Credo 0.6's actual behaviour for SD-JWT and the
    // reason our boundary compares it itself — a captured presentation would be
    // reusable forever simply by asking for a new challenge each time.
    const { vp } = await challengeAndPresent(pharmacistLicenceJwt);
    const fresh = await newChallenge();
    const prescriptionId = await seedPrescription('stale nonce');

    const result = await dispense(fresh.requestId, vp, prescriptionId);

    // 403, not 401: a presentation WAS supplied and WAS verified — it failed
    // verification on the nonce. Retrying cannot help, which is what the code
    // is telling the client.
    expect(result.status).toBe(403);
    expect(result.error?.code).toBe('PROFESSIONAL_AUTHORITY_REFUSED');
    expect(await wasDispensed(prescriptionId)).toBe(false);
  });
});

describe('401 vs 403 — the split Phase A only claimed', () => {
  it('no presentation at all is 401, and does not burn a challenge', async () => {
    const challenge = await newChallenge();
    const prescriptionId = await seedPrescription('no presentation');

    const response = await fetch(`${BASE_URL}/api/pharmacy/dispense`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ prescriptionId, quantity: 30 }),
    });
    const body = (await response.json()) as { error?: { code?: string } };

    expect(response.status).toBe(401);
    expect(body.error?.code).toBe('PROFESSIONAL_PRESENTATION_REQUIRED');
    expect(await wasDispensed(prescriptionId)).toBe(false);

    // ORDERING. The headers are read BEFORE the challenge is spent, so a caller
    // who forgot them can still use the challenge they were given. Were it the
    // other way round, anyone able to reach the route could burn a
    // professional's challenges without presenting anything.
    const row = await db.presentation.findUnique({ where: { requestId: challenge.requestId } });
    expect(row?.status).toBe('REQUESTED');
  });

  it('an unknown challenge id is 401 — the challenge, not the presentation, is missing', async () => {
    const prescriptionId = await seedPrescription('unknown challenge');
    const { vp } = await challengeAndPresent(pharmacistLicenceJwt);

    const result = await dispense(randomUUID(), vp, prescriptionId);

    expect(result.status).toBe(401);
    expect(result.error?.code).toBe('PROFESSIONAL_PRESENTATION_REQUIRED');
    expect(await wasDispensed(prescriptionId)).toBe(false);
  });

  it('an unreadable presentation against a real challenge is 403, not 401', async () => {
    const challenge = await newChallenge();
    const prescriptionId = await seedPrescription('garbage presentation');

    const result = await dispense(challenge.requestId, 'not-a-presentation', prescriptionId);

    // The distinction is real work, not cosmetics: 401 says "you have not
    // presented, go get a challenge"; 403 says "you presented and it did not
    // verify". Collapsing them would tell a wallet with a broken signer to
    // retry forever.
    expect(result.status).toBe(403);
    expect(result.error?.code).toBe('PROFESSIONAL_AUTHORITY_REFUSED');
    expect(await wasDispensed(prescriptionId)).toBe(false);
  });

  it('a VALID licence that does not authorise dispensing is 403 with attributable reasons', async () => {
    const prescriptionId = await seedPrescription('doctor licence');
    const { challenge, vp } = await challengeAndPresent(doctorLicenceJwt);

    const result = await dispense(challenge.requestId, vp, prescriptionId);

    expect(result.status).toBe(403);
    expect(result.error?.code).toBe('PROFESSIONAL_AUTHORITY_REFUSED');

    // A doctor's licence is a perfectly good credential from a pinned
    // authority. It is refused for WHAT IT AUTHORISES, and the client is told
    // which — a professional refused for a revoked licence and one refused for
    // the wrong profession must be able to tell the difference, or the only
    // available response is to keep retrying.
    expect(result.error?.message).toMatch(/requires a pharmacist/i);
    expect(result.error?.message).toMatch(/does not cover dispense/i);

    expect(await wasDispensed(prescriptionId)).toBe(false);
  });

  it('an unauthenticated caller never reaches the guard at all', async () => {
    // requireWallet runs first. Identity and authority are separate questions
    // and the guard deliberately does not answer the first.
    const response = await fetch(`${BASE_URL}/api/pharmacy/dispense`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prescriptionId: 'whatever', quantity: 1 }),
    });
    const body = (await response.json()) as { error?: { code?: string } };

    expect(response.status).toBe(401);
    expect(body.error?.code).toBe('AUTH_REQUIRED');
  });
});

describe('SUBJECT BINDING — a licence presented by a key it does not name', () => {
  /**
   * The credential names one DID as the professional and is bound to a
   * DIFFERENT holder's key. The presenter genuinely controls the `cnf` key, so
   * the boundary's holder-binding check is satisfied; what is wrong is that the
   * licence is about somebody else.
   *
   * Built by hand rather than through `issueCredential`, which derives `cnf`
   * from the subject and therefore cannot express the mismatch.
   */
  let mismatched: string;

  beforeAll(async () => {
    const subject = { id: ISSUER, ...PHARMACIST_LICENCE };
    const signed = await signSdJwtCredential(agent, {
      credential: new W3cV2Credential({
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: `urn:uuid:${randomUUID()}`,
        type: ['VerifiableCredential', PROFESSIONAL_LICENCE_CREDENTIAL_TYPE],
        issuer: ISSUER,
        validFrom: new Date().toISOString(),
        validUntil: new Date(Date.now() + 86_400_000).toISOString(),
        credentialSubject: new W3cV2CredentialSubject(subject),
      }),
      verificationMethod: `${ISSUER}#key-1`,
      // Bound to HOLDER's key while naming ISSUER as the professional.
      holder: { method: 'did', didUrl: `${HOLDER}#key-1` },
      disclosureFrame: buildDisclosureFrame(subject),
    });
    mismatched = signed.encoded;
  });

  it('is refused, and no dispense occurs', async () => {
    const prescriptionId = await seedPrescription('subject mismatch');
    const challenge = await newChallenge();
    const vp = await signProfessionalPresentation(agent, {
      holderDid: HOLDER,
      licence: mismatched,
      challenge,
    });

    const result = await dispense(challenge.requestId, vp, prescriptionId);

    expect(result.status).toBe(403);
    expect(result.error?.code).toBe('PROFESSIONAL_AUTHORITY_REFUSED');
    expect(await wasDispensed(prescriptionId)).toBe(false);
  });

  it('names the layer that refused it, so the defence in depth stays visible', async () => {
    // ATTRIBUTION, AND A DELIBERATE RECORD OF WHICH CHECK ACTUALLY FIRES.
    //
    // `subjectBinding` in `authoriseProfessional` is defence in depth, and this
    // case shows what it is behind: with `credentialSubject.id` in cleartext
    // (which the shipped disclosure policy guarantees), Credo's own
    // `credentialSubjectAuthentication` compares the subject id to the
    // presentation signer and rejects FIRST, at the verification boundary. The
    // request never reaches the authority decision.
    //
    // That is the correct outcome and the reason `subjectBinding` exists is
    // unchanged — Credo skips that comparison entirely when no subject id is
    // disclosed, so the two checks cover different holes. Recorded here rather
    // than left implicit, because a future reader measuring coverage would
    // otherwise conclude `subjectBinding` is dead code.
    const challenge = await newChallenge();
    const vp = await signProfessionalPresentation(agent, {
      holderDid: HOLDER,
      licence: mismatched,
      challenge,
    });

    await dispense(challenge.requestId, vp, await seedPrescription('subject mismatch attribution'));

    const row = await db.presentation.findUnique({ where: { requestId: challenge.requestId } });
    const outcome = row?.verificationResult as { verified?: boolean; reasons?: string[] } | null;

    expect(row?.status).toBe('FAILED');
    expect(outcome?.verified).toBe(false);
    expect(outcome?.reasons?.length ?? 0).toBeGreaterThan(0);
  });
});

describe('the headers are the ones the guard reads', () => {
  it('the client and the middleware agree on both names, case-insensitively', async () => {
    // Node lower-cases incoming header names; the client sends the canonical
    // casing. This asserts they meet — a mismatch here would surface as a 401
    // that looks exactly like "the wallet did not present", which is the most
    // expensive kind of bug to diagnose from a log.
    const headers = professionalPresentationHeaders('request-id', 'vp-token');
    expect(Object.keys(headers).map((name) => name.toLowerCase()).sort()).toEqual([
      'x-presentation-request-id',
      'x-professional-presentation',
    ]);
  });
});
