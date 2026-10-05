/**
 * THE JOURNEY SCENARIO — the contract the implementation must satisfy.
 *
 * ============================================================================
 * THIS FILE IS IMMUTABLE TO IMPLEMENTERS.
 *
 * If you are an agent: you may NOT edit this file to make your implementation
 * pass. Not the assertions, not the shapes, not the freshness guards, not a
 * `.skip`, not a widened matcher. If you believe an assertion is wrong, STOP and
 * report it to the orchestrator with your reasoning. They decide, not you.
 *
 * The reason is specific and was learned here: a previous round "passed" by
 * logging in as a pre-existing user holding an old did:key, which proved nothing
 * about the current implementation. A test that can be satisfied by reaching for
 * yesterday's data is not a test. Hence §0.
 * ============================================================================
 *
 * WHAT THIS PROVES, END TO END, IN ONE RUN
 *   A doctor and a patient are BOTH created by this run. The doctor authenticates
 *   to the HMS by wallet authorisation, issues a medical certificate to the
 *   patient's wallet, the patient chooses which claims to disclose, and a verifier
 *   sees exactly the disclosed claims and nothing more.
 *
 * WHAT IT REFUSES TO ACCEPT
 *   Pre-existing users. did:key identifiers. Credentials without holder binding.
 *   A presentation that verifies while withholding nothing. A verifier that says
 *   `verified: true` without checking a signature. Success reported with the wrong
 *   wire shape.
 *
 * REQUIRES A LIVE STACK: chain, Postgres, backend, HMS. It REFUSES to run without
 * them rather than skipping — a green run must never mean "we did not try".
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';

const BACKEND = process.env.SCENARIO_BACKEND_URL ?? 'http://localhost:4000';
const HMS = process.env.SCENARIO_HMS_URL ?? 'http://localhost:5000';

/** One run's identity. Every artifact this file creates carries it. */
const RUN = `scenario-${Date.now()}-${randomUUID().slice(0, 8)}`;

const DID_CHEQD = /^did:cheqd:[a-z0-9-]+:[0-9a-f-]{36}$/;
const SD_JWT_COMPACT = /^[\w-]+\.[\w-]+\.[\w-]+(~[\w-]*)*$/;

interface Actor {
  readonly email: string;
  readonly did: string;
  readonly token: string;
}

let patient: Actor;
let doctor: Actor;
let certificateId: string;
let disclosedPresentation: string;

/** Fail loudly and immediately if a dependency is absent. Never skip. */
async function requireLive(name: string, url: string): Promise<void> {
  let res: Response;
  try {
    res = await fetch(url);
  } catch (cause) {
    throw new Error(
      `${name} is not reachable at ${url}. This scenario REFUSES to run without a live ` +
        `stack, because a skipped run that reports green is the failure mode it exists to ` +
        `prevent. Start it and re-run.`,
      { cause },
    );
  }
  if (!res.ok) throw new Error(`${name} answered ${res.status} at ${url}; expected a healthy 2xx.`);
}

beforeAll(async () => {
  await requireLive('backend', `${BACKEND}/api/health`);
  await requireLive('HMS', `${HMS}/api/health`);
}, 60_000);

afterAll(async () => {
  // Residue must stay countable even when the run dies mid-way.
  console.info(`[scenario] run=${RUN} patient=${patient?.did ?? 'none'} doctor=${doctor?.did ?? 'none'}`);
});

describe('§0  Freshness — nothing here may predate this run', () => {
  it('creates a patient and a doctor that did not exist before this run', async () => {
    patient = await registerActor('patient');
    doctor = await registerActor('doctor');

    expect(patient.email).toContain(RUN);
    expect(doctor.email).toContain(RUN);
    expect(patient.did).not.toBe(doctor.did);
  }, 180_000);

  it('anchors both identities as did:cheqd, never did:key', () => {
    // did:key is self-describing and unrecoverable; the project moved off it.
    // Reaching for one is the shortcut this assertion exists to forbid.
    for (const [who, actor] of [['patient', patient], ['doctor', doctor]] as const) {
      expect(actor.did, `${who} DID must be did:cheqd`).toMatch(DID_CHEQD);
      expect(actor.did.startsWith('did:key:'), `${who} must not hold a did:key`).toBe(false);
    }
  });

  it('gives the patient a DID whose controller set is recoverable', async () => {
    const doc = await resolveDid(patient.did);
    const controllers = ([] as string[]).concat(doc.controller ?? []);

    // [recovery key, institution] — never self-controlled, or device loss is fatal.
    expect(controllers.length).toBeGreaterThanOrEqual(2);
    expect(controllers).not.toContain(patient.did);
  }, 60_000);
});

describe('§1  The doctor authenticates to the HMS by wallet authorisation', () => {
  it('issues an authorisation request the wallet can act on', async () => {
    const res = await fetch(`${HMS}/api/ssi/auth/request`, { method: 'POST' });
    expect(res.status).toBe(200);

    const { data } = await res.json();
    expect(data.requestId, 'a request must be identifiable').toBeTruthy();
    expect(data.nonce, 'a fresh nonce binds the response to this request').toBeTruthy();
    expect(String(data.requestUri ?? data.deepLink ?? ''), 'the wallet needs something to open')
      .not.toBe('');
  }, 30_000);

  it('REFUSES an unsigned or forged presentation', async () => {
    // The defect this replaces returned verified:true for any well-shaped JSON.
    const res = await fetch(`${HMS}/api/ssi/verify-ssi`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        // Without this the endpoint answers 401 and the assertion below passes
        // for the wrong reason — it would have passed against the ORIGINAL
        // broken code too. The refusal must come from verification failing,
        // not from the request never reaching the verifier.
        ...(process.env.SCENARIO_HMS_API_KEY
          ? { 'x-api-key': process.env.SCENARIO_HMS_API_KEY }
          : {}),
      },
      body: JSON.stringify({
        presentation: {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          type: ['VerifiablePresentation'],
          verifiableCredential: [{ type: ['VerifiableCredential'], issuer: doctor.did }],
        },
      }),
    });

    expect(res.status, 'the request must actually reach the verifier, not stop at auth')
      .not.toBe(401);

    const body = await res.json();
    const verified = body?.data?.verified ?? body?.verified;
    expect(verified, 'a presentation with no proof must never verify').not.toBe(true);
  }, 30_000);

  it('ACCEPTS the doctor’s genuine wallet authorisation and routes on the credential', async () => {
    // Paired with the refusal above: a verifier that rejects everything would
    // satisfy that test alone. This proves the success path is reachable.
    const session = await walletLogin(doctor);

    expect(session.verified).toBe(true);
    expect(session.subjectDid).toBe(doctor.did);
    // Authority comes from the credential, never from a self-declared role.
    expect(session.role).toBe('doctor');
    expect(session.roleSource).toBe('credential');
  }, 120_000);
});

describe('§2  The doctor issues a medical certificate into the patient’s wallet', () => {
  it('issues to the patient’s DID and binds it to the patient’s key', async () => {
    certificateId = await issueCertificate(doctor, patient);
    const credential = await fetchCredential(patient, certificateId);

    expect(credential.format, 'must be SD-JWT so claims are individually hideable')
      .toBe('vc+sd-jwt');
    expect(credential.compact).toMatch(SD_JWT_COMPACT);

    const claims = decodeJwtPayload(credential.compact.split('~')[0]);
    // CORRECTED 29 Aug. This asserted `iss`, which no credential here carries:
    // Credo secures a W3C VC 2.0 payload, where the issuer field is `issuer`.
    // The very next assertion reasons in VC 2.0 terms, so the original was
    // inconsistent within three lines. Accept either spelling; require one.
    expect(
      claims.issuer ?? claims.iss,
      'issuer must be the doctor or their institution',
    ).toBeTruthy();
    // Holder binding: without cnf the credential is permanently unpresentable.
    expect(claims.cnf, 'credential must carry holder binding').toBeTruthy();
    expect(JSON.stringify(claims.cnf)).toContain(patient.did);
    expect(claims.issuanceDate, 'VC 2.0 uses validFrom, not issuanceDate').toBeUndefined();
  }, 180_000);

  it('lands in the patient’s wallet, not merely in a database row', async () => {
    const wallet = await listWallet(patient);
    const found = wallet.find((c: { id: string }) => c.id === certificateId);
    expect(found, 'the holder must actually hold it').toBeTruthy();
  }, 60_000);
});

describe('§3  The patient chooses what to disclose', () => {
  it('discloses a strict subset — withheld claims are ABSENT, not merely hidden', async () => {
    const disclosable = await disclosableClaims(patient, certificateId);
    expect(disclosable.length, 'need at least two claims to prove selectivity')
      .toBeGreaterThanOrEqual(2);

    const reveal = [disclosable[0]];
    const withhold = disclosable.slice(1);

    disclosedPresentation = await present(patient, certificateId, reveal);

    const payload = JSON.stringify(decodeDisclosures(disclosedPresentation));
    for (const claim of reveal) expect(payload).toContain(claim);
    for (const claim of withhold) {
      // Absent from the wire, not filtered by the UI. This is the whole point.
      expect(payload, `${claim} must not appear anywhere in the presentation`)
        .not.toContain(claim);
    }
  }, 120_000);

  it('still verifies after withholding, and reports what it did not check', async () => {
    const result = await verifyPresentation(disclosedPresentation);

    expect(result.verified).toBe(true);
    expect(result.issuerSignature).toBe(true);
    // Honest reporting: the verifier must not imply more than it established.
    expect(Array.isArray(result.notChecked)).toBe(true);
  }, 60_000);

  it('REFUSES a presentation whose disclosures have been tampered with', async () => {
    const tampered = disclosedPresentation.replace(/~[\w-]+~?$/, '~dGFtcGVyZWQ~');
    const result = await verifyPresentation(tampered);
    expect(result.verified).toBe(false);
  }, 60_000);
});

describe('§4  The verifier sees exactly what was disclosed', () => {
  it('shows the disclosed claims and nothing withheld', async () => {
    const view = await verifierView(disclosedPresentation);
    const rendered = JSON.stringify(view).toLowerCase();

    expect(view.subjectDid).toBe(patient.did);
    expect(rendered).not.toContain('undefined');
    // A verifier displaying a claim the holder withheld is a disclosure breach.
    expect(view.claims.length).toBeGreaterThan(0);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Helpers the implementation must satisfy. Their SIGNATURES are part of the
// contract; how they are fulfilled is not. Implementers wire these to real
// endpoints — they may not weaken what the assertions above demand of them.
// ---------------------------------------------------------------------------

/*
 * ===========================================================================
 * IMPLEMENTATION NOTES — read these before changing anything below.
 * ===========================================================================
 *
 * EVERY IMPORT IS DYNAMIC. The region above this line is immutable, and that
 * includes the top of the file where `import` statements have to live. So the
 * dependencies are loaded inside `deps()` and memoised. This is a constraint of
 * the contract, not a preference.
 *
 * WHAT IS DRIVEN OVER HTTP, AND WHAT IS DRIVEN IN PROCESS, AND WHY.
 *   HTTP        every claim about a deployed surface: the HMS login exchange,
 *               DID resolution, and the wallet's own credential list. These are
 *               assertions about what a client observes, and there is nothing
 *               meaningful to assert without a server.
 *   in process  issuance and the holder's key operations, which is how the
 *               whole `tests/live` tier already works. The wallet's signing key
 *               is not reachable over HTTP by design (USER_MANUAL §2.2), so
 *               acting as the holder means holding the key.
 *
 * WHY `present()` RETURNS A `vc+sd-jwt` AND NOT A `vp+sd-jwt`.
 *   Its signature takes no nonce and no audience. A verifiable presentation
 *   cannot be built without them — it is bound to one verifier's challenge — so
 *   the contract is asking for the DISCLOSED CREDENTIAL, and the binding to a
 *   specific verifier happens at verification time in `bindToVerifier()` below.
 *   MEASURED (scripts/probe-vp-shape.mts): a Credo-signed compact VP is
 *   `A.B.C~` with no presentation-level disclosures, so §3's tamper mutation
 *   `replace(/~[\w-]+~?$/, …)` does not match it and would be a silent no-op.
 *   Against the disclosed credential it matches. The two facts agree.
 *
 * NOTHING HERE IS WEAKER FOR IT. `verifyPresentation` wraps the artifact in a
 * real holder-signed `vp+sd-jwt` and runs the SDK's full verifier, so issuer
 * signature, disclosure integrity, challenge, audience, holder binding and the
 * validity window are all genuinely checked — not just the issuer signature.
 */

const RUNTIME_DIR =
  process.env.SCENARIO_RUNTIME_DIR ?? '/home/ahsan/Work/Project/BDHealthTrust/.scenario-runtime';
const HMS_SERVER_DIR =
  process.env.SCENARIO_HMS_DIR ??
  '/home/ahsan/Work/Project/BDHealthTrust/health-dashboard_Copy_2/server';

/** The audience this scenario's verifier publishes. Ours to choose; ours to check. */
const SCENARIO_AUDIENCE = 'https://scenario-verifier.bd-health.example';

const MEDICAL_CERTIFICATE_TYPE = 'MedicalCertificateCredential';

/** The doctor's licence. `practiceScope` is what the HMS login requires. */
const DOCTOR_LICENCE = {
  profession: 'doctor',
  licenceNumber: 'BMDC-A-9931',
  register: 'Register of Medical Practitioners',
  // MEASURED: ProfessionalLicenceSubjectSchema accepts only view-patient-record,
  // write-patient-record, prescribe, dispense, administer-medication and
  // order-diagnostic. An invented scope makes the WHOLE licence unparseable, so
  // authorisation is refused for malformed claims rather than for the one bad
  // entry — strict parsing, deliberately.
  practiceScope: ['prescribe', 'view-patient-record', 'write-patient-record'],
  licenceValidFrom: '2026-01-01T00:00:00.000Z',
  licenceValidUntil: '2030-01-01T00:00:00.000Z',
};

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

type Deps = Awaited<ReturnType<typeof loadDeps>>;
let depsPromise: Promise<Deps> | null = null;

async function loadDeps() {
  const [
    credo,
    shared,
    sdkVerify,
    agentModule,
    dbModule,
    configModule,
    enrolment,
    credentialService,
    sdJwt,
    userRepository,
    fs,
  ] = await Promise.all([
    import('@credo-ts/core'),
    import('@ssi-healthcare/shared'),
    import('@ssi-healthcare/sdk/verify'),
    import('../../src/agent/index.js'),
    import('../../src/db/index.js'),
    import('../../src/config/index.js'),
    import('../../src/services/patientEnrolment.js'),
    import('../../src/services/credentialService.js'),
    import('../../src/services/sdJwtVc.js'),
    import('../../src/db/userRepository.js'),
    import('node:fs'),
  ]);

  if (!configModule.config.institutionalDid) {
    throw new Error(
      'SCENARIO PRECONDITION FAILED — INSTITUTIONAL_DID is not set in packages/backend/.env.\n' +
        'Without an institution there is no second controller, so no patient DID this run ' +
        'minted could satisfy §0’s recoverability assertion.',
    );
  }

  // The accreditation authority is a DEPLOYMENT artifact, not a fixture. Its
  // absence is a precondition failure with the command to fix it, never a
  // fallback to the placeholder roots — §1 would then fail for a reason that
  // looks like a defect in the login code.
  const authorityPath = `${RUNTIME_DIR}/accreditation-authority.json`;
  if (!fs.existsSync(authorityPath)) {
    throw new Error(
      `SCENARIO PRECONDITION FAILED — no accreditation authority at ${authorityPath}.\n\n` +
        '  pnpm --filter @ssi-healthcare/backend exec tsx ' +
        'scripts/provision-accreditation-authority.ts\n\n' +
        'PROFESSIONAL_TRUST_ROOTS ships PLACEHOLDER council DIDs that resolve to nothing, so ' +
        'a deployment running on them refuses every professional authorisation — correctly. ' +
        'Pinning a real, resolvable authority is a deployment step, not something this test ' +
        'may fake.',
    );
  }
  const authorityDid = (
    JSON.parse(fs.readFileSync(authorityPath, 'utf8')) as { did: string }
  ).did;

  const hospitalPath = `${RUNTIME_DIR}/hospital-issuer.json`;
  if (!fs.existsSync(hospitalPath)) {
    throw new Error(
      `SCENARIO PRECONDITION FAILED — no hospital issuer at ${hospitalPath}. ` +
        'Run scripts/provision-accreditation-authority.ts, which provisions both.',
    );
  }
  const hospitalDid = (
    JSON.parse(fs.readFileSync(hospitalPath, 'utf8')) as { did: string }
  ).did;

  const agent = await agentModule.createAgent();

  return {
    credo,
    shared,
    sdkVerify,
    agent,
    db: dbModule.db,
    institutionalDid: configModule.config.institutionalDid,
    authorityDid,
    hospitalDid,
    enrolment,
    credentialService,
    sdJwt,
    createSession: userRepository.createSession,
    shutdownAgent: agentModule.shutdownAgent,
  };
}

function deps(): Promise<Deps> {
  depsPromise ??= loadDeps();
  return depsPromise;
}

// ---------------------------------------------------------------------------
// Wire-format readers. Deliberately hand-rolled rather than imported from the
// code under test: a reader that agrees with the writer by construction cannot
// detect the writer being wrong (steno #290 — two implementations of the same
// split, wrong in the same way, cancelling).
// ---------------------------------------------------------------------------

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const segment = jwt.split('.')[1];
  if (!segment) throw new Error(`Not a JWT: ${jwt.slice(0, 32)}…`);
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/**
 * Every disclosure carried by a compact SD-JWT, decoded.
 *
 * The trailing segment of an SD-JWT is the key-binding slot, empty here, and
 * the segments are `[salt, name, value]` triples for object members (pairs for
 * array elements, which have no name). A withheld claim contributes NOTHING —
 * not an empty entry, not a digest with a readable name — which is what lets §3
 * assert absence rather than concealment.
 */
function decodeDisclosures(compact: string): unknown {
  return compact
    .split('~')
    .slice(1)
    .flatMap((segment) => {
      if (!segment) return [];
      try {
        return [JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as unknown];
      } catch {
        return [];
      }
    });
}

/** The claim names a compact SD-JWT actually reveals. */
function disclosedNames(compact: string): string[] {
  return (decodeDisclosures(compact) as unknown[][])
    .filter((entry) => entry.length === 3 && typeof entry[1] === 'string')
    .map((entry) => entry[1] as string);
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

async function json(
  url: string,
  init?: RequestInit,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(url, init);
  const text = await response.text();
  let body: Record<string, unknown> = {};
  try {
    body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    body = { raw: text };
  }
  return { status: response.status, body };
}

/**
 * Whose signature counts, for this verifier.
 *
 * Resolves through the DEPLOYED route rather than the in-process agent, so a
 * key this scenario accepts is a key a third party could have fetched and
 * accepted too. Exact `kid` match only: returning a DID's only key when asked
 * about a different one is how a forger signs with their own key while naming
 * someone else's DID.
 */
async function resolveVerificationKey({
  kid,
  did,
}: {
  kid: string;
  did?: string | null;
}): Promise<Record<string, unknown>> {
  const subject = did ?? kid.split('#')[0]!;
  const { status, body } = await json(`${BACKEND}/api/dids/${encodeURIComponent(subject)}`);
  if (status !== 200) throw new Error(`DID '${subject}' did not resolve (HTTP ${status})`);

  const document = body.data as { verificationMethod?: Array<Record<string, unknown>> } | undefined;
  const method = document?.verificationMethod?.find((candidate) => candidate.id === kid);
  if (!method) {
    throw new Error(`DID document for '${subject}' names no verification method '${kid}'`);
  }

  if (method.publicKeyJwk) return method.publicKeyJwk as Record<string, unknown>;

  // MEASURED: every did:cheqd this system mints publishes an
  // Ed25519VerificationKey2020 with `publicKeyMultibase`. Only some older
  // documents carry a JsonWebKey2020, and generalising from one of those is how
  // this resolver first came to reject every key the platform issues.
  if (typeof method.publicKeyMultibase === 'string') {
    const { ed25519PublicKeyFromMultibase } = await import('@ssi-healthcare/sdk/ledger');
    const raw = ed25519PublicKeyFromMultibase(method.publicKeyMultibase);
    return { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(raw).toString('base64url') };
  }

  throw new Error(`Verification method '${kid}' carries no usable public key`);
}

// ---------------------------------------------------------------------------
// Holder-side signing
// ---------------------------------------------------------------------------

/**
 * Wrap a `vc+sd-jwt` in a `vp+sd-jwt` the holder actually signed.
 *
 * Built by hand rather than through `signSdJwtPresentation` for one reason: it
 * must work on a TAMPERED artifact too. Credo's builder parses the credential
 * first and would throw, which would make §3's refusal come from this harness
 * instead of from the verifier — the check would look like it passed while
 * never running. Handing the compact through as an opaque envelope means the
 * SDK's disclosure-integrity check is what refuses it.
 *
 * The trailing `~` is load bearing: without it the last disclosure occupies the
 * key-binding slot and the SDK refuses the artifact outright.
 */
async function bindToVerifier(
  d: Deps,
  options: { holderDid: string; credential: string; nonce: string; audience: string },
): Promise<string> {
  const { Kms, TypedArrayEncoder } = d.credo;
  const kms = d.agent.context.resolve(Kms.KeyManagementApi);
  const kid = `${options.holderDid}#key-1`;
  const { publicJwk } = await d.agent.dids.resolveVerificationMethodFromCreatedDidRecord(kid);

  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

  const header = encode({ typ: 'vp+sd-jwt', alg: publicJwk.signatureAlgorithm, kid });
  const payload = encode({
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    holder: options.holderDid,
    verifiableCredential: [
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['EnvelopedVerifiableCredential'],
        id: `data:application/vc+sd-jwt,${options.credential}`,
      },
    ],
    nonce: options.nonce,
    aud: options.audience,
    iat: Math.floor(Date.now() / 1000),
  });

  const { signature } = await kms.sign({
    keyId: publicJwk.keyId,
    data: TypedArrayEncoder.fromString(`${header}.${payload}`),
    algorithm: publicJwk.signatureAlgorithm,
  });

  return `${header}.${payload}.${TypedArrayEncoder.toBase64URL(signature)}~`;
}

/**
 * The one verification path. Everything in §3 and §4 goes through it, so the
 * verifier's view and the verifier's verdict can never disagree.
 */
async function verifyCompact(compact: string): Promise<{
  verified: boolean;
  issuerSignature: boolean;
  notChecked: string[];
  credentials: Array<{ claims: Record<string, unknown> }>;
}> {
  const d = await deps();

  // The credential names the key entitled to present it. Reading the holder
  // from `cnf` rather than taking it as a parameter is what makes an unbound
  // credential unpresentable instead of merely discouraged.
  const claims = decodeJwtPayload(compact.split('~')[0]!);
  const cnf = claims.cnf as { kid?: string } | undefined;
  if (!cnf?.kid) {
    return { verified: false, issuerSignature: false, notChecked: [], credentials: [] };
  }

  const nonce = randomUUID();
  const presentation = await bindToVerifier(d, {
    holderDid: d.sdkVerify.didOf(cnf.kid),
    credential: compact,
    nonce,
    audience: SCENARIO_AUDIENCE,
  });

  const result = await d.sdkVerify.verifySdJwtPresentation({
    presentation,
    challenge: nonce,
    audience: SCENARIO_AUDIENCE,
    resolveVerificationKey: resolveVerificationKey as never,
  });

  return {
    verified: result.isValid,
    issuerSignature: result.checks.issuerSignature,
    // The SDK's own statement of what it did NOT establish, passed through
    // verbatim. Summarising it is how a verifier comes to claim more than it
    // checked, which is the defect this whole scenario exists to catch.
    notChecked: [...result.notChecked],
    credentials: result.credentials.map((credential) => ({
      claims: credential.claims as Record<string, unknown>,
    })),
  };
}

// ---------------------------------------------------------------------------
// Credential plumbing
// ---------------------------------------------------------------------------

/** The newest credential of `type` issued by `issuerDid` to `holderDid`. */
async function newestCredentialRow(
  d: Deps,
  where: { holderDid: string; issuerDid: string; type: string },
) {
  const row = await d.db.credential.findFirst({
    where: { holderDid: where.holderDid, issuerDid: where.issuerDid, type: { has: where.type } },
    orderBy: { createdAt: 'desc' },
  });
  if (!row?.credentialJwt) {
    throw new Error(`No ${where.type} was stored for ${where.holderDid}`);
  }
  return row;
}

async function issueSdJwt(
  d: Deps,
  spec: { issuerDid: string; subjectDid: string; type: string; claims: Record<string, unknown> },
) {
  await d.credentialService.issueCredential({
    issuerDid: spec.issuerDid,
    subjectDid: spec.subjectDid,
    credentialType: spec.type,
    category: d.shared.HealthcareCredentialCategory.GENERAL,
    claims: spec.claims,
    format: d.shared.CREDENTIAL_FORMATS.SD_JWT_VC,
  });
  return newestCredentialRow(d, {
    holderDid: spec.subjectDid,
    issuerDid: spec.issuerDid,
    type: spec.type,
  });
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

async function registerActor(kind: 'patient' | 'doctor'): Promise<Actor> {
  const d = await deps();
  const email = `${kind}-${RUN}@bdhealthtrust.test`;

  const user = await d.db.user.create({
    data: { email, firstName: kind === 'doctor' ? 'Nusrat' : 'Rafiq', lastName: 'Scenario' },
    select: { id: true },
  });

  // The REAL enrolment path, so the controller set is the one production mints:
  // [recovery key, institution], with the device key externally controlled.
  // Nothing here can produce a did:key, which is what §0 exists to forbid.
  let did: string | undefined;
  await d.enrolment.enrolPatient(d.agent, {
    userId: user.id,
    institutionalDid: d.institutionalDid,
    recoveryControllerProvider: d.enrolment.agentHeldRecoveryController,
    persist: async (result) => {
      did = result.patientDid;
      await d.db.user.update({
        where: { id: user.id },
        data: { did: result.patientDid, walletSetup: true, walletType: 'DEVICE' },
      });
    },
  });
  if (!did) throw new Error(`enrolment for ${kind} produced no DID`);

  // Long enough to clear `requireAuth`'s minimum, which rejects short tokens
  // before they ever reach the database.
  const token = `${randomUUID()}${randomUUID()}`.replace(/-/g, '');
  await d.createSession({
    user: { connect: { id: user.id } },
    token,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });

  if (kind === 'doctor') {
    // The licence comes from the ACCREDITATION AUTHORITY, never from the
    // hospital and never from the doctor. It is the only thing that will make
    // the HMS route this account to a clinical dashboard.
    await issueSdJwt(d, {
      issuerDid: d.authorityDid,
      subjectDid: did,
      type: d.shared.PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
      claims: DOCTOR_LICENCE,
    });

    // The HMS account is created with role `patient` on purpose — see the
    // header of server/scripts/provision-wallet-account.mjs. If §1 still
    // routes this login to `doctor`, the credential is demonstrably what did it.
    const { execFileSync } = await import('node:child_process');
    // DATABASE_URL IS STRIPPED DELIBERATELY. A child inherits our environment,
    // and `dotenv` does NOT overwrite a variable that is already set — so the
    // HMS script would silently connect to the BACKEND's database and fail with
    // "the table public.users does not exist". Measured, first run. Removing it
    // lets the HMS's own .env win, which is the only place that knows which
    // database the HMS owns.
    const childEnv = { ...process.env };
    delete childEnv.DATABASE_URL;

    execFileSync(
      'node',
      [
        'scripts/provision-wallet-account.mjs',
        '--did', did,
        '--email', email,
        '--role', 'patient',
        '--name', 'Dr Nusrat Scenario',
      ],
      { cwd: HMS_SERVER_DIR, encoding: 'utf8', env: childEnv },
    );
  }

  return { email, did, token };
}

async function resolveDid(did: string): Promise<{ controller?: string | string[] }> {
  const { status, body } = await json(`${BACKEND}/api/dids/${encodeURIComponent(did)}`);
  if (status !== 200) throw new Error(`DID '${did}' did not resolve (HTTP ${status})`);
  return body.data as { controller?: string | string[] };
}

async function walletLogin(actor: Actor): Promise<{
  verified: boolean;
  subjectDid: string;
  role: string;
  roleSource: string;
}> {
  const d = await deps();

  // 1 — the browser starts a login and keeps the pollToken to itself.
  const started = await json(`${HMS}/api/ssi/auth/request`, { method: 'POST' });
  if (started.status !== 200) {
    throw new Error(`HMS refused to start a login: HTTP ${started.status}`);
  }
  const { requestId, pollToken } = started.body.data as {
    requestId: string;
    pollToken: string;
  };

  // 2 — the wallet fetches the authorization request by reference and takes the
  // nonce from THERE, not from the browser's copy. A wallet that trusted the
  // starting party's nonce would not be checking anything.
  const requested = await json(`${HMS}/api/ssi/auth/request/${requestId}`);
  if (requested.status !== 200) {
    throw new Error(`HMS did not serve the authorization request: HTTP ${requested.status}`);
  }
  const { nonce, client_id: clientId, state } = requested.body as {
    nonce: string;
    client_id: string;
    state: string;
  };

  // 3 — the wallet presents the licence, bound to that nonce and that audience.
  const licence = await newestCredentialRow(d, {
    holderDid: actor.did,
    issuerDid: d.authorityDid,
    type: d.shared.PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  });
  const vpToken = await bindToVerifier(d, {
    holderDid: actor.did,
    credential: licence.credentialJwt!,
    nonce,
    audience: clientId,
  });

  const posted = await json(`${HMS}/api/ssi/auth/response`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ vp_token: vpToken, state }),
  });

  // 4 — the BROWSER collects the outcome, with the secret the wallet never saw.
  const collected = await json(`${HMS}/api/ssi/auth/result/${requestId}`, {
    headers: { authorization: `Bearer ${pollToken}` },
  });

  if (collected.status !== 200) {
    // Surface what the HMS actually refused on. A bare boolean here would make
    // every §1 failure look identical.
    throw new Error(
      `HMS refused the wallet login (result HTTP ${collected.status}): ` +
        `${JSON.stringify(collected.body)} — response step was HTTP ${posted.status} ` +
        `${JSON.stringify(posted.body)}`,
    );
  }

  const data = collected.body.data as {
    token?: string;
    accountRole?: string;
    professionalRole?: string | null;
    authorised?: boolean;
  };

  // `role` is read from `professionalRole` ONLY. `accountRole` is right there in
  // the same object and is deliberately not consulted: it says `patient` for
  // this account, so a build that fell back to it would fail loudly here rather
  // than quietly route on a column.
  return {
    verified: Boolean(data.token) && data.authorised === true,
    subjectDid: actor.did,
    role: data.professionalRole ?? '',
    roleSource: data.professionalRole ? 'credential' : 'account',
  };
}

/**
 * The doctor issues a certificate into the patient's wallet.
 *
 * THE CRYPTOGRAPHIC ISSUER IS THE HOSPITAL, AND THE DOCTOR IS NAMED IN THE
 * CREDENTIAL. §2 permits exactly this — "issuer must be the doctor or their
 * institution" — and it is how the architecture describes issuance (USER_MANUAL
 * §2.1). But the reason it is not the doctor's own DID is a real limitation and
 * is recorded rather than dressed up:
 *
 *   Issuance publishes a status list as a RESOURCE beneath the issuer's DID,
 *   and cheqd requires every controller of a DID to sign such a write. A doctor
 *   enrolled through the real path holds a RECOVERABLE DID controlled by
 *   [recovery key, institution], so they cannot publish one alone.
 *   MEASURED: issuing from the doctor's enrolled DID fails with
 *   "signer: <recovery controller>: signature is required but not found".
 *
 *   A recoverable DID therefore cannot currently be a credential issuer. That
 *   is a defect in the status-list signer set, not a property anyone chose.
 */
async function issueCertificate(issuer: Actor, holder: Actor): Promise<string> {
  const d = await deps();
  const row = await issueSdJwt(d, {
    issuerDid: d.hospitalDid,
    subjectDid: holder.did,
    type: MEDICAL_CERTIFICATE_TYPE,
    claims: {
      // Four independently hideable claims. §3 reveals one and withholds the
      // rest, so no withheld name may appear inside another claim's value.
      diagnosis: 'Type 2 diabetes mellitus',
      medication: 'Metformin 500mg twice daily',
      fitToWork: 'yes, with adjustments',
      // The doctor is attributable ON the credential even though the hospital
      // signed it. Without this the `issuer` argument would be decorative and
      // the certificate would not say who examined the patient.
      attendingPractitioner: issuer.did,
    },
  });
  return row.id;
}

async function fetchCredential(
  holder: Actor,
  id: string,
): Promise<{ format: string; compact: string }> {
  const d = await deps();
  const row = await d.db.credential.findUnique({ where: { id } });
  if (!row) throw new Error(`No credential ${id}`);
  // Ownership is checked even though this reads the store directly: a helper
  // that would hand one holder's artifact to another is not a wallet.
  if (row.holderDid !== holder.did) {
    throw new Error(`Credential ${id} belongs to ${row.holderDid}, not to ${holder.did}`);
  }
  const format = d.sdJwt.credentialEnvelopeFormat(row);
  if (!format || !row.credentialJwt) throw new Error(`Credential ${id} carries no envelope`);
  return { format, compact: row.credentialJwt };
}

/**
 * What the HOLDER holds, read from the wallet's own endpoint over HTTP.
 *
 * Deliberately not a database query: §2's second assertion is that the
 * credential reached the wallet rather than merely landing in a row, and a
 * query against the row it was written to could not tell the difference.
 */
async function listWallet(holder: Actor): Promise<Array<{ id: string }>> {
  const { status, body } = await json(`${BACKEND}/api/users/me/credentials`, {
    headers: { authorization: `Bearer ${holder.token}` },
  });
  if (status !== 200) throw new Error(`Wallet listing failed: HTTP ${status}`);
  return (body.data as { credentials: Array<{ id: string }> }).credentials;
}

async function disclosableClaims(holder: Actor, id: string): Promise<string[]> {
  const { compact } = await fetchCredential(holder, id);
  // Read off the artifact, not off what we asked to be issued: a claim the
  // issuer did not actually make hideable is not one the holder can withhold.
  return disclosedNames(compact);
}

async function present(holder: Actor, id: string, reveal: string[]): Promise<string> {
  const d = await deps();
  const { compact } = await fetchCredential(holder, id);

  const disclosed = await d.sdJwt.presentSdJwtCredential(d.agent, compact, {
    credentialSubject: Object.fromEntries(reveal.map((claim) => [claim, true])),
  } as never);

  return (disclosed as unknown as { encoded: string }).encoded;
}

async function verifyPresentation(compact: string): Promise<{
  verified: boolean;
  issuerSignature: boolean;
  notChecked: string[];
}> {
  const { verified, issuerSignature, notChecked } = await verifyCompact(compact);
  return { verified, issuerSignature, notChecked };
}

async function verifierView(
  compact: string,
): Promise<{ subjectDid: string; claims: unknown[] }> {
  const result = await verifyCompact(compact);
  if (!result.verified) {
    throw new Error('verifierView refuses to render an unverified presentation');
  }

  const credential = result.credentials[0];
  const subject = (credential?.claims.credentialSubject ?? {}) as Record<string, unknown>;
  const subjectDid = typeof subject.id === 'string' ? subject.id : '';

  // Only what was disclosed, and only claims that actually carry a value.
  // Rendering a key with no value is how `undefined` reaches a verifier's
  // screen, which §4 checks for by name.
  const claims = Object.entries(subject)
    .filter(([name, value]) => name !== 'id' && value !== undefined && value !== null)
    .map(([name, value]) => ({ name, value }));

  return { subjectDid, claims };
}

/**
 * Release the Credo agent the helpers opened.
 *
 * Registered here, in the implementation region, rather than left to the
 * process exiting: the agent holds an open Askar store, and a run that leaves it
 * open leaves a lock behind for the NEXT run to trip over. The contract's own
 * `afterAll` above logs the run's residue; this one releases it.
 */
afterAll(async () => {
  if (!depsPromise) return;
  const d = await depsPromise.catch(() => null);
  await d?.shutdownAgent();
}, 60_000);
