/**
 * OID4VCI SD-JWT NEGOTIATION — evidence probe, over real HTTP.
 *
 * Metadata that advertises `vc+sd-jwt` is a PROMISE. This probe drives the
 * actual token and credential endpoints to check the promise is kept — that a
 * wallet which discovers the format, asks for it, and gets a 200 has genuinely
 * received a selectively-disclosable credential rather than a plain JWT with an
 * agreeable-looking response.
 *
 * The offer row is created directly, because POST /oid4vci/offers requires a
 * wallet session and the thing under test here is the pre-authorized code flow
 * that follows it, which is unauthenticated by design.
 */
import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { db } from './src/db/index.js';

const BASE = `http://localhost:${process.env.PORT ?? 3001}`;
const ISSUER = 'did:cheqd:bdhealthtestnet:fa3fc79f-9d49-43f5-9aa7-4f2df973bbb0';
const HOLDER = 'did:cheqd:bdhealthtestnet:7cd03fdc-6a88-4895-9d89-e63445abe0c1';

const claims = {
  patientName: 'Ahsan Rahman',
  hivStatus: 'negative',
  bloodType: 'O+',
  medications: ['Metformin 500mg', 'Lisinopril 10mg', 'Sertraline 50mg'],
};

const failures: string[] = [];
function hr(t: string) { console.log(`\n${'='.repeat(74)}\n${t}\n${'='.repeat(74)}`); }
function check(label: string, ok: boolean, detail?: unknown) {
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${label}${detail === undefined ? '' : ` -> ${JSON.stringify(detail)}`}`);
  if (!ok) failures.push(label);
}

function decodeJwtPayload(compact: string): Record<string, unknown> {
  // The issuer-signed payload. For an SD-JWT the tildes ride along on the
  // signature segment, so this is the view a verifier gets when the holder
  // discloses NOTHING — which is exactly where a leak would show up.
  const raw = compact.split('~')[0]!.split('.')[1]!;
  return JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** Run the pre-authorized code flow end to end, asking for `format`. */
async function issueVia(format: string | undefined): Promise<{ format: string; credential: string }> {
  const preAuthorizedCode = randomUUID();
  await db.credentialOffer.create({
    data: {
      issuerDid: ISSUER,
      holderDid: HOLDER,
      credentialType: 'LabResultCredential',
      category: 'LAB_RESULTS',
      preAuthorizedCode,
      pinRequired: false,
      offerData: claims,
      expiresAt: new Date(Date.now() + 3600_000),
    },
  });

  const tokenResponse = await fetch(`${BASE}/oid4vci/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': preAuthorizedCode,
    }),
  });
  const token = (await tokenResponse.json()) as { access_token?: string };
  if (!token.access_token) throw new Error(`token endpoint failed: ${JSON.stringify(token)}`);

  const credentialResponse = await fetch(`${BASE}/oid4vci/credential`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token.access_token}`,
    },
    body: JSON.stringify({
      ...(format ? { format } : {}),
      credential_definition: { type: ['VerifiableCredential', 'LabResultCredential'] },
    }),
  });
  const body = (await credentialResponse.json()) as { format?: string; credential?: string; error?: unknown };
  if (!credentialResponse.ok || !body.credential) {
    throw new Error(`credential endpoint failed (${credentialResponse.status}): ${JSON.stringify(body)}`);
  }
  return { format: body.format!, credential: body.credential };
}

async function main() {
  // =========================================================================
  hr('1. METADATA — the format is discoverable');
  // =========================================================================
  const metadata = (await (await fetch(`${BASE}/.well-known/openid-credential-issuer`)).json()) as {
    credentials_supported: Array<{ format: string; id: string }>;
    credential_configurations_supported: Record<string, { format: string }>;
  };
  const advertised = new Set(metadata.credentials_supported.map((e) => e.format));
  check('credentials_supported advertises vc+sd-jwt', advertised.has('vc+sd-jwt'), [...advertised]);
  check('credential_configurations_supported advertises it too',
    Object.values(metadata.credential_configurations_supported).some((c) => c.format === 'vc+sd-jwt'));
  check('the legacy array and the modern map describe the SAME set',
    metadata.credentials_supported.length ===
      Object.keys(metadata.credential_configurations_supported).length,
    {
      array: metadata.credentials_supported.length,
      map: Object.keys(metadata.credential_configurations_supported).length,
    });
  check('vc+jwt is still advertised — SD-JWT is additive, not a cutover',
    advertised.has('vc+jwt'));

  // =========================================================================
  hr('2. THE PROMISE IS KEPT — asking for vc+sd-jwt yields an SD-JWT');
  // =========================================================================
  const sdJwt = await issueVia('vc+sd-jwt');
  check('the response reports the format it produced', sdJwt.format === 'vc+sd-jwt', sdJwt.format);
  check('the credential is an SD-JWT (carries disclosures)', sdJwt.credential.includes('~'));

  const payload = decodeJwtPayload(sdJwt.credential);
  const subject = payload.credentialSubject as Record<string, unknown>;
  console.log('  issuer-signed credentialSubject keys:', JSON.stringify(Object.keys(subject)));

  check('the issuer-signed payload carries _sd digests', Array.isArray(subject._sd));
  for (const key of ['patientName', 'hivStatus', 'bloodType', 'medications']) {
    check(`'${key}' is a DIGEST, not cleartext, in the signed payload`, !(key in subject));
  }
  check('credentialSubject.id remains in cleartext — the policy carve-out holds',
    subject.id === HOLDER);
  check('no claim VALUE appears anywhere in the issuer-signed segment',
    !['Ahsan Rahman', 'negative', 'O+', 'Sertraline 50mg'].some((v) =>
      JSON.stringify(payload).includes(v)));
  check('cnf holder binding present — the credential is not a bearer token',
    payload.cnf !== undefined);
  check('the row records the format explicitly rather than leaving it to be sniffed',
    (await db.credential.findFirst({
      where: { credentialJwt: sdJwt.credential },
      select: { credentialFormat: true },
    }))?.credentialFormat === 'vc+sd-jwt');

  // =========================================================================
  hr('3. DEFAULTS AND LEGACY — silence still means vc+jwt');
  // =========================================================================
  const defaulted = await issueVia(undefined);
  check('omitting `format` still yields vc+jwt', defaulted.format === 'vc+jwt', defaulted.format);
  check('...and that credential is a plain JWT', !defaulted.credential.includes('~'));
  const defaultedSubject = (decodeJwtPayload(defaulted.credential).credentialSubject as Record<string, unknown>);
  check('...carrying every claim in cleartext, as a JWT credential must',
    defaultedSubject.hivStatus === 'negative' && defaultedSubject.patientName === 'Ahsan Rahman');

  const legacy = await issueVia('jwt_vc_json');
  check('a legacy VC 1.1 request is ACCEPTED, not rejected', legacy.credential.length > 0);
  check('...and is told plainly it received vc+jwt instead', legacy.format === 'vc+jwt', legacy.format);

  // =========================================================================
  hr('SUMMARY');
  // =========================================================================
  if (failures.length === 0) console.log('RESULT: PASS — all checks green');
  else {
    console.log(`RESULT: FAIL — ${failures.length} check(s) failed:`);
    for (const f of failures) console.log(`  - ${f}`);
  }
  process.exit(failures.length === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
