/**
 * Live-tier fixtures: real DIDs on our chain, real keys, real signatures.
 *
 * Harvested from `packages/backend/probe-sdjwt.mts`, which proved these
 * properties by hand. The probe stays as the narrated, human-readable evidence
 * artifact; this module is the same mechanics with the narration removed.
 */
import { randomUUID } from 'node:crypto';
import {
  W3cV2Credential,
  W3cV2CredentialSubject,
  W3cV2Presentation,
  W3cV2EnvelopedVerifiableCredential,
  JsonTransformer,
  TypedArrayEncoder,
  Hasher,
  Kms,
  type Agent,
} from '@credo-ts/core';

/**
 * Pre-existing throwaway DIDs on the localnet.
 *
 * DELIBERATELY NOT CREATED BY THIS SUITE. DID creation is a concurrently-edited
 * area (see the wallet-setup 503 in TESTING_MANUAL.md §3.1) and minting a DID
 * per test run would both slow the suite and write permanent unrecoverable
 * identifiers to the ledger for no benefit. These three are already-audited
 * test data (steno #217).
 *
 * If a run fails resolving these, the fixture has drifted from the chain state
 * — replace the constants, do not disable the test.
 */
export const ISSUER = 'did:cheqd:bdhealthtestnet:fa3fc79f-9d49-43f5-9aa7-4f2df973bbb0';
export const HOLDER = 'did:cheqd:bdhealthtestnet:7cd03fdc-6a88-4895-9d89-e63445abe0c1';
export const ATTACKER = 'did:cheqd:bdhealthtestnet:a697648c-7a8a-43b3-825b-7bb50725d764';

export const VERIFIER_DOMAIN = 'https://pharmacy.bd-health.example';

/** The subject every live test issues over. One array, one nested container. */
export const CLAIMS = {
  patientName: 'Ahsan Rahman',
  hivStatus: 'negative',
  bloodType: 'O+',
  testDate: '2026-08-10',
  prescriber: { name: 'Dr Karim', licence: 'BMDC-4471' },
  medications: ['Metformin 500mg', 'Lisinopril 10mg', 'Sertraline 50mg'],
};

/** A bare credential, for tests that must bypass the shipped issuance policy. */
export function buildRawCredential(): W3cV2Credential {
  return new W3cV2Credential({
    context: ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
    id: `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', 'LabResultCredential'],
    issuer: ISSUER,
    validFrom: new Date().toISOString(),
    validUntil: new Date(Date.now() + 86_400_000).toISOString(),
    credentialSubject: new W3cV2CredentialSubject({ id: HOLDER, ...CLAIMS }),
  });
}

/**
 * Sign an arbitrary presentation payload with an arbitrary key — i.e. act as
 * an attacker who controls their own DID and wants to wrap someone else's
 * credential in it.
 *
 * This deliberately does NOT go through `signSdJwtPresentation`, because that
 * function derives the signing key from the credential's own `cnf` and so
 * cannot express the attack. Going around it is the point.
 */
export async function forgePresentation(
  agent: Agent,
  presentation: W3cV2Presentation,
  signerDid: string,
  nonce: string,
  audience: string,
): Promise<string> {
  const { SDJwtInstance } = await import('@sd-jwt/core');
  const kms = agent.context.resolve(Kms.KeyManagementApi);

  const document = await agent.dids.resolve(signerDid);
  const authentication = document.didDocument!.authentication![0];
  const kid =
    typeof authentication === 'string' ? authentication : (authentication as { id: string }).id;
  const keyId = (await agent.dids.getCreatedDids({ did: signerDid }))[0]!.keys![0]!.kmsKeyId;

  const payload = JsonTransformer.toJSON(presentation) as Record<string, unknown>;
  payload.nonce = nonce;
  payload.aud = audience;

  return new SDJwtInstance({
    hasher: (data: string | ArrayBuffer, alg: string) =>
      Hasher.hash(typeof data === 'string' ? data : new Uint8Array(data), alg),
    saltGenerator: (length: number) =>
      TypedArrayEncoder.toBase64URL(kms.randomBytes({ length })).slice(0, length),
    signer: async (input: string) =>
      TypedArrayEncoder.toBase64URL(
        (
          await kms.sign({
            keyId,
            data: TypedArrayEncoder.fromString(input),
            algorithm: 'EdDSA',
          })
        ).signature,
      ),
    signAlg: 'EdDSA',
    hashAlg: 'sha-256',
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any).issue(payload, undefined, {
    header: { typ: 'vp+sd-jwt', alg: 'EdDSA', kid },
  });
}

/** Wrap a disclosed credential in a presentation held by `holder`. */
export function presentationOf(
  holder: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  disclosed: any,
): W3cV2Presentation {
  return new W3cV2Presentation({
    holder,
    verifiableCredential: [
      W3cV2EnvelopedVerifiableCredential.fromVerifiableCredential(disclosed),
    ],
  });
}

/**
 * Split a compact SD-JWT — the fixture's OWN reading of the wire format.
 *
 * Deliberately not imported from `sdJwtVc.ts`. The `sd_hash` below is computed
 * over the byte range this split produces, so if the two disagree the KB-JWT
 * fails to verify and the test says so. Sharing the helper would make the
 * fixture agree with the code under test by construction, which is exactly the
 * property a fixture must not have here — steno #290 was two implementations of
 * this split being wrong in the same way and cancelling.
 */
function splitForFixture(compact: string): {
  jwt: string;
  disclosures: string[];
  kbJwt: string;
} {
  const segments = compact.split('~');
  if (segments.length === 1) return { jwt: segments[0]!, disclosures: [], kbJwt: '' };
  return {
    jwt: segments[0]!,
    disclosures: segments.slice(1, -1),
    kbJwt: segments[segments.length - 1]!,
  };
}

/**
 * Attach a GENUINE key-binding JWT, signed with a real key held in the agent's
 * wallet.
 *
 * REAL, NOT SIMULATED. The signature comes from the KMS over the actual signing
 * input; `sd_hash` is the real digest, under the artifact's own `_sd_alg`, of
 * the artifact exactly as it goes on the wire minus the key binding — the byte
 * range RFC 9807 §4.3 names and the one `@sd-jwt/core`'s `calculateSDHash`
 * hashes. Nothing in this system emits a KB-JWT yet (that is the whole reason
 * steno #290 sat unreachable), so the only way to test the parser against one is
 * to mint one properly. A stubbed KB-JWT would test the stub.
 *
 * `signerDid` is separate from the credential's `cnf` on purpose: passing the
 * ATTACKER is how the forged-signature control is expressed, and a real
 * signature by the wrong key is a far better negative than random bytes.
 */
export async function attachKeyBindingJwt(
  agent: Agent,
  compact: string,
  signerDid: string,
  options: {
    nonce: string;
    audience: string;
    /** Override the computed digest — for the lifted / replayed KB-JWT case. */
    sdHash?: string;
    typ?: string;
  },
): Promise<string> {
  const kms = agent.context.resolve(Kms.KeyManagementApi);
  const { publicJwk } = await agent.dids.resolveVerificationMethodFromCreatedDidRecord(
    `${signerDid}#key-1`,
  );

  const parts = splitForFixture(compact);
  const covered = [parts.jwt, ...parts.disclosures, ''].join('~');

  let alg = 'sha-256';
  try {
    const payload = JSON.parse(
      Buffer.from(parts.jwt.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    if (typeof payload._sd_alg === 'string') alg = payload._sd_alg;
  } catch {
    throw new Error('attachKeyBindingJwt: issuer payload is unreadable');
  }

  const sdHash =
    options.sdHash ??
    TypedArrayEncoder.toBase64URL(Hasher.hash(TypedArrayEncoder.fromString(covered), alg));

  const b64 = (value: unknown): string =>
    Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

  const header = b64({ typ: options.typ ?? 'kb+jwt', alg: publicJwk.signatureAlgorithm });
  const payload = b64({
    iat: Math.floor(Date.now() / 1000),
    aud: options.audience,
    nonce: options.nonce,
    sd_hash: sdHash,
  });

  const { signature } = await kms.sign({
    keyId: publicJwk.keyId,
    data: TypedArrayEncoder.fromString(`${header}.${payload}`),
    algorithm: publicJwk.signatureAlgorithm,
  });

  return [
    parts.jwt,
    ...parts.disclosures,
    `${header}.${payload}.${TypedArrayEncoder.toBase64URL(signature)}`,
  ].join('~');
}

/** Flip a disclosure's value in place, leaving the issuer signature untouched. */
export function tamperDisclosure(
  compact: string,
  matches: (decoded: unknown[]) => boolean,
  replacement: (decoded: unknown[]) => unknown[],
): string {
  const segments = compact.split('~');
  const index = segments.findIndex((segment, i) => {
    if (i === 0 || !segment) return false;
    try {
      return matches(JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as unknown[]);
    } catch {
      return false;
    }
  });
  if (index === -1) throw new Error('tamperDisclosure: no disclosure matched');

  const original = JSON.parse(
    Buffer.from(segments[index]!, 'base64url').toString('utf8'),
  ) as unknown[];
  const next = [...segments];
  next[index] = Buffer.from(JSON.stringify(replacement(original)), 'utf8').toString('base64url');
  return next.join('~');
}
