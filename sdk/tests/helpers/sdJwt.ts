/**
 * Fixtures for the vendored SD-JWT tests.
 *
 * WHAT IS REAL HERE. Everything that the assertions are about. The disclosure
 * machinery is the vendored library at full strength; the signatures are real
 * Ed25519 over real WebCrypto keys; the hasher is the same `webCryptoHasher`
 * the shipping verifier uses. Nothing under test is stubbed.
 *
 * WHAT IS SIMULATED. DID resolution. There is no ledger in this tier, so
 * `resolverFor` is a map from key id to JWK — which is exactly the shape
 * `ResolveVerificationKey` has, so the code path under test is the production
 * one and only the source of the key material differs. The wire format the
 * fixtures produce is copied from what Credo 0.6.3 actually emits (see
 * `packages/backend/tests/live/helpers/liveSdJwt.ts`), not invented here.
 */
import { generateKeyPair, exportJWK } from 'jose';
import { SDJwtInstance } from '../../src/vendor/sd-jwt/core';
import { webCryptoHasher, webCryptoSaltGenerator } from '../../src/verify/crypto';
import { uint8ArrayToBase64Url, base64urlDecode, base64urlEncode } from '../../src/vendor/sd-jwt/utils';
import type { VerificationJwk, ResolveVerificationKey } from '../../src/verify/presentation';

export const SD_SEPARATOR = '~';

export interface TestIdentity {
  did: string;
  kid: string;
  publicJwk: VerificationJwk;
  privateKey: CryptoKey;
}

let didCounter = 0;

/** An Ed25519 identity with a did:cheqd-shaped identifier and a `#key-1` fragment. */
export async function createIdentity(): Promise<TestIdentity> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  didCounter += 1;
  const did = `did:cheqd:bdhealthtestnet:00000000-0000-4000-8000-${String(didCounter).padStart(12, '0')}`;
  return {
    did,
    kid: `${did}#key-1`,
    publicJwk: (await exportJWK(publicKey)) as VerificationJwk,
    privateKey: privateKey as CryptoKey,
  };
}

/** The `Signer` shape the vendored library expects, backed by a real key. */
function signerFor(identity: TestIdentity) {
  return async (data: string): Promise<string> => {
    const signature = await crypto.subtle.sign(
      'Ed25519',
      identity.privateKey,
      new TextEncoder().encode(data),
    );
    return uint8ArrayToBase64Url(new Uint8Array(signature));
  };
}

/** An `SDJwtInstance` from the VENDORED copy, configured as production does. */
export function vendoredInstance(identity: TestIdentity): SDJwtInstance<Record<string, unknown>> {
  return new SDJwtInstance<Record<string, unknown>>({
    hasher: webCryptoHasher,
    hashAlg: 'sha-256',
    saltGenerator: webCryptoSaltGenerator,
    signer: signerFor(identity),
    signAlg: 'EdDSA',
  });
}

/**
 * The same instance built from the PUBLISHED `@sd-jwt/core@0.19.0`.
 *
 * The control arm of every differential test. It is a devDependency and is
 * never shipped; its only job is to demonstrate that a divergence changes
 * behaviour rather than merely claiming to.
 */
export async function upstreamInstance(identity: TestIdentity): Promise<{
  issue: (payload: unknown, frame: unknown) => Promise<string>;
  getClaims: (compact: string) => Promise<unknown>;
}> {
  const { SDJwtInstance: Upstream } = await import('@sd-jwt/core');
  const instance = new Upstream({
    hasher: webCryptoHasher,
    hashAlg: 'sha-256',
    saltGenerator: webCryptoSaltGenerator,
    signer: signerFor(identity),
    signAlg: 'EdDSA',
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    issue: (payload, frame) => (instance as any).issue(payload, frame),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    getClaims: (compact) => (instance as any).getClaims(compact),
  };
}

/** The issuer-signed payload of a compact SD-JWT, decoded. */
export function issuerSignedPayload(compact: string): Record<string, unknown> {
  const jwt = compact.split(SD_SEPARATOR)[0]!;
  return JSON.parse(base64urlDecode(jwt.split('.')[1]!)) as Record<string, unknown>;
}

/**
 * Split a compact SD-JWT the way the wire format actually defines it.
 *
 * THE TRAILING `~` IS LOAD BEARING and is the reason this is a shared helper
 * rather than an inline `.split('~').slice(1)`. The last segment is the
 * key-binding JWT, EMPTY when there is none — so an artifact with disclosures
 * and no KB-JWT ends in `~`. A helper that filters empty segments away and
 * rejoins without one silently promotes the last disclosure to the KB-JWT
 * position, and the next decode fails with "Invalid JWT as input" from
 * somewhere unrelated. That cost a debugging round here; do not re-inline it.
 */
export function splitCompact(compact: string): {
  jws: string;
  disclosures: string[];
  kbJwt: string;
} {
  const segments = compact.split(SD_SEPARATOR);
  if (segments.length === 1) return { jws: segments[0]!, disclosures: [], kbJwt: '' };
  return {
    jws: segments[0]!,
    disclosures: segments.slice(1, -1),
    kbJwt: segments[segments.length - 1]!,
  };
}

/** Reassemble, preserving the KB-JWT position. */
export function joinCompact(parts: {
  jws: string;
  disclosures: string[];
  kbJwt: string;
}): string {
  return [parts.jws, ...parts.disclosures, parts.kbJwt].join(SD_SEPARATOR);
}

/** Every disclosure on the wire, still base64url-encoded, in wire order. */
export function encodedDisclosures(compact: string): string[] {
  return splitCompact(compact).disclosures.filter((segment) => segment.length > 0);
}

/**
 * Every disclosure, decoded.
 *
 * `[salt, claimName, value]` for an object member, `[salt, value]` for an array
 * element — the length is how you tell them apart, and the leak tests depend on
 * that distinction.
 */
export function decodedDisclosures(compact: string): unknown[][] {
  return encodedDisclosures(compact).map(
    (encoded) => JSON.parse(base64urlDecode(encoded)) as unknown[],
  );
}

/** Replace the disclosure at `index`, leaving the issuer-signed JWT untouched. */
export function replaceDisclosure(
  compact: string,
  index: number,
  disclosure: unknown[],
): string {
  const parts = splitCompact(compact);
  const disclosures = [...parts.disclosures];
  disclosures[index] = base64urlEncode(JSON.stringify(disclosure));
  return joinCompact({ ...parts, disclosures });
}

/** Append a disclosure the issuer never committed to. */
export function injectDisclosure(compact: string, disclosure: unknown[]): string {
  const parts = splitCompact(compact);
  return joinCompact({
    ...parts,
    disclosures: [...parts.disclosures, base64urlEncode(JSON.stringify(disclosure))],
  });
}

/** A `ResolveVerificationKey` backed by a fixed set of identities. */
export function resolverFor(...identities: TestIdentity[]): ResolveVerificationKey {
  const byKid = new Map(identities.map((identity) => [identity.kid, identity.publicJwk]));
  return ({ kid }) => {
    const jwk = byKid.get(kid);
    if (!jwk) throw new Error(`no key for ${kid}`);
    return jwk;
  };
}
