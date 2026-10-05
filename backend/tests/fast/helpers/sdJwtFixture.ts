/**
 * Build real SD-JWT artifacts with no chain, no DID and no key management.
 *
 * WHAT IS REAL HERE AND WHAT IS NOT — this matters, because a helper that
 * quietly stubs the thing under test turns every assertion above it into
 * theatre.
 *
 *   REAL: `@sd-jwt/core` itself. Disclosure construction, salting, digest
 *         computation, `_sd` placement and the `{"...": digest}` array-element
 *         encoding are all done by the shipping library at its pinned version.
 *         Every claim these fixtures support is a claim about that library.
 *
 *   NOT REAL: the signature. `signer` returns a constant. Nothing in the fast
 *         tier verifies a signature, so a real key would add setup cost and
 *         prove nothing extra. Signature verification is exercised in the LIVE
 *         tier against real DIDs on the real chain, which is the only place it
 *         means anything.
 *
 * The hasher is the genuine SHA-256 that `Hasher.hash` uses, because digest
 * matching IS under test in `disclosureIntegrity.test.ts`.
 */
import {
  createHash,
  randomBytes,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from 'node:crypto';

const base64url = (input: Uint8Array | Buffer): string => Buffer.from(input).toString('base64url');

/** The separator between the issuer-signed JWT and each disclosure. */
export const SD_JWT_SEPARATOR = '~';

/**
 * An `SDJwtInstance` configured the way this codebase configures it.
 *
 * Typed loosely on purpose: `@sd-jwt/core`'s constructor generic wants a
 * payload type we do not care about here, and the tests assert on decoded JSON
 * rather than on the library's own types.
 */
export async function createSdJwtInstance(): Promise<{
  issue: (payload: unknown, frame: unknown) => Promise<string>;
}> {
  const { SDJwtInstance } = await import('@sd-jwt/core');
  const instance = new SDJwtInstance({
    hasher: (data: string | ArrayBuffer) =>
      new Uint8Array(
        createHash('sha256')
          .update(typeof data === 'string' ? data : Buffer.from(data))
          .digest(),
      ),
    hashAlg: 'sha-256',
    saltGenerator: (length: number) => base64url(randomBytes(length)).slice(0, length),
    signer: async () => base64url(Buffer.from('not-a-real-signature')),
    signAlg: 'EdDSA',
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);

  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    issue: (payload: unknown, frame: unknown) => (instance as any).issue(payload, frame),
  };
}

/** The issuer-signed payload of a compact SD-JWT, decoded. */
export function issuerSignedPayload(compact: string): Record<string, unknown> {
  const jwt = compact.split(SD_JWT_SEPARATOR)[0]!;
  const payloadSegment = jwt.split('.')[1]!;
  return JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
}

/**
 * Split a compact SD-JWT the way the wire format actually defines it.
 *
 * THE TRAILING `~` IS LOAD BEARING. The last segment is the KEY-BINDING JWT
 * position, empty when there is none, so an artifact with disclosures and no
 * key binding ends in `~`. A helper that filters the empty slot away and
 * rejoins without one silently promotes the last disclosure into the
 * key-binding position — which is the same defect steno #290 found in
 * `assertDisclosuresResolve`, and the reason it went unnoticed here: the two
 * cancelled, so every fixture this file built was mis-shaped in exactly the way
 * the checker was mis-reading. Do not re-inline this.
 */
export function splitCompact(compact: string): {
  jwt: string;
  disclosures: string[];
  kbJwt: string;
} {
  const segments = compact.split(SD_JWT_SEPARATOR);
  if (segments.length === 1) return { jwt: segments[0]!, disclosures: [], kbJwt: '' };
  return {
    jwt: segments[0]!,
    disclosures: segments.slice(1, -1).filter((segment) => segment.length > 0),
    kbJwt: segments[segments.length - 1]!,
  };
}

/** Reassemble, preserving the key-binding position. */
export function joinCompact(parts: {
  jwt: string;
  disclosures: string[];
  kbJwt: string;
}): string {
  return [parts.jwt, ...parts.disclosures, parts.kbJwt].join(SD_JWT_SEPARATOR);
}

/** Every disclosure on the wire, still base64url-encoded, in wire order. */
export function encodedDisclosures(compact: string): string[] {
  return splitCompact(compact).disclosures;
}

/**
 * Every disclosure, decoded.
 *
 * A disclosure is `[salt, claimName, value]` for an object member and
 * `[salt, value]` for an array element — the two-element form is how you tell
 * them apart, and several tests depend on that distinction.
 */
export function decodedDisclosures(compact: string): unknown[][] {
  return encodedDisclosures(compact).map(
    (encoded) => JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as unknown[],
  );
}

/** Re-encode a decoded disclosure so it can be spliced back onto a compact SD-JWT. */
export function encodeDisclosure(disclosure: unknown[]): string {
  return base64url(Buffer.from(JSON.stringify(disclosure), 'utf8'));
}

/** Replace the disclosure at `index`, leaving the issuer-signed JWT untouched. */
export function replaceDisclosure(
  compact: string,
  index: number,
  disclosure: unknown[],
): string {
  const parts = splitCompact(compact);
  const disclosures = [...parts.disclosures];
  disclosures[index] = encodeDisclosure(disclosure);
  return joinCompact({ ...parts, disclosures });
}

/** Append an extra disclosure the issuer never committed to. */
export function injectDisclosure(compact: string, disclosure: unknown[]): string {
  const parts = splitCompact(compact);
  return joinCompact({
    ...parts,
    disclosures: [...parts.disclosures, encodeDisclosure(disclosure)],
  });
}

/** Keep only the disclosures at `indices` — what selective disclosure does. */
export function keepOnlyDisclosures(compact: string, indices: number[]): string {
  const parts = splitCompact(compact);
  return joinCompact({
    ...parts,
    disclosures: indices.map((index) => parts.disclosures[index]!),
  });
}

/**
 * A REAL Ed25519 key pair, and a REAL key-binding JWT over a real artifact.
 *
 * This is the one place the fast tier signs anything. It has to be genuine: a
 * hand-waved KB-JWT — a stub string, a constant signature, a payload with the
 * right keys and the wrong hash — would exercise the parser against an input no
 * holder would ever produce, and a parser test built on a fake proves nothing
 * about the format. The signature is a real Ed25519 signature over the real
 * signing input; `sd_hash` is the real digest of the real byte range RFC 9807
 * §4.3 names.
 *
 * What the fast tier still cannot do is CHECK that signature: verification
 * resolves `cnf.kid` on the ledger. That half lives in the live tier.
 */
export function createHolderKeyPair(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync('ed25519');
}

/**
 * Attach a genuine key-binding JWT to `compact`.
 *
 * `sd_hash` covers the issuer JWT, the disclosures and the trailing `~` — i.e.
 * the artifact exactly as it would go on the wire WITHOUT a key binding, which
 * is what `@sd-jwt/core`'s own `calculateSDHash` hashes.
 */
export function attachKeyBindingJwt(
  compact: string,
  privateKey: KeyObject,
  options: { nonce: string; audience: string; sdHash?: string; typ?: string; alg?: string },
): string {
  const parts = splitCompact(compact);
  const covered = joinCompact({ ...parts, kbJwt: '' });
  const sdHash =
    options.sdHash ?? base64url(createHash('sha256').update(Buffer.from(covered, 'utf8')).digest());

  const header = base64url(
    Buffer.from(JSON.stringify({ typ: options.typ ?? 'kb+jwt', alg: options.alg ?? 'EdDSA' }), 'utf8'),
  );
  const payload = base64url(
    Buffer.from(
      JSON.stringify({
        iat: Math.floor(Date.now() / 1000),
        aud: options.audience,
        nonce: options.nonce,
        sd_hash: sdHash,
      }),
      'utf8',
    ),
  );
  const signature = base64url(nodeSign(null, Buffer.from(`${header}.${payload}`, 'utf8'), privateKey));

  return joinCompact({ ...parts, kbJwt: `${header}.${payload}.${signature}` });
}
