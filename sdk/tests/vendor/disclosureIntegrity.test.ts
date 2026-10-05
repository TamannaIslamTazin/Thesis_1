/**
 * DIVERGENCE D3 — unmatched disclosures rejected, per RFC 9807 §7.3.
 *
 * THE PROPERTY. A disclosure whose digest matches no `_sd` entry (and no
 * `{"...": digest}` array-element entry) in the issuer-signed payload must be
 * REJECTED. Upstream cannot do that, structurally: resolution is payload-driven,
 * so a disclosure nothing points at is never visited and there is no code path
 * on which it could raise anything.
 *
 * WHAT IT COSTS, PRECISELY. No claim can be FORGED — the digest is what makes
 * forgery impossible. The problem is that TAMPERING BECOMES UNDETECTABLE: flip
 * one byte of a disclosure and the claim vanishes from the resolved claims while
 * the artifact still verifies, and the verifier cannot distinguish that from the
 * holder having withheld it. Verifier logic that reads "no allergy recorded" or
 * "no restriction on this licence" as a benign default is then reading an
 * attacker-controlled value.
 *
 * DIFFERENTIAL, like D2: the upstream arm demonstrates the silent drop, the
 * vendored arm demonstrates the refusal.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  createIdentity,
  vendoredInstance,
  upstreamInstance,
  decodedDisclosures,
  replaceDisclosure,
  injectDisclosure,
  type TestIdentity,
} from '../helpers/sdJwt';
import { SdJwtDisclosureError } from '../../src/vendor/sd-jwt/utils';
import { webCryptoHasher } from '../../src/verify/crypto';
import { SDJwt } from '../../src/vendor/sd-jwt/core';

const CLAIMS = {
  patientName: 'Ahsan Rahman',
  hivStatus: 'negative',
  allergies: 'penicillin',
};

const FRAME = { _sd: ['patientName', 'hivStatus', 'allergies'] };

/** Resolve a compact SD-JWT's claims through the VENDORED decoder. */
async function vendoredClaims(compact: string): Promise<Record<string, unknown>> {
  const sdJwt = await SDJwt.fromEncode(compact, webCryptoHasher);
  return sdJwt.getClaims<Record<string, unknown>>(webCryptoHasher);
}

describe('D3 — a disclosure the issuer never committed to', () => {
  let issuer: TestIdentity;
  let upstream: Awaited<ReturnType<typeof upstreamInstance>>;
  let genuine: string;

  beforeAll(async () => {
    issuer = await createIdentity();
    upstream = await upstreamInstance(issuer);
    genuine = await vendoredInstance(issuer).issue({ ...CLAIMS }, FRAME as never);
  });

  it('both implementations accept the untampered artifact', async () => {
    // The baseline. Without this, a test that rejects everything would pass.
    await expect(vendoredClaims(genuine)).resolves.toMatchObject(CLAIMS);
    await expect(upstream.getClaims(genuine)).resolves.toMatchObject(CLAIMS);
  });

  it('UPSTREAM 0.19.0 silently DROPS a tampered disclosure — the control', async () => {
    // Change the value inside one disclosure. The issuer-signed JWT is
    // untouched, so its signature still verifies; only the digest stops
    // matching.
    const index = decodedDisclosures(genuine).findIndex((d) => d[1] === 'allergies');
    expect(index, 'expected an allergies disclosure').toBeGreaterThanOrEqual(0);

    const original = decodedDisclosures(genuine)[index]!;
    const tampered = replaceDisclosure(genuine, index, [original[0], 'allergies', 'none']);

    const claims = (await upstream.getClaims(tampered)) as Record<string, unknown>;

    // No error. And the claim did not become 'none' — it VANISHED. A verifier
    // defaulting an absent `allergies` to "no known allergies" has just been
    // handed an attacker's choice.
    expect(claims.allergies).toBeUndefined();
    expect(claims.patientName).toBe(CLAIMS.patientName);
  });

  it('VENDORED rejects the tampered disclosure', async () => {
    const index = decodedDisclosures(genuine).findIndex((d) => d[1] === 'allergies');
    const original = decodedDisclosures(genuine)[index]!;
    const tampered = replaceDisclosure(genuine, index, [original[0], 'allergies', 'none']);

    await expect(vendoredClaims(tampered)).rejects.toBeInstanceOf(SdJwtDisclosureError);
    await expect(vendoredClaims(tampered)).rejects.toThrow(/RFC 9807/);
  });

  it('UPSTREAM 0.19.0 silently ignores an INJECTED disclosure', async () => {
    // The mix-and-match case: a well-formed disclosure of the attacker's own
    // construction, spliced on. It hashes to nothing the issuer signed.
    const injected = injectDisclosure(genuine, ['aaaaaaaaaaaaaaaa', 'clearance', 'top-secret']);
    const claims = (await upstream.getClaims(injected)) as Record<string, unknown>;

    expect(claims.clearance).toBeUndefined();
    expect(claims.patientName).toBe(CLAIMS.patientName);
  });

  it('VENDORED rejects the injected disclosure', async () => {
    const injected = injectDisclosure(genuine, ['aaaaaaaaaaaaaaaa', 'clearance', 'top-secret']);
    await expect(vendoredClaims(injected)).rejects.toBeInstanceOf(SdJwtDisclosureError);
  });

  it('VENDORED accepts a genuine NARROWED presentation', async () => {
    // The check must not misfire on the normal case. A holder withholding a
    // claim removes a disclosure, leaving a digest with nothing behind it —
    // which resolution skips. The strictness runs the other way: a disclosure
    // with no digest. If this ever fails, selective disclosure is broken.
    const narrowed = await vendoredInstance(issuer).present(genuine, {
      patientName: true,
    } as never);

    const claims = await vendoredClaims(narrowed);
    expect(claims.patientName).toBe(CLAIMS.patientName);
    expect(claims.hivStatus).toBeUndefined();
    expect(claims.allergies).toBeUndefined();
  });

  it('VENDORED accepts decoys, which are digests with no disclosure behind them', async () => {
    // `_sd_decoy` deliberately creates unmatched DIGESTS. Rejecting those would
    // break the feature that exists to hide how many claims a credential has.
    const withDecoys = await vendoredInstance(issuer).issue(
      { ...CLAIMS },
      { ...FRAME, _sd_decoy: 3 } as never,
    );
    await expect(vendoredClaims(withDecoys)).resolves.toMatchObject(CLAIMS);
  });

  it('VENDORED accepts NESTED disclosures, whose digests live inside a container', async () => {
    // The false positive the backend's equivalent check hit while being built:
    // a container disclosure carries its members' digests in its own value, and
    // those are unreachable from the payload until the container resolves. A
    // naive "collect digests from the payload only" check flags every nested
    // disclosure as unmatched and rejects an honest credential.
    const nested = await vendoredInstance(issuer).issue(
      { prescriber: { name: 'Dr Karim', licence: 'BMDC-4471' } },
      { _sd: ['prescriber'], prescriber: { _sd: ['licence'] } } as never,
    );

    const claims = await vendoredClaims(nested);
    expect(claims.prescriber).toMatchObject({ name: 'Dr Karim', licence: 'BMDC-4471' });
  });

  it('VENDORED honours _sd_alg rather than assuming sha-256', async () => {
    // The other false positive: assuming sha-256 marks every disclosure of a
    // sha-512 credential as unmatched and rejects the whole thing.
    const sha512 = new (await import('../../src/vendor/sd-jwt/core')).SDJwtInstance<
      Record<string, unknown>
    >({
      hasher: webCryptoHasher,
      hashAlg: 'sha-512',
      saltGenerator: (await import('../../src/verify/crypto')).webCryptoSaltGenerator,
      signer: async () => 'not-checked-here',
      signAlg: 'EdDSA',
    });

    const compact = await sha512.issue({ ...CLAIMS }, FRAME as never);
    expect(JSON.parse(atob(compact.split('~')[0]!.split('.')[1]!))._sd_alg).toBe('sha-512');
    await expect(vendoredClaims(compact)).resolves.toMatchObject(CLAIMS);
  });
});
