/**
 * `verifySdJwtPresentation` — the SDK's local verification boundary.
 *
 * WHAT THIS SUITE IS REALLY ABOUT. Not "does the happy path work". It is about
 * the trap recorded in steno #275: `@sd-jwt/core` closes the DISCLOSURE layer
 * and nothing else, so a verifier built on it alone would pass every attack
 * that lives at the PRESENTATION layer — replay, and credential theft — while
 * reporting success. The two `THE THIRD-PATH TRAP` blocks below are the ones
 * that would fail if someone ever simplified this module down to a
 * `@sd-jwt/core` call, and they are the reason the module exists in this shape.
 *
 * Every signature here is a real Ed25519 signature over a real WebCrypto key.
 * Nothing in the module under test is mocked; only DID resolution is supplied
 * from a map, through the same `ResolveVerificationKey` interface production
 * uses.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { verifySdJwtPresentation, NOT_CHECKED } from '../../src/verify';
import {
  createIdentity,
  resolverFor,
  decodedDisclosures,
  replaceDisclosure,
  injectDisclosure,
  type TestIdentity,
} from '../helpers/sdJwt';
import {
  issueCredential,
  discloseCredential,
  signPresentation,
  SUBJECT,
} from '../helpers/presentation';

const CHALLENGE = 'nonce-issued-by-this-verifier-0001';
const AUDIENCE = 'https://pharmacy.bd-health.example';

describe('verifySdJwtPresentation', () => {
  let issuer: TestIdentity;
  let holder: TestIdentity;
  let attacker: TestIdentity;
  let credential: string;
  let disclosed: string;

  beforeAll(async () => {
    issuer = await createIdentity();
    holder = await createIdentity();
    attacker = await createIdentity();
    credential = await issueCredential({ issuer, holder });
    // The holder reveals their blood type and one medication, withholding the
    // HIV status and the other two medications. This is the shape a real
    // selective disclosure has, and several assertions below depend on it.
    disclosed = await discloseCredential(holder, credential, {
      credentialSubject: { bloodType: true, medications: { 1: true } },
    });
  });

  const goodPresentation = () =>
    signPresentation({
      signer: holder,
      credentials: [disclosed],
      challenge: CHALLENGE,
      audience: AUDIENCE,
    });

  const verify = (presentation: string, overrides: Record<string, unknown> = {}) =>
    verifySdJwtPresentation({
      presentation,
      challenge: CHALLENGE,
      audience: AUDIENCE,
      resolveVerificationKey: resolverFor(issuer, holder, attacker),
      ...overrides,
    });

  // ==========================================================================
  describe('the honest case', () => {
    it('accepts a genuine presentation and passes every check', async () => {
      const result = await verify(await goodPresentation());

      expect(result.errors).toEqual([]);
      expect(result.isValid).toBe(true);
      expect(result.checks).toEqual({
        structure: true,
        holderSignature: true,
        issuerSignature: true,
        disclosureIntegrity: true,
        challenge: true,
        audience: true,
        holderBinding: true,
        validityWindow: true,
      });
    });

    it('returns exactly the claims the holder chose to disclose', async () => {
      const result = await verify(await goodPresentation());
      const subject = result.credentials[0]!.claims.credentialSubject as Record<string, unknown>;

      expect(subject.bloodType).toBe(SUBJECT.bloodType);
      expect(subject.medications).toEqual([SUBJECT.medications[1]]);

      // Withheld claims are ABSENT, not blank. A caller cannot distinguish
      // "withheld" from "never existed", which is the privacy property.
      expect('hivStatus' in subject).toBe(false);
      expect('patientName' in subject).toBe(false);
    });

    it('strips envelope claims, so `cnf` and `iat` do not masquerade as credential data', async () => {
      const result = await verify(await goodPresentation());
      const claims = result.credentials[0]!.claims;

      expect(claims['@context']).toBeDefined();
      expect(claims.cnf).toBeUndefined();
      expect(claims.iat).toBeUndefined();
      expect(claims._sd_alg).toBeUndefined();

      // But the binding is still reported, on its own field, for a caller that
      // needs it.
      expect(result.credentials[0]!.cnfKeyId).toBe(holder.kid);
      expect(result.credentials[0]!.issuer).toBe(issuer.did);
    });

    it('reports what it did NOT establish, inside the result', async () => {
      const result = await verify(await goodPresentation());
      expect(result.notChecked).toBe(NOT_CHECKED);
      expect(result.notChecked.join(' ')).toMatch(/revocation/i);
    });
  });

  // ==========================================================================
  describe('THE THIRD-PATH TRAP #1 — replay', () => {
    /**
     * Credo's `verifyPresentation` accepts `challenge`/`domain` and never reads
     * them (CREDO-SECURITY-REPORT §2), and `@sd-jwt/core` has no concept of
     * either. So a verifier built on the disclosure layer alone passes every
     * assertion in this block while accepting a replayed presentation.
     */
    it('refuses a presentation minted for a DIFFERENT verifier`s nonce', async () => {
      const forVerifierA = await signPresentation({
        signer: holder,
        credentials: [disclosed],
        challenge: 'nonce-for-verifier-A',
        audience: AUDIENCE,
      });

      const result = await verify(forVerifierA);

      expect(result.isValid).toBe(false);
      expect(result.checks.challenge).toBe(false);
      // Everything the disclosure layer can see is still fine. That is the
      // whole point: signatures and digests check out, and the presentation
      // must still be refused.
      expect(result.checks.holderSignature).toBe(true);
      expect(result.checks.issuerSignature).toBe(true);
      expect(result.checks.disclosureIntegrity).toBe(true);
      expect(result.errors.join(' ')).toMatch(/nonce does not match/i);
    });

    it('refuses a presentation minted for a DIFFERENT audience', async () => {
      const forHospital = await signPresentation({
        signer: holder,
        credentials: [disclosed],
        challenge: CHALLENGE,
        audience: 'https://hospital-a.bd-health.example',
      });

      const result = await verify(forHospital);

      expect(result.isValid).toBe(false);
      expect(result.checks.audience).toBe(false);
      expect(result.checks.holderSignature).toBe(true);
    });

    it('refuses a presentation carrying NO nonce at all — absence is not a skip', async () => {
      // The fail-open shape every bug in this area has taken: treating "nothing
      // to compare" as "nothing to object to".
      const noNonce = await signPresentation({
        signer: holder,
        credentials: [disclosed],
        challenge: '',
        audience: AUDIENCE,
      });

      const result = await verify(noNonce);
      expect(result.checks.challenge).toBe(false);
      expect(result.errors.join(' ')).toMatch(/carries no nonce/i);
    });

    it('refuses a presentation carrying no audience, even though the backend treats domain as optional', async () => {
      // Deliberately STRICTER than `packages/backend/src/services/sdJwtVc.ts`,
      // where `domain` is optional and an absent one passes. A third-party
      // relying party that did not state its own audience has no cross-verifier
      // replay defence, and this SDK must never be the weaker path.
      const noAudience = await signPresentation({
        signer: holder,
        credentials: [disclosed],
        challenge: CHALLENGE,
        audience: '',
      });

      const result = await verify(noAudience);
      expect(result.checks.audience).toBe(false);
    });
  });

  // ==========================================================================
  describe('THE THIRD-PATH TRAP #2 — credential theft via cnf', () => {
    /**
     * The attack from CREDO-SECURITY-REPORT §3, reproduced here against our own
     * verifier. An attacker who captured a disclosed credential wraps it in a
     * presentation of their own construction, signs it with THEIR key under
     * THEIR DID, and submits it. Every signature is genuine. Every digest
     * matches. The disclosure layer has no objection whatsoever.
     *
     * The only thing that refuses it is comparing the credential's `cnf` — the
     * binding the ISSUER signed — to the party that signed the presentation.
     */
    it('refuses a captured credential re-presented by the attacker', async () => {
      const stolen = await signPresentation({
        signer: attacker,
        credentials: [disclosed],
        challenge: CHALLENGE,
        audience: AUDIENCE,
      });

      const result = await verify(stolen);

      expect(result.isValid).toBe(false);
      expect(result.checks.holderBinding).toBe(false);
      // The attacker's own signature is VALID. So are the issuer's and the
      // digests. A verifier stopping at the disclosure layer accepts this.
      expect(result.checks.holderSignature).toBe(true);
      expect(result.checks.issuerSignature).toBe(true);
      expect(result.checks.disclosureIntegrity).toBe(true);
      expect(result.checks.challenge).toBe(true);
      expect(result.checks.audience).toBe(true);
      expect(result.errors.join(' ')).toMatch(/signed by .* but the credential is bound to/i);
    });

    it('refuses it EVEN WHEN the subject id is withheld — the fail-open case', async () => {
      // Credo's nearest check compares `credentialSubject.id` and SKIPS ITSELF
      // when no subject id is disclosed. That makes the hole open precisely when
      // the holder exercises privacy — the more privacy, the less
      // authentication. Our check is unconditional, so withholding `id` changes
      // nothing.
      const idWithheld = await discloseCredential(holder, credential, {
        credentialSubject: { bloodType: true },
      });
      const stolen = await signPresentation({
        signer: attacker,
        credentials: [idWithheld],
        challenge: CHALLENGE,
        audience: AUDIENCE,
      });

      const result = await verify(stolen);
      expect(result.checks.holderBinding).toBe(false);
      expect(result.isValid).toBe(false);
    });

    it('refuses an UNBOUND credential — a bearer token is not a holder proof', async () => {
      const unbound = await issueCredential({ issuer, holder, omitCnf: true });
      const presented = await signPresentation({
        signer: holder,
        credentials: [unbound],
        challenge: CHALLENGE,
        audience: AUDIENCE,
      });

      const result = await verify(presented);
      expect(result.checks.holderBinding).toBe(false);
      expect(result.errors.join(' ')).toMatch(/no cnf holder binding/i);
    });

    it('accepts a RELATIVE kid fragment, resolved against the holder DID', async () => {
      // A `kid` may legitimately be `#key-1` while `cnf.kid` is absolute.
      // Comparing them as plain strings would reject every honest presentation
      // that used the relative form — a fail-CLOSED bug, but still a bug, and
      // one that only shows up against a wallet we did not write.
      const presentation = await signPresentation({
        signer: holder,
        credentials: [disclosed],
        challenge: CHALLENGE,
        audience: AUDIENCE,
        kid: '#key-1',
      });

      const header = JSON.parse(
        Buffer.from(presentation.split('~')[0]!.split('.')[0]!, 'base64url').toString(),
      );
      expect(header.kid, 'fixture must actually use the relative form').toBe('#key-1');

      const result = await verify(presentation);
      expect(result.errors).toEqual([]);
      expect(result.checks.holderBinding).toBe(true);
      expect(result.isValid).toBe(true);
      expect(result.holderKeyId).toBe(holder.kid);
    });

    it('refuses a relative kid when the presentation names no holder to resolve it against', async () => {
      // `#key-1` with no `holder` claim cannot be attributed to anyone, so it
      // must fail rather than be compared as the literal string '#key-1'.
      const orphan = await signPresentation({
        signer: holder,
        holderDid: '',
        credentials: [disclosed],
        challenge: CHALLENGE,
        audience: AUDIENCE,
        kid: '#key-1',
      });

      const result = await verify(orphan);
      expect(result.checks.holderBinding).toBe(false);
      expect(result.errors.join(' ')).toMatch(/does not name the key that signed it/i);
    });
  });

  // ==========================================================================
  describe('disclosure integrity, carried up from the vendored layer', () => {
    it('refuses a presentation whose credential has a TAMPERED disclosure', async () => {
      const index = decodedDisclosures(disclosed).findIndex((d) => d[1] === 'bloodType');
      expect(index).toBeGreaterThanOrEqual(0);
      const original = decodedDisclosures(disclosed)[index]!;
      const tampered = replaceDisclosure(disclosed, index, [original[0], 'bloodType', 'AB-']);

      const result = await verify(
        await signPresentation({
          signer: holder,
          credentials: [tampered],
          challenge: CHALLENGE,
          audience: AUDIENCE,
        }),
      );

      expect(result.isValid).toBe(false);
      expect(result.checks.disclosureIntegrity).toBe(false);
      expect(result.errors.join(' ')).toMatch(/RFC 9807/);
    });

    it('refuses a presentation with an INJECTED disclosure', async () => {
      const injected = injectDisclosure(disclosed, ['aaaaaaaaaaaaaaaa', 'clearance', 'full']);

      const result = await verify(
        await signPresentation({
          signer: holder,
          credentials: [injected],
          challenge: CHALLENGE,
          audience: AUDIENCE,
        }),
      );

      expect(result.checks.disclosureIntegrity).toBe(false);
      expect(result.isValid).toBe(false);
    });

    it('withholds claims entirely when integrity fails', async () => {
      // The reason `credentials` is gated on `isValid`: a caller that reads
      // claims out of a failed verification is acting on unauthenticated data.
      const injected = injectDisclosure(disclosed, ['aaaaaaaaaaaaaaaa', 'clearance', 'full']);
      const result = await verify(
        await signPresentation({
          signer: holder,
          credentials: [injected],
          challenge: CHALLENGE,
          audience: AUDIENCE,
        }),
      );

      expect(result.credentials).toEqual([]);
    });
  });

  // ==========================================================================
  describe('signatures', () => {
    it('refuses a presentation signed by a key the resolver will not vouch for', async () => {
      const stranger = await createIdentity();
      const presentation = await signPresentation({
        signer: stranger,
        credentials: [disclosed],
        challenge: CHALLENGE,
        audience: AUDIENCE,
      });

      // The resolver knows nothing about `stranger`, so it throws — which must
      // FAIL the check, never skip it.
      const result = await verify(presentation);
      expect(result.checks.holderSignature).toBe(false);
      expect(result.errors.join(' ')).toMatch(/could not be resolved/i);
    });

    it('refuses a presentation whose signature does not verify under the named key', async () => {
      const presentation = await goodPresentation();
      // Corrupt the signature segment only, leaving header and payload intact.
      const [jws, ...rest] = presentation.split('~');
      const [h, p, s] = jws!.split('.');
      const flipped = s!.slice(0, -4) + (s!.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
      const broken = [[h, p, flipped].join('.'), ...rest].join('~');

      const result = await verify(broken);
      expect(result.checks.holderSignature).toBe(false);
      expect(result.isValid).toBe(false);
    });

    it('refuses an algorithm outside the allowlist', async () => {
      const result = await verify(await goodPresentation(), { algorithms: ['ES256'] });
      expect(result.checks.holderSignature).toBe(false);
      expect(result.errors.join(' ')).toMatch(/not in the accepted list/i);
    });
  });

  // ==========================================================================
  describe('validity window', () => {
    it('refuses an expired credential', async () => {
      const expired = await issueCredential({
        issuer,
        holder,
        validFrom: new Date(Date.now() - 172_800_000).toISOString(),
        validUntil: new Date(Date.now() - 86_400_000).toISOString(),
      });
      const result = await verify(
        await signPresentation({
          signer: holder,
          credentials: [expired],
          challenge: CHALLENGE,
          audience: AUDIENCE,
        }),
      );

      expect(result.checks.validityWindow).toBe(false);
      expect(result.errors.join(' ')).toMatch(/expired/i);
    });

    it('refuses a credential that is not yet valid', async () => {
      const future = await issueCredential({
        issuer,
        holder,
        validFrom: new Date(Date.now() + 86_400_000).toISOString(),
        validUntil: new Date(Date.now() + 172_800_000).toISOString(),
      });
      const result = await verify(
        await signPresentation({
          signer: holder,
          credentials: [future],
          challenge: CHALLENGE,
          audience: AUDIENCE,
        }),
      );

      expect(result.checks.validityWindow).toBe(false);
      expect(result.errors.join(' ')).toMatch(/not valid until/i);
    });

    it('honours the VC 1.1 field names too', async () => {
      // A wallet holding credentials from before the VC 2.0 migration sees
      // issuanceDate/expirationDate. Reading only validFrom/validUntil is how a
      // legacy credential silently verifies as "always valid".
      const legacy = await issueCredential({ issuer, holder });
      const payload = JSON.parse(
        Buffer.from(legacy.split('~')[0]!.split('.')[1]!, 'base64url').toString(),
      );
      expect(payload.validUntil).toBeDefined();

      const result = await verify(
        await signPresentation({
          signer: holder,
          credentials: [legacy],
          challenge: CHALLENGE,
          audience: AUDIENCE,
        }),
        { now: new Date(Date.now() + 172_800_000) },
      );
      expect(result.checks.validityWindow).toBe(false);
    });
  });

  // ==========================================================================
  // ==========================================================================
  // steno #344. This module does not verify key binding, so it must not accept
  // an artifact carrying one. Before this, a KB-JWT with a wrong `sd_hash`, a
  // stale nonce, another verifier's audience and a garbage signature returned
  // `isValid: true` with NO errors, because nothing looked at the slot.
  //
  // Both halves are here on purpose. This project has been bitten three times
  // by fail-closed code that hid its own defects — most memorably two of three
  // tamper tests passing while the hash function under them was broken — so a
  // refusal test without a paired success test proves nothing: `return false`
  // would satisfy it.
  describe('key binding is refused, not ignored', () => {
    /** A syntactically valid `kb+jwt` whose every claim and signature is wrong. */
    const forgedKbJwt = () => {
      const header = Buffer.from(
        JSON.stringify({ typ: 'kb+jwt', alg: 'EdDSA' }),
      ).toString('base64url');
      const payload = Buffer.from(
        JSON.stringify({
          nonce: 'not-the-challenge',
          aud: 'https://attacker.example',
          sd_hash: 'wrong',
        }),
      ).toString('base64url');
      return `${header}.${payload}.${Buffer.from('garbage').toString('base64url')}`;
    };

    it('refuses a presentation carrying a KB-JWT in its own slot', async () => {
      const vp = await goodPresentation();
      const segments = vp.split('~');
      const withKb = [...segments.slice(0, -1), forgedKbJwt()].join('~');

      const result = await verify(withKb);

      expect(result.isValid).toBe(false);
      expect(result.checks.structure).toBe(false);
      expect(result.errors.join(' ')).toMatch(/key-binding JWT, which this SDK does not verify/);
      expect(result.credentials).toEqual([]);
    });

    it('refuses a KB-JWT on an EMBEDDED credential, not just the envelope', async () => {
      // The envelope is the obvious slot; a credential inside it has one too,
      // and checking only the outer one would leave the inner path fail-open.
      const disclosedSegments = disclosed.split('~');
      const kbBearing = [...disclosedSegments.slice(0, -1), forgedKbJwt()].join('~');
      const vp = await signPresentation({
        signer: holder,
        credentials: [kbBearing],
        challenge: CHALLENGE,
        audience: AUDIENCE,
      });

      const result = await verify(vp);

      expect(result.isValid).toBe(false);
      expect(result.checks.structure).toBe(false);
      expect(result.errors.join(' ')).toMatch(/key-binding JWT, which this SDK does not verify/);
    });

    it('THE PAIRED SUCCESS PATH: an artifact with an EMPTY KB slot still verifies', async () => {
      // The refusal above must key on a POPULATED slot. Every honest artifact
      // this SDK sees ends with a trailing separator and an empty KB position,
      // so a refusal that keyed on the separator instead would reject
      // everything — and the two tests above would still pass.
      const vp = await goodPresentation();
      expect(vp.endsWith('~')).toBe(true);

      const result = await verify(vp);

      expect(result.isValid).toBe(true);
      expect(result.checks.structure).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.credentials).toHaveLength(1);
    });

    it('names key binding in notChecked, so the verdict stays honest', async () => {
      const result = await verify(await goodPresentation());
      expect(result.notChecked.join(' ')).toMatch(/key binding/i);
    });
  });

  describe('the API refuses to be used as a weaker thing', () => {
    it('refuses a bare vc+sd-jwt passed as a presentation', async () => {
      // Without this, the most natural mistake — verifying a credential and
      // believing you verified a presentation — degrades this function into
      // exactly the disclosure-layer-only verifier it exists not to be. A bare
      // credential has no nonce, no aud and no holder signature.
      const result = await verify(disclosed);
      expect(result.isValid).toBe(false);
      expect(result.checks.structure).toBe(false);
      expect(result.errors.join(' ')).toMatch(/typ is 'vc\+sd-jwt', expected 'vp\+sd-jwt'/);
    });

    it('THROWS rather than returning a verdict when the challenge is missing', async () => {
      // A caller that forgot the challenge has a bug in its own code. Returning
      // `isValid: false` would let that bug look like a verification outcome;
      // returning `isValid: true` would be the fail-open catastrophe. Throwing
      // is the only honest third option.
      await expect(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        verifySdJwtPresentation({
          presentation: await goodPresentation(),
          audience: AUDIENCE,
          resolveVerificationKey: resolverFor(issuer, holder),
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } as any),
      ).rejects.toThrow(TypeError);
    });

    it('THROWS when the audience or the resolver is missing', async () => {
      const presentation = await goodPresentation();
      await expect(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        verifySdJwtPresentation({ presentation, challenge: CHALLENGE } as any),
      ).rejects.toThrow(/audience, resolveVerificationKey/);
    });

    it('THROWS on an empty algorithms allowlist rather than rejecting everything', async () => {
      await expect(
        verify(await goodPresentation(), { algorithms: [] }),
      ).rejects.toThrow(TypeError);
    });

    it('never reports isValid without every check being true', async () => {
      // The structural guarantee. If someone adds a check to the interface and
      // forgets to fold it into the verdict, this fails.
      const result = await verify(await goodPresentation());
      expect(result.isValid).toBe(Object.values(result.checks).every(Boolean));
      expect(Object.keys(result.checks).length).toBe(8);
    });
  });
});
