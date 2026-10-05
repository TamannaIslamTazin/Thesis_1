/**
 * THE THREE SD-JWT NEGATIVE CONTROLS — replay, theft, tampering.
 *
 * These are the three holes in Credo 0.6 that this project closes in its own
 * code (`src/services/sdJwtVc.ts`). Each one returns `isValid: true` on
 * unmodified Credo. If our compensations silently regress — a refactor, a
 * dependency bump, a well-meaning simplification — the system goes back to
 * accepting replayed, stolen and tampered presentations, and NOTHING ELSE IN
 * THE REPO WOULD NOTICE. That is what this file is for.
 *
 * ---------------------------------------------------------------------------
 * THE SHAPE OF EVERY TEST HERE, AND WHY IT IS NOT NEGOTIABLE
 * ---------------------------------------------------------------------------
 * Each control asserts THREE things, in this order:
 *
 *   BEFORE      unmodified Credo ACCEPTS the attack. Without this, a test that
 *               "passes" may be passing because the attack was never viable —
 *               and would keep passing after our check was deleted.
 *   AFTER       our boundary REJECTS it.
 *   ATTRIBUTION the NAMED check is false and THE OTHERS ARE STILL TRUE.
 *
 * The attribution assertion is the one that carries the weight. `isValid:false`
 * on its own is compatible with the presentation having failed for an unrelated
 * reason — an expired credential, an unreachable resolver, a typo in a DID.
 * Pinning `checks.challenge === false` while `checks.signatures === true`
 * proves the rejection came from the specific control under test.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE CANNOT BE MOVED TO THE FAST TIER
 * ---------------------------------------------------------------------------
 * The BEFORE half is the reason. Demonstrating that Credo accepts the attack
 * requires Credo to genuinely verify real Ed25519 signatures over real DID
 * documents resolved from our chain. Stub any of that and the BEFORE assertion
 * becomes a statement about the stub. The detection logic that CAN be isolated
 * — digest matching — is already covered in `tests/fast/disclosureIntegrity.test.ts`;
 * what is left here is exactly the part that needs the live stack.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import { W3cV2SdJwtVerifiablePresentation, type Agent } from '@credo-ts/core';
import { buildDisclosureFrame } from '@ssi-healthcare/shared';
import { createAgent, shutdownAgent } from '../../src/agent/index.js';
import {
  signSdJwtCredential,
  presentSdJwtCredential,
  signSdJwtPresentation,
  verifySdJwtPresentation,
  toV2SdJwtVerifiableCredential,
} from '../../src/services/sdJwtVc.js';
import {
  ISSUER,
  HOLDER,
  ATTACKER,
  VERIFIER_DOMAIN,
  CLAIMS,
  buildRawCredential,
  forgePresentation,
  presentationOf,
  tamperDisclosure,
} from './helpers/liveSdJwt.js';

let agent: Agent;

/** A credential issued under the SHIPPED policy, disclosed to a strict subset. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let disclosed: any;
let honestNonce: string;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let honestVp: any;

beforeAll(async () => {
  agent = await createAgent();

  const signed = await signSdJwtCredential(agent, {
    credential: buildRawCredential(),
    verificationMethod: `${ISSUER}#key-1`,
    holder: { method: 'did', didUrl: `${HOLDER}#key-1` },
    disclosureFrame: buildDisclosureFrame({ id: HOLDER, ...CLAIMS }),
  });

  // The holder reveals only their HIV status and one of three medications.
  disclosed = await presentSdJwtCredential(agent, signed, {
    credentialSubject: { hivStatus: true, medications: { 1: true } },
  });

  honestNonce = randomUUID();
  honestVp = await signSdJwtPresentation(agent, {
    holderDid: HOLDER,
    credential: disclosed,
    challenge: honestNonce,
    domain: VERIFIER_DOMAIN,
  });
});

afterAll(async () => {
  await shutdownAgent();
});

describe('the honest baseline', () => {
  it('a genuine presentation verifies with EVERY check green', async () => {
    // The control for the controls. If this fails, every rejection below is
    // uninterpretable — they might all be failing for the same unrelated
    // reason rather than for the attack each one models.
    const result = await verifySdJwtPresentation(agent, {
      presentation: honestVp,
      challenge: honestNonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.errors).toEqual([]);
    expect(result.isValid).toBe(true);
    expect(result.checks).toEqual({
      signatures: true,
      disclosureIntegrity: true,
      challenge: true,
      domain: true,
      holderBinding: true,
      // Credo 0.6's `vp+sd-jwt` attaches no KB-JWT, so there is none to check.
      // NEGATIVE CONTROL 4 covers the case where one IS attached.
      keyBinding: true,
    });
    expect(result.credentials.length).toBeGreaterThan(0);
  });
});

describe('NEGATIVE CONTROL 1 — REPLAY (HOLE 1)', () => {
  it('BEFORE: unmodified Credo accepts a VP replayed against a different nonce', async () => {
    // Credo's `verifyPresentation` accepts a `challenge` option and never reads
    // it. This asserts the hole is still open upstream; if it ever closes, this
    // test fails and the compensating code's justification must be re-read.
    const credo = await agent.w3cV2Credentials.verifyPresentation({
      presentation: W3cV2SdJwtVerifiablePresentation.fromCompact(honestVp.encoded),
      challenge: randomUUID(),
      domain: VERIFIER_DOMAIN,
    });
    expect(credo.isValid).toBe(true);
  });

  it('AFTER: our boundary rejects it, on the CHALLENGE, with signatures still green', async () => {
    const result = await verifySdJwtPresentation(agent, {
      presentation: honestVp.encoded,
      challenge: randomUUID(),
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.challenge).toBe(false);
    // ATTRIBUTION: the signature was fine. Only the binding failed.
    expect(result.checks.signatures).toBe(true);
    expect(result.checks.holderBinding).toBe(true);
    expect(result.checks.disclosureIntegrity).toBe(true);
    // No claims are handed back from a failed verification, so a caller cannot
    // accidentally act on unauthenticated data.
    expect(result.credentials).toEqual([]);
  });

  it('BEFORE: unmodified Credo accepts a VP addressed to a different verifier', async () => {
    const credo = await agent.w3cV2Credentials.verifyPresentation({
      presentation: W3cV2SdJwtVerifiablePresentation.fromCompact(honestVp.encoded),
      challenge: honestNonce,
      domain: 'https://attacker.example',
    });
    expect(credo.isValid).toBe(true);
  });

  it('AFTER: our boundary rejects it, on the DOMAIN', async () => {
    // The hospital-A presentation replayed at pharmacy-B.
    const result = await verifySdJwtPresentation(agent, {
      presentation: honestVp.encoded,
      challenge: honestNonce,
      domain: 'https://attacker.example',
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.domain).toBe(false);
    expect(result.checks.signatures).toBe(true);
    expect(result.checks.challenge).toBe(true);
  });

  it('a VP carrying NO nonce FAILS CLOSED rather than skipping the check', async () => {
    // "There was nothing to check" is the shape every fail-open bug in this
    // codebase has taken.
    const noNonce = await forgePresentation(
      agent,
      presentationOf(HOLDER, disclosed),
      HOLDER,
      '',
      VERIFIER_DOMAIN,
    );

    const result = await verifySdJwtPresentation(agent, {
      presentation: noNonce,
      challenge: randomUUID(),
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.challenge).toBe(false);
  });
});

describe('NEGATIVE CONTROL 2 — THEFT (HOLE 2)', () => {
  /**
   * THIS CONTROL NEEDS CARE TO BE WORTH ANYTHING.
   *
   * Under the SHIPPED policy `credentialSubject.id` stays in cleartext, so
   * Credo's own `credentialSubjectAuthentication` also catches the theft. A
   * test written that way passes while proving nothing about OUR check — it
   * would keep passing with our check deleted.
   *
   * So the credential below is reissued under a deliberately UNSAFE policy that
   * makes `id` disclosable, and the attacker withholds it. Credo's check then
   * short-circuits on an empty `credentialSubjectIds` and ACCEPTS the theft,
   * leaving our unconditional `cnf`-to-signer comparison as the only thing
   * standing in the way.
   */
  const UNSAFE_POLICY = { alwaysDisclosed: [] as string[], maxDepth: 12 };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let unsafeDisclosed: any;
  let stolenCompact: string;
  let theftNonce: string;

  beforeAll(async () => {
    const unsafeFrame = buildDisclosureFrame({ id: HOLDER, ...CLAIMS }, UNSAFE_POLICY)!;
    const unsafeSigned = await signSdJwtCredential(agent, {
      credential: buildRawCredential(),
      verificationMethod: `${ISSUER}#key-1`,
      holder: { method: 'did', didUrl: `${HOLDER}#key-1` },
      disclosureFrame: unsafeFrame,
    });

    // `id` deliberately withheld.
    unsafeDisclosed = await presentSdJwtCredential(agent, unsafeSigned, {
      credentialSubject: { hivStatus: true },
    });

    theftNonce = randomUUID();
    stolenCompact = await forgePresentation(
      agent,
      presentationOf(ATTACKER, unsafeDisclosed),
      ATTACKER,
      theftNonce,
      VERIFIER_DOMAIN,
    );
  });

  it('the unsafe policy really does make credentialSubject.id disclosable', () => {
    const frame = buildDisclosureFrame({ id: HOLDER, ...CLAIMS }, UNSAFE_POLICY)!;
    expect((frame.credentialSubject as { _sd: string[] })._sd).toContain('id');
  });

  it('the attacker really did withhold the subject id', () => {
    const subject = unsafeDisclosed.sdJwt.prettyClaims.credentialSubject as Record<string, unknown>;
    expect('id' in subject).toBe(false);
  });

  it('BEFORE: unmodified Credo ACCEPTS the stolen credential outright', async () => {
    // The whole hole in one assertion: a captured credential, wrapped in a
    // presentation under the attacker's own DID and signed with the attacker's
    // own key, and Credo says yes.
    const credo = await agent.w3cV2Credentials.verifyPresentation({
      presentation: W3cV2SdJwtVerifiablePresentation.fromCompact(stolenCompact),
      challenge: theftNonce,
      domain: VERIFIER_DOMAIN,
    });
    expect(credo.isValid).toBe(true);
  });

  it('AFTER: caught by holderBinding ALONE — every other check passed', async () => {
    const result = await verifySdJwtPresentation(agent, {
      presentation: stolenCompact,
      challenge: theftNonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    // The attribution that makes this test mean something: our binding check is
    // the ONLY thing that objected.
    expect(result.checks).toEqual({
      signatures: true,
      disclosureIntegrity: true,
      challenge: true,
      domain: true,
      holderBinding: false,
      keyBinding: true,
    });
    expect(result.credentials).toEqual([]);
  });

  it('AFTER: the error names both DIDs, so an operator can see who did what', async () => {
    const result = await verifySdJwtPresentation(agent, {
      presentation: stolenCompact,
      challenge: theftNonce,
      domain: VERIFIER_DOMAIN,
    });
    expect(result.errors.some((e) => e.includes(ATTACKER) && e.includes(HOLDER))).toBe(true);
  });

  it('the binding check does NOT reject the genuine holder of the same credential', async () => {
    // A control that rejects everything is not a control. This is what stops
    // someone "fixing" a failure here by tightening the check into uselessness.
    const nonce = randomUUID();
    const vp = await signSdJwtPresentation(agent, {
      holderDid: HOLDER,
      credential: unsafeDisclosed,
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    const result = await verifySdJwtPresentation(agent, {
      presentation: vp,
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.errors).toEqual([]);
    expect(result.isValid).toBe(true);
    expect(result.checks.holderBinding).toBe(true);
  });
});

describe('NEGATIVE CONTROL 3 — UNMATCHED DISCLOSURE (HOLE 3)', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let tamperedVp: any;
  let tamperedNonce: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let tamperedClaims: Record<string, unknown>;

  beforeAll(async () => {
    // Flip a negative HIV result to positive. The digest stops matching, so the
    // claim is DROPPED rather than forged — and Credo reports success anyway.
    const tamperedCompact = tamperDisclosure(
      disclosed.encoded,
      (d) => d.length === 3 && d[1] === 'hivStatus',
      (d) => [d[0], d[1], 'positive'],
    );

    const tamperedCred = toV2SdJwtVerifiableCredential(tamperedCompact)!;
    tamperedClaims = tamperedCred.sdJwt.prettyClaims.credentialSubject as Record<string, unknown>;

    tamperedNonce = randomUUID();
    tamperedVp = await signSdJwtPresentation(agent, {
      holderDid: HOLDER,
      credential: tamperedCred,
      challenge: tamperedNonce,
      domain: VERIFIER_DOMAIN,
    });
  });

  it('the forged value is never reachable — the claim VANISHES instead', () => {
    // Establishes what the attack actually achieves. It is claim DELETION, not
    // claim forgery, which is why it is easy to under-rate and easy to miss.
    expect(tamperedClaims.hivStatus).not.toBe('positive');
    expect('hivStatus' in tamperedClaims).toBe(false);
  });

  it('BEFORE: unmodified Credo ACCEPTS a presentation whose claim silently vanished', async () => {
    // A verifier that asked for `hivStatus` gets `isValid: true` and no
    // `hivStatus`. Any verifier logic treating an absent claim as a default is
    // now attacker-controlled.
    const credo = await agent.w3cV2Credentials.verifyPresentation({
      presentation: W3cV2SdJwtVerifiablePresentation.fromCompact(tamperedVp.encoded),
      challenge: tamperedNonce,
      domain: VERIFIER_DOMAIN,
    });
    expect(credo.isValid).toBe(true);
  });

  it('AFTER: rejected on disclosureIntegrity, with the other checks still green', async () => {
    const result = await verifySdJwtPresentation(agent, {
      presentation: tamperedVp,
      challenge: tamperedNonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.disclosureIntegrity).toBe(false);
    // ATTRIBUTION: nothing else objected.
    expect(result.checks.signatures).toBe(true);
    expect(result.checks.challenge).toBe(true);
    expect(result.checks.domain).toBe(true);
    expect(result.checks.holderBinding).toBe(true);
    expect(JSON.stringify(result.credentials)).not.toContain('positive');
  });

  it('AFTER: an INJECTED extra disclosure is refused too', async () => {
    const injected = `${disclosed.encoded}${Buffer.from(
      JSON.stringify(['aaaaaaaaaaaaaaaa', 'clearanceLevel', 'top-secret']),
    ).toString('base64url')}~`;

    const nonce = randomUUID();
    const vp = await signSdJwtPresentation(agent, {
      holderDid: HOLDER,
      credential: toV2SdJwtVerifiableCredential(injected)!,
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    const result = await verifySdJwtPresentation(agent, {
      presentation: vp,
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.disclosureIntegrity).toBe(false);
  });
});
