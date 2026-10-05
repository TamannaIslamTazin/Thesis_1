/**
 * NEGATIVE CONTROL 4 — KEY-BINDING JWTs (HOLE 4, and the steno #290 defect).
 *
 * ---------------------------------------------------------------------------
 * TWO SEPARATE FAULTS, ONE ARTIFACT
 * ---------------------------------------------------------------------------
 * OURS (steno #290). `assertDisclosuresResolve` split the compact SD-JWT as
 * `slice(1).filter(Boolean)`, which swept the FINAL segment in with the
 * disclosures. That segment is the key-binding position, not a disclosure. So a
 * presentation carrying a real KB-JWT had it hashed as a disclosure, matched
 * nothing the issuer committed to, and was REJECTED — an honest presentation
 * refused. Fail-closed, and reachable the moment a wallet outside Credo 0.6
 * signs one. R5 Phase B moves signing to the device, which is what produces
 * KB-JWTs.
 *
 * CREDO'S (HOLE 4). Credo reaches `@sd-jwt/core`'s `verify(encoded, options)`,
 * which returns BEFORE looking at the key binding unless `keyBindingNonce` is
 * passed — and Credo never passes it, in `verifyCredential` or in
 * `verifyPresentation`. Credo does construct a `kbVerifier`; it is simply never
 * invoked. So a KB-JWT with a wrong signature, a wrong `sd_hash`, a stale nonce
 * or somebody else's audience verifies exactly as if it were absent. That is
 * worse than the parse failure: it reads as a second factor and is not one.
 *
 * Fixing only ours would have produced precisely that — a KB-JWT that sails
 * past the disclosure check and is never verified by anything. So the boundary
 * verifies it.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS TIER
 * ---------------------------------------------------------------------------
 * `tests/fast/keyBindingSlot.test.ts` covers the parsing and the §7.3
 * arithmetic, which need no chain. What is here is the half that does: a KB-JWT
 * signed by a REAL key in the wallet, verified against a `cnf` resolved from
 * OUR ledger, plus the BEFORE assertions that show Credo accepts each attack.
 * Stub any of that and the BEFORE half becomes a statement about the stub.
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
  splitSdJwtCompact,
} from '../../src/services/sdJwtVc.js';
import {
  ISSUER,
  HOLDER,
  ATTACKER,
  VERIFIER_DOMAIN,
  CLAIMS,
  buildRawCredential,
  attachKeyBindingJwt,
} from './helpers/liveSdJwt.js';

let agent: Agent;
/** The holder's disclosed credential, before any key binding is attached. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let disclosed: any;

beforeAll(async () => {
  agent = await createAgent();

  const signed = await signSdJwtCredential(agent, {
    credential: buildRawCredential(),
    verificationMethod: `${ISSUER}#key-1`,
    holder: { method: 'did', didUrl: `${HOLDER}#key-1` },
    disclosureFrame: buildDisclosureFrame({ id: HOLDER, ...CLAIMS }),
  });

  disclosed = await presentSdJwtCredential(agent, signed, {
    credentialSubject: { hivStatus: true, medications: { 1: true } },
  });
});

afterAll(async () => {
  await shutdownAgent();
});

/** The `sd_hash` a KB-JWT claims to cover. */
function sdHashOf(compact: string): string {
  const payload = splitSdJwtCompact(compact).keyBindingJwt.split('.')[1]!;
  return (JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { sd_hash: string })
    .sd_hash;
}

/**
 * Present a credential that carries `kbCompact`'s key binding.
 *
 * The KB-JWT rides on the CREDENTIAL, which is where SD-JWT VC puts it and
 * where R5 Phase B's device-signed binding will land.
 */
async function presentWithKeyBinding(
  kbCompact: string,
  challenge: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<any> {
  return signSdJwtPresentation(agent, {
    holderDid: HOLDER,
    credential: toV2SdJwtVerifiableCredential(kbCompact)!,
    challenge,
    domain: VERIFIER_DOMAIN,
  });
}

describe('the premise: a KB-JWT survives Credo end to end', () => {
  it('Credo PARSES a compact SD-JWT carrying a key-binding JWT and round-trips it', async () => {
    // If Credo refused to read one, the defect would be unreachable by
    // construction and this whole file would be theatre. It does not refuse.
    const nonce = randomUUID();
    const withKb = await attachKeyBindingJwt(agent, disclosed.encoded, HOLDER, {
      nonce,
      audience: VERIFIER_DOMAIN,
    });

    const parsed = toV2SdJwtVerifiableCredential(withKb);
    expect(parsed).not.toBeNull();
    expect(parsed!.encoded).toBe(withKb);
    expect(splitSdJwtCompact(parsed!.encoded).keyBindingJwt.split('.')).toHaveLength(3);
    expect(splitSdJwtCompact(disclosed.encoded).keyBindingJwt).toBe('');
  });
});

describe('THE #290 FIX — an honest presentation carrying a KB-JWT is ACCEPTED', () => {
  it('verifies with every check green, key binding included', async () => {
    // Before the fix this was rejected on `disclosureIntegrity` with 'carries a
    // disclosure the issuer never committed to' — an honest holder refused.
    const nonce = randomUUID();
    const withKb = await attachKeyBindingJwt(agent, disclosed.encoded, HOLDER, {
      nonce,
      audience: VERIFIER_DOMAIN,
    });

    const result = await verifySdJwtPresentation(agent, {
      presentation: await presentWithKeyBinding(withKb, nonce),
      challenge: nonce,
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
      keyBinding: true,
    });
    expect(result.credentials.length).toBeGreaterThan(0);
  });

  it('a presentation with NO key binding still works exactly as before', async () => {
    // The regression guard on the other side. A fix that accepted KB-JWTs by
    // breaking the ordinary path would be no fix.
    const nonce = randomUUID();
    const result = await verifySdJwtPresentation(agent, {
      presentation: await signSdJwtPresentation(agent, {
        holderDid: HOLDER,
        credential: disclosed,
        challenge: nonce,
        domain: VERIFIER_DOMAIN,
      }),
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.errors).toEqual([]);
    expect(result.isValid).toBe(true);
    expect(result.checks.keyBinding).toBe(true);
  });
});

describe('HOLE 4 — Credo parses a KB-JWT and never verifies it', () => {
  it('BEFORE: unmodified Credo accepts a KB-JWT signed by the WRONG KEY', async () => {
    // The attacker's own real Ed25519 signature over a credential bound to the
    // holder. Credo says yes, because it never asks.
    const nonce = randomUUID();
    const forged = await attachKeyBindingJwt(agent, disclosed.encoded, ATTACKER, {
      nonce,
      audience: VERIFIER_DOMAIN,
    });

    const credo = await agent.w3cV2Credentials.verifyPresentation({
      presentation: W3cV2SdJwtVerifiablePresentation.fromCompact(
        (await presentWithKeyBinding(forged, nonce)).encoded,
      ),
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });
    expect(credo.isValid).toBe(true);
  });

  it('AFTER: rejected on keyBinding ALONE — every other check still green', async () => {
    const nonce = randomUUID();
    const forged = await attachKeyBindingJwt(agent, disclosed.encoded, ATTACKER, {
      nonce,
      audience: VERIFIER_DOMAIN,
    });

    const result = await verifySdJwtPresentation(agent, {
      presentation: await presentWithKeyBinding(forged, nonce),
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks).toEqual({
      signatures: true,
      disclosureIntegrity: true,
      challenge: true,
      domain: true,
      holderBinding: true,
      keyBinding: false,
    });
    expect(result.credentials).toEqual([]);
    expect(result.errors.some((e) => e.includes(`${HOLDER}#key-1`))).toBe(true);
  });

  it('AFTER: a KB-JWT LIFTED from another artifact is refused on sd_hash', async () => {
    // The reason `sd_hash` exists. Take a genuine KB-JWT the holder signed for
    // presentation A and staple it onto presentation B: same key, same nonce,
    // same audience, wrong artifact.
    const nonce = randomUUID();
    const other = await presentSdJwtCredential(agent, disclosed, {
      credentialSubject: { hivStatus: true },
    });
    const otherSdHash = sdHashOf(
      await attachKeyBindingJwt(agent, other.encoded, HOLDER, {
        nonce,
        audience: VERIFIER_DOMAIN,
      }),
    );
    expect(otherSdHash).not.toBe(sdHashOf(await attachKeyBindingJwt(agent, disclosed.encoded, HOLDER, {
      nonce,
      audience: VERIFIER_DOMAIN,
    })));

    const lifted = await attachKeyBindingJwt(agent, disclosed.encoded, HOLDER, {
      nonce,
      audience: VERIFIER_DOMAIN,
      sdHash: otherSdHash,
    });

    const result = await verifySdJwtPresentation(agent, {
      presentation: await presentWithKeyBinding(lifted, nonce),
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.keyBinding).toBe(false);
    expect(result.checks.signatures).toBe(true);
    expect(result.errors.some((e) => e.includes('does not cover the artifact'))).toBe(true);
  });

  it('AFTER: a KB-JWT minted for a STALE NONCE is refused', async () => {
    const nonce = randomUUID();
    const stale = await attachKeyBindingJwt(agent, disclosed.encoded, HOLDER, {
      nonce: randomUUID(),
      audience: VERIFIER_DOMAIN,
    });

    const result = await verifySdJwtPresentation(agent, {
      presentation: await presentWithKeyBinding(stale, nonce),
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.keyBinding).toBe(false);
    // The VP's own nonce is correct; only the key binding replays.
    expect(result.checks.challenge).toBe(true);
  });

  it('AFTER: a KB-JWT addressed to ANOTHER VERIFIER is refused', async () => {
    const nonce = randomUUID();
    const elsewhere = await attachKeyBindingJwt(agent, disclosed.encoded, HOLDER, {
      nonce,
      audience: 'https://attacker.example',
    });

    const result = await verifySdJwtPresentation(agent, {
      presentation: await presentWithKeyBinding(elsewhere, nonce),
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.keyBinding).toBe(false);
    expect(result.checks.domain).toBe(true);
  });

  it('AFTER: a verifier that named no domain REFUSES a key binding rather than skipping the audience check', async () => {
    // Fail closed. `domain` is optional elsewhere because a verifier may decline
    // to name itself — but a holder who minted a possession proof named an
    // audience on purpose, and not reading it re-opens cross-verifier replay.
    const nonce = randomUUID();
    const withKb = await attachKeyBindingJwt(agent, disclosed.encoded, HOLDER, {
      nonce,
      audience: VERIFIER_DOMAIN,
    });

    const result = await verifySdJwtPresentation(agent, {
      presentation: await presentWithKeyBinding(withKb, nonce),
      challenge: nonce,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.keyBinding).toBe(false);
    expect(result.checks.domain).toBe(true);
    expect(result.errors.some((e) => e.includes('stated no domain'))).toBe(true);
  });

  it("Credo's own parser refuses a trailing segment that is not a JWT at all", async () => {
    // Measured, and it bounds the attack rather than removing the need for our
    // check. An attacker who appends a raw disclosure with no trailing `~`
    // lands it in the key-binding position, and `KBJwt.fromKBEncode` cannot
    // decode it — so that particular compact never becomes a Credo credential.
    // Our structural gate still has to exist: `verifySdJwtPresentation` accepts
    // a compact STRING, and a non-Credo wallet is exactly the reason this defect
    // stops being theoretical. The gate itself is asserted directly against
    // `assertDisclosuresResolve` in `tests/fast/keyBindingSlot.test.ts`.
    const smuggled = `${disclosed.encoded}${Buffer.from(
      JSON.stringify(['aaaaaaaaaaaaaaaa', 'clearanceLevel', 'top-secret']),
    ).toString('base64url')}`;

    expect(toV2SdJwtVerifiableCredential(smuggled)).toBeNull();
  });

  it('AFTER: a trailing JWT that is NOT a kb+jwt is refused, not skipped', async () => {
    // The reachable version of the same attack: three segments, so Credo parses
    // it happily, but `typ` is not `kb+jwt`. If the key-binding slot were merely
    // excused from the disclosure check, anything JWT-shaped could ride along
    // unexamined.
    const nonce = randomUUID();
    const notAKb = await attachKeyBindingJwt(agent, disclosed.encoded, HOLDER, {
      nonce,
      audience: VERIFIER_DOMAIN,
      typ: 'JWT',
    });
    expect(toV2SdJwtVerifiableCredential(notAKb)).not.toBeNull();

    const result = await verifySdJwtPresentation(agent, {
      presentation: await presentWithKeyBinding(notAKb, nonce),
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.disclosureIntegrity).toBe(false);
    expect(result.checks.keyBinding).toBe(false);
    expect(result.credentials).toEqual([]);
  });
});

describe('§7.3 survived the change', () => {
  it('an INJECTED disclosure is still rejected when a valid KB-JWT is present', async () => {
    // The assertion that says key-binding support was not bought by loosening
    // the unmatched-disclosure check.
    const nonce = randomUUID();
    const injected = `${disclosed.encoded}${Buffer.from(
      JSON.stringify(['aaaaaaaaaaaaaaaa', 'clearanceLevel', 'top-secret']),
    ).toString('base64url')}~`;
    const withKb = await attachKeyBindingJwt(agent, injected, HOLDER, {
      nonce,
      audience: VERIFIER_DOMAIN,
    });

    const result = await verifySdJwtPresentation(agent, {
      presentation: await presentWithKeyBinding(withKb, nonce),
      challenge: nonce,
      domain: VERIFIER_DOMAIN,
    });

    expect(result.isValid).toBe(false);
    expect(result.checks.disclosureIntegrity).toBe(false);
    // ATTRIBUTION: the key binding itself was genuine. Only §7.3 objected.
    expect(result.checks.keyBinding).toBe(true);
    expect(
      result.errors.some((e) => e.includes('the issuer never committed to')),
    ).toBe(true);
    expect(JSON.stringify(result.credentials)).not.toContain('top-secret');
  });
});
