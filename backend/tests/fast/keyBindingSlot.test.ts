/**
 * THE KEY-BINDING SLOT — steno #290.
 *
 * WHAT THE DEFECT WAS. `assertDisclosuresResolve` read the compact SD-JWT as
 * `split('~').slice(1).filter(Boolean)`, which includes the FINAL segment. That
 * segment is not a disclosure: the wire format is
 * `<jws>~<d1>~…~<dn>~<kb-jwt>`, and the element after the last `~` is the
 * key-binding position, empty when there is no key binding. So a presentation
 * carrying a real KB-JWT had that KB-JWT hashed as if it were a disclosure,
 * matched nothing the issuer committed to, and was rejected as tampered. An
 * HONEST presentation, refused. Fail-closed, and unreachable today only because
 * Credo 0.6's `vp+sd-jwt` signer never attaches one — R5 Phase B's device-side
 * signing is what makes it reachable.
 *
 * WHAT THIS TIER CAN AND CANNOT ESTABLISH. Everything here is about STRING
 * SHAPE and digest arithmetic, which needs no chain: whether the trailing slot
 * is attributed to the right role, and whether the RFC 9807 §7.3 rejection
 * survived the change. The KB-JWTs are genuinely signed with a real Ed25519 key
 * over the real signing input with the real `sd_hash`, because a parser test
 * built on a fabricated artifact tests the fabrication. What is NOT here is
 * SIGNATURE verification of a KB-JWT — that resolves `cnf.kid` on the ledger and
 * lives in `tests/live/holderBinding.live.test.ts`.
 *
 * THE LOAD-BEARING TEST IN THIS FILE is 'an unmatched disclosure is STILL
 * rejected when a valid KB-JWT is present'. Making room for the key-binding
 * slot must not have been bought by relaxing §7.3, and that is the assertion
 * that says so.
 */
import { describe, it, expect } from 'vitest';
import {
  assertDisclosuresResolve,
  splitSdJwtCompact,
  parseKeyBindingJwt,
} from '../../src/services/sdJwtVc.js';
import {
  createSdJwtInstance,
  decodedDisclosures,
  injectDisclosure,
  replaceDisclosure,
  splitCompact,
  joinCompact,
  attachKeyBindingJwt,
  createHolderKeyPair,
  encodeDisclosure,
  SD_JWT_SEPARATOR,
} from './helpers/sdJwtFixture.js';

const HOLDER = 'did:cheqd:bdhealthtestnet:00000000-0000-4000-8000-000000000001';
const NONCE = 'nonce-fast-tier';
const AUDIENCE = 'https://pharmacy.bd-health.example';

const holderKey = createHolderKeyPair();

async function honestSdJwt(): Promise<string> {
  const sdJwt = await createSdJwtInstance();
  return sdJwt.issue(
    {
      credentialSubject: {
        id: HOLDER,
        hivStatus: 'negative',
        bloodType: 'O+',
        prescriber: { name: 'Dr Karim', licence: 'BMDC-4471' },
      },
    },
    { credentialSubject: { _sd: ['hivStatus', 'bloodType', 'prescriber'] } },
  );
}

function withKeyBinding(compact: string, overrides = {}): string {
  return attachKeyBindingJwt(compact, holderKey.privateKey, {
    nonce: NONCE,
    audience: AUDIENCE,
    ...overrides,
  });
}

describe('splitSdJwtCompact — position decides the role, not content', () => {
  it('puts the trailing empty slot in the key-binding position, not the disclosure list', async () => {
    // The premise the whole fix rests on, measured rather than assumed:
    // `@sd-jwt/core` always emits the trailing separator.
    const compact = await honestSdJwt();
    expect(compact.endsWith(SD_JWT_SEPARATOR)).toBe(true);

    const parts = splitSdJwtCompact(compact);
    expect(parts.keyBindingJwt).toBe('');
    expect(parts.disclosures).toHaveLength(decodedDisclosures(compact).length);
    expect(parts.disclosures.every((segment) => segment.length > 0)).toBe(true);
  });

  it('puts a KB-JWT in the key-binding position and leaves the disclosures alone', async () => {
    const compact = await honestSdJwt();
    const before = splitSdJwtCompact(compact);
    const after = splitSdJwtCompact(withKeyBinding(compact));

    expect(after.disclosures).toEqual(before.disclosures);
    expect(after.issuerJwt).toBe(before.issuerJwt);
    expect(after.keyBindingJwt.split('.')).toHaveLength(3);
  });

  it('reports no disclosures and no key binding for a bare JWT', () => {
    const parts = splitSdJwtCompact('a.b.c');
    expect(parts).toEqual({ issuerJwt: 'a.b.c', disclosures: [], keyBindingJwt: '' });
  });
});

describe('parseKeyBindingJwt — a KB-JWT is recognised by structure', () => {
  it('accepts a genuine one', async () => {
    const parsed = parseKeyBindingJwt(splitSdJwtCompact(withKeyBinding(await honestSdJwt())).keyBindingJwt);
    expect(parsed).not.toBeNull();
    expect(parsed!.header.typ).toBe('kb+jwt');
    expect(parsed!.payload.nonce).toBe(NONCE);
    expect(parsed!.signingInput.split('.')).toHaveLength(2);
  });

  it('refuses one whose typ is not kb+jwt', async () => {
    // Without the typ check, any three-segment JWT — including a whole second
    // credential — would be waved through the key-binding slot.
    const compact = withKeyBinding(await honestSdJwt(), { typ: 'JWT' });
    expect(parseKeyBindingJwt(splitSdJwtCompact(compact).keyBindingJwt)).toBeNull();
  });

  it('refuses alg: none', async () => {
    const compact = withKeyBinding(await honestSdJwt(), { alg: 'none' });
    expect(parseKeyBindingJwt(splitSdJwtCompact(compact).keyBindingJwt)).toBeNull();
  });

  it('refuses an encoded DISCLOSURE sitting in the key-binding slot', () => {
    // The attack the structural check exists for: a disclosure is base64url
    // JSON with no dots, so it can never be mistaken for a JWS.
    expect(parseKeyBindingJwt(encodeDisclosure(['salt', 'clearance', 'top-secret']))).toBeNull();
  });

  it('refuses a two-segment JWT and an empty signature', () => {
    expect(parseKeyBindingJwt('aGVhZGVy.cGF5bG9hZA')).toBeNull();
    expect(parseKeyBindingJwt('aGVhZGVy.cGF5bG9hZA.')).toBeNull();
  });
});

describe('assertDisclosuresResolve — the KB-JWT slot is not a disclosure', () => {
  it('ACCEPTS a presentation carrying a valid key-binding JWT', async () => {
    // The defect itself. Before the fix this returned two errors — 'not
    // decodable' and 'never committed to' — for an entirely honest artifact.
    const compact = await honestSdJwt();
    expect(assertDisclosuresResolve(withKeyBinding(compact))).toEqual([]);
  });

  it('still accepts a presentation with NO key-binding JWT, unchanged', async () => {
    const compact = await honestSdJwt();
    expect(assertDisclosuresResolve(compact)).toEqual([]);
  });

  it('accepts a KB-JWT on a SELECTIVELY DISCLOSED subset', async () => {
    const compact = await honestSdJwt();
    const parts = splitCompact(compact);
    const subset = joinCompact({ ...parts, disclosures: [parts.disclosures[0]!] });
    expect(assertDisclosuresResolve(withKeyBinding(subset))).toEqual([]);
  });

  it('REFUSES a trailing segment that is not a key-binding JWT', async () => {
    // An attacker appends a disclosure with no trailing `~`, so it lands in the
    // key-binding position. If the slot were merely "skipped", that append would
    // buy an exemption from §7.3. It does not.
    const compact = await honestSdJwt();
    const smuggled = `${compact}${encodeDisclosure(['ZZZZZZZZZZZZZZZZ', 'clearance', 'top-secret'])}`;

    const errors = assertDisclosuresResolve(smuggled);
    expect(errors).toEqual([
      'Presentation carries a trailing segment that is neither absent nor a key-binding JWT',
    ]);
  });

  it('REFUSES a malformed key-binding JWT rather than ignoring it', async () => {
    const compact = await honestSdJwt();
    for (const broken of [
      `${compact}not-a-jwt-at-all`,
      `${compact}only.two`,
      withKeyBinding(compact, { typ: 'JWT' }),
      withKeyBinding(compact, { alg: 'none' }),
    ]) {
      expect(assertDisclosuresResolve(broken).length).toBeGreaterThan(0);
    }
  });
});

describe('RFC 9807 §7.3 was not loosened to make room for the KB-JWT', () => {
  it('REJECTS an injected disclosure even when a valid KB-JWT is present', async () => {
    // THE test this change has to pass. Key-binding support must cost nothing
    // in disclosure integrity.
    const compact = await honestSdJwt();
    const injected = injectDisclosure(compact, ['ZZZZZZZZZZZZZZZZ', 'clearance', 'top-secret']);
    const errors = assertDisclosuresResolve(withKeyBinding(injected));

    expect(errors).toContain(
      'Presentation carries a disclosure the issuer never committed to — it has been tampered with or injected',
    );
  });

  it('REJECTS a tampered disclosure even when a valid KB-JWT is present', async () => {
    const compact = await honestSdJwt();
    const index = decodedDisclosures(compact).findIndex((d) => d[1] === 'hivStatus');
    const salt = decodedDisclosures(compact)[index]![0];
    const tampered = replaceDisclosure(compact, index, [salt, 'hivStatus', 'positive']);

    expect(assertDisclosuresResolve(withKeyBinding(tampered)).length).toBeGreaterThan(0);
  });

  it('reports one error per tampered disclosure, KB-JWT or not', async () => {
    // The KB-JWT must not inflate or deflate the count — that count is how an
    // operator learns how much of the presentation was touched.
    const compact = await honestSdJwt();
    const decoded = decodedDisclosures(compact);
    const hiv = decoded.findIndex((d) => d[1] === 'hivStatus');
    const blood = decoded.findIndex((d) => d[1] === 'bloodType');

    let tampered = replaceDisclosure(compact, hiv, [decoded[hiv]![0], 'hivStatus', 'positive']);
    tampered = replaceDisclosure(tampered, blood, [decoded[blood]![0], 'bloodType', 'AB-']);

    expect(assertDisclosuresResolve(tampered)).toHaveLength(2);
    expect(assertDisclosuresResolve(withKeyBinding(tampered))).toHaveLength(2);
  });
});
