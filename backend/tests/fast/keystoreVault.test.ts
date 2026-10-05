/**
 * The keystore vault (AUTH-AND-KEYSTORE-API.md §2-4) — handle format, HMAC
 * derivation, the store's create/replace/conflict outcomes (against an
 * in-memory fake of `KeystoreEnvelopeStore`), the envelope shape guard, and
 * the timing-floor helper.
 *
 * NOT COVERED HERE: the real Prisma-backed store (`prismaKeystoreEnvelopeStore`)
 * and the HTTP route's rate limiting, which need a live Postgres and a running
 * server respectively — see the round report for what was and was not run.
 */
import { describe, it, expect } from 'vitest';

import {
  assertE164Handle,
  handleHmac,
  ownerTag,
  passphraseEnvelopeShape,
  withTimingFloor,
  type KeystoreEnvelopeStore,
  type KeystoreEnvelopeRecord,
  type ValidatedPassphraseEnvelope,
  type PutOutcome,
} from '../../src/services/keystoreVault.js';
import { AppError } from '../../src/middleware/errorHandler.js';

const SAMPLE_ENVELOPE: ValidatedPassphraseEnvelope = {
  version: 1,
  kdf: { name: 'scrypt', N: 2 ** 15, r: 8, p: 1, dkLen: 32, salt: 'AAAAAAAAAAAAAAAAAAAAAA' },
  envelope: { version: 1, salt: 'AAAAAAAAAAAAAAAAAAAAAA', nonce: 'BBBBBBBBBBBBBBBB', ciphertext: 'Y2lwaGVydGV4dA' },
};

function createInMemoryStore(): KeystoreEnvelopeStore & {
  readonly rows: Map<string, KeystoreEnvelopeRecord>;
} {
  const rows = new Map<string, KeystoreEnvelopeRecord>();
  return {
    rows,
    async find(handleHmacValue) {
      return rows.get(handleHmacValue) ?? null;
    },
    async put({ handleHmac: handleHmacValue, ownerTag: ownerTagValue, envelope }): Promise<PutOutcome> {
      const existing = rows.get(handleHmacValue);
      if (!existing) {
        rows.set(handleHmacValue, { ownerTag: ownerTagValue, envelope });
        return 'created';
      }
      if (existing.ownerTag !== ownerTagValue) return 'conflict';
      rows.set(handleHmacValue, { ownerTag: ownerTagValue, envelope });
      return 'replaced';
    },
  };
}

describe('assertE164Handle — refuses anything that is not E.164, rather than guessing a normalisation', () => {
  const malformedHandles: ReadonlyArray<readonly [string, unknown]> = [
    ['a bare national number', '01711000000'],
    ['spaces', '+880 1711 000000'],
    ['a hyphenated number', '+880-1711-000000'],
    ['no leading +', '8801711000000'],
    ['empty string', ''],
    ['not a string at all', 12345],
  ];

  it.each(malformedHandles)('refuses %s', (_label, input) => {
    expect(() => assertE164Handle(input)).toThrow(AppError);
  });

  it('accepts a well-formed E.164 number', () => {
    expect(assertE164Handle('+8801711000000')).toBe('+8801711000000');
  });
});

describe('handleHmac / ownerTag — deterministic, and derived under separate peppers', () => {
  it('the same handle always HMACs to the same value', () => {
    expect(handleHmac('+8801711000000')).toBe(handleHmac('+8801711000000'));
  });

  it('different handles HMAC to different values', () => {
    expect(handleHmac('+8801711000000')).not.toBe(handleHmac('+8801711000001'));
  });

  it('handleHmac and ownerTag of the same underlying string differ (different peppers, different domains)', () => {
    // Not a security proof on its own — just confirms the two derivations are
    // not accidentally the same function under two names.
    expect(handleHmac('same-value')).not.toBe(ownerTag('same-value'));
  });
});

describe('putEnvelope semantics — store once, replace by the same owner, refuse a different owner', () => {
  const handle = handleHmac('+8801711000000');
  const ownerA = ownerTag('user-a');
  const ownerB = ownerTag('user-b');

  it('a first PUT creates the slot', async () => {
    const store = createInMemoryStore();
    const outcome = await store.put({ handleHmac: handle, ownerTag: ownerA, envelope: SAMPLE_ENVELOPE });
    expect(outcome).toBe('created');
    expect(store.rows.get(handle)?.ownerTag).toBe(ownerA);
  });

  it('the SAME owner may replace their own slot', async () => {
    const store = createInMemoryStore();
    await store.put({ handleHmac: handle, ownerTag: ownerA, envelope: SAMPLE_ENVELOPE });
    const replaced: ValidatedPassphraseEnvelope = { ...SAMPLE_ENVELOPE, kdf: { ...SAMPLE_ENVELOPE.kdf, salt: 'different-salt-value-2' } };
    const outcome = await store.put({ handleHmac: handle, ownerTag: ownerA, envelope: replaced });
    expect(outcome).toBe('replaced');
    expect(store.rows.get(handle)?.envelope.kdf.salt).toBe('different-salt-value-2');
  });

  it('a DIFFERENT owner is refused, not merged — the existing envelope is left untouched', async () => {
    // Verified by hand that this goes red if the store's ownerTag check is
    // removed (the fake would then report 'replaced' and overwrite ownerA's
    // row) — see the round report.
    const store = createInMemoryStore();
    await store.put({ handleHmac: handle, ownerTag: ownerA, envelope: SAMPLE_ENVELOPE });
    const attackerEnvelope: ValidatedPassphraseEnvelope = {
      ...SAMPLE_ENVELOPE,
      kdf: { ...SAMPLE_ENVELOPE.kdf, salt: 'attacker-supplied-salt' },
    };
    const outcome = await store.put({ handleHmac: handle, ownerTag: ownerB, envelope: attackerEnvelope });
    expect(outcome).toBe('conflict');
    expect(store.rows.get(handle)?.ownerTag).toBe(ownerA);
    expect(store.rows.get(handle)?.envelope.kdf.salt).toBe(SAMPLE_ENVELOPE.kdf.salt);
  });
});

describe('passphraseEnvelopeShape — validates structure, never opens the envelope', () => {
  it('accepts a well-formed envelope', () => {
    expect(passphraseEnvelopeShape.safeParse(SAMPLE_ENVELOPE).success).toBe(true);
  });

  const malformedCases: ReadonlyArray<readonly [string, unknown]> = [
    ['wrong version', { ...SAMPLE_ENVELOPE, version: 2 }],
    ['wrong kdf name', { ...SAMPLE_ENVELOPE, kdf: { ...SAMPLE_ENVELOPE.kdf, name: 'argon2id' } }],
    ['missing ciphertext', { ...SAMPLE_ENVELOPE, envelope: { ...SAMPLE_ENVELOPE.envelope, ciphertext: undefined } }],
    ['N is not a number', { ...SAMPLE_ENVELOPE, kdf: { ...SAMPLE_ENVELOPE.kdf, N: '32768' } }],
    ['not an object at all', 'just a string'],
  ];

  it.each(malformedCases)('refuses %s', (_label, malformed) => {
    expect(passphraseEnvelopeShape.safeParse(malformed).success).toBe(false);
  });
});

describe('withTimingFloor — pads fast work up to the floor, never shortens slow work', () => {
  it('a fast function is delayed until at least the floor has elapsed', async () => {
    const startedAt = Date.now();
    const result = await withTimingFloor(60, async () => 'done');
    const elapsed = Date.now() - startedAt;
    expect(result).toBe('done');
    expect(elapsed).toBeGreaterThanOrEqual(55); // small tolerance for timer granularity
  });

  it('a function that already exceeds the floor is not delayed further', async () => {
    const startedAt = Date.now();
    await withTimingFloor(20, async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    const elapsed = Date.now() - startedAt;
    // Should be close to the 50ms the work itself took, not 50 + 20.
    expect(elapsed).toBeLessThan(90);
  });
});
