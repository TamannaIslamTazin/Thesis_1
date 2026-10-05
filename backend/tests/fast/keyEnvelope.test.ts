/**
 * The shared 32-byte key envelope (#340 locker work), and the proof that
 * folding `prfEnvelope.ts` onto it did not change a single stored byte.
 *
 * Lives under backend/tests/fast to match prfEnvelope.test.ts — `packages/shared`
 * has no runner of its own, and splitting these two suites across packages
 * would hide the compatibility test from whoever next edits the PRF envelope.
 *
 * EVERY REFUSAL BELOW IS PAIRED WITH THE SUCCESS CASE THAT PROVES IT
 * DISCRIMINATES. A suite of `expect(...).toThrow()` alone passes perfectly
 * against an `openKey` that always throws, which is how this project once got
 * two of three tamper tests passing over a broken hash.
 */
import { describe, it, expect } from 'vitest';
import { gcm } from '@noble/ciphers/aes';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import {
  EMPTY_AAD,
  KeyEnvelopeError,
  openKey,
  sealKey,
  unwrapRecoveryKeyWithPrf,
  wrapRecoveryKeyWithPrf,
} from '@ssi-healthcare/shared';

function random32(): Uint8Array {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}

const PURPOSE_A = { info: 'bdhealthtrust/test-purpose-a/v1', aad: EMPTY_AAD };
const PURPOSE_B = { info: 'bdhealthtrust/test-purpose-b/v1', aad: EMPTY_AAD };

const SLOT_ONE = {
  info: 'bdhealthtrust/test-purpose-a/v1',
  aad: new TextEncoder().encode('slot|one'),
};
const SLOT_TWO = {
  info: 'bdhealthtrust/test-purpose-a/v1',
  aad: new TextEncoder().encode('slot|two'),
};

describe('keyEnvelope — the success path works', () => {
  it('round-trips a 32-byte secret', () => {
    const secret = random32();
    const wrapping = random32();
    const opened = openKey(sealKey(secret, wrapping, PURPOSE_A), wrapping, PURPOSE_A);
    expect(Buffer.from(opened)).toEqual(Buffer.from(secret));
  });

  it('never stores the secret in the clear', () => {
    const secret = random32();
    const envelope = sealKey(secret, random32(), PURPOSE_A);
    const secretB64 = Buffer.from(secret).toString('base64url');
    expect(envelope.ciphertext).not.toContain(secretB64);
    expect(JSON.stringify(envelope)).not.toContain(secretB64);
  });

  it('re-sealing the SAME secret produces a different envelope (fresh salt and nonce)', () => {
    const secret = random32();
    const wrapping = random32();
    const a = sealKey(secret, wrapping, PURPOSE_A);
    const b = sealKey(secret, wrapping, PURPOSE_A);
    expect(a.salt).not.toBe(b.salt);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.ciphertext).not.toBe(b.ciphertext);
    // ...and both still open, so the difference is nonce/salt, not corruption.
    expect(Buffer.from(openKey(a, wrapping, PURPOSE_A))).toEqual(Buffer.from(secret));
    expect(Buffer.from(openKey(b, wrapping, PURPOSE_A))).toEqual(Buffer.from(secret));
  });
});

describe('keyEnvelope — domain separation is real, not decorative', () => {
  it('SUCCESS: the same info opens it, so the refusal below is discriminating', () => {
    const secret = random32();
    const wrapping = random32();
    expect(Buffer.from(openKey(sealKey(secret, wrapping, PURPOSE_A), wrapping, PURPOSE_A))).toEqual(
      Buffer.from(secret),
    );
  });

  it('a DIFFERENT info does not open it, even with the identical wrapping key', () => {
    const wrapping = random32();
    const envelope = sealKey(random32(), wrapping, PURPOSE_A);
    // This is the whole reason the locker did not reuse the RCK's info string.
    expect(() => openKey(envelope, wrapping, PURPOSE_B)).toThrow(KeyEnvelopeError);
  });

  it('refuses a context with no info rather than substituting a default', () => {
    const wrapping = random32();
    expect(() => sealKey(random32(), wrapping, { info: '', aad: EMPTY_AAD })).toThrow(
      KeyEnvelopeError,
    );
    expect(() => sealKey(random32(), wrapping, { info: '   ', aad: EMPTY_AAD })).toThrow(
      KeyEnvelopeError,
    );
  });
});

describe('keyEnvelope — AAD binds an envelope to its slot', () => {
  it('SUCCESS: the same slot opens it', () => {
    const secret = random32();
    const wrapping = random32();
    expect(Buffer.from(openKey(sealKey(secret, wrapping, SLOT_ONE), wrapping, SLOT_ONE))).toEqual(
      Buffer.from(secret),
    );
  });

  it('an envelope lifted into another slot does not open', () => {
    const wrapping = random32();
    const envelope = sealKey(random32(), wrapping, SLOT_ONE);
    expect(() => openKey(envelope, wrapping, SLOT_TWO)).toThrow(KeyEnvelopeError);
  });

  it('a slot-bound envelope does not open with no AAD at all', () => {
    const wrapping = random32();
    const envelope = sealKey(random32(), wrapping, SLOT_ONE);
    expect(() => openKey(envelope, wrapping, PURPOSE_A)).toThrow(KeyEnvelopeError);
  });
});

describe('keyEnvelope — fails closed on unusable material', () => {
  it('SUCCESS: good material seals, so the refusals below are not universal', () => {
    expect(sealKey(random32(), random32(), PURPOSE_A).version).toBe(1);
  });

  it('refuses an all-zero secret (an uninitialised buffer, not entropy)', () => {
    expect(() => sealKey(new Uint8Array(32), random32(), PURPOSE_A)).toThrow(KeyEnvelopeError);
  });

  it('refuses an all-zero wrapping key', () => {
    expect(() => sealKey(random32(), new Uint8Array(32), PURPOSE_A)).toThrow(KeyEnvelopeError);
  });

  it('refuses a short secret and a short wrapping key', () => {
    expect(() => sealKey(new Uint8Array(16).fill(3), random32(), PURPOSE_A)).toThrow(
      KeyEnvelopeError,
    );
    expect(() => sealKey(random32(), new Uint8Array(16).fill(3), PURPOSE_A)).toThrow(
      KeyEnvelopeError,
    );
  });

  it('refuses the wrong wrapping key on open', () => {
    const envelope = sealKey(random32(), random32(), PURPOSE_A);
    expect(() => openKey(envelope, random32(), PURPOSE_A)).toThrow(KeyEnvelopeError);
  });

  it('refuses a tampered ciphertext', () => {
    const wrapping = random32();
    const envelope = sealKey(random32(), wrapping, PURPOSE_A);
    const raw = Buffer.from(envelope.ciphertext, 'base64url');
    raw[0] ^= 0xff;
    const tampered = { ...envelope, ciphertext: raw.toString('base64url') };
    expect(() => openKey(tampered, wrapping, PURPOSE_A)).toThrow(KeyEnvelopeError);
  });

  it('refuses an unknown version rather than guessing the layout', () => {
    const wrapping = random32();
    const envelope = sealKey(random32(), wrapping, PURPOSE_A);
    expect(() => openKey({ ...envelope, version: 2 as never }, wrapping, PURPOSE_A)).toThrow(
      KeyEnvelopeError,
    );
  });
});

/**
 * THE MIGRATION SAFETY PROOF.
 *
 * `prfEnvelope.ts` now delegates to `sealKey`/`openKey`. If that changed the
 * derivation or the cipher input by even one byte, every RCK envelope ever
 * written would be silently unopenable — discovered only at a recovery, which
 * is the one moment nothing can be done about it.
 *
 * So this reconstructs an envelope using the ORIGINAL algorithm verbatim
 * (HKDF-SHA256 over the PRF output with the old info string, AES-GCM with NO
 * aad argument) and requires the CURRENT code to open it.
 */
describe('prfEnvelope — envelopes written before the refactor still open', () => {
  const LEGACY_INFO = 'bdhealthtrust/rck-prf-envelope/v1';

  function sealTheOldWay(seed: Uint8Array, prfOutput: Uint8Array) {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const key = hkdf(sha256, prfOutput, salt, LEGACY_INFO, 32);
    // No AAD argument at all — exactly as the pre-refactor code called it.
    const ciphertext = gcm(key, nonce).encrypt(seed);
    const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64url');
    return { version: 1 as const, salt: b64(salt), nonce: b64(nonce), ciphertext: b64(ciphertext) };
  }

  it('opens a legacy envelope byte-for-byte, proving the wire format is unchanged', () => {
    const seed = random32();
    const prfOutput = random32();
    const legacy = sealTheOldWay(seed, prfOutput);
    const opened = unwrapRecoveryKeyWithPrf(legacy, prfOutput);
    expect(Buffer.from(opened)).toEqual(Buffer.from(seed));
  });

  it('and the reverse: a NEW envelope opens under the OLD algorithm', () => {
    const seed = random32();
    const prfOutput = random32();
    const fresh = wrapRecoveryKeyWithPrf(seed, prfOutput);
    const key = hkdf(sha256, prfOutput, Buffer.from(fresh.salt, 'base64url'), LEGACY_INFO, 32);
    const opened = gcm(key, Buffer.from(fresh.nonce, 'base64url')).decrypt(
      Buffer.from(fresh.ciphertext, 'base64url'),
    );
    expect(Buffer.from(opened)).toEqual(Buffer.from(seed));
  });

  it('a legacy envelope still refuses the wrong PRF output', () => {
    const legacy = sealTheOldWay(random32(), random32());
    expect(() => unwrapRecoveryKeyWithPrf(legacy, random32())).toThrow();
  });
});
