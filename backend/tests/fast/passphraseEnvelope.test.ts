/**
 * The passphrase-wrapped recovery key envelope (device-side signup/login
 * work, R5). Lives under backend/tests/fast to match prfEnvelope.test.ts and
 * keyEnvelope.test.ts — `packages/shared` has no runner of its own.
 *
 * EVERY REFUSAL BELOW IS PAIRED WITH THE SUCCESS CASE THAT PROVES IT
 * DISCRIMINATES, for the same reason keyEnvelope.test.ts states it: a suite
 * of `expect(...).toThrow()` alone passes against an `openKey` that always
 * throws.
 */
import { describe, it, expect } from 'vitest';
import {
  PASSPHRASE_KDF_N,
  PASSPHRASE_KDF_R,
  PASSPHRASE_KDF_P,
  PASSPHRASE_KDF_DKLEN,
  PassphraseEnvelopeError,
  deriveScryptKey,
  generateRecoveryKeySeed,
  unwrapRecoveryKeyWithPassphrase,
  wrapRecoveryKeyWithPassphrase,
  type PassphraseEnvelope,
} from '@ssi-healthcare/shared';

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

describe('passphraseEnvelope — the known-answer test that catches parameter drift', () => {
  it('scrypt(N=2^15,r=8,p=1,dkLen=32) over a fixed passphrase and salt is pinned', async () => {
    // Any change to PASSPHRASE_KDF_N/R/P/DKLEN, or to how the passphrase or
    // salt feed scrypt, changes this hex. That is the point: a drift here is
    // a silent, permanent inability to open every envelope written before it,
    // discovered only at the one moment nothing can be done about it.
    expect(PASSPHRASE_KDF_N).toBe(2 ** 15);
    expect(PASSPHRASE_KDF_R).toBe(8);
    expect(PASSPHRASE_KDF_P).toBe(1);
    expect(PASSPHRASE_KDF_DKLEN).toBe(32);

    const salt = new Uint8Array(16);
    for (let i = 0; i < 16; i += 1) salt[i] = i;

    const key = await deriveScryptKey('correct horse battery staple', salt, {
      N: PASSPHRASE_KDF_N,
      r: PASSPHRASE_KDF_R,
      p: PASSPHRASE_KDF_P,
      dkLen: PASSPHRASE_KDF_DKLEN,
    });

    expect(hex(key)).toBe('7a8e34241db898d59175c696538c417467a975ffe569068425f16188d3159c58');
  });
});

describe('passphraseEnvelope — the envelope wraps the key and never becomes its derivation', () => {
  it('round-trips the seed', async () => {
    const seed = generateRecoveryKeySeed();
    const envelope = await wrapRecoveryKeyWithPassphrase(seed, 'a reasonable passphrase');
    const opened = await unwrapRecoveryKeyWithPassphrase(envelope, 'a reasonable passphrase');
    expect(hex(opened)).toBe(hex(seed));
  });

  it('never puts the seed in the envelope in the clear', async () => {
    const seed = generateRecoveryKeySeed();
    const envelope = await wrapRecoveryKeyWithPassphrase(seed, 'a reasonable passphrase');
    const serialised = JSON.stringify(envelope);
    expect(serialised).not.toContain(Buffer.from(seed).toString('base64url'));
    expect(serialised).not.toContain(hex(seed));
  });

  it('is self-describing: the KDF name and parameters travel with the envelope', async () => {
    const seed = generateRecoveryKeySeed();
    const envelope = await wrapRecoveryKeyWithPassphrase(seed, 'a reasonable passphrase');
    expect(envelope.kdf).toEqual({
      name: 'scrypt',
      N: PASSPHRASE_KDF_N,
      r: PASSPHRASE_KDF_R,
      p: PASSPHRASE_KDF_P,
      dkLen: PASSPHRASE_KDF_DKLEN,
      salt: envelope.kdf.salt,
    });
    expect(typeof envelope.kdf.salt).toBe('string');
  });

  it('re-wrapping the SAME seed under the SAME passphrase produces a different envelope', async () => {
    const seed = generateRecoveryKeySeed();
    const a = await wrapRecoveryKeyWithPassphrase(seed, 'a reasonable passphrase');
    const b = await wrapRecoveryKeyWithPassphrase(seed, 'a reasonable passphrase');

    expect(a.kdf.salt).not.toBe(b.kdf.salt);
    expect(a.envelope.ciphertext).not.toBe(b.envelope.ciphertext);
    expect(hex(await unwrapRecoveryKeyWithPassphrase(a, 'a reasonable passphrase'))).toBe(hex(seed));
    expect(hex(await unwrapRecoveryKeyWithPassphrase(b, 'a reasonable passphrase'))).toBe(hex(seed));
  });

  it('a different passphrase does not open it — AES-GCM fails on the tag', async () => {
    const seed = generateRecoveryKeySeed();
    const envelope = await wrapRecoveryKeyWithPassphrase(seed, 'the right passphrase');

    await expect(unwrapRecoveryKeyWithPassphrase(envelope, 'the wrong passphrase')).rejects.toThrow(
      /did not authenticate/i,
    );
  });

  it('a tampered ciphertext does not open', async () => {
    const seed = generateRecoveryKeySeed();
    const envelope = await wrapRecoveryKeyWithPassphrase(seed, 'a reasonable passphrase');

    const raw = Buffer.from(envelope.envelope.ciphertext, 'base64url');
    raw[0] ^= 0x01;
    const tampered: PassphraseEnvelope = {
      ...envelope,
      envelope: { ...envelope.envelope, ciphertext: raw.toString('base64url') },
    };

    await expect(unwrapRecoveryKeyWithPassphrase(tampered, 'a reasonable passphrase')).rejects.toThrow(
      /did not authenticate/i,
    );
  });

  it('a tampered KDF salt derives a different key, so it also fails to authenticate', async () => {
    const seed = generateRecoveryKeySeed();
    const envelope = await wrapRecoveryKeyWithPassphrase(seed, 'a reasonable passphrase');

    const raw = Buffer.from(envelope.kdf.salt, 'base64url');
    raw[0] ^= 0x01;
    const tampered: PassphraseEnvelope = {
      ...envelope,
      kdf: { ...envelope.kdf, salt: raw.toString('base64url') },
    };

    await expect(unwrapRecoveryKeyWithPassphrase(tampered, 'a reasonable passphrase')).rejects.toThrow(
      PassphraseEnvelopeError,
    );
  });

  it('refuses an unknown envelope version rather than guessing its layout', async () => {
    const envelope = await wrapRecoveryKeyWithPassphrase(generateRecoveryKeySeed(), 'a reasonable passphrase');
    await expect(
      unwrapRecoveryKeyWithPassphrase({ ...envelope, version: 2 as unknown as 1 }, 'a reasonable passphrase'),
    ).rejects.toThrow(/Unknown passphrase envelope version/i);
  });

  it('refuses an unknown KDF name rather than guessing its layout', async () => {
    const envelope = await wrapRecoveryKeyWithPassphrase(generateRecoveryKeySeed(), 'a reasonable passphrase');
    const corrupted: PassphraseEnvelope = {
      ...envelope,
      kdf: { ...envelope.kdf, name: 'argon2id' as unknown as 'scrypt' },
    };
    await expect(unwrapRecoveryKeyWithPassphrase(corrupted, 'a reasonable passphrase')).rejects.toThrow(
      /Unknown KDF/i,
    );
  });
});

describe('passphraseEnvelope — fails closed on unusable input', () => {
  it.each([
    ['an empty passphrase', ''],
  ])('refuses to wrap under %s', async (_label, passphrase) => {
    await expect(wrapRecoveryKeyWithPassphrase(generateRecoveryKeySeed(), passphrase)).rejects.toThrow(
      /non-empty string/i,
    );
  });

  it('refuses to unwrap under an empty passphrase too, not just to wrap', async () => {
    const envelope = await wrapRecoveryKeyWithPassphrase(generateRecoveryKeySeed(), 'a reasonable passphrase');
    await expect(unwrapRecoveryKeyWithPassphrase(envelope, '')).rejects.toThrow(/non-empty string/i);
  });

  it('refuses an all-zero seed at wrap time (an uninitialised buffer, not entropy)', async () => {
    await expect(
      wrapRecoveryKeyWithPassphrase(new Uint8Array(32), 'a reasonable passphrase'),
    ).rejects.toThrow();
  });
});
