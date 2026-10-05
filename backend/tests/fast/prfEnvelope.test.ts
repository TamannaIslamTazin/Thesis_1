/**
 * R5 PHASE B — PRF as an envelope, and the silent drop that makes it necessary.
 *
 * ---------------------------------------------------------------------------
 * THE MEASUREMENT BEING DEFENDED (S-2 §3.3, §3.4)
 * ---------------------------------------------------------------------------
 * Below Play services `252400000` on Android <= 13, `androidx.credentials`
 * takes the legacy GIS FIDO2 path, which rebuilds the request field by field
 * and carries only `uvm` and `credProps`. PRF IS DROPPED AND THE CEREMONY STILL
 * SUCCEEDS. 56% of Bangladeshi Android traffic sits in that tier.
 *
 * The two properties below are therefore NOT the same property, and the tests
 * are grouped to keep them apart:
 *
 *   1. DETECTION IS TOTAL. Every shape that is not a usable 32-byte PRF output
 *      is classified as absent, with a reason. Nothing returns `undefined` and
 *      nothing throws where the caller is meant to degrade.
 *   2. THE CRYPTO BOUNDARY NEVER DEGRADES. There is no input that produces a
 *      key from an absent output. A key derived from `undefined` is
 *      unrecoverable on the 56% and looks exactly like success on the rest.
 */
import { describe, it, expect } from 'vitest';

import {
  PRF_OUTPUT_BYTES,
  generateRecoveryKeySeed,
  probePrfOutput,
  unwrapRecoveryKeyWithPrf,
  wrapRecoveryKeyWithPrf,
  type PrfAbsenceReason,
} from '@ssi-healthcare/shared';

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

const usableOutput = (): Uint8Array => {
  const output = new Uint8Array(PRF_OUTPUT_BYTES);
  globalThis.crypto.getRandomValues(output);
  return output;
};

const base64Url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64url');

describe('silent PRF absence is DETECTED, never assumed away', () => {
  const absent = (assertion: unknown): PrfAbsenceReason => {
    const outcome = probePrfOutput(assertion as never);
    if (outcome.available) throw new Error('expected PRF to be reported absent');
    return outcome.reason;
  };

  it('the S-2 §3.4 silent drop: ceremony succeeded, no prf member', () => {
    // This is the modal failure on the 56% tier. A valid assertion comes back
    // and clientExtensionResults simply has no `prf`.
    expect(absent({ clientExtensionResults: { credProps: { rk: true }, uvm: [] } })).toBe(
      'EXTENSION_DROPPED',
    );
  });

  it('no clientExtensionResults at all', () => {
    expect(absent({})).toBe('NO_CLIENT_EXTENSION_RESULTS');
    expect(absent(null)).toBe('NO_CLIENT_EXTENSION_RESULTS');
    expect(absent(undefined)).toBe('NO_CLIENT_EXTENSION_RESULTS');
  });

  it('prf present but carrying no results.first', () => {
    expect(absent({ clientExtensionResults: { prf: {} } })).toBe('NO_RESULTS_FIRST');
    expect(absent({ clientExtensionResults: { prf: { results: {} } } })).toBe(
      'NO_RESULTS_FIRST',
    );
    expect(absent({ clientExtensionResults: { prf: { enabled: true } } })).toBe(
      'NO_RESULTS_FIRST',
    );
  });

  it('results.first of the wrong length', () => {
    expect(
      absent({
        clientExtensionResults: { prf: { results: { first: new Uint8Array(16) } } },
      }),
    ).toBe('WRONG_LENGTH');
    expect(
      absent({
        clientExtensionResults: { prf: { results: { first: base64Url(new Uint8Array(64)) } } },
      }),
    ).toBe('WRONG_LENGTH');
  });

  it('results.first that is not decodable as bytes', () => {
    expect(absent({ clientExtensionResults: { prf: { results: { first: 42 } } } })).toBe(
      'NOT_DECODABLE',
    );
    expect(
      absent({ clientExtensionResults: { prf: { results: { first: { nested: true } } } } }),
    ).toBe('NOT_DECODABLE');
  });

  it('an all-zero output, which is an uninitialised buffer rather than entropy', () => {
    expect(
      absent({
        clientExtensionResults: {
          prf: { results: { first: new Uint8Array(PRF_OUTPUT_BYTES) } },
        },
      }),
    ).toBe('ALL_ZEROES');
  });

  it('detection REPORTS rather than throws, so enrolment can degrade to guardians', () => {
    // The policy boundary must be able to carry on. A device without PRF still
    // has to be able to enrol — that is reason 2 in #240 for the envelope.
    expect(() => probePrfOutput({ clientExtensionResults: {} })).not.toThrow();
    const outcome = probePrfOutput({ clientExtensionResults: {} });
    expect(outcome.available).toBe(false);
    if (!outcome.available) expect(outcome.detail).toMatch(/\S/);
  });

  it('accepts a genuine output, as bytes or as base64url', () => {
    const output = usableOutput();

    const asBytes = probePrfOutput({
      clientExtensionResults: { prf: { results: { first: output } } },
    });
    expect(asBytes.available).toBe(true);

    const asString = probePrfOutput({
      clientExtensionResults: { prf: { results: { first: base64Url(output) } } },
    });
    expect(asString.available).toBe(true);
    if (asString.available) expect(hex(asString.output)).toBe(hex(output));
  });
});

describe('the envelope wraps the key and never becomes its derivation', () => {
  it('round-trips the seed', () => {
    const seed = generateRecoveryKeySeed();
    const output = usableOutput();

    const envelope = wrapRecoveryKeyWithPrf(seed, output);
    expect(hex(unwrapRecoveryKeyWithPrf(envelope, output))).toBe(hex(seed));
  });

  it('never puts the seed in the envelope in the clear', () => {
    const seed = generateRecoveryKeySeed();
    const envelope = wrapRecoveryKeyWithPrf(seed, usableOutput());
    expect(JSON.stringify(envelope)).not.toContain(Buffer.from(seed).toString('base64url'));
    expect(JSON.stringify(envelope)).not.toContain(hex(seed));
  });

  it('re-wrapping the SAME seed produces a different envelope', () => {
    // Fresh salt and nonce per wrap. This is what lets the envelope be redone
    // — new salt, new KDF, new provider — while the on-chain key never moves,
    // which is reason 1 in #240 for wrapping rather than deriving.
    const seed = generateRecoveryKeySeed();
    const output = usableOutput();
    const a = wrapRecoveryKeyWithPrf(seed, output);
    const b = wrapRecoveryKeyWithPrf(seed, output);

    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.salt).not.toBe(b.salt);
    expect(hex(unwrapRecoveryKeyWithPrf(a, output))).toBe(hex(seed));
    expect(hex(unwrapRecoveryKeyWithPrf(b, output))).toBe(hex(seed));
  });

  it('a different passkey does not open it — AES-GCM fails on the tag', () => {
    const seed = generateRecoveryKeySeed();
    const envelope = wrapRecoveryKeyWithPrf(seed, usableOutput());

    // The important half: it does not return plausible garbage.
    expect(() => unwrapRecoveryKeyWithPrf(envelope, usableOutput())).toThrow(
      /did not authenticate/i,
    );
  });

  it('a tampered envelope does not open', () => {
    const seed = generateRecoveryKeySeed();
    const output = usableOutput();
    const envelope = wrapRecoveryKeyWithPrf(seed, output);

    const flipped = Buffer.from(envelope.ciphertext, 'base64url');
    flipped[0] ^= 0x01;

    expect(() =>
      unwrapRecoveryKeyWithPrf(
        { ...envelope, ciphertext: flipped.toString('base64url') },
        output,
      ),
    ).toThrow(/did not authenticate/i);
  });

  it('refuses an unknown envelope version rather than guessing its layout', () => {
    const envelope = wrapRecoveryKeyWithPrf(generateRecoveryKeySeed(), usableOutput());
    expect(() =>
      unwrapRecoveryKeyWithPrf({ ...envelope, version: 2 as unknown as 1 }, usableOutput()),
    ).toThrow(/Unknown PRF envelope version/i);
  });
});

describe('there is no path from an absent PRF output to a key', () => {
  const seed = () => generateRecoveryKeySeed();

  it.each([
    ['an empty output', new Uint8Array(0)],
    ['a short output', new Uint8Array(16)],
    ['a long output', new Uint8Array(64)],
  ])('refuses to wrap under %s', (_label, output) => {
    expect(() => wrapRecoveryKeyWithPrf(seed(), output)).toThrow(/Refusing to derive/i);
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a string', 'not-bytes'],
  ])('refuses to wrap under %s', (_label, output) => {
    expect(() => wrapRecoveryKeyWithPrf(seed(), output as never)).toThrow(/Refusing to derive/i);
  });

  it('refuses to UNWRAP under an absent output too, not just to wrap', () => {
    const envelope = wrapRecoveryKeyWithPrf(seed(), usableOutput());
    expect(() => unwrapRecoveryKeyWithPrf(envelope, undefined as never)).toThrow(
      /Refusing to derive/i,
    );
  });
});
