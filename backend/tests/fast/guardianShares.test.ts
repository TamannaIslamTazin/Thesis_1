/**
 * R5 PHASE B — the guardian split, and the library underneath it.
 *
 * ---------------------------------------------------------------------------
 * WHY THE OFFICIAL VECTORS ARE IN HERE RATHER THAN CHECKED ONCE BY HAND
 * ---------------------------------------------------------------------------
 * `slip39@0.1.9` is a single-maintainer package last published in 2024, and it
 * is load-bearing for a key that CANNOT BE REPAIRED (S-1 §5.4). "It looked
 * right when we added it" is not a standard that survives a dependency bump.
 *
 * So the 45 official Trezor vectors run on every fast suite. The 30 NEGATIVE
 * ones matter more than the 15 positive: a library that silently accepted a
 * corrupted or below-threshold share set would hand back a plausible wrong key,
 * and every downstream check would agree with it.
 *
 * Vector file: https://github.com/trezor/python-shamir-mnemonic `vectors.json`.
 * Shape is `[description, mnemonics[], masterSecretHex, xprv]`, where an EMPTY
 * masterSecretHex means the set must be REFUSED.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import Slip39 from 'slip39';

import {
  DEFAULT_GUARDIAN_POLICY,
  assertPolicyIsSane,
  combineGuardianShares,
  generateRecoveryKeySeed,
  splitRecoveryKey,
  type GuardianPolicy,
} from '@ssi-healthcare/shared';

type Slip39Vector = [string, string[], string, string];

const vectors: Slip39Vector[] = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('./fixtures/slip39-official-vectors.json', import.meta.url)),
    'utf8',
  ),
);

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

describe('the SLIP-39 library, against the official Trezor vectors', () => {
  it('has the vectors it claims to have', () => {
    expect(vectors).toHaveLength(45);
    expect(vectors.filter((v) => v[2] !== '')).toHaveLength(15);
    expect(vectors.filter((v) => v[2] === '')).toHaveLength(30);
  });

  it.each(vectors.filter((v) => v[2] !== '').map((v) => [v[0], v[1], v[2]] as const))(
    'recovers the master secret: %s',
    (_description, mnemonics, expectedHex) => {
      const recovered = Uint8Array.from(Slip39.recoverSecret([...mnemonics], 'TREZOR'));
      expect(hex(recovered)).toBe(expectedHex);
    },
  );

  it.each(vectors.filter((v) => v[2] === '').map((v) => [v[0], v[1]] as const))(
    'REFUSES the invalid set: %s',
    (_description, mnemonics) => {
      // The property is refusal. A library that returned *something* here would
      // silently hand a wrong key to a caller with no way to tell.
      expect(() => Slip39.recoverSecret([...mnemonics], 'TREZOR')).toThrow();
    },
  );
});

describe('splitting a recovery key', () => {
  it('round-trips through exactly the threshold, from any subset', () => {
    const seed = generateRecoveryKeySeed();
    const split = splitRecoveryKey(seed, DEFAULT_GUARDIAN_POLICY);

    expect(split.shares).toHaveLength(5);

    const first = combineGuardianShares(split.shares.slice(0, 3).map((s) => s.mnemonic));
    expect(hex(first.seed)).toBe(hex(seed));

    // A different subset of the same size must work — otherwise the scheme is
    // "any 3 as long as they are the first 3", which is not a threshold.
    const other = combineGuardianShares(
      [split.shares[1]!, split.shares[3]!, split.shares[4]!].map((s) => s.mnemonic),
    );
    expect(hex(other.seed)).toBe(hex(seed));
  });

  it('refuses to reconstruct from below the threshold', () => {
    const seed = generateRecoveryKeySeed();
    const split = splitRecoveryKey(seed, DEFAULT_GUARDIAN_POLICY);

    expect(() =>
      combineGuardianShares(split.shares.slice(0, 2).map((s) => s.mnemonic)),
    ).toThrow();
  });

  it('refuses shares belonging to two different patients', () => {
    const a = splitRecoveryKey(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    const b = splitRecoveryKey(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);

    expect(() =>
      combineGuardianShares([
        a.shares[0]!.mnemonic,
        a.shares[1]!.mnemonic,
        b.shares[0]!.mnemonic,
      ]),
    ).toThrow(/different splits/i);
  });

  it('refuses a share with one mistyped word', () => {
    const split = splitRecoveryKey(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    const mangled = split.shares[2]!.mnemonic
      .split(' ')
      .map((word, index) => (index === 7 ? 'academic' : word))
      .join(' ');

    expect(() =>
      combineGuardianShares([split.shares[0]!.mnemonic, split.shares[1]!.mnemonic, mangled]),
    ).toThrow();
  });

  it('produces shares short enough to be a QR code rather than a transcription', () => {
    // #240: presented as words to copy, this fails the target population. The
    // mnemonic is a QR payload; this asserts it stays one.
    const split = splitRecoveryKey(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    for (const share of split.shares) {
      expect(Buffer.byteLength(share.mnemonic, 'utf8')).toBeLessThan(400);
    }
  });
});

describe('the policy refuses splits that are not really splits', () => {
  const withGuardians = (threshold: number, count: number): GuardianPolicy => ({
    threshold,
    guardians: Array.from({ length: count }, (_, i) => ({
      label: `Guardian ${i + 1}`,
      role: 'FAMILY' as const,
    })),
  });

  it('rejects a threshold of 1, which is not a threshold', () => {
    expect(() => assertPolicyIsSane(withGuardians(1, 5))).toThrow(/>= 2/);
  });

  it('rejects a threshold larger than the guardian count', () => {
    expect(() => assertPolicyIsSane(withGuardians(6, 5))).toThrow(/never be reconstructed/i);
  });

  it('rejects n-of-n, which one unreachable guardian freezes', () => {
    expect(() => assertPolicyIsSane(withGuardians(3, 3))).toThrow(/leave slack/i);
  });

  it('rejects fewer than three guardians', () => {
    expect(() => assertPolicyIsSane({ ...withGuardians(2, 2) })).toThrow(/at least 3/i);
  });

  it('rejects a policy where the institution alone meets the threshold', () => {
    // The custodial outcome the whole split exists to prevent (#240).
    expect(() =>
      assertPolicyIsSane({
        threshold: 2,
        guardians: [
          { label: 'Hospital A', role: 'INSTITUTION' },
          { label: 'Hospital B', role: 'INSTITUTION' },
          { label: 'Cousin', role: 'FAMILY' },
          { label: 'Neighbour', role: 'FAMILY' },
        ],
      }),
    ).toThrow(/reconstruct the patient key alone/i);
  });

  it('accepts the shipped default', () => {
    expect(() => assertPolicyIsSane(DEFAULT_GUARDIAN_POLICY)).not.toThrow();
    // Exactly one institutional voice among several, which is the #240 shape.
    expect(
      DEFAULT_GUARDIAN_POLICY.guardians.filter((g) => g.role === 'INSTITUTION'),
    ).toHaveLength(1);
  });
});
