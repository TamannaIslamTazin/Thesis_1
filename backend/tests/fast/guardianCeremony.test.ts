/**
 * R5 PHASE B — the guardian ceremony, and the composition rule it enforces.
 *
 * ---------------------------------------------------------------------------
 * WHAT THESE TESTS ARE ACTUALLY ABOUT (#315)
 * ---------------------------------------------------------------------------
 * "Per-step failsafes do not compose. A procedure is only failsafe if each
 * phase CHECKS its precondition instead of assuming the prior phase succeeded."
 *
 * That is not an abstract worry here. Enrolment is multi-phase, guardian shares
 * CANNOT BE RETROFITTED (S-2 §8), and a patient DID whose RCK shares were never
 * delivered is unrecoverable from birth while looking completely healthy. The
 * damage is invisible until the day recovery is first needed, which is exactly
 * the shape of failure that revoked 79 credentials this week.
 *
 * So the assertions below are mostly REFUSALS. Each one is a way of skipping a
 * phase, and each must be caught by the phase that depends on it rather than by
 * the phase that was skipped.
 */
import { describe, it, expect } from 'vitest';

import {
  DEFAULT_GUARDIAN_POLICY,
  GuardianCeremony,
  generateRecoveryKeySeed,
  recoveryKeyPublicKey,
} from '@ssi-healthcare/shared';

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** Drive a ceremony to the point where it is legitimately completable. */
function readyCeremony(): { ceremony: GuardianCeremony; seedHex: string } {
  const seed = generateRecoveryKeySeed();
  const seedHex = hex(seed);
  const ceremony = GuardianCeremony.begin(seed, DEFAULT_GUARDIAN_POLICY);

  for (const share of ceremony.shares.slice(0, DEFAULT_GUARDIAN_POLICY.threshold)) {
    ceremony.confirm(share.index, share.mnemonic);
  }
  ceremony.rehearse();

  return { ceremony, seedHex };
}

describe('a guardian must PROVE possession, not merely be shown a share', () => {
  it('accepts a correct read-back', () => {
    const ceremony = GuardianCeremony.begin(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    const status = ceremony.confirm(0, ceremony.shares[0]!.mnemonic);
    expect(status.confirmedCount).toBe(1);
  });

  it('tolerates whitespace and case, which a scanner or a human will vary', () => {
    const ceremony = GuardianCeremony.begin(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    const noisy = `  ${ceremony.shares[0]!.mnemonic.toUpperCase().replace(/ /g, '   ')}  `;
    expect(() => ceremony.confirm(0, noisy)).not.toThrow();
  });

  it('refuses a read-back that is not that share', () => {
    const ceremony = GuardianCeremony.begin(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    expect(() => ceremony.confirm(0, 'academic academic academic')).toThrow(
      /not the share they were given/i,
    );
    expect(ceremony.status().confirmedCount).toBe(0);
  });

  it('names the collision when a guardian reads back SOMEONE ELSE’S share', () => {
    // This is share co-location caught in the act — #240's most likely failure
    // mode. Two guardians holding one share is a split of one fewer, and it
    // passes every cryptographic check.
    const ceremony = GuardianCeremony.begin(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    expect(() => ceremony.confirm(0, ceremony.shares[1]!.mnemonic)).toThrow(
      /read back the share belonging to/i,
    );
    expect(ceremony.status().confirmedCount).toBe(0);
  });
});

describe('completion re-establishes its precondition instead of inheriting it (#315)', () => {
  it('refuses with no confirmations at all', () => {
    const ceremony = GuardianCeremony.begin(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    expect(() => ceremony.complete()).toThrow(/Only 0 of 5 guardians have proved possession/i);
    expect(() => ceremony.complete()).toThrow(/3 are needed/i);
  });

  it('refuses below the threshold, and says who is outstanding', () => {
    const ceremony = GuardianCeremony.begin(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    ceremony.confirm(0, ceremony.shares[0]!.mnemonic);
    ceremony.confirm(1, ceremony.shares[1]!.mnemonic);

    expect(() => ceremony.complete()).toThrow(/Only 2 of 5 guardians have proved possession/i);
    expect(() => ceremony.complete()).toThrow(/Community witness/);
  });

  it('counts DISTINCT guardians, so confirming one twice does not reach the threshold', () => {
    // The counter-shaped bug: an implementation that incremented per call
    // rather than recomputing from the recorded set would pass this at 3.
    const ceremony = GuardianCeremony.begin(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    ceremony.confirm(0, ceremony.shares[0]!.mnemonic);
    ceremony.confirm(0, ceremony.shares[0]!.mnemonic);
    ceremony.confirm(0, ceremony.shares[0]!.mnemonic);

    expect(ceremony.status().confirmedCount).toBe(1);
    expect(() => ceremony.complete()).toThrow(/Only 1 of 5 guardians have proved possession/i);
  });

  it('refuses when the threshold is met but recovery was never rehearsed', () => {
    const ceremony = GuardianCeremony.begin(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    for (const share of ceremony.shares.slice(0, 3)) {
      ceremony.confirm(share.index, share.mnemonic);
    }

    expect(ceremony.status().confirmedCount).toBe(3);
    expect(() => ceremony.complete()).toThrow(/has not been rehearsed/i);
  });

  it('completes once every phase actually happened, and yields the seed', () => {
    const { ceremony, seedHex } = readyCeremony();
    expect(ceremony.status().canComplete).toBe(true);
    expect(hex(ceremony.complete())).toBe(seedHex);
  });
});

describe('rehearsal is a real reconstruction, not a formality', () => {
  it('refuses to rehearse below the threshold', () => {
    const ceremony = GuardianCeremony.begin(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    ceremony.confirm(0, ceremony.shares[0]!.mnemonic);

    expect(() => ceremony.rehearse()).toThrow(/Cannot rehearse recovery with 1 confirmed/i);
  });

  it('rebuilds the key from the CONFIRMED shares', () => {
    const seed = generateRecoveryKeySeed();
    const ceremony = GuardianCeremony.begin(seed, DEFAULT_GUARDIAN_POLICY);
    // Deliberately not the first three, to prove it uses what was confirmed.
    for (const index of [1, 3, 4]) {
      ceremony.confirm(index, ceremony.shares[index]!.mnemonic);
    }

    expect(ceremony.rehearse()).toEqual({ reconstructed: true, sharesUsed: 3 });
  });
});

describe('the seed does not outlive the ceremony', () => {
  it('is released exactly once', () => {
    const { ceremony } = readyCeremony();
    ceremony.complete();
    expect(() => ceremony.complete()).toThrow(/is COMPLETE, not DISTRIBUTING/i);
  });

  it('abandoning zeroises and blocks every further step', () => {
    const ceremony = GuardianCeremony.begin(generateRecoveryKeySeed(), DEFAULT_GUARDIAN_POLICY);
    ceremony.abandon();

    expect(() => ceremony.complete()).toThrow(/ABANDONED/);
    expect(() => ceremony.confirm(0, ceremony.shares[0]!.mnemonic)).toThrow(/ABANDONED/);
    expect(() => ceremony.recoveryPublicKey()).toThrow(/no longer holds a seed/i);
  });

  it('exposes the public key so recovery can be checked against the LEDGER', () => {
    const seed = generateRecoveryKeySeed();
    const expected = hex(recoveryKeyPublicKey(seed));
    const ceremony = GuardianCeremony.begin(seed, DEFAULT_GUARDIAN_POLICY);

    expect(hex(ceremony.recoveryPublicKey())).toBe(expected);
  });
});
