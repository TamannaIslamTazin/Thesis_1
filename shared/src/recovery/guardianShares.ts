/**
 * SLIP-39 guardian split of the RCK seed — the universal recovery path (#240).
 *
 * ===========================================================================
 * WHY THRESHOLD CUSTODY IS AVAILABLE AT ALL, GIVEN S-1 SAID IT WAS NOT
 * ===========================================================================
 * S-1 §8.2 recorded k-of-n as "unimplementable". That verdict is correct AND
 * narrower than it sounds: it is unimplementable ON CHAIN. `x/did` verifies one
 * Ed25519 signature per controller DID and has no threshold predicate. But HOW
 * that one key is custodied is invisible to consensus (#240). So the threshold
 * lives strictly below the identifier layer, and the ledger never learns it
 * exists.
 *
 * ===========================================================================
 * WHY SLIP-39 AND NOT FROST (#240)
 * ===========================================================================
 * FROST-Ed25519 (RFC 9591) would never reconstitute the whole key, which is
 * strictly better cryptography. It also needs two interactive rounds with
 * guardians simultaneously online. In rural Bangladesh "bring three pieces of
 * paper" is a far more achievable ask than "three people online at once with a
 * coordinator". SLIP-39 for v1; FROST needs no chain migration if the
 * moment-of-reconstitution ever becomes the binding threat.
 *
 * ===========================================================================
 * THE PRESENTATION IS THE LOAD-BEARING PART, NOT THE SPLIT (#240)
 * ===========================================================================
 * #240's low-literacy assessment is explicit: presented as a 33-word English
 * mnemonic this WILL fail the target population. A Bengali speaker with limited
 * literacy cannot reliably transcribe it. The mnemonic is therefore treated
 * here as a WIRE FORMAT, not as something a human copies — {@link GuardianShare}
 * carries it for QR encoding and for standards conformance, and the ceremony is
 * expected to render the QR. The words remain available as a last-resort
 * fallback for a guardian with no phone, which is a different thing from being
 * the primary channel.
 *
 * ===========================================================================
 * NO PASSPHRASE, DELIBERATELY
 * ===========================================================================
 * SLIP-39 supports a passphrase over the shares. We pass the empty one. A
 * forgotten passphrase is indistinguishable from a lost key and destroys every
 * share at once — it converts a k-of-n scheme back into a 1-of-1 secret, which
 * is exactly what the split exists to avoid. The shares ARE the secret.
 */

import Slip39 from 'slip39';

import { RECOVERY_KEY_SEED_BYTES, assertWellFormedSeed } from './recoveryKey.js';
import { withSlip39Runtime } from './slip39Runtime.js';

/** Who holds a share. Recorded so a ceremony can show the patient their own list. */
export type GuardianRole = 'FAMILY' | 'COMMUNITY' | 'INSTITUTION' | 'PATIENT_OFFLINE';

export interface GuardianAssignment {
  readonly label: string;
  readonly role: GuardianRole;
}

export interface GuardianPolicy {
  /** How many shares reconstruct the key. */
  readonly threshold: number;
  readonly guardians: readonly GuardianAssignment[];
}

export interface GuardianShare {
  readonly index: number;
  readonly guardian: GuardianAssignment;
  /** SLIP-39 mnemonic. The QR payload, and only incidentally readable words. */
  readonly mnemonic: string;
  /** Cheap human cross-check that two shares belong to the same split. */
  readonly groupPrefix: string;
}

export interface GuardianSplit {
  readonly policy: GuardianPolicy;
  readonly shares: readonly GuardianShare[];
  /**
   * Identifies the split WITHOUT identifying the secret. SLIP-39 puts a random
   * 15-bit identifier in every share of a set, and the first two mnemonic words
   * encode it, so this is derived from public share data rather than from the
   * seed. Safe to persist; useless to an attacker.
   */
  readonly splitId: string;
}

export class GuardianShareError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GuardianShareError';
  }
}

/**
 * The default #240 argues for: one share institutional, so the institution is
 * ONE VOICE AMONG SEVERAL rather than the recovery authority. That is the
 * difference between this and the institution-assisted path it replaces.
 */
export const DEFAULT_GUARDIAN_POLICY: GuardianPolicy = {
  threshold: 3,
  guardians: [
    { label: 'Family member 1', role: 'FAMILY' },
    { label: 'Family member 2', role: 'FAMILY' },
    { label: 'Community witness', role: 'COMMUNITY' },
    { label: 'Enrolling institution', role: 'INSTITUTION' },
    { label: 'Patient offline copy', role: 'PATIENT_OFFLINE' },
  ],
};

export function assertPolicyIsSane(policy: GuardianPolicy): void {
  const n = policy.guardians.length;
  const k = policy.threshold;

  if (!Number.isInteger(k) || k < 2) {
    throw new GuardianShareError(
      `Guardian threshold must be an integer >= 2, got ${k}. A threshold of 1 is not a ` +
        'split — any single share would reconstruct the identity on its own.',
    );
  }
  if (k > n) {
    throw new GuardianShareError(
      `Guardian threshold ${k} exceeds the ${n} guardians nominated, so the key could ` +
        'never be reconstructed. This is unrecoverable at enrolment, not later.',
    );
  }
  if (n < 3) {
    throw new GuardianShareError(
      `${n} guardians is too few to survive one becoming unreachable over the lifetime ` +
        'of a health identity. Nominate at least 3.',
    );
  }
  if (k === n) {
    throw new GuardianShareError(
      `A ${k}-of-${n} split freezes the identity the moment ONE guardian is unreachable. ` +
        'Guardian churn over years is the most likely failure mode (#240); leave slack.',
    );
  }
  const institutional = policy.guardians.filter((g) => g.role === 'INSTITUTION').length;
  if (institutional >= k) {
    throw new GuardianShareError(
      `${institutional} of the ${k} shares needed are institutional, so the institution ` +
        'could reconstruct the patient key alone. That is the custodial outcome the ' +
        'guardian split exists to prevent (#240).',
    );
  }
}

/**
 * Split a seed into guardian shares.
 *
 * FAILSAFE: the split is REPRODUCED FROM ITS OWN OUTPUT before it is returned.
 * Handing out shares that do not reconstruct is the one failure here that is
 * both silent and terminal — it would surface years later, at the only moment
 * the shares are ever used, when nothing can be done. Verifying costs one
 * reconstruction and converts that into a loud failure at enrolment.
 */
export function splitRecoveryKey(seed: Uint8Array, policy: GuardianPolicy): GuardianSplit {
  assertWellFormedSeed(seed);
  assertPolicyIsSane(policy);

  const n = policy.guardians.length;

  // Everything that touches SLIP-39, including the reconstruction check, runs
  // inside one scope so React Native gets the `Buffer` the library assumes. On
  // Node this wrapper is a no-op. See slip39Runtime.ts.
  const shares = withSlip39Runtime((): GuardianShare[] => {
    const built = Slip39.fromArray(Array.from(seed), {
      passphrase: '',
      // One group; the threshold lives inside it. `threshold: 1` here means "one
      // group must be satisfied", which is the group-level degenerate case.
      threshold: 1,
      groups: [[policy.threshold, n, 'guardians']],
    });

    const mnemonics: string[] = built.fromPath('r/0').mnemonics;

    if (mnemonics.length !== n) {
      throw new GuardianShareError(
        `SLIP-39 produced ${mnemonics.length} shares for ${n} guardians. Refusing to ` +
          'distribute a share set that does not match the policy.',
      );
    }

    const producedShares: GuardianShare[] = mnemonics.map((mnemonic, index) => ({
      index,
      guardian: policy.guardians[index]!,
      mnemonic,
      groupPrefix: mnemonic.split(' ').slice(0, 2).join(' '),
    }));

    assertSplitReconstructs(seed, producedShares, policy.threshold);

    return producedShares;
  });

  return {
    policy,
    shares,
    splitId: shares[0]!.groupPrefix,
  };
}

/**
 * Prove the shares reconstruct the seed, and prove one fewer does not.
 *
 * The negative half matters as much as the positive one: a library bug that
 * reconstructed from below the threshold would silently weaken every split we
 * have ever issued, and would look exactly like success.
 */
function assertSplitReconstructs(
  seed: Uint8Array,
  shares: readonly GuardianShare[],
  threshold: number,
): void {
  const atThreshold = shares.slice(0, threshold).map((s) => s.mnemonic);
  let reconstructed: Uint8Array;
  try {
    reconstructed = Uint8Array.from(Slip39.recoverSecret(atThreshold, ''));
  } catch (error) {
    throw new GuardianShareError(
      'The freshly generated guardian shares did not reconstruct the key they were made ' +
        `from: ${error instanceof Error ? error.message : String(error)}. Nothing has been ` +
        'distributed and no identity has been created.',
    );
  }

  if (
    reconstructed.length !== seed.length ||
    !reconstructed.every((byte, i) => byte === seed[i])
  ) {
    throw new GuardianShareError(
      'The freshly generated guardian shares reconstructed a DIFFERENT key. Refusing to ' +
        'distribute them.',
    );
  }

  if (threshold > 1) {
    let belowThresholdSucceeded = false;
    try {
      Slip39.recoverSecret(
        shares.slice(0, threshold - 1).map((s) => s.mnemonic),
        '',
      );
      belowThresholdSucceeded = true;
    } catch {
      // Expected: below the threshold must not reconstruct.
    }
    if (belowThresholdSucceeded) {
      throw new GuardianShareError(
        `${threshold - 1} shares reconstructed a ${threshold}-of-n split. The threshold is ` +
          'not being enforced; refusing to distribute.',
      );
    }
  }
}

export interface GuardianRecoveryAttempt {
  readonly seed: Uint8Array;
  readonly sharesUsed: number;
}

/**
 * Reconstruct the seed from collected shares.
 *
 * Fails closed on every distinguishable wrong input — measured against the
 * library, not assumed: below-threshold sets, shares from two different splits,
 * and a single mistyped word are all refused (the last by SLIP-39's own
 * checksum). What it CANNOT detect is a correct-but-different valid set, which
 * is why the caller must additionally check the reconstructed key against the
 * public key recorded on chain before acting on it.
 */
export function combineGuardianShares(mnemonics: readonly string[]): GuardianRecoveryAttempt {
  if (mnemonics.length === 0) {
    throw new GuardianShareError('No guardian shares were supplied.');
  }

  const prefixes = new Set(mnemonics.map((m) => m.trim().split(/\s+/).slice(0, 2).join(' ')));
  if (prefixes.size > 1) {
    throw new GuardianShareError(
      `These shares come from ${prefixes.size} different splits (${[...prefixes].join(' | ')}). ` +
        'Mixing splits cannot reconstruct anything; collect shares for one patient only.',
    );
  }

  let seed: Uint8Array;
  try {
    seed = Uint8Array.from(withSlip39Runtime(() => Slip39.recoverSecret([...mnemonics], '')));
  } catch (error) {
    throw new GuardianShareError(
      `Guardian shares did not reconstruct a key: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  if (seed.length !== RECOVERY_KEY_SEED_BYTES) {
    throw new GuardianShareError(
      `Reconstructed ${seed.length} bytes, expected ${RECOVERY_KEY_SEED_BYTES}. These shares ` +
        'encode something that is not one of our recovery keys.',
    );
  }

  return { seed, sharesUsed: mnemonics.length };
}
