/**
 * The guardian-share ceremony — the part a non-technical person has to complete.
 *
 * ===========================================================================
 * WHAT THIS IS DEFENDING AGAINST, IN LIKELIHOOD ORDER (#240)
 * ===========================================================================
 * #240's low-literacy assessment lists the real failure modes, and they are
 * social rather than cryptographic:
 *
 *   1. SHARE CO-LOCATION — every share in one drawer, or one WhatsApp thread.
 *      This silently collapses a 3-of-5 to a 1-of-1 while looking complete.
 *   2. GUARDIAN CHURN over the years the identity must survive.
 *   3. TRANSCRIPTION ERROR.
 *   4. COERCION and family power dynamics — acute for a HEALTH wallet touching
 *      reproductive or mental-health data.
 *   5. THE LITERACY FLOOR — a Bengali speaker with limited literacy cannot
 *      reliably transcribe a 33-word English mnemonic.
 *
 * (1) is the one this module can actually enforce, and it is also the most
 * dangerous, because a co-located split PASSES every technical check. So
 * confirmation is per-guardian and requires a READ-BACK: a share counts as
 * delivered only when it comes back from where it was sent. Displaying a share
 * proves nothing about whether anyone received it.
 *
 * (5) is why {@link GuardianShare.mnemonic} is treated as a QR payload rather
 * than as words to copy — see `guardianShares.ts`.
 *
 * ===========================================================================
 * WHY THIS IS A STATE MACHINE AND NOT A SEQUENCE OF CALLS (#315)
 * ===========================================================================
 * "Per-step failsafes do not compose." A ceremony whose final step trusts that
 * the earlier steps ran is exactly the join that revoked 79 credentials while
 * re-issuing none: every individual step was correct and the composition was
 * destructive.
 *
 * So {@link GuardianCeremony.complete} does NOT ask "did we run the delivery
 * step?". It recomputes, from the confirmations actually recorded, whether
 * enough DISTINCT guardians have proved possession — and it re-verifies that
 * those confirmed shares still reconstruct the key. Every precondition is
 * re-established from observable state at the moment it is relied on.
 */

import {
  type GuardianPolicy,
  type GuardianShare,
  type GuardianSplit,
  GuardianShareError,
  assertPolicyIsSane,
  combineGuardianShares,
  splitRecoveryKey,
} from './guardianShares.js';
import {
  assertWellFormedSeed,
  recoveryKeyPublicKey,
  zeroise,
} from './recoveryKey.js';

export type CeremonyPhase =
  | 'SPLIT'
  | 'DISTRIBUTING'
  | 'REHEARSAL'
  | 'COMPLETE'
  | 'ABANDONED';

export interface GuardianConfirmation {
  readonly shareIndex: number;
  readonly confirmedAt: Date;
  /** How possession was proved. Kept for the audit trail, not for logic. */
  readonly method: 'QR_READ_BACK' | 'WORD_READ_BACK';
}

export interface CeremonyStatus {
  readonly phase: CeremonyPhase;
  readonly threshold: number;
  readonly guardianCount: number;
  readonly confirmedCount: number;
  readonly outstanding: readonly string[];
  readonly canComplete: boolean;
}

export class GuardianCeremonyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GuardianCeremonyError';
  }
}

/**
 * Drives one patient's guardian split from generation to a proven, rehearsed
 * distribution.
 *
 * HOLDS THE SEED IN MEMORY for its lifetime, which is unavoidable — the RCK is
 * a software key because it must sign cheqd transactions (S-2 §8). The
 * mitigation is lifetime, not avoidance: {@link abandon} and {@link complete}
 * both zeroise, and nothing here ever persists the seed.
 */
export class GuardianCeremony {
  private phase: CeremonyPhase = 'SPLIT';
  private readonly confirmations = new Map<number, GuardianConfirmation>();
  private seed: Uint8Array | null;
  private readonly split: GuardianSplit;
  private rehearsed = false;

  private constructor(seed: Uint8Array, split: GuardianSplit) {
    this.seed = seed;
    this.split = split;
  }

  /**
   * Begin a ceremony over an already-generated seed.
   *
   * The split is verified to reconstruct before any share is shown — see
   * `splitRecoveryKey`, which reproduces the secret from its own output and
   * refuses to return shares that do not.
   */
  static begin(seed: Uint8Array, policy: GuardianPolicy): GuardianCeremony {
    assertWellFormedSeed(seed);
    assertPolicyIsSane(policy);
    const split = splitRecoveryKey(seed, policy);
    const ceremony = new GuardianCeremony(seed, split);
    ceremony.phase = 'DISTRIBUTING';
    return ceremony;
  }

  get shares(): readonly GuardianShare[] {
    return this.split.shares;
  }

  get splitId(): string {
    return this.split.splitId;
  }

  /**
   * The public key the reconstructed seed must produce.
   *
   * Exposed so that recovery can be checked against the LEDGER rather than
   * against anything this process remembers.
   */
  recoveryPublicKey(): Uint8Array {
    if (!this.seed) {
      throw new GuardianCeremonyError('This ceremony no longer holds a seed.');
    }
    return recoveryKeyPublicKey(this.seed);
  }

  /**
   * Record that a guardian proved possession by reading their share back.
   *
   * The read-back is compared against the share we issued. An echo that does
   * not match is refused rather than warned about: a guardian who scanned the
   * wrong QR, or read back a neighbour's share, has NOT got their own, and
   * accepting it here is precisely how a 3-of-5 silently becomes a 2-of-5.
   */
  confirm(
    shareIndex: number,
    readBack: string,
    method: GuardianConfirmation['method'] = 'QR_READ_BACK',
  ): CeremonyStatus {
    this.assertPhase('DISTRIBUTING', 'record a guardian confirmation');

    const share = this.split.shares[shareIndex];
    if (!share) {
      throw new GuardianCeremonyError(
        `No share at index ${shareIndex}; this split has ${this.split.shares.length}.`,
      );
    }

    const normalise = (value: string): string => value.trim().replace(/\s+/g, ' ').toLowerCase();
    if (normalise(readBack) !== normalise(share.mnemonic)) {
      const matchedOther = this.split.shares.findIndex(
        (candidate) => normalise(candidate.mnemonic) === normalise(readBack),
      );
      throw new GuardianCeremonyError(
        matchedOther >= 0
          ? `'${share.guardian.label}' read back the share belonging to ` +
            `'${this.split.shares[matchedOther]!.guardian.label}'. Two guardians holding the ` +
            'same share is a split of one fewer, not of the same size. Re-issue this share.'
          : `'${share.guardian.label}' read back something that is not the share they were ` +
            'given. Nothing has been recorded for them.',
      );
    }

    this.confirmations.set(shareIndex, {
      shareIndex,
      confirmedAt: new Date(),
      method,
    });

    return this.status();
  }

  /**
   * Rehearse recovery in front of the patient, before enrolment commits.
   *
   * #240 asks for this explicitly, and it is the only step that tests the
   * SOCIAL system rather than the cryptographic one: whether the patient can
   * actually get the shares back from the people they chose. Doing it at
   * enrolment is the difference between finding out now and finding out on the
   * day the phone is lost.
   *
   * It reconstructs from the CONFIRMED shares only, because those are the ones
   * that demonstrably exist outside this device.
   */
  rehearse(): { readonly reconstructed: boolean; readonly sharesUsed: number } {
    this.assertPhase('DISTRIBUTING', 'rehearse recovery');

    if (!this.seed) {
      throw new GuardianCeremonyError('This ceremony no longer holds a seed to rehearse against.');
    }

    const confirmed = this.confirmedShares();
    if (confirmed.length < this.split.policy.threshold) {
      throw new GuardianCeremonyError(
        `Cannot rehearse recovery with ${confirmed.length} confirmed shares; the threshold ` +
          `is ${this.split.policy.threshold}. Rehearsing against shares nobody has confirmed ` +
          'would prove only that this device can still do arithmetic.',
      );
    }

    const attempt = combineGuardianShares(
      confirmed.slice(0, this.split.policy.threshold).map((share) => share.mnemonic),
    );

    const matches =
      attempt.seed.length === this.seed.length &&
      attempt.seed.every((byte, index) => byte === this.seed![index]);

    zeroise(attempt.seed);

    if (!matches) {
      throw new GuardianCeremonyError(
        'Rehearsal reconstructed a DIFFERENT key from the confirmed shares. This split is ' +
          'not usable; abandon the ceremony rather than enrolling against it.',
      );
    }

    this.rehearsed = true;
    return { reconstructed: true, sharesUsed: attempt.sharesUsed };
  }

  status(): CeremonyStatus {
    const confirmedCount = this.confirmations.size;
    return {
      phase: this.phase,
      threshold: this.split.policy.threshold,
      guardianCount: this.split.shares.length,
      confirmedCount,
      outstanding: this.split.shares
        .filter((share) => !this.confirmations.has(share.index))
        .map((share) => share.guardian.label),
      canComplete: confirmedCount >= this.split.policy.threshold && this.rehearsed,
    };
  }

  /**
   * Hand the seed over for enrolment, and end the ceremony.
   *
   * #315 IN ONE METHOD. This does not ask whether `confirm` or `rehearse` were
   * called. It recomputes the precondition from what was actually recorded:
   *
   *   - enough DISTINCT guardians confirmed, counted from the map rather than
   *     from a counter something else maintained;
   *   - those confirmed shares STILL reconstruct the seed, re-verified here and
   *     not inherited from the rehearsal;
   *   - the rehearsal happened.
   *
   * A caller that skipped a phase gets a refusal, not a half-provisioned
   * identity that fails years later.
   */
  complete(): Uint8Array {
    this.assertPhase('DISTRIBUTING', 'complete the ceremony');

    if (!this.seed) {
      throw new GuardianCeremonyError('This ceremony no longer holds a seed.');
    }

    const confirmed = this.confirmedShares();
    const threshold = this.split.policy.threshold;

    if (confirmed.length < threshold) {
      throw new GuardianCeremonyError(
        `Only ${confirmed.length} of ${this.split.shares.length} guardians have proved ` +
          `possession, and ${threshold} are needed. Enrolling now would create an identity ` +
          'whose recovery path does not yet exist — and shares cannot be retrofitted ' +
          '(S-2 §8). Outstanding: ' +
          this.status().outstanding.join(', '),
      );
    }

    if (!this.rehearsed) {
      throw new GuardianCeremonyError(
        'Recovery has not been rehearsed with this patient. #240 requires it at enrolment, ' +
          'because it is the only check on whether the patient can actually retrieve shares ' +
          'from the people they nominated.',
      );
    }

    // Re-established, not inherited: prove ONE MORE TIME that the confirmed
    // shares reconstruct this exact seed, at the moment the identity is about
    // to be anchored to it.
    const attempt = combineGuardianShares(
      confirmed.slice(0, threshold).map((share) => share.mnemonic),
    );
    const matches =
      attempt.seed.length === this.seed.length &&
      attempt.seed.every((byte, index) => byte === this.seed![index]);
    zeroise(attempt.seed);

    if (!matches) {
      throw new GuardianCeremonyError(
        'At completion, the confirmed guardian shares no longer reconstruct the key. ' +
          'Refusing to enrol.',
      );
    }

    this.phase = 'COMPLETE';
    const seed = this.seed;
    this.seed = null;
    return seed;
  }

  /**
   * Give up, and leave nothing behind.
   *
   * Distributed shares are residue that cannot be recalled — but they are inert
   * once no DID is anchored to the key, which is why abandonment must happen
   * BEFORE enrolment rather than after it.
   */
  abandon(): void {
    if (this.seed) zeroise(this.seed);
    this.seed = null;
    this.phase = 'ABANDONED';
  }

  private confirmedShares(): GuardianShare[] {
    return [...this.confirmations.keys()]
      .sort((a, b) => a - b)
      .map((index) => this.split.shares[index]!)
      .filter((share): share is GuardianShare => Boolean(share));
  }

  private assertPhase(expected: CeremonyPhase, action: string): void {
    if (this.phase !== expected) {
      throw new GuardianCeremonyError(
        `Cannot ${action}: this ceremony is ${this.phase}, not ${expected}.`,
      );
    }
  }
}

export { GuardianShareError };
