/**
 * The dispense ledger: how much of a prescription has been drawn down.
 *
 * ===========================================================================
 * WHY THIS EXISTS
 * ===========================================================================
 * A prescription is an ALLOWANCE, not a single event. A doctor authorises 30
 * tablets; a patient may collect 20 at one pharmacy and the remaining 10 at
 * another, or collect all 30 but split across two visits when the first counter
 * is short of stock. The old `/api/pharmacy/dispense` treated it as fill-once:
 * it refused the second dispense as a replay, so a legitimate partial draw-down
 * was impossible, and nothing anywhere summed the quantities. That is how the
 * same 30 tablets could be collected twice with no layer able to notice.
 *
 * THE INVARIANT: the sum of dispensed quantities, across all pharmacies and all
 * time, must not exceed what a prescriber authorised. Raising the authorisation
 * requires a NEW prescriber-signed credential — the owner's ruling, and the
 * reason no hard-coded ceiling is needed here.
 *
 * ===========================================================================
 * THE BALANCE IS RECOMPUTED, NEVER STORED
 * ===========================================================================
 * Owner's decision on attack 1: this is a VERIFIABLE STORE, not a trusted
 * service. There is no mutable "remaining" counter to trust — a disputed tally
 * is re-derived from the append records, so whoever operates the database cannot
 * forge a balance. A stored counter would be an authority; a recomputed sum is
 * an observation.
 *
 * The consequence, and it is deliberate: computing a balance costs a read of the
 * prescription's appends. That is the price of the register having no discretion.
 */

/** One recorded dispense. Signed by the pharmacy that performed it. */
export interface DispenseAppend {
  readonly prescriptionId: string;
  readonly quantity: number;
  /** The DID that performed the dispense. */
  readonly pharmacyDid: string;
  /** Idempotency key: a retry of the SAME dispense must not count twice. */
  readonly dispenseId: string;
  readonly dispensedAt: string;
}

export interface Allowance {
  /** What the prescriber authorised. */
  readonly authorised: number;
  /** The prescriber's own words, for display ("30 tablets"). */
  readonly authorisedText?: string;
}

export interface Balance {
  readonly authorised: number;
  readonly dispensed: number;
  readonly remaining: number;
  /** True when the allowance is exhausted. */
  readonly complete: boolean;
}

/**
 * The balance for one prescription.
 *
 * DUPLICATE `dispenseId`s COUNT ONCE. A counter that retried a timed-out request
 * would otherwise consume the allowance twice for a single sale, and the patient
 * would be recorded as having received medicine they never got. Keyed on the
 * append; the LAST occurrence wins, because a retry carries the same figure.
 */
export function computeBalance(allowance: Allowance, appends: readonly DispenseAppend[]): Balance {
  const byDispenseId = new Map<string, DispenseAppend>();
  for (const append of appends) byDispenseId.set(append.dispenseId, append);

  const dispensed = [...byDispenseId.values()].reduce(
    (sum, append) => sum + append.quantity,
    0,
  );
  const remaining = Math.max(0, allowance.authorised - dispensed);

  return {
    authorised: allowance.authorised,
    dispensed,
    remaining,
    complete: remaining === 0,
  };
}

export class DispenseRefused extends Error {
  constructor(
    message: string,
    readonly code: 'EXCEEDS_ALLOWANCE' | 'NO_ALLOWANCE' | 'ALREADY_COMPLETE',
  ) {
    super(message);
    this.name = 'DispenseRefused';
  }
}

/**
 * May this dispense proceed? Throws a named refusal if not.
 *
 * TWO REFUSALS THE DESIGN REQUIRES, and one it must make impossible:
 *
 *   - A quantity that would EXCEED the allowance is refused, with the remaining
 *     amount in the message — the counter's next question is always "so how much
 *     can I give them", and a refusal that does not say sends them back to the
 *     prescriber for nothing.
 *   - A prescription with NO allowance is refused rather than treated as
 *     unlimited. Credentials issued before the allowance existed carry none, and
 *     "I could not check" must never read as "no limit" (#163/#184's rule).
 *   - Exhausting the allowance exactly is ALLOWED, and completes it.
 *
 * Returns the dispense that may proceed, so the caller does not recompute it and
 * cannot disagree with what was checked.
 */
export function authoriseDispense(
  allowance: Allowance,
  appends: readonly DispenseAppend[],
  requested: number,
): Balance {
  if (!Number.isInteger(requested) || requested <= 0) {
    throw new DispenseRefused(
      `A dispense must be a whole number of units greater than zero, not ${requested}.`,
      'EXCEEDS_ALLOWANCE',
    );
  }

  if (!Number.isFinite(allowance.authorised) || allowance.authorised <= 0) {
    throw new DispenseRefused(
      'This prescription states no authorised quantity, so a dispense cannot be counted ' +
        'against it. It may have been issued before the allowance was recorded.',
      'NO_ALLOWANCE',
    );
  }

  const balance = computeBalance(allowance, appends);

  if (balance.complete) {
    throw new DispenseRefused(
      `All ${balance.authorised} units of this prescription have already been dispensed. ` +
        'A further supply requires a new prescription from the prescriber.',
      'ALREADY_COMPLETE',
    );
  }

  if (requested > balance.remaining) {
    throw new DispenseRefused(
      `Only ${balance.remaining} of ${balance.authorised} units remain on this prescription, ` +
        `so ${requested} cannot be dispensed. A further supply requires a new prescription ` +
        'from the prescriber.',
      'EXCEEDS_ALLOWANCE',
    );
  }

  return balance;
}
