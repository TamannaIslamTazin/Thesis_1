/**
 * Token settlement: the state machine that decides whether a dispense happened.
 *
 * ===========================================================================
 * WHY A TOKEN EXISTS AT ALL
 * ===========================================================================
 * A queue token is minted by the counter when a dispense is authorised, so that
 * the patient can be addressed by number rather than by name. That is its only
 * purpose, and it is deliberately DUMB: it carries no timer, no authority, and it
 * is never signed. The pharmacy's local row id is what it is, and it stays local.
 *
 * ===========================================================================
 * WHY IT IS NOT IN THE SIGNED BYTES
 * ===========================================================================
 * `canonicalAppendMessage` is positional and its order is protocol. Adding the
 * token there would bind a pharmacy's signature to its own database internals,
 * and two pharmacies that choose different token schemes would sign different
 * bytes for the same dispense. The token therefore travels as a SETTLEMENT FIELD
 * beside `dispenseId`, which is the same place and the same kind of thing.
 *
 * ===========================================================================
 * WHY THE BALANCE MOVES ON SETTLEMENT AND NOT ON SCAN
 * ===========================================================================
 * The owner's edge case: a patient may scan a prescription and then decline to
 * buy. Moving the balance at scan would deduct medicine that was never collected,
 * and in a health record that is worse than a missing entry. So a dispense is
 * recorded as an OBLIGATION when issued and becomes a FACT only when settled.
 *
 *   ISSUED      the counter authorised it; the wallet shows the number
 *   SETTLED     the patient paid; the wallet moves the balance
 *   ABANDONED   the patient declined, OR 24h elapsed with no settlement
 *
 * SETTLED and ABANDONED are TERMINAL. A second transition is refused rather than
 * overwriting, which is what stops a double-click in the other direction from
 * reversing a payment (attack tested before implementation).
 *
 * ===========================================================================
 * THE 24-HOUR RULE IS READ-TIME, AND IT IS A CONVENTION
 * ===========================================================================
 * There is no scheduler. The rule is applied where the append is READ: a token
 * issued more than 24 hours ago and still ISSUED reads as ABANDONED (expired).
 *
 * This means the expiry is a CONVENTION, not an enforcement — anyone holding the
 * record could ignore it. That is acceptable for now and is stated here rather
 * than left to look like a guarantee. Making it a guarantee needs a public clock
 * the reader cannot rewind; see __docs__/design/TOKEN-EXPIRY-CLOCK-OWNERSHIP.md
 * (steno #584). A device clock must never be the authority: it is defeatable by
 * changing the phone's date, which is the failure the note exists to record.
 */

/** 24 hours, in milliseconds. The owner's policy; the note explains why it is not a guarantee. */
export const TOKEN_LIFETIME_MS = 24 * 60 * 60 * 1000;

export type TokenState = 'ISSUED' | 'SETTLED' | 'ABANDONED' | 'ABANDONED_EXPIRED';

/** The settlement fields carried beside an append. All optional: legacy rows have none. */
export interface SettlementFields {
  /** The pharmacy's own queue number. Dumb, local, never signed. */
  readonly queueToken?: number;
  readonly settledAt?: string;
  readonly settledBy?: string;
  /** Why it was abandoned. Absent for a settled token. */
  readonly abandonedReason?: 'declined' | 'expired';
}

/**
 * Derive the state of a token from an append's fields and the current time.
 *
 * The `now` argument is injected rather than read from the clock inside, so the
 * expiry boundary can be tested at exactly 24 hours instead of by sleeping. It is
 * still the SERVER's clock that a caller passes; the wallet never calls this with
 * a device time.
 */
export function tokenState(
  fields: SettlementFields,
  issuedAt: string,
  now: number = Date.now(),
): TokenState {
  if (fields.settledAt && !fields.abandonedReason) return 'SETTLED';
  if (fields.abandonedReason === 'declined') return 'ABANDONED';
  if (fields.abandonedReason === 'expired') return 'ABANDONED_EXPIRED';

  const issued = Date.parse(issuedAt);
  // An unparseable issued-at must not silently mean "still alive": that would
  // keep a token in the wallet forever. Treat it as expired, which is the
  // fail-closed direction — the patient collects at the counter and the counter
  // can settle a token whose wallet display has already gone.
  if (Number.isNaN(issued)) return 'ABANDONED_EXPIRED';
  if (now - issued >= TOKEN_LIFETIME_MS) return 'ABANDONED_EXPIRED';
  return 'ISSUED';
}

export class SettlementRefused extends Error {
  constructor(
    message: string,
    /** Machine-readable, so the counter can distinguish the cases rather than parse prose. */
    readonly code: 'ALREADY_TERMINAL' | 'NOT_FOUND' | 'WRONG_PHARMACY',
  ) {
    super(message);
    this.name = 'SettlementRefused';
  }
}

/**
 * Check whether a transition is permitted. Pure: it decides, it does not write.
 *
 * A terminal token refuses EVERY further transition, including one to the same
 * state. That is deliberate: "already settled" arriving twice is a double-click,
 * and answering it as success would hide a fault rather than report one.
 */
export function assertTransitionAllowed(current: TokenState): void {
  if (current === 'SETTLED') {
    throw new SettlementRefused('This token has already been settled.', 'ALREADY_TERMINAL');
  }
  if (current === 'ABANDONED' || current === 'ABANDONED_EXPIRED') {
    throw new SettlementRefused('This token was already closed as not collected.', 'ALREADY_TERMINAL');
  }
}

/** True when the state means the dispense happened. The only state that moves a balance. */
export function isSettled(state: TokenState): boolean {
  return state === 'SETTLED';
}
