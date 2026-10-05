/**
 * A prescription is an allowance, and the ledger sums against it.
 *
 * ===========================================================================
 * THE DEFECT THIS PINS (flaw C, 24 Sep 2026)
 * ===========================================================================
 * `/api/pharmacy/dispense` treated a prescription as fill-once: it looked for any
 * existing `PRESCRIPTION_DISPENSED` audit row and refused a second dispense as a
 * replay. So a legitimate partial draw-down was impossible, and — the part that
 * matters — nothing summed quantities. A patient could collect 30 tablets at one
 * pharmacy and the same 30 at another, because neither counter nor any shared
 * record knew what the other had handed over.
 *
 * The owner's ruling that makes the ceiling hold: raising the authorisation
 * requires a NEW prescriber-signed credential. So the cap is enforced by the
 * issuer, not by a number hard-coded anywhere.
 *
 * ===========================================================================
 * WHY THIS IS TESTED AS PURE FUNCTIONS
 * ===========================================================================
 * `computeBalance` and `authoriseDispense` take an allowance and the appends and
 * return a sum or a refusal. Testing through the database would make the
 * assertions depend on seeded rows, and the properties under test are about
 * ARITHMETIC and REFUSAL — including what happens when a figure is retried or
 * missing, which is exactly what a fixture tends to hide.
 *
 * EVERY REFUSAL IS PAIRED WITH A SUCCESS. A suite asserting only refusals passes
 * perfectly against a ledger that refuses everything (#345, #347, #352).
 */
import { describe, expect, it } from 'vitest';
import {
  authoriseDispense,
  computeBalance,
  DispenseRefused,
  type DispenseAppend,
} from '../../src/services/dispenseLedger.js';

const PHARMACY_A = 'did:cheqd:bdhealthtestnet:aaaa0000-0000-4000-8000-00000000000a';
const PHARMACY_B = 'did:cheqd:bdhealthtestnet:bbbb0000-0000-4000-8000-00000000000b';

function append(
  partial: Partial<DispenseAppend> & Pick<DispenseAppend, 'dispenseId' | 'quantity'>,
): DispenseAppend {
  return {
    prescriptionId: 'rx-1',
    pharmacyDid: PHARMACY_A,
    dispensedAt: '2026-09-24T00:00:00.000Z',
    ...partial,
  };
}

describe('dispense ledger — the balance', () => {
  it('is the full allowance when nothing has been dispensed', () => {
    expect(computeBalance({ authorised: 30 }, [])).toEqual({
      authorised: 30,
      dispensed: 0,
      remaining: 30,
      complete: false,
    });
  });

  it('subtracts a partial dispense', () => {
    const b = computeBalance({ authorised: 30 }, [append({ dispenseId: 'd1', quantity: 20 })]);
    expect(b.dispensed).toBe(20);
    expect(b.remaining).toBe(10);
    expect(b.complete).toBe(false);
  });

  it('sums across DIFFERENT pharmacies — the whole point of a shared ledger', () => {
    // The owner's exact scenario: 20 at one counter, 10 at another, 30 total.
    const b = computeBalance({ authorised: 30 }, [
      append({ dispenseId: 'd1', quantity: 20, pharmacyDid: PHARMACY_A }),
      append({ dispenseId: 'd2', quantity: 10, pharmacyDid: PHARMACY_B }),
    ]);
    expect(b.dispensed).toBe(30);
    expect(b.remaining).toBe(0);
    expect(b.complete).toBe(true);
  });

  it('counts a RETRIED dispense once, not twice', () => {
    // A counter that times out and retries sends the same dispenseId. Counting it
    // twice would consume the allowance for medicine nobody received.
    const b = computeBalance({ authorised: 30 }, [
      append({ dispenseId: 'd1', quantity: 20 }),
      append({ dispenseId: 'd1', quantity: 20 }),
    ]);
    expect(b.dispensed).toBe(20);
    expect(b.remaining).toBe(10);
  });

  it('never returns a negative remaining, even if appends somehow exceed the allowance', () => {
    // Should not happen once authoriseDispense is the only writer, but a balance
    // of -5 rendered in a wallet is worse than a floor of 0. The excess is
    // visible in `dispensed` for anyone reconciling.
    const b = computeBalance({ authorised: 30 }, [append({ dispenseId: 'd1', quantity: 45 })]);
    expect(b.remaining).toBe(0);
    expect(b.dispensed).toBe(45);
  });
});

describe('dispense ledger — authorisation', () => {
  // -- Successes. Without these, "refuse everything" passes the rest. --

  it('allows a partial dispense and reports the balance', () => {
    const b = authoriseDispense({ authorised: 30 }, [], 20);
    expect(b.remaining).toBe(30);
  });

  it('allows the remainder at a second pharmacy', () => {
    const b = authoriseDispense({ authorised: 30 }, [append({ dispenseId: 'd1', quantity: 20 })], 10);
    expect(b.remaining).toBe(10);
  });

  it('allows a dispense that exactly exhausts the allowance', () => {
    const b = authoriseDispense({ authorised: 30 }, [append({ dispenseId: 'd1', quantity: 20 })], 10);
    expect(b.remaining).toBe(10);
    // The dispense of 10 is permitted; the NEXT one is what must fail.
    const after = computeBalance({ authorised: 30 }, [
      append({ dispenseId: 'd1', quantity: 20 }),
      append({ dispenseId: 'd2', quantity: 10 }),
    ]);
    expect(after.complete).toBe(true);
  });

  // -- The refusals that stop the misuse. --

  it('REFUSES a dispense that would exceed the remaining allowance, and says how much is left', () => {
    let caught: DispenseRefused | null = null;
    try {
      authoriseDispense({ authorised: 30 }, [append({ dispenseId: 'd1', quantity: 20 })], 20);
    } catch (e) {
      caught = e as DispenseRefused;
    }
    expect(caught).not.toBeNull();
    expect(caught?.code).toBe('EXCEEDS_ALLOWANCE');
    // The counter's next question is "how much CAN I give them" — a refusal that
    // does not say sends the patient away for nothing.
    expect(caught?.message).toContain('10');
    expect(caught?.message).toContain('30');
  });

  it('REFUSES any further dispense once the allowance is exhausted', () => {
    let caught: DispenseRefused | null = null;
    try {
      authoriseDispense(
        { authorised: 30 },
        [
          append({ dispenseId: 'd1', quantity: 20 }),
          append({ dispenseId: 'd2', quantity: 10 }),
        ],
        1,
      );
    } catch (e) {
      caught = e as DispenseRefused;
    }
    expect(caught?.code).toBe('ALREADY_COMPLETE');
    // It must point at the only legitimate route to more medicine.
    expect(caught?.message).toMatch(/new prescription/i);
  });

  it('REFUSES a prescription with no allowance rather than treating it as unlimited', () => {
    // Credentials issued before the allowance existed carry none. "I could not
    // check" must never read as "no limit" (#163/#184).
    for (const authorised of [0, -1, Number.NaN, undefined as unknown as number]) {
      let caught: DispenseRefused | null = null;
      try {
        authoriseDispense({ authorised }, [], 5);
      } catch (e) {
        caught = e as DispenseRefused;
      }
      expect(caught?.code).toBe('NO_ALLOWANCE');
    }
  });

  it('REFUSES zero, negative and fractional quantities', () => {
    for (const quantity of [0, -5, 2.5, Number.NaN]) {
      expect(() => authoriseDispense({ authorised: 30 }, [], quantity)).toThrow(DispenseRefused);
    }
  });

  it('does NOT refuse a legitimate dispense because of an unrelated retry', () => {
    // The pairing that makes the retry test meaningful: a retry of d1 consumed
    // nothing extra, so 10 must still be available.
    const appends = [
      append({ dispenseId: 'd1', quantity: 20 }),
      append({ dispenseId: 'd1', quantity: 20 }),
    ];
    expect(() => authoriseDispense({ authorised: 30 }, appends, 10)).not.toThrow();
  });
});
