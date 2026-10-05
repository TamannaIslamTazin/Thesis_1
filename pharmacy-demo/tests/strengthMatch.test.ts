/**
 * The counter may only hand over the STRENGTH the clinician wrote.
 *
 * ===========================================================================
 * THE DEFECT THIS PINS (found 24 Sep 2026, pharmacy flow review flaw B)
 * ===========================================================================
 * The pharmacy's OID4VP request declared `medication.dosage` REQUIRED, and
 * `readPrescription` then read only `medication.name` and discarded it. So a
 * claim the verifier enforced was thrown away at the point of dispense, and a
 * shelf holding 5mg could satisfy a prescription for 10mg with nothing to
 * notice. A required field nobody reads is a lie to the next reader — and, at a
 * counter, a dosing error.
 *
 * ===========================================================================
 * WHY THIS IS TESTED AS A PURE FUNCTION
 * ===========================================================================
 * `compareStrength` takes the prescribed dosage and the stocked medicine and
 * returns a refusal reason or null. Testing it through a seeded shelf would make
 * the assertions depend on fixture data, and the property under test is the
 * COMPARISON — including its two failure modes, which are about what is MISSING
 * rather than what is present.
 *
 * EVERY REFUSAL IS PAIRED WITH A SUCCESS. A suite asserting only refusals passes
 * perfectly against a function that refuses everything, which is exactly how a
 * broken counter looks green (#345, #347, #352).
 */
import { describe, expect, it } from 'vitest';
import { compareStrength } from '../src/lib/prescriptionRules';

const stocked = (name: string, strength: string) => ({ name, strength });

describe('prescribed strength must match the shelf', () => {
  // -- Successes. Without these, "refuse everything" passes the rest. --

  it('accepts an exact match', () => {
    expect(compareStrength('10mg', stocked('Lisinopril', '10 mg'))).toBeNull();
  });

  it('accepts a match that differs only in whitespace', () => {
    // The clinician types "10mg"; the shelf says "10 mg". An equality test on
    // the raw strings refuses a CORRECT dispense, which is the failure mode that
    // gets a check switched off in frustration.
    expect(compareStrength('10mg', stocked('Lisinopril', '10 mg'))).toBeNull();
    expect(compareStrength('10 mg', stocked('Lisinopril', '10mg'))).toBeNull();
    expect(compareStrength('500  mg', stocked('Paracetamol', '500 mg'))).toBeNull();
  });

  it('accepts a match that differs only in case', () => {
    expect(compareStrength('500MCG', stocked('Salbutamol Inhaler', '500 mcg'))).toBeNull();
  });

  // -- The refusal that is the point. --

  it('REFUSES the wrong strength, naming both sides', () => {
    const reason = compareStrength('10mg', stocked('Lisinopril', '5 mg'));
    expect(reason).not.toBeNull();
    // The counter has to order the right thing; a message that does not say
    // which strength is prescribed cannot be acted on.
    expect(reason).toContain('5 mg');
    expect(reason).toContain('10mg');
  });

  it('refuses a 10x error, which is the error that harms', () => {
    expect(compareStrength('50mg', stocked('Losartan', '5 mg'))).not.toBeNull();
    expect(compareStrength('5mg', stocked('Losartan', '50 mg'))).not.toBeNull();
  });

  // -- Fail closed on what is MISSING. --

  it('REFUSES when the prescription records no dosage', () => {
    // The pattern this codebase has already been caught by once: "no value" read
    // as "no constraint" (#163/#184, an unresolvable status list as
    // "not revoked"). Absence must refuse, not pass.
    const reason = compareStrength(undefined, stocked('Lisinopril', '10 mg'));
    expect(reason).not.toBeNull();
    expect(reason).toContain('no dosage');
  });

  it('REFUSES when the shelf entry carries no strength', () => {
    // Oral Rehydration Salts are seeded without one. Saying the prescription is
    // unmatched is not enough — the message must name WHICH side is missing, or
    // the pharmacist looks at the prescription for a fault that is not there.
    const reason = compareStrength('10mg', stocked('Oral Rehydration Salts', ''));
    expect(reason).not.toBeNull();
    expect(reason).toContain('without a strength');
  });

  it('does not mistake an empty prescribed string for a match', () => {
    expect(compareStrength('', stocked('Lisinopril', '10 mg'))).not.toBeNull();
    expect(compareStrength('   ', stocked('Lisinopril', '10 mg'))).not.toBeNull();
  });

  it('does not normalise ACROSS units — mg and g are different, and guessing is how magnitude errors enter', () => {
    // Deliberately NOT treated as equal. Unit conversion is a real need and is
    // not solved here; silently converting would be a guess with a 1000x blast
    // radius, so the refusal is the honest answer until units are modelled.
    expect(compareStrength('1g', stocked('Paracetamol', '1000 mg'))).not.toBeNull();
  });
});
