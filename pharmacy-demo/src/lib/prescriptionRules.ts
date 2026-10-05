/**
 * Pure checks over a prescription before anything is written.
 *
 * WHY THIS IS ITS OWN MODULE. These functions are the counter's rules — does the
 * shelf hold the strength the clinician wrote — and they have no business
 * importing a database. They lived in `dispense.ts`, which imports `node:sqlite`
 * through `./db`, so testing them dragged a database driver into a test runner
 * that has no business loading one. A rule that cannot be tested in isolation
 * gets tested through a fixture, and then the ASSERTIONS depend on fixture data
 * rather than on the rule (#185, #272 — the same trap as logic that could not be
 * imported without React Native).
 *
 * No imports, no I/O, no environment. Given the same inputs these return the
 * same answer, which is what makes them safe to call before a write.
 */

/** The strength as it should be compared: lowercase, no internal spaces. */
export function normaliseStrength(value: string): string {
  return value.toLowerCase().replace(/\s+/g, '');
}

/**
 * Does the stocked strength match the prescribed dosage?
 *
 * Returns a refusal REASON, or null when the two agree.
 *
 * Three outcomes, and the distinction between them is the point:
 *
 *   - prescribed and stocked agree              -> null (dispense may proceed)
 *   - prescribed and stocked DISAGREE           -> refusal naming both strengths
 *   - either side is MISSING                    -> refusal saying which side
 *
 * Missing is what makes this fail closed. Treating "no dosage recorded" as "no
 * constraint" is how a check silently becomes a no-op — the same pattern as an
 * unresolvable status list read as "not revoked" (#163/#184).
 *
 * Units are deliberately NOT converted. "1g" against "1000 mg" is a refusal, not
 * a match: conversion is a real need and is not solved here, and guessing at a
 * unit is how a thousand-fold error enters a dispense.
 */
export function compareStrength(
  prescribed: string | undefined,
  medicine: { name: string; strength?: string | null },
): string | null {
  const stocked = (medicine.strength ?? '').trim();
  const wanted = (prescribed ?? '').trim();

  if (wanted.length === 0) {
    return (
      `${medicine.name} cannot be dispensed: the prescription records no dosage, so the ` +
      'strength on the shelf cannot be checked against it.'
    );
  }

  if (stocked.length === 0) {
    return (
      `${medicine.name} is stocked without a strength, so it cannot be matched to the ` +
      `prescribed ${wanted}.`
    );
  }

  if (normaliseStrength(stocked) !== normaliseStrength(wanted)) {
    return (
      `${medicine.name} is stocked as ${stocked} but the prescription is for ${wanted}. ` +
      'Dispense the prescribed strength, or refer the patient back to the prescriber.'
    );
  }

  return null;
}
