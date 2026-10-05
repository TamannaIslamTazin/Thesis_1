/**
 * From a VERIFIED presentation to a token and a pack list.
 *
 * This is the whole of the pharmacy's business logic, and it is deliberately
 * small: match what the prescription asks for against what the shelf holds,
 * price it, mint the token. It never verifies anything itself — verification
 * happened before this is called, and its result is a precondition, not an
 * input this module can be tricked about.
 *
 * WHAT IT REFUSES. A prescription naming a medicine that is not stocked, or
 * more than the shelf holds, is refused WHOLE rather than partly dispensed.
 * Handing over half a course is worse than handing over none, and a partial
 * dispense is the kind of state a counter then has to reconcile by hand.
 */
import { findMedicine, recordDispense, type DispenseLineInput } from './db';
// The counter's rules live in their own module: they are pure, and importing
// node:sqlite to reach them would drag a database driver into every caller.
import { compareStrength } from './prescriptionRules';

export interface PrescriptionItem {
  readonly name: string;
  readonly quantity: number;
  /**
   * The strength the CLINICIAN wrote, e.g. "10mg".
   *
   * The request asked for `medication.dosage` and this dispenser then ignored
   * it, so a claim declared REQUIRED was enforced by the verifier and thrown
   * away here. That made the requirement a lie and — worse — let a counter hand
   * over 5mg against a prescription that said 10mg with nothing to notice.
   *
   * Optional because the legacy `prescription.items[]` shape does not carry one,
   * and because an older credential may predate the field. `null` is NOT the
   * same as absent for enforcement: see `assertStrengthMatches`.
   */
  readonly prescribedStrength?: string;
}

export interface Prescription {
  readonly id: string;
  readonly items: readonly PrescriptionItem[];
}

export type DispenseOutcome =
  | { readonly ok: true; readonly token: number; readonly lines: readonly DispenseLineInput[]; readonly total: number }
  | { readonly ok: false; readonly reason: string };

/**
 * Pull a prescription out of whatever the presentation carried.
 *
 * THE HMS ISSUES `medication`, NOT `prescription`. This read only the latter,
 * so every verified presentation was refused with "carried no prescription to
 * dispense" — the verification had passed and the shape was never consulted
 * against what the issuer actually signs. Measured 23 Sep 2026, on a real
 * presentation from a real doctor.
 *
 * QUANTITY IS DERIVED HERE, AND IT IS NOT IN THE CREDENTIAL. A clinician writes
 * a medicine, a dose and a frequency; a pack count is a PHARMACY's decision
 * made against what is on the shelf. Asking the issuer for one would put a
 * number in a signed credential that no clinician wrote — the same fabrication
 * the HMS's UNTRANSCRIBED licence sentinel exists to prevent. So one course is
 * dispensed per presentation, and the counter adjusts at the bench.
 */
export function readPrescription(claims: Record<string, unknown>): Prescription | null {
  const issued = readIssuedPrescriptionShape(claims);
  if (issued) return issued;

  const legacy = readLegacyPrescriptionShape(claims);
  if (legacy) return legacy;

  return null;
}

/** The shape the hospital issuer signs today. */
function readIssuedPrescriptionShape(claims: Record<string, unknown>): Prescription | null {
  const medication = claims.medication;
  if (!medication || typeof medication !== 'object') return null;

  const med = medication as { name?: unknown; dosage?: unknown; frequency?: unknown };
  if (typeof med.name !== 'string' || med.name.trim().length === 0) return null;

  // Identity for the single-use guarantee. `dispenses.prescription_id` is
  // UNIQUE, so this string is what stops one presentation being redeemed twice.
  // It is built from what the credential actually contains — the medication
  // and the moment it was written — rather than a field that is not there.
  const issuedAt = typeof claims.issuedAt === 'string' ? claims.issuedAt : '';
  const patientId = typeof claims.patientId === 'string' ? claims.patientId : '';
  const id = `hms:${patientId}:${issuedAt}:${med.name}`;

  return { id, items: [{ name: med.name.trim(), quantity: 1, prescribedStrength: readDosage(med) }] };
}

/**
 * The dosage as a comparable string, or undefined when the issuer supplied none.
 *
 * Normalised because the two sides are typed by different people: a clinician
 * writes "10mg", a pharmacist stocks "10 mg", and an equality test on the raw
 * strings would refuse a correct dispense. Spaces are the difference that
 * actually occurs; anything beyond that (mg vs milligram) is deliberately NOT
 * guessed at, because guessing at a unit is how a 1000x error gets in.
 */
function readDosage(med: { dosage?: unknown }): string | undefined {
  return typeof med.dosage === 'string' && med.dosage.trim().length > 0
    ? med.dosage.trim()
    : undefined;
}

/** The shape this dispenser was originally written against. */
function readLegacyPrescriptionShape(claims: Record<string, unknown>): Prescription | null {
  const raw = claims.prescription;
  if (!raw || typeof raw !== 'object') return null;
  const candidate = raw as { id?: unknown; items?: unknown };
  if (typeof candidate.id !== 'string' || !Array.isArray(candidate.items)) return null;

  const items: PrescriptionItem[] = [];
  for (const entry of candidate.items) {
    if (!entry || typeof entry !== 'object') return null;
    const item = entry as { name?: unknown; quantity?: unknown };
    if (typeof item.name !== 'string' || typeof item.quantity !== 'number') return null;
    if (item.quantity <= 0) return null;
    items.push({ name: item.name, quantity: Math.floor(item.quantity) });
  }
  if (items.length === 0) return null;
  return { id: candidate.id, items };
}

export function dispense(prescription: Prescription, dispenseId: string): DispenseOutcome {
  const lines: DispenseLineInput[] = [];

  // Price the WHOLE prescription before writing anything, so a shortage on the
  // last item cannot leave the first ones already deducted from stock.
  for (const item of prescription.items) {
    const medicine = findMedicine(item.name);
    if (!medicine) {
      return { ok: false, reason: `${item.name} is not stocked` };
    }

    // THE STRENGTH MUST MATCH WHAT WAS PRESCRIBED.
    //
    // Refusing here rather than warning: handing over the wrong strength is a
    // dosing error, and the counter has no way to correct it once the packet is
    // out. The request declares `medication.dosage` required, so a presentation
    // that reached this point has stated one; this is where that statement is
    // finally honoured.
    //
    // An ABSENT dosage is refused too — but with a different message, because
    // the two are different problems: one is a shelf mismatch the pharmacist can
    // fix, the other is a credential that predates the field. Collapsing them
    // would tell the counter to go looking for the wrong thing.
    const mismatch = compareStrength(item.prescribedStrength, medicine);
    if (mismatch) return { ok: false, reason: mismatch };

    if (medicine.stock < item.quantity) {
      return {
        ok: false,
        reason: `${medicine.name} has ${medicine.stock} in stock but ${item.quantity} was prescribed`,
      };
    }
    lines.push({
      medicineId: medicine.id,
      name: `${medicine.name}${medicine.strength ? ` ${medicine.strength}` : ''}`,
      quantity: item.quantity,
      unitPrice: medicine.unitPrice,
      lineTotal: Number((medicine.unitPrice * item.quantity).toFixed(2)),
    });
  }

  const total = Number(lines.reduce((sum, line) => sum + line.lineTotal, 0).toFixed(2));
  try {
    const token = recordDispense(prescription.id, lines, dispenseId);
    return { ok: true, token, lines, total };
  } catch (error) {
    // The prescription id is UNIQUE, so a replayed prescription lands here. That
    // is the single-use guarantee doing its job, not a database fault.
    if (String(error).includes('UNIQUE')) {
      return { ok: false, reason: 'This prescription has already been dispensed' };
    }
    throw error;
  }
}
