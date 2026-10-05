/**
 * Medicine balances, recomputed from the holder's own data.
 *
 * ===========================================================================
 * WHAT A BALANCE IS, AND WHERE IT IS COMPUTED
 * ===========================================================================
 * "How much of my prescription is left" has one authority: the pharmacy side,
 * which recomputes consumption from the recorded appends and refuses a dispense
 * that would exceed the prescriber's ceiling. The wallet therefore stores no
 * balance of its own. It applies the same rule to the same facts it can see:
 *
 *   dispensed = every append            medicine that has left a shelf
 *   bought    = appends with settledAt  paid for; the dispense is a fact
 *   pending   = open appends            issued at a counter, not settled
 *   abandoned = appends closed as not collected
 *   left      = authorised - dispensed  what any counter will still hand over
 *
 * bought + pending + abandoned + left = authorised, which is what makes the
 * numbers readable together. Nothing here consults a device clock, and no
 * medicine name comes from the operator: names are read from the holder's own
 * credentials and quantities from the holder's own appends.
 *
 * ===========================================================================
 * MATCHING, AND ITS LIMIT
 * ===========================================================================
 * An append is joined to a held prescription by prescription id when the
 * credential states one. Otherwise it is joined by medicine name, which the
 * counter encodes as the last segment of the prescription id it builds
 * (`hms:<patientId>:<issuedAt>:<name>`). Two prescriptions of the same medicine
 * with no id therefore share their dispenses; the id is always preferred when
 * it exists, and an append whose prescription is not held still appears, named
 * from its id and with no ceiling.
 *
 * ===========================================================================
 * WHY THIS FILE IMPORTS NOTHING
 * ===========================================================================
 * It is deliberately free of React Native, so a test can import it directly.
 * Logic that cannot be imported without a device is logic no test ever reaches
 * (steno #185, #272).
 */

export interface HeldPrescription {
  /** The medicine as the holder's own credential names it. */
  readonly medicineName: string;
  /** The prescription's identity as the counter records it, when stated. */
  readonly prescriptionId: string | null;
  /** The prescriber's ceiling; null when the credential states none. */
  readonly authorised: number | null;
}

export interface RecordedDispense {
  readonly prescriptionId: string;
  readonly quantity: number;
  readonly settledAt: string | null;
  readonly abandonedReason: string | null;
}

export interface MedicineBalance {
  /** Stable list key: the prescription id, else the name and its position. */
  readonly key: string;
  readonly medicineName: string;
  readonly prescriptionId: string | null;
  readonly authorised: number | null;
  readonly dispensed: number;
  readonly bought: number;
  readonly pending: number;
  readonly abandoned: number;
  readonly left: number | null;
}

/** The credential body, whether the caller holds a view-model or raw claims. */
function readSubject(credential: unknown): Record<string, unknown> | null {
  if (!credential || typeof credential !== 'object') return null;
  const c = credential as {
    verifiableCredential?: { credentialSubject?: unknown };
    claims?: unknown;
  };
  const subject = c.verifiableCredential?.credentialSubject ?? c.claims;
  return subject && typeof subject === 'object' ? (subject as Record<string, unknown>) : null;
}

function positiveNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : null;
}

/**
 * Pull a held prescription out of a credential.
 *
 * Tolerates both shapes the system has produced: `medication` as an OBJECT (the
 * hospital's current issuance: name, dosage, quantityValue) and as a STRING
 * (older credentials, e.g. "Amoxicillin 500mg"). A credential with no medicine
 * is not a prescription and is skipped, so this doubles as the filter.
 */
export function readHeldPrescription(credential: unknown): HeldPrescription | null {
  const subject = readSubject(credential);
  if (!subject) return null;

  const medication = subject.medication;
  let medicineName: string | null = null;
  let authorised: number | null = null;

  if (typeof medication === 'string' && medication.trim()) {
    medicineName = medication.trim();
  } else if (medication && typeof medication === 'object') {
    const med = medication as { name?: unknown; quantityValue?: unknown; quantity?: unknown };
    if (typeof med.name === 'string' && med.name.trim()) medicineName = med.name.trim();
    // quantityValue first: it is the prescriber's count. `quantity` is a
    // fallback for the legacy shape, and a string ("as needed") is deliberately
    // NOT parsed into a number — guessing a count is how a wrong ceiling enters.
    authorised = positiveNumber(med.quantityValue) ?? positiveNumber(med.quantity);
  }

  if (!medicineName) return null;
  const id = typeof subject.prescriptionId === 'string' && subject.prescriptionId ? subject.prescriptionId : null;
  return { medicineName, prescriptionId: id, authorised };
}

/** The medicine name the counter encoded in a prescription id, or null. */
export function medicineNameFromPrescriptionId(prescriptionId: string): string | null {
  const last = prescriptionId.split(':').pop()?.trim();
  return last ? last : null;
}

function quantityOf(dispense: RecordedDispense): number {
  return positiveNumber(dispense.quantity) ?? 0;
}

/**
 * Join held prescriptions to recorded dispenses and produce one balance each.
 * Pure: same inputs, same output, no clock, no network, no state.
 */
export function computeMedicineBalances(
  held: readonly HeldPrescription[],
  dispenses: readonly RecordedDispense[],
): MedicineBalance[] {
  interface Accumulator {
    key: string;
    medicineName: string;
    prescriptionId: string | null;
    authorised: number | null;
    dispensed: number;
    bought: number;
    pending: number;
    abandoned: number;
  }

  const rows: Accumulator[] = held.map((prescription, index) => ({
    // The id when there is one; otherwise the name AND the position, because
    // two prescriptions of the same medicine with no id are indistinguishable
    // by name alone and duplicate React keys drop rows from the list.
    key: prescription.prescriptionId ?? `name:${prescription.medicineName.toLowerCase()}:${index}`,
    medicineName: prescription.medicineName,
    prescriptionId: prescription.prescriptionId,
    authorised: prescription.authorised,
    dispensed: 0,
    bought: 0,
    pending: 0,
    abandoned: 0,
  }));

  const byId = new Map<string, Accumulator>();
  const byName = new Map<string, Accumulator[]>();
  for (const row of rows) {
    if (row.prescriptionId) byId.set(row.prescriptionId, row);
    // Indexed by name EVEN when the row carries an id: the credential's stored
    // id and the counter's constructed id are different formats in practice
    // (urn:uuid against hms:...), so a failed id match must still be able to
    // fall back to the name. The unique-match guard below keeps that safe.
    const name = row.medicineName.toLowerCase();
    byName.set(name, [...(byName.get(name) ?? []), row]);
  }

  const unmatched: Accumulator[] = [];
  for (const dispense of dispenses) {
    let target = dispense.prescriptionId ? byId.get(dispense.prescriptionId) : undefined;
    if (!target) {
      const name = medicineNameFromPrescriptionId(dispense.prescriptionId);
      const candidates = name ? byName.get(name.toLowerCase()) : undefined;
      // Only a UNIQUE name match attaches; an ambiguous one would silently give
      // one prescription another's dispenses. It becomes its own row instead.
      if (candidates && candidates.length === 1) target = candidates[0];
    }
    if (!target) {
      const name = medicineNameFromPrescriptionId(dispense.prescriptionId) ?? 'Prescription';
      target = unmatched.find((row) => row.prescriptionId === dispense.prescriptionId);
      if (!target) {
        target = {
          key: `dispense:${dispense.prescriptionId}`,
          medicineName: name,
          prescriptionId: dispense.prescriptionId || null,
          authorised: null,
          dispensed: 0,
          bought: 0,
          pending: 0,
          abandoned: 0,
        };
        unmatched.push(target);
      }
    }

    const quantity = quantityOf(dispense);
    target.dispensed += quantity;
    if (dispense.settledAt) target.bought += quantity;
    else if (dispense.abandonedReason) target.abandoned += quantity;
    else target.pending += quantity;
  }

  return [...rows, ...unmatched]
    .map((row): MedicineBalance => ({
      key: row.key,
      medicineName: row.medicineName,
      prescriptionId: row.prescriptionId,
      authorised: row.authorised,
      dispensed: row.dispensed,
      bought: row.bought,
      pending: row.pending,
      abandoned: row.abandoned,
      // Never negative: a wallet must not render "-2 left" if it sees more
      // dispensed than authorised (an id mismatch, or a ceiling changed after
      // issuance). Zero is the honest floor; the excess is visible above it.
      left: row.authorised === null ? null : Math.max(0, row.authorised - row.dispensed),
    }))
    .sort((a, b) => a.medicineName.localeCompare(b.medicineName));
}
