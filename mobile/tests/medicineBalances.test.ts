/**
 * The medicine-balance rule, pinned.
 *
 * The arithmetic joins two things the holder owns — prescriptions (the ceiling)
 * and dispense appends (the consumption) — and the edge cases are the point:
 * an open append must read as pending rather than bought, an abandoned one must
 * consume the ceiling without counting as either, and a credential that states
 * no ceiling must yield "unknown", never an invented number (#163/#184: "could
 * not check" must not read as a value). Every refusal-shaped case is paired with
 * the success it distinguishes from (#345/#347/#352).
 */
import { describe, expect, it } from 'vitest';
import {
  computeMedicineBalances,
  medicineNameFromPrescriptionId,
  readHeldPrescription,
  type HeldPrescription,
  type RecordedDispense,
} from '../src/utils/medicineBalances';

const credentialWith = (subject: Record<string, unknown>) =>
  ({ verifiableCredential: { credentialSubject: subject } }) as unknown;

const dispense = (over: Partial<RecordedDispense> = {}): RecordedDispense => ({
  prescriptionId: 'hms:PAT-1:2026-09-23T00:00:00.000Z:Amoxicillin',
  quantity: 10,
  settledAt: null,
  abandonedReason: null,
  ...over,
});

describe('reading a held prescription out of a credential', () => {
  it('reads the current object shape, ceiling from quantityValue', () => {
    const held = readHeldPrescription(
      credentialWith({ id: 'did:chex:abc', medication: { name: 'Amoxicillin', quantityValue: 30 } }),
    );
    expect(held).toEqual({ medicineName: 'Amoxicillin', prescriptionId: null, authorised: 30 });
  });

  it('reads the legacy string shape, with no ceiling claimed', () => {
    const held = readHeldPrescription(credentialWith({ id: 'did:chex:abc', medication: 'Amoxicillin 500mg' }));
    expect(held).toEqual({ medicineName: 'Amoxicillin 500mg', prescriptionId: null, authorised: null });
  });

  it('carries a stated prescription id through', () => {
    const held = readHeldPrescription(
      credentialWith({ medication: { name: 'Lisinopril', quantityValue: 30 }, prescriptionId: 'hms:X' }),
    );
    expect(held?.prescriptionId).toBe('hms:X');
  });

  it('does not parse a non-numeric quantity into a ceiling', () => {
    const held = readHeldPrescription(credentialWith({ medication: { name: 'Amoxicillin', quantity: 'as needed' } }));
    expect(held?.authorised).toBeNull();
  });

  it('skips a credential that carries no medicine', () => {
    expect(readHeldPrescription(credentialWith({ id: 'did:chex:abc' }))).toBeNull();
    expect(readHeldPrescription(null)).toBeNull();
  });
});

describe('the counter encodes the medicine as the prescription id tail', () => {
  it('reads the name from the last segment', () => {
    expect(
      medicineNameFromPrescriptionId('hms:PAT-1:2026-09-23T00:00:00.000Z:Amoxicillin'),
    ).toBe('Amoxicillin');
  });

  it('returns null when there is nothing to read', () => {
    expect(medicineNameFromPrescriptionId('')).toBeNull();
  });
});

describe('balances: bought, pending, abandoned, left', () => {
  const held: HeldPrescription[] = [
    { medicineName: 'Amoxicillin', prescriptionId: null, authorised: 30 },
  ];

  it('a settled append is bought, and the ceiling comes down', () => {
    const [balance] = computeMedicineBalances(held, [dispense({ quantity: 10, settledAt: '2026-09-28T00:00:00Z' })]);
    expect(balance).toMatchObject({ bought: 10, pending: 0, abandoned: 0, left: 20 });
  });

  it('an OPEN append is pending, never bought', () => {
    // The whole reason the distinction exists: a patient may scan and walk away,
    // and "dispensed" on a token that was never settled would be a lie about
    // medicine they may never have taken (#586).
    const [balance] = computeMedicineBalances(held, [dispense({ quantity: 10 })]);
    expect(balance).toMatchObject({ bought: 0, pending: 10, abandoned: 0, left: 20 });
  });

  it('an abandoned append consumes the ceiling without being bought or pending', () => {
    const [balance] = computeMedicineBalances(held, [
      dispense({ quantity: 10, abandonedReason: 'declined' }),
    ]);
    expect(balance).toMatchObject({ bought: 0, pending: 0, abandoned: 10, left: 20 });
  });

  it('mixed appends add up: bought + pending + abandoned + left = authorised', () => {
    const [balance] = computeMedicineBalances(held, [
      dispense({ quantity: 10, settledAt: '2026-09-28T00:00:00Z' }),
      dispense({ quantity: 5 }),
      dispense({ quantity: 3, abandonedReason: 'declined' }),
    ]);
    expect(balance).toMatchObject({ bought: 10, pending: 5, abandoned: 3, dispensed: 18, left: 12 });
    expect(balance.bought + balance.pending + balance.abandoned + (balance.left ?? 0)).toBe(30);
  });

  it('no dispenses: everything is left, nothing was bought', () => {
    const [balance] = computeMedicineBalances(held, []);
    expect(balance).toMatchObject({ bought: 0, pending: 0, dispensed: 0, left: 30 });
  });

  it('no stated ceiling: left is UNKNOWN, not zero or the dispensed count', () => {
    const [balance] = computeMedicineBalances(
      [{ medicineName: 'Amoxicillin', prescriptionId: null, authorised: null }],
      [dispense({ quantity: 10, settledAt: '2026-09-28T00:00:00Z' })],
    );
    expect(balance).toMatchObject({ bought: 10, left: null });
  });

  it('never renders a negative ceiling: overshoot floors left at zero', () => {
    const [balance] = computeMedicineBalances(held, [
      dispense({ quantity: 30, settledAt: '2026-09-28T00:00:00Z' }),
      dispense({ quantity: 5, settledAt: '2026-09-29T00:00:00Z' }),
    ]);
    expect(balance).toMatchObject({ dispensed: 35, left: 0 });
  });

  it('ignores a nonsensical quantity rather than counting it', () => {
    const [balance] = computeMedicineBalances(held, [dispense({ quantity: -4 }), dispense({ quantity: 2 })]);
    expect(balance).toMatchObject({ dispensed: 2, pending: 2, left: 28 });
  });
});

describe('joining appends to prescriptions', () => {
  it('prefers an exact prescription id', () => {
    const balances = computeMedicineBalances(
      [
        { medicineName: 'Amoxicillin', prescriptionId: 'hms:PAT-1:2026-09-23T00:00:00.000Z:Amoxicillin', authorised: 30 },
        { medicineName: 'Amoxicillin', prescriptionId: 'hms:PAT-2:2026-09-24T00:00:00.000Z:Amoxicillin', authorised: 30 },
      ],
      [dispense({ prescriptionId: 'hms:PAT-2:2026-09-24T00:00:00.000Z:Amoxicillin', quantity: 7, settledAt: 'x' })],
    );
    const second = balances.find((b) => b.prescriptionId === 'hms:PAT-2:2026-09-24T00:00:00.000Z:Amoxicillin');
    const first = balances.find((b) => b.prescriptionId === 'hms:PAT-1:2026-09-23T00:00:00.000Z:Amoxicillin');
    expect(second).toMatchObject({ bought: 7, left: 23 });
    expect(first).toMatchObject({ bought: 0, left: 30 });
  });

  it('falls back to a UNIQUE medicine name when ids do not match', () => {
    const balances = computeMedicineBalances(
      [{ medicineName: 'Amoxicillin', prescriptionId: 'urn:uuid:elsewhere', authorised: 30 }],
      [dispense({ quantity: 10, settledAt: 'x' })],
    );
    expect(balances).toHaveLength(1);
    expect(balances[0]).toMatchObject({ bought: 10, left: 20 });
  });

  it('does NOT attach an ambiguous name to one of two prescriptions', () => {
    // Two same-name prescriptions and one name-only append: attaching it to the
    // first would silently credit one ceiling and debit the other. It stays its
    // own row, where it is visible rather than wrong.
    const balances = computeMedicineBalances(
      [
        { medicineName: 'Amoxicillin', prescriptionId: null, authorised: 30 },
        { medicineName: 'Amoxicillin', prescriptionId: null, authorised: 30 },
      ],
      [dispense({ quantity: 10 })],
    );
    const unmatched = balances.find((b) => b.key.startsWith('dispense:'));
    expect(unmatched).toMatchObject({
      medicineName: 'Amoxicillin',
      authorised: null,
      dispensed: 10,
      pending: 10,
      left: null,
    });
    expect(balances.filter((b) => b.authorised === 30)).toHaveLength(2);
  });

  it('gives same-name prescriptions with no id UNIQUE list keys', () => {
    // Measured on the handset: three id-less Lisinopril prescriptions produced
    // duplicate React keys and the list raised "Encountered two children with
    // the same key". The position is the only available discriminator.
    const balances = computeMedicineBalances(
      [
        { medicineName: 'Lisinopril', prescriptionId: null, authorised: null },
        { medicineName: 'Lisinopril', prescriptionId: null, authorised: null },
        { medicineName: 'Lisinopril', prescriptionId: null, authorised: null },
      ],
      [],
    );
    const keys = balances.map((b) => b.key);
    expect(new Set(keys).size).toBe(3);
  });

  it('shows an append whose prescription is not held, named from its id', () => {
    const balances = computeMedicineBalances([], [dispense({ quantity: 10, settledAt: 'x' })]);
    expect(balances).toHaveLength(1);
    expect(balances[0]).toMatchObject({
      medicineName: 'Amoxicillin',
      prescriptionId: 'hms:PAT-1:2026-09-23T00:00:00.000Z:Amoxicillin',
      authorised: null,
      bought: 10,
      left: null,
    });
  });
});
