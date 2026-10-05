/**
 * THE DISCLOSURE-FRAME LEAK.
 *
 * TESTING_MANUAL.md §6.4 calls this "the most dangerous known failure in this
 * system, because it is silent and the type system points the wrong way". This
 * file is the automation of that section.
 *
 * The property, stated precisely: in a disclosure frame, array element indices
 * must be NUMBERS. Written as strings, `@sd-jwt/core` does not throw, does not
 * warn, and does not partially apply the directive — it ignores it and emits
 * the entire array as one cleartext value inside the container's disclosure.
 * A holder who asked to reveal one of three medications reveals all three,
 * including the psychiatric one. Nothing in the issuance or presentation
 * response says so.
 *
 * WHY THIS IS WORTH PINNING RATHER THAN JUST FIXING ONCE. Credo's published
 * `IDisclosureFrame` types `_sd` as `string[]`. Obeying the vendor's own type
 * produces the leak. So the correct code here looks, to a reader and to `tsc`,
 * marginally wrong — which is exactly the kind of code a well-meaning future
 * cleanup deletes. These tests are the thing that objects.
 *
 * WHAT EACH HALF ASSERTS.
 *
 *   1. `@sd-jwt/core` STILL BEHAVES THIS WAY. This is a characterisation test
 *      of a third-party library at its pinned version. If a future bump makes
 *      string indices work, or makes them throw, this test fails — and that is
 *      a SUCCESS, because it tells us the compensating guard's justification
 *      has changed and must be re-read rather than silently carried forward.
 *      A characterisation test that "breaks" on an upstream fix is doing its
 *      job; do not delete it, re-measure and rewrite it.
 *
 *   2. OUR frame builder emits numbers. This is the part we control.
 *
 * No chain, no database, no agent — the leak is a pure payload-construction
 * property, so nothing here needs a live dependency to be trustworthy.
 */
import { describe, it, expect } from 'vitest';
import { buildDisclosureFrame } from '@ssi-healthcare/shared';
import {
  createSdJwtInstance,
  issuerSignedPayload,
  decodedDisclosures,
} from './helpers/sdJwtFixture.js';

/**
 * The subject from the demonstrated leak: one array, three elements, one of
 * which is the claim a patient would most want to withhold.
 */
const SUBJECT = {
  id: 'did:cheqd:bdhealthtestnet:00000000-0000-4000-8000-000000000001',
  medications: ['Metformin 500mg', 'Lisinopril 10mg', 'Sertraline 50mg'],
};

/** An object-member disclosure is `[salt, name, value]`; an element is `[salt, value]`. */
const isMemberDisclosure = (d: unknown[]): boolean => d.length === 3;

/** The `medications` container disclosure, whichever position it landed in. */
function medicationsDisclosure(compact: string): unknown[] | undefined {
  return decodedDisclosures(compact).find(
    (d) => isMemberDisclosure(d) && d[1] === 'medications',
  );
}

async function issueWithIndices(indices: Array<number | string>): Promise<string> {
  const sdJwt = await createSdJwtInstance();
  return sdJwt.issue(
    { credentialSubject: { ...SUBJECT } },
    {
      credentialSubject: {
        _sd: ['medications'],
        medications: { _sd: indices },
      },
    },
  );
}

describe('array indices in a disclosure frame — the silent leak', () => {
  it('NUMERIC indices make each array element individually disclosable', async () => {
    const compact = await issueWithIndices([0, 1, 2]);

    const container = medicationsDisclosure(compact);
    expect(container, 'expected a disclosure for the medications container').toBeDefined();

    // The container's VALUE must be a list of digest references, not values.
    // This is the shape that lets a holder reveal the array while still hiding
    // individual elements.
    const value = container![2] as Array<Record<string, unknown>>;
    expect(Array.isArray(value)).toBe(true);
    expect(value).toHaveLength(3);
    for (const element of value) {
      expect(Object.keys(element)).toEqual(['...']);
      expect(typeof element['...']).toBe('string');
    }

    // And no medication name appears anywhere in the container disclosure.
    const containerJson = JSON.stringify(container);
    for (const medication of SUBJECT.medications) {
      expect(containerJson).not.toContain(medication);
    }

    // The three element values exist as separate, individually withholdable
    // disclosures: four disclosures total, three of them element-shaped.
    const all = decodedDisclosures(compact);
    const elements = all.filter((d) => !isMemberDisclosure(d));
    expect(elements.map((d) => d[1]).sort()).toEqual([...SUBJECT.medications].sort());
  });

  it('STRING indices silently emit the WHOLE array in cleartext', async () => {
    // The directive `{ _sd: ['0','1','2'] }` is what Credo's own IDisclosureFrame
    // type invites you to write.
    const compact = await issueWithIndices(['0', '1', '2']);

    const container = medicationsDisclosure(compact);
    expect(container, 'expected a disclosure for the medications container').toBeDefined();

    // THE LEAK: the container disclosure carries the raw values.
    expect(container![2]).toEqual(SUBJECT.medications);

    // There are no per-element disclosures at all, so a holder disclosing
    // `medications` has no way to withhold any single one of them.
    const elements = decodedDisclosures(compact).filter((d) => !isMemberDisclosure(d));
    expect(elements).toHaveLength(0);
  });

  it('the string-index leak is SILENT — issuance neither throws nor flags it', async () => {
    // The reason a guard is needed at all. If this ever starts rejecting, the
    // library has changed and `assertNothingDisclosableLeaked`'s rationale must
    // be re-read.
    await expect(issueWithIndices(['0', '1', '2'])).resolves.toBeTypeOf('string');
  });

  it('both frames produce an identical, innocent-looking issuer payload', async () => {
    // Why inspecting the signed payload is not enough to catch this, and why
    // the guard has to look at disclosures. In both cases `medications` is
    // correctly replaced by a digest at the top level; the difference is buried
    // one layer down, inside the disclosure.
    const numeric = issuerSignedPayload(await issueWithIndices([0, 1, 2]));
    const strings = issuerSignedPayload(await issueWithIndices(['0', '1', '2']));

    for (const payload of [numeric, strings]) {
      const subject = payload.credentialSubject as Record<string, unknown>;
      expect(subject.medications).toBeUndefined();
      expect(Array.isArray(subject._sd)).toBe(true);
      expect(subject.id).toBe(SUBJECT.id);
    }
    expect(Object.keys(numeric.credentialSubject as object).sort()).toEqual(
      Object.keys(strings.credentialSubject as object).sort(),
    );
  });
});

describe('buildDisclosureFrame emits the safe form', () => {
  it('uses NUMBERS for array indices, never strings', () => {
    const frame = buildDisclosureFrame(SUBJECT)!;
    const subjectFrame = frame.credentialSubject as Record<string, unknown>;
    const medications = subjectFrame.medications as { _sd: unknown[] };

    expect(medications._sd).toEqual([0, 1, 2]);
    for (const index of medications._sd) {
      expect(typeof index).toBe('number');
    }
  });

  it('the frame it builds actually redacts the elements, end to end', async () => {
    // Closes the loop: it is not enough that the frame LOOKS right, it has to
    // survive contact with the library. This is the same assertion as the
    // NUMERIC case above, but driven by production code rather than a literal.
    const sdJwt = await createSdJwtInstance();
    const compact = await sdJwt.issue(
      { credentialSubject: { ...SUBJECT } },
      buildDisclosureFrame(SUBJECT),
    );

    const container = medicationsDisclosure(compact);
    const value = container![2] as Array<Record<string, unknown>>;
    expect(value.every((element) => '...' in element)).toBe(true);

    const elements = decodedDisclosures(compact).filter((d) => !isMemberDisclosure(d));
    expect(elements.map((d) => d[1]).sort()).toEqual([...SUBJECT.medications].sort());
  });
});
