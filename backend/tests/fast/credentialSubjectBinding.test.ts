/**
 * A credential may only be presented by its own subject.
 *
 * ===========================================================================
 * THE DEFECT THIS PINS (found 24 Sep 2026, pharmacy flow review flaw A)
 * ===========================================================================
 * The verifier checked that a credential was genuine — signed by an issuer the
 * trust roots accept, unrevoked, unexpired, correctly bound to the presentation's
 * nonce and audience. Every one of those checks passed for a prescription that
 * belonged to SOMEBODY ELSE, because the prescription was genuinely valid; it
 * was simply not the presenter's.
 *
 * Nothing compared the credential's `credentialSubject.id` to the DID that
 * signed the presentation. OID4VP answers "give me a PrescriptionCredential"
 * with any matching credential the holder carries, so a family member's
 * prescription — held by the same wallet, issued earlier — satisfied the request
 * and the counter dispensed against it.
 *
 * ===========================================================================
 * THE SHAPE OF THIS TEST, AND WHY IT IS THIS SHAPE
 * ===========================================================================
 * The check is a pure predicate over (credential subject, presentation holder),
 * so it is tested as one: no database, no HTTP, no signed fixture. That is
 * deliberate — the failure mode being guarded against is a comparison that is
 * MISSING or that treats "cannot read the subject" as "nothing to check", and
 * both are visible in the predicate.
 *
 * EVERY REFUSAL IS PAIRED WITH A SUCCESS. A test suite that only asserts
 * refusals passes perfectly against code that refuses everything, which is how
 * a broken verifier looks green (#345, #347, #352).
 */
import { describe, expect, it } from 'vitest';
import { credentialSubjectId } from '@ssi-healthcare/shared';

/**
 * Mirrors the subject-binding rule in `routes/oid4vp.ts`.
 *
 * Kept as a local copy ON PURPOSE, exactly as credentialOfferHolderMatch.test.ts
 * keeps its clause builder local: the route's copy sits inside a 1000-line
 * handler that needs a signed presentation to reach, and a test that could only
 * run through it would not run at all.
 *
 * If the route's rule changes, this must change with it. The route's comment
 * points here.
 */
function subjectBindingError(
  subjectId: string | null,
  holderDid: string | undefined,
): string | null {
  if (subjectId !== null && holderDid) {
    return subjectId !== holderDid
      ? `presented by ${holderDid} but issued to ${subjectId}`
      : null;
  }
  if (subjectId === null) {
    return 'names no subject, so it cannot be attributed to the presenter';
  }
  return null;
}

const ALICE = 'did:cheqd:bdhealthtestnet:aaaaaaaa-0000-4000-8000-000000000001';
const BOB = 'did:cheqd:bdhealthtestnet:bbbbbbbb-0000-4000-8000-000000000002';

function credentialFor(subject: unknown) {
  return { credentialSubject: subject };
}

describe('credential subject binding', () => {
  // -- The success paths. Without these, "refuse everything" looks correct. --

  it('accepts a credential presented by its own subject', () => {
    const subject = credentialSubjectId(credentialFor({ id: ALICE, medication: {} }));
    expect(subject).toBe(ALICE);
    expect(subjectBindingError(subject, ALICE)).toBeNull();
  });

  it('reads the id even when the subject carries many other claims', () => {
    // The prescription's subject has patientId, patientName, medication,
    // prescribedBy, issuedAt. A reader that took the FIRST key would take
    // `patientId` and compare a serial to a DID — refusing every valid
    // presentation while passing the mismatch test below by accident.
    const subject = credentialSubjectId(
      credentialFor({ patientId: 'PAT-QYBC67PA', id: ALICE, medication: { name: 'Lisinopril' } }),
    );
    expect(subject).toBe(ALICE);
    expect(subjectBindingError(subject, ALICE)).toBeNull();
  });

  // -- The refusal, which is the point. --

  it('REFUSES a valid credential belonging to someone else', () => {
    // Bob presents Alice's prescription. The credential is genuine; Bob is not
    // its subject, and that is the only thing that makes this wrong.
    const subject = credentialSubjectId(credentialFor({ id: ALICE, medication: {} }));
    const error = subjectBindingError(subject, BOB);
    expect(error).not.toBeNull();
    expect(error).toContain(ALICE);
    expect(error).toContain(BOB);
  });

  // -- Fail closed when the subject cannot be read. --

  it('REFUSES a credential with no subject id rather than treating it as unconstrained', () => {
    // "I could not check" and "it is fine" are the two answers this codebase has
    // already confused once (#163/#184: an unresolvable status list read as
    // "not revoked"). A credential that names no subject cannot be attributed to
    // anyone, so it must not be actionable.
    expect(subjectBindingError(credentialSubjectId(credentialFor({})), BOB)).not.toBeNull();
    expect(subjectBindingError(credentialSubjectId(credentialFor({ id: '' })), BOB)).not.toBeNull();
    expect(subjectBindingError(credentialSubjectId(credentialFor(null)), BOB)).not.toBeNull();
    expect(subjectBindingError(credentialSubjectId(credentialFor('not-an-object')), BOB)).not.toBeNull();
    expect(subjectBindingError(credentialSubjectId(credentialFor(undefined)), BOB)).not.toBeNull();
  });

  it('does not confuse a missing subject with a non-string id', () => {
    // A numeric or object id is malformed rather than absent; both must refuse,
    // and neither may be coerced into a string that accidentally matches.
    expect(credentialSubjectId(credentialFor({ id: 12345 }))).toBeNull();
    expect(credentialSubjectId(credentialFor({ id: { nested: ALICE } }))).toBeNull();
    expect(credentialSubjectId({})).toBeNull();
  });
});
