/**
 * THE DECISION FUNCTION REFUSES WHEN IT CANNOT ESTABLISH SOMETHING.
 *
 * `authoriseProfessional` is the only thing standing between a verified
 * presentation and a privileged action. This file exercises the branches where
 * the honest answer is "I don't know", and asserts that every one of them comes
 * out as a refusal rather than a pass.
 *
 * ---------------------------------------------------------------------------
 * MOVED FROM THE BACKEND, AND WHAT CHANGED IN THE MOVE
 * ---------------------------------------------------------------------------
 * These cases were `backend/tests/fast/professionalAuthorityFailsClosed.test.ts`
 * until the decision itself moved into the SDK (steno #352). The assertions are
 * unchanged. What changed is where revocation comes from, and it is worth being
 * precise about because it is a strengthening, not a port.
 *
 * IN THE BACKEND, every case here refused on revocation as a SIDE EFFECT: with
 * no Credo agent initialised, `checkStatusOnLedger` happened to return
 * `{ checked: false }`. The suite's own header said so, and noted the
 * consequence — no test in the file could ever produce `authorised: true`, so
 * the positive path was reachable only in the live suite. An ambient accident
 * was doing the work of a fixture.
 *
 * HERE THE PORT IS EXPLICIT, so "the list could not be read" is stated rather
 * than arranged, AND THE POSITIVE PATH IS NOW REACHABLE WITHOUT A LEDGER. That
 * matters beyond tidiness: fail-closed code hides its own defects, and until
 * now nothing fast proved this function could return `true` at all. A build in
 * which every check silently failed would have passed the old file completely.
 *
 * ---------------------------------------------------------------------------
 * WHY THE FIXTURE IS HAND-BUILT
 * ---------------------------------------------------------------------------
 * `PresentedLicence` is the shape a presentation verifier only ever emits after
 * signatures, disclosure integrity, nonce, audience and holder binding have all
 * passed. Constructing one directly is therefore not a mock of the boundary —
 * it is the boundary's contract, stated. Nothing in this file re-tests the
 * boundary; that is `presentation.test.ts`.
 */
import { describe, it, expect } from 'vitest';
import {
  PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  PROFESSIONAL_TRUST_ROOTS,
  VC_CONTEXTS,
  collectLogs,
  type CredentialStatus,
  type VerifiableCredential,
} from '@ssi-healthcare/shared';
import {
  authoriseProfessional,
  type PresentedLicence,
  type RevocationPort,
  type RevocationStatus,
} from '../../src/verify';

const PCB = PROFESSIONAL_TRUST_ROOTS.find((a) => a.shortName === 'PCB')!;
const BNMC = PROFESSIONAL_TRUST_ROOTS.find((a) => a.shortName === 'BNMC')!;

const HOLDER = 'did:cheqd:bdhealthtestnet:7cd03fdc-6a88-4895-9d89-e63445abe0c1';
const HOLDER_KEY = `${HOLDER}#key-1`;
const OTHER = 'did:cheqd:bdhealthtestnet:a697648c-7a8a-43b3-825b-7bb50725d764';

const NOW = new Date('2026-08-21T12:00:00.000Z');

/**
 * A revocation port that records what it was asked.
 *
 * Recording rather than merely answering, because the mandatory port's whole
 * value is that it is CONSULTED. A port that were required by the type system
 * and then never called would satisfy every refusal assertion in this file.
 */
function revocationPort(
  answer: RevocationStatus,
): RevocationPort & { readonly asked: (CredentialStatus | undefined)[] } {
  const asked: (CredentialStatus | undefined)[] = [];
  return {
    asked,
    check: async (status) => {
      asked.push(status);
      return answer;
    },
  };
}

/** The list could not be dereferenced. What the backend returns with no agent. */
const UNREADABLE = { revoked: false, checked: false, error: 'no ledger in a fast test' } as const;
/** The list was read and this credential's bit is clear. */
const LIVE = { revoked: false, checked: true } as const;
/** The list was read and this credential's bit is set. */
const REVOKED = { revoked: true, checked: true } as const;

function licence(
  overrides: {
    issuer?: string;
    validFrom?: string;
    validUntil?: string;
    type?: string[];
    subject?: Record<string, unknown>;
  } = {},
): VerifiableCredential {
  return {
    '@context': [VC_CONTEXTS.W3C_CREDENTIALS_V2],
    id: 'urn:uuid:11111111-2222-3333-4444-555555555555',
    type: overrides.type ?? ['VerifiableCredential', PROFESSIONAL_LICENCE_CREDENTIAL_TYPE],
    issuer: overrides.issuer ?? PCB.did,
    validFrom: overrides.validFrom ?? '2026-06-01T00:00:00.000Z',
    validUntil: overrides.validUntil ?? '2027-06-01T00:00:00.000Z',
    credentialSubject: overrides.subject ?? {
      id: HOLDER,
      profession: 'pharmacist',
      licenceNumber: 'PCB-A-9931',
      register: 'Register of Pharmacists, Grade A',
      practiceScope: ['dispense', 'view-patient-record'],
      licenceValidFrom: '2026-02-01T00:00:00.000Z',
      licenceValidUntil: '2027-02-01T00:00:00.000Z',
    },
    credentialStatus: {
      id: `${PCB.did}?resourceName=revocation&resourceType=BitstringStatusListRevocation#7`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '7',
      statusListCredential: `${PCB.did}?resourceName=revocation&resourceType=BitstringStatusListRevocation`,
    },
  };
}

function presented(
  credential: VerifiableCredential,
  cnfKeyId: string | null = HOLDER_KEY,
): PresentedLicence {
  return { credential, cnfKeyId };
}

const DISPENSE = { profession: 'pharmacist', scope: ['dispense'] } as const;

describe('an unreadable status list is a refusal, not a pass', () => {
  it('refuses an otherwise perfect licence and says why', async () => {
    // Everything else about this licence is correct. The ONLY thing missing is
    // a dereferenceable status list — and that alone must be fatal.
    const decision = await authoriseProfessional({
      presented: presented(licence()),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(UNREADABLE),
    });

    expect(decision.authorised).toBe(false);
    expect(decision.checks.notRevoked).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/Revocation status could not be established/);

    // THE ASSERTION THAT CARRIES THE WEIGHT: everything else passed. Without
    // this, a build where all checks failed for unrelated reasons would look
    // identical to one where only revocation was unavailable.
    expect(decision.checks.credentialType).toBe(true);
    expect(decision.checks.claimsDisclosed).toBe(true);
    expect(decision.checks.subjectBinding).toBe(true);
    expect(decision.checks.issuerAccreditedAtIssuance).toBe(true);
    expect(decision.checks.issuerWithinMandate).toBe(true);
    expect(decision.checks.credentialInForce).toBe(true);
    expect(decision.checks.licenceInForce).toBe(true);
    expect(decision.checks.professionMatches).toBe(true);
    expect(decision.checks.scopeCovered).toBe(true);
  });

  it('never hands back an identity on a refusal', async () => {
    // A caller reading `professional` off a failed decision is a caller acting
    // on unproven claims. The easiest way to make that impossible is to not
    // populate it.
    const decision = await authoriseProfessional({
      presented: presented(licence()),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(UNREADABLE),
    });
    expect(decision.professional).toBeUndefined();
  });
});

describe('the credential has to be a licence at all', () => {
  it('refuses a lab result and does not read licence claims off it', async () => {
    const decision = await authoriseProfessional({
      presented: presented(licence({ type: ['VerifiableCredential', 'LabResultCredential'] })),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.authorised).toBe(false);
    expect(decision.checks.credentialType).toBe(false);
    // It stopped at the type. Reading subject claims from a credential of
    // another type would be reading claims its issuer never made about
    // professional authority.
    expect(decision.checks.claimsDisclosed).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/is not a ProfessionalLicenceCredential/);
  });
});

describe('the licence has to name the person presenting it', () => {
  it('refuses a licence bound to one key but naming another DID as the professional', async () => {
    // The verification boundary proves the presentation was signed by the key
    // the credential is bound to. It does NOT prove that key belongs to the DID
    // in `credentialSubject.id`. This is the gap between the two.
    const decision = await authoriseProfessional({
      presented: presented(licence(), `${OTHER}#key-1`),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.authorised).toBe(false);
    expect(decision.checks.subjectBinding).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/but was presented by/);
  });

  it('refuses a credential with no holder binding at all', async () => {
    const decision = await authoriseProfessional({
      presented: presented(licence(), null),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.authorised).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/no holder binding/);
  });
});

describe('the issuer has to have been accredited, at the right time, for the right thing', () => {
  it('refuses an issuer that is not a pinned authority', async () => {
    const decision = await authoriseProfessional({
      presented: presented(licence({ issuer: OTHER })),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.authorised).toBe(false);
    expect(decision.checks.issuerAccreditedAtIssuance).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/not a pinned accrediting authority/);
    // Reported once. The chain walk and the issuance-time check both notice,
    // and two entries would read as two separate defects.
    expect(
      decision.reasons.filter((r) => /not a pinned accrediting authority/.test(r)),
    ).toHaveLength(1);
  });

  it('refuses a licence backdated before its authority held a mandate', async () => {
    // TEMPORAL 1. The signature verifies and the licence is in force today; the
    // council simply had no mandate on the date the credential claims.
    const decision = await authoriseProfessional({
      presented: presented(licence({ validFrom: '2025-06-01T00:00:00.000Z' })),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.authorised).toBe(false);
    expect(decision.checks.issuerAccreditedAtIssuance).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/held no mandate at the credential's issuance time/);
  });

  it('refuses a council issuing outside the profession it regulates', async () => {
    const decision = await authoriseProfessional({
      presented: presented(licence({ issuer: BNMC.did })),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.authorised).toBe(false);
    expect(decision.checks.issuerAccreditedAtIssuance).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/BNMC does not accredit 'pharmacist'/);
  });

  it('refuses a licence granting more than the issuing authority may grant', async () => {
    // Scope escalation at the root. The Pharmacy Council's own mandate has no
    // `prescribe` in it, so a pharmacist licence carrying it is void however
    // well signed.
    const decision = await authoriseProfessional({
      presented: presented(
        licence({
          subject: {
            id: HOLDER,
            profession: 'pharmacist',
            licenceNumber: 'PCB-A-9931',
            register: 'Register of Pharmacists, Grade A',
            practiceScope: ['dispense', 'prescribe'],
            licenceValidFrom: '2026-02-01T00:00:00.000Z',
            licenceValidUntil: '2027-02-01T00:00:00.000Z',
          },
        }),
      ),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.authorised).toBe(false);
    expect(decision.checks.issuerWithinMandate).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/beyond the issuing authority's mandate/);
  });
});

describe('two validity windows, checked separately', () => {
  it('refuses when the attestation has expired even though the licence has not', async () => {
    const decision = await authoriseProfessional({
      presented: presented(licence({ validUntil: '2026-07-01T00:00:00.000Z' })),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.checks.credentialInForce).toBe(false);
    expect(decision.checks.licenceInForce).toBe(true);
    expect(decision.reasons.join(' ')).toMatch(/Licence attestation: Expired/);
  });

  it('refuses when the licence has lapsed even though the attestation has not', async () => {
    // The council re-issued the attestation and the underlying registration
    // lapsed anyway. Collapsing the two windows would let the newer envelope
    // silently extend the older right.
    const decision = await authoriseProfessional({
      presented: presented(
        licence({
          subject: {
            id: HOLDER,
            profession: 'pharmacist',
            licenceNumber: 'PCB-A-9931',
            register: 'Register of Pharmacists, Grade A',
            practiceScope: ['dispense', 'view-patient-record'],
            licenceValidFrom: '2025-02-01T00:00:00.000Z',
            licenceValidUntil: '2026-02-01T00:00:00.000Z',
          },
        }),
      ),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.checks.credentialInForce).toBe(true);
    expect(decision.checks.licenceInForce).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/Licence: Expired/);
  });
});

describe('profession and scope', () => {
  it('refuses a pharmacist where a doctor is required', async () => {
    const decision = await authoriseProfessional({
      presented: presented(licence()),
      requirement: { profession: 'doctor', scope: ['prescribe'] },
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.checks.professionMatches).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/requires a doctor; the presented licence is for a pharmacist/);
  });

  it('refuses a scope the licence does not carry, naming it', async () => {
    const decision = await authoriseProfessional({
      presented: presented(licence()),
      requirement: { profession: 'pharmacist', scope: ['dispense', 'write-patient-record'] },
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.checks.scopeCovered).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/does not cover write-patient-record/);
  });

  it('a licence covering more than the route asks for still satisfies it', async () => {
    // Narrowing, not equality. A licence with extra scope is not a mismatch.
    const decision = await authoriseProfessional({
      presented: presented(licence()),
      requirement: { profession: 'pharmacist', scope: ['view-patient-record'] },
      now: NOW,
      revocation: revocationPort(LIVE),
    });
    expect(decision.checks.scopeCovered).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The port itself — new with the move, and the part a refusal test cannot prove
// ---------------------------------------------------------------------------

describe('the revocation port is mandatory AND actually consulted', () => {
  it('authorises a genuine licence when the list says it is live', async () => {
    // THE PAIRED SUCCESS CASE. Everything above asserts a refusal, and a
    // function that returned `authorised: false` unconditionally would pass all
    // of them. This is the one that makes the rest mean something — and it was
    // unreachable in a fast test until revocation became injectable.
    const port = revocationPort(LIVE);
    const decision = await authoriseProfessional({
      presented: presented(licence()),
      requirement: DISPENSE,
      now: NOW,
      revocation: port,
    });

    expect(decision.reasons).toEqual([]);
    expect(decision.authorised).toBe(true);
    expect(Object.values(decision.checks).every(Boolean)).toBe(true);
    expect(decision.professional).toEqual({
      did: HOLDER,
      profession: 'pharmacist',
      licenceNumber: 'PCB-A-9931',
      register: 'Register of Pharmacists, Grade A',
      practiceScope: ['dispense', 'view-patient-record'],
      accreditedBy: PCB.did,
      accreditedByName: 'PCB',
      licenceCredentialId: 'urn:uuid:11111111-2222-3333-4444-555555555555',
    });
  });

  it('asks the port exactly once, with the credential\'s own status entry', async () => {
    // The port being REQUIRED buys nothing if the decision never calls it, and
    // nothing else in this file would notice: a hardcoded `notRevoked = true`
    // passes the success case above and every refusal case as well. So the call
    // is asserted directly, and so is the argument — a decision that asked
    // about some OTHER credential's status entry would be checking the wrong
    // bit while reporting confidently.
    const port = revocationPort(LIVE);
    const credential = licence();
    await authoriseProfessional({
      presented: presented(credential),
      requirement: DISPENSE,
      now: NOW,
      revocation: port,
    });

    expect(port.asked).toHaveLength(1);
    expect(port.asked[0]).toBe(credential.credentialStatus);
  });

  it('refuses when the list is readable and says REVOKED', async () => {
    // Distinct from "could not be read": same refusal, different reason, and an
    // operator must be able to tell a revoked licence from an unreachable
    // ledger. Also unreachable in a fast test before the port existed.
    const decision = await authoriseProfessional({
      presented: presented(licence()),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(REVOKED),
    });

    expect(decision.authorised).toBe(false);
    expect(decision.checks.notRevoked).toBe(false);
    expect(decision.reasons).toContain('Licence has been revoked by its issuing authority');
    expect(decision.reasons.join(' ')).not.toMatch(/could not be established/);
    expect(decision.professional).toBeUndefined();
  });

  it('refuses rather than throwing when a credential carries no status entry at all', async () => {
    // The port decides what an absent entry means; the decision only insists
    // that "nothing to check" is never a pass. A port that answered
    // `{ checked: true, revoked: false }` here would be asserting a list it
    // never named, which is why the backend's binding does not.
    const credential = licence();
    delete credential.credentialStatus;
    const port = revocationPort({ revoked: false, checked: false, error: 'no credentialStatus' });

    const decision = await authoriseProfessional({
      presented: presented(credential),
      requirement: DISPENSE,
      now: NOW,
      revocation: port,
    });

    expect(port.asked).toEqual([undefined]);
    expect(decision.authorised).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/no credentialStatus/);
  });
});

describe('logging survives the move out of the backend', () => {
  it('logs the refusal with the DEDUPED reasons the caller was given', async () => {
    // Log lines are how this project debugs incidents, and a service that
    // quietly logs nothing after being extracted is the failure the LoggerPort
    // was introduced to make visible (#350). An operator comparing a log line
    // to a 403 body must see the same list.
    const log = collectLogs();
    const decision = await authoriseProfessional({
      presented: presented(licence({ issuer: OTHER })),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
      log,
    });

    expect(decision.authorised).toBe(false);
    const warned = log.entries.filter((e) => e.level === 'warn');
    expect(warned).toHaveLength(1);
    expect(warned[0]!.message).toBe('Professional authority REFUSED');
    expect(warned[0]!.context?.reasons).toEqual(decision.reasons);
  });

  it('logs the success with the granted scope, not the whole licence', async () => {
    const log = collectLogs();
    await authoriseProfessional({
      presented: presented(licence()),
      requirement: DISPENSE,
      now: NOW,
      revocation: revocationPort(LIVE),
      log,
    });

    const info = log.entries.filter((e) => e.level === 'info');
    expect(info).toHaveLength(1);
    expect(info[0]!.message).toBe('Professional authority established');
    expect(info[0]!.context).toMatchObject({
      holderDid: HOLDER,
      profession: 'pharmacist',
      accreditedBy: 'PCB',
      grantedFor: DISPENSE.scope,
    });
    // The log is not a second copy of the credential.
    expect(JSON.stringify(info[0]!.context)).not.toMatch(/PCB-A-9931/);
  });

  it('omitting the logger is silence, not a crash', async () => {
    // Deliberate asymmetry with `revocation`, which has no default: a logger
    // asserts nothing, so an integrator who supplies none loses observability
    // rather than gaining an outage.
    await expect(
      authoriseProfessional({
        presented: presented(licence()),
        requirement: DISPENSE,
        now: NOW,
        revocation: revocationPort(LIVE),
      }),
    ).resolves.toMatchObject({ authorised: true });
  });
});
