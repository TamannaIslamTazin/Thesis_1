/**
 * THE ADAPTER REALLY BINDS THE LEDGER AND REALLY BINDS WINSTON.
 *
 * The decision itself moved to `@ssi-healthcare/sdk/verify` (steno #352) and is
 * tested there, against injected ports. What CANNOT be tested there is whether
 * this deployment injects the right things — and that is the half where a
 * mistake is invisible.
 *
 * WHY THIS FILE HAS TO EXIST. Making `revocation` mandatory in the SDK stops an
 * integrator from silently getting `notRevoked: true` for a list nobody read.
 * It does not stop an integrator from satisfying the type with something inert.
 * A backend that bound `revocation` to `async () => ({ revoked: false, checked:
 * true })` would compile, would pass every test in the SDK suite, would return
 * `authorised: true` for revoked licences in production, and nothing else in
 * this repository would notice. The type system moved the failure from silent
 * to constructible; only an assertion about the WIRING closes it.
 *
 * The same argument applies to the logger, one notch weaker: `log` is optional
 * and defaults to silence, so a backend that simply forgot to pass one would
 * lose every professional-authority log line without a single test going red.
 *
 * NO LEDGER AND NO AGENT HERE, deliberately — `checkStatusOnLedger` returns
 * `{ checked: false }` with the agent's own error rather than throwing, and
 * that error string is what makes the binding identifiable.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Transport from 'winston-transport';
import {
  PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  PROFESSIONAL_TRUST_ROOTS,
  VC_CONTEXTS,
  type VerifiableCredential,
} from '@ssi-healthcare/shared';
import { authoriseProfessional } from '../../src/services/professionalAuthority.js';
import { checkStatusOnLedger } from '../../src/services/statusListService.js';
import { logger } from '../../src/utils/logger.js';

const PCB = PROFESSIONAL_TRUST_ROOTS.find((a) => a.shortName === 'PCB')!;
const HOLDER = 'did:cheqd:bdhealthtestnet:7cd03fdc-6a88-4895-9d89-e63445abe0c1';
const NOW = new Date('2026-08-21T12:00:00.000Z');

function licence(): VerifiableCredential {
  return {
    '@context': [VC_CONTEXTS.W3C_CREDENTIALS_V2],
    id: 'urn:uuid:11111111-2222-3333-4444-555555555555',
    type: ['VerifiableCredential', PROFESSIONAL_LICENCE_CREDENTIAL_TYPE],
    issuer: PCB.did,
    validFrom: '2026-06-01T00:00:00.000Z',
    validUntil: '2027-06-01T00:00:00.000Z',
    credentialSubject: {
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

const DISPENSE = { profession: 'pharmacist', scope: ['dispense'] } as const;

describe('the exported signature did not change for callers', () => {
  it('takes the same options it always did, with no port in sight', async () => {
    // `requireProfessional` and the live suite call it exactly like this and
    // were not edited. Supplying the ports is a deployment decision and must
    // not be reachable from a request.
    const decision = await authoriseProfessional({
      presented: { credential: licence(), cnfKeyId: `${HOLDER}#key-1` },
      requirement: DISPENSE,
      now: NOW,
    });
    expect(decision.authorised).toBe(false);
    expect(decision.checks.credentialType).toBe(true);
  });
});

describe('the revocation port is bound to the real ledger reader', () => {
  it('reports the error checkStatusOnLedger itself produces, not a generic one', async () => {
    // THE DISCRIMINATING ASSERTION. Rather than matching a hardcoded string —
    // which any stub could be written to satisfy — this calls the real
    // `checkStatusOnLedger` with the same input and requires the refusal to
    // quote ITS answer verbatim. An inert or substituted port cannot pass, and
    // the assertion cannot rot when the agent's message changes.
    const credential = licence();
    const direct = await checkStatusOnLedger(credential.credentialStatus);

    // Guard the premise: if a live agent ever appeared in the fast suite this
    // test would be asserting nothing, so say so loudly instead.
    expect(direct.checked).toBe(false);
    expect(typeof direct.error).toBe('string');

    const decision = await authoriseProfessional({
      presented: { credential, cnfKeyId: `${HOLDER}#key-1` },
      requirement: DISPENSE,
      now: NOW,
    });

    expect(decision.checks.notRevoked).toBe(false);
    expect(decision.reasons.join(' ')).toContain(
      `Revocation status could not be established (${direct.error})`,
    );
  });

  it('refuses an otherwise perfect licence, so the port is load-bearing', async () => {
    // Every other check on this credential passes. The refusal is attributable
    // to revocation alone — which is what makes the assertion above a statement
    // about the port rather than about the fixture.
    const decision = await authoriseProfessional({
      presented: { credential: licence(), cnfKeyId: `${HOLDER}#key-1` },
      requirement: DISPENSE,
      now: NOW,
    });

    const { notRevoked, ...rest } = decision.checks;
    expect(notRevoked).toBe(false);
    expect(Object.values(rest).every(Boolean)).toBe(true);
    expect(decision.professional).toBeUndefined();
  });
});

describe('the logger is bound to real winston, not left to default to silence', () => {
  let seen: Record<string, unknown>[];
  let capture: Transport;

  beforeEach(() => {
    seen = [];
    class CapturingTransport extends Transport {
      override log(info: Record<string, unknown>, next: () => void): void {
        seen.push({ ...info });
        next();
      }
    }
    capture = new CapturingTransport();
    logger.add(capture);
  });

  afterEach(() => {
    logger.remove(capture);
  });

  it('emits the refusal through the real transport chain', async () => {
    // Captured from winston itself rather than from a collector handed to the
    // SDK: a `collectLogs()` here would prove the SDK logs, which is already
    // proven in the SDK, and would say nothing about what this backend passes.
    const decision = await authoriseProfessional({
      presented: { credential: licence(), cnfKeyId: `${HOLDER}#key-1` },
      requirement: DISPENSE,
      now: NOW,
    });

    const refusals = seen.filter((e) => e.message === 'Professional authority REFUSED');
    expect(refusals).toHaveLength(1);
    expect(refusals[0]!.level).toBe('warn');
    // The structured context survives the port, which is the property #350
    // exists to protect — an incident query filters on these fields.
    expect(refusals[0]!.reasons).toEqual(decision.reasons);
    expect(refusals[0]!.holderDid).toBe(HOLDER);
  });
});
