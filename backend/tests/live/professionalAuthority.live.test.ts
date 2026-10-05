/**
 * ROLE IS A CREDENTIAL — THE FOUR REFUSALS, AGAINST A REAL CHAIN.
 *
 *   1. an unaccredited issuer is refused
 *   2. a revoked licence is refused
 *   3. a valid licence is admitted
 *   4. a licence whose issuer was not authorised AT ISSUANCE TIME is refused
 *
 * Every case runs the whole path: issue a real `vc+sd-jwt` licence signed by a
 * real DID on our ledger, have the holder sign a real `vp+sd-jwt` over it,
 * push it through the hardened verification boundary, and then ask
 * `authoriseProfessional` for a decision.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS CANNOT BE MOCKED
 * ---------------------------------------------------------------------------
 * Case 2 is a BitstringStatusList published as a DID-linked resource on the
 * ledger and dereferenced by `checkStatusOnLedger`. Stubbing the resolver would
 * replace the one thing under test. Case 3 depends on real issuer and holder
 * signatures and on a real `cnf` binding. A stubbed boundary returning
 * `{isValid:true}` would prove that the stub returned what it was told.
 *
 * ---------------------------------------------------------------------------
 * WHY THE TESTNET AUTHORITY IS INJECTED RATHER THAN PINNED
 * ---------------------------------------------------------------------------
 * The shipped root store holds BMDC / BNMC / PCB as inert placeholder DIDs that
 * nobody controls — which is the safe state for a store that has not yet been
 * populated with the councils' real DIDs. To sign a licence we need a DID whose
 * key is in our wallet, and putting THAT into the shipped store would mean a
 * deployment which forgot to swap it would trust a key sitting in a developer's
 * agent. So the store is a parameter with a safe default, and only this file
 * passes a different one. No request can reach that parameter and the guard
 * never passes it.
 *
 * CASE 4 IS EXPRESSED THROUGH THE AUTHORITY'S MANDATE START, NOT A BACKDATED
 * CREDENTIAL. "Issued before the issuer was authorised" is a relation between
 * two instants; moving either one exercises the same comparison, and moving the
 * mandate needs no bypass of the shipped issuance policy. Backdating the
 * credential instead would have required hand-signing outside `issueCredential`,
 * which would also have skipped status-list allocation — and then case 4 would
 * have been refused for a MISSING STATUS LIST rather than for the temporal
 * reason it claims to test. The check is attributed field by field below so
 * that substitution cannot hide.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import {
  CREDENTIAL_FORMATS,
  HealthcareCredentialCategory,
  PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  PROFESSIONAL_TRUST_ROOTS,
  type AccreditationAuthority,
} from '@ssi-healthcare/shared';
import type { Agent } from '@credo-ts/core';
import { createAgent, shutdownAgent } from '../../src/agent/index.js';
import { issueCredential, revokeCredential } from '../../src/services/credentialService.js';
import {
  presentSdJwtCredential,
  signSdJwtPresentation,
  verifySdJwtPresentation,
  type PresentedSdJwtCredential,
} from '../../src/services/sdJwtVc.js';
import { authoriseProfessional } from '../../src/services/professionalAuthority.js';
import { db } from '../../src/db/index.js';
import { ISSUER, HOLDER, VERIFIER_DOMAIN } from './helpers/liveSdJwt.js';

/**
 * The testnet stand-in for an accrediting council.
 *
 * One authority covering all three professions rather than three separate DIDs.
 * Minting per-council DIDs would need `createCheqdDID`, whose controller set is
 * the open owner decision blocking R5 (#242) — and the profession/scope
 * narrowing it would exercise is pure logic, already covered exhaustively in
 * `tests/fast/accreditationTrustRoots.test.ts`. What this tier uniquely proves
 * is that real signatures and a real status list flow through the decision.
 */
const TESTNET_COUNCIL: AccreditationAuthority = {
  did: ISSUER,
  name: 'BDHealthTrust testnet accreditation stand-in',
  shortName: 'TESTNET',
  professions: ['doctor', 'nurse', 'pharmacist'],
  maxScope: [
    'view-patient-record',
    'write-patient-record',
    'prescribe',
    'dispense',
    'administer-medication',
    'order-diagnostic',
  ],
  authorisedFrom: '2026-01-01T00:00:00.000Z',
  placeholder: true,
};

const TESTNET_ROOTS: readonly AccreditationAuthority[] = [TESTNET_COUNCIL];

/** The same council, whose mandate does not begin until well after today. */
const NOT_YET_MANDATED: readonly AccreditationAuthority[] = [
  { ...TESTNET_COUNCIL, authorisedFrom: '2030-01-01T00:00:00.000Z' },
];

const LICENCE_CLAIMS = {
  profession: 'pharmacist',
  licenceNumber: 'PCB-A-9931',
  register: 'Register of Pharmacists, Grade A',
  practiceScope: ['dispense', 'view-patient-record'],
  licenceValidFrom: '2026-02-01T00:00:00.000Z',
  licenceValidUntil: '2030-02-01T00:00:00.000Z',
};

const DISPENSE = { profession: 'pharmacist', scope: ['dispense'] } as const;

let agent: Agent;
/** The row this run issued, so revocation targets it and nothing else. */
let licenceRowId: string;
/** The credential as it reaches the decision, via the verification boundary. */
let presentedLicence: PresentedSdJwtCredential;

/** Issue a licence, present it, and push it through the boundary. */
async function presentFreshLicence(): Promise<PresentedSdJwtCredential> {
  const row = await db.credential.findUnique({ where: { id: licenceRowId } });

  // Full disclosure. Every licence claim is required by
  // `ProfessionalLicenceSubjectSchema`, so a partial frame is refused — which
  // is itself asserted in the fast tier rather than here.
  const disclosed = await presentSdJwtCredential(agent, row!.credentialJwt!, true);

  const nonce = randomUUID();
  const vp = await signSdJwtPresentation(agent, {
    holderDid: HOLDER,
    credential: disclosed,
    challenge: nonce,
    domain: VERIFIER_DOMAIN,
  });

  const verified = await verifySdJwtPresentation(agent, {
    presentation: vp,
    challenge: nonce,
    domain: VERIFIER_DOMAIN,
  });

  // The control for every assertion below. If the boundary rejected this, the
  // authorization refusals that follow would be uninterpretable — they could
  // all be failing on the same unrelated signature problem.
  expect(verified.errors).toEqual([]);
  expect(verified.isValid).toBe(true);
  expect(verified.credentials).toHaveLength(1);

  return verified.credentials[0]!;
}

beforeAll(async () => {
  agent = await createAgent();

  await issueCredential({
    issuerDid: ISSUER,
    subjectDid: HOLDER,
    credentialType: PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
    category: HealthcareCredentialCategory.PROFESSIONAL,
    claims: LICENCE_CLAIMS,
    format: CREDENTIAL_FORMATS.SD_JWT_VC,
  });

  const row = await db.credential.findFirst({
    where: { holderDid: HOLDER, issuerDid: ISSUER, type: { has: PROFESSIONAL_LICENCE_CREDENTIAL_TYPE } },
    orderBy: { createdAt: 'desc' },
  });
  licenceRowId = row!.id;

  presentedLicence = await presentFreshLicence();
});

afterAll(async () => {
  await shutdownAgent();
});

describe('the licence is a real, ledger-backed credential before anything is asserted about it', () => {
  it('was issued as vc+sd-jwt into the PROFESSIONAL folder with a status entry', async () => {
    const row = await db.credential.findUnique({ where: { id: licenceRowId } });

    expect(row!.credentialFormat).toBe(CREDENTIAL_FORMATS.SD_JWT_VC);
    // Filed where a wallet can find it. The Prisma PROFESSIONAL folder had no
    // reachable mapping before R4, so a licence would have landed in GENERAL.
    expect(row!.category).toBe('PROFESSIONAL');
    // Without an allocated status index there is no revocation to check, and
    // case 2 below would be testing nothing.
    expect(row!.statusListId).toBeTruthy();
    expect(row!.statusListIndex).not.toBeNull();
  });

  it('carries the licence claims the issuer signed, not a husk of digests', () => {
    const subject = presentedLicence.credential.credentialSubject as Record<string, unknown>;
    expect(subject.id).toBe(HOLDER);
    expect(subject.profession).toBe('pharmacist');
    expect(subject.practiceScope).toEqual(['dispense', 'view-patient-record']);
  });
});

describe('CASE 3 — a valid licence is admitted', () => {
  it('authorises a pharmacist to dispense, with every check green', async () => {
    const decision = await authoriseProfessional({
      presented: presentedLicence,
      requirement: DISPENSE,
      trustRoots: TESTNET_ROOTS,
    });

    expect(decision.reasons).toEqual([]);
    expect(decision.authorised).toBe(true);

    // Enumerated rather than checked in aggregate. `authorised` is an AND over
    // these, so a check that silently stopped being evaluated would still show
    // green in the aggregate while being false here.
    expect(decision.checks).toEqual({
      credentialType: true,
      claimsDisclosed: true,
      subjectBinding: true,
      issuerAccreditedAtIssuance: true,
      issuerWithinMandate: true,
      notRevoked: true,
      credentialInForce: true,
      licenceInForce: true,
      professionMatches: true,
      scopeCovered: true,
    });

    // Identity is handed over ONLY here, and names who vouched for the holder.
    expect(decision.professional?.did).toBe(HOLDER);
    expect(decision.professional?.profession).toBe('pharmacist');
    expect(decision.professional?.accreditedBy).toBe(ISSUER);
    expect(decision.professional?.licenceNumber).toBe('PCB-A-9931');
  });

  it('refuses the SAME licence for an action it does not cover', async () => {
    // Same credential, same presentation, different requirement. Whatever is
    // being decided here, it is being decided per action and not once per
    // person — which is the difference between a scope and a role.
    const decision = await authoriseProfessional({
      presented: presentedLicence,
      requirement: { profession: 'pharmacist', scope: ['prescribe'] },
      trustRoots: TESTNET_ROOTS,
    });

    expect(decision.authorised).toBe(false);
    expect(decision.checks.scopeCovered).toBe(false);
    // ATTRIBUTION: refused on scope alone. Everything else about the licence
    // was still fine, which is what distinguishes "not allowed to" from
    // "not a valid licence".
    expect(decision.checks.notRevoked).toBe(true);
    expect(decision.checks.issuerAccreditedAtIssuance).toBe(true);
    expect(decision.reasons.join(' ')).toMatch(/does not cover prescribe/);
  });
});

describe('CASE 1 — an unaccredited issuer is refused', () => {
  it('refuses the identical credential against the SHIPPED root store', async () => {
    // Byte-for-byte the presentation that just passed. The only thing that
    // changed is which authorities are pinned — and the real chain's opinion of
    // the signature is unchanged, which is the point: cryptographic validity is
    // not accreditation.
    const decision = await authoriseProfessional({
      presented: presentedLicence,
      requirement: DISPENSE,
      trustRoots: PROFESSIONAL_TRUST_ROOTS,
    });

    expect(decision.authorised).toBe(false);
    expect(decision.checks.issuerAccreditedAtIssuance).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/is not a pinned accrediting authority/);

    // The signature and holder binding were never in doubt; the boundary
    // already passed this artifact. A build that refused here for a signature
    // reason would be refusing for the wrong reason.
    expect(decision.checks.subjectBinding).toBe(true);
    expect(decision.checks.claimsDisclosed).toBe(true);
  });
});

describe('CASE 4 — the issuer was not authorised at the credential issuance time', () => {
  it('refuses a licence issued before its authority held a mandate', async () => {
    const decision = await authoriseProfessional({
      presented: presentedLicence,
      requirement: DISPENSE,
      trustRoots: NOT_YET_MANDATED,
    });

    expect(decision.authorised).toBe(false);
    expect(decision.checks.issuerAccreditedAtIssuance).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(
      /held no mandate at the credential's issuance time/,
    );

    // THE ASSERTION THAT MAKES THIS CASE DISTINCT FROM CASE 2. The credential
    // is NOT revoked — the status list was read from the ledger and says so.
    // Refusal here is entirely about WHEN the issuer held authority, which is
    // the separation #214 insists on: retirement and fraud are different, and
    // a single "is this issuer trusted" boolean cannot express both.
    expect(decision.checks.notRevoked).toBe(true);
    // The authority IS pinned. It simply was not yet mandated on that date.
    expect(decision.reasons.join(' ')).not.toMatch(/not a pinned accrediting authority/);
  });
});

describe('CASE 2 — a revoked licence is refused', () => {
  it('revoking republishes the status list to the ledger', async () => {
    // THE CHECKTX TRAP. Cosmos SDK v0.50 does not execute the message in
    // CheckTx, so a sync broadcast returns code 0 for transactions the module
    // will later reject. A revocation that only succeeded at broadcast is not a
    // revocation, and the assertion below would then be reading Postgres.
    const revoked = await revokeCredential(
      licenceRowId,
      ISSUER,
      'R4 live suite: a revoked licence must lose authority',
    );

    expect(revoked.publishError).toBeFalsy();
    expect(revoked.statusListPublished).toBe(true);
  });

  it('the same professional, freshly presenting, is now refused ON REVOCATION', async () => {
    // A FRESH presentation, not the cached one. The holder still has the
    // credential and can still sign a perfectly valid presentation of it —
    // revocation is not something the holder's wallet enforces, and a test
    // reusing the earlier artifact would leave open whether the refusal came
    // from staleness rather than from the ledger.
    const represented = await presentFreshLicence();

    const decision = await authoriseProfessional({
      presented: represented,
      requirement: DISPENSE,
      trustRoots: TESTNET_ROOTS,
    });

    expect(decision.authorised).toBe(false);

    // ATTRIBUTION. An empty reason list beside `false` is the false pass this
    // project has already shipped once.
    expect(decision.checks.notRevoked).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/revoked by its issuing authority/);

    // And ONLY revocation. The licence is otherwise perfect — same claims, same
    // dates, same accredited issuer. This is what proves the status bit was
    // read rather than the decision failing early for some other reason.
    expect(decision.checks.issuerAccreditedAtIssuance).toBe(true);
    expect(decision.checks.licenceInForce).toBe(true);
    expect(decision.checks.scopeCovered).toBe(true);
    expect(decision.professional).toBeUndefined();
  });
});
