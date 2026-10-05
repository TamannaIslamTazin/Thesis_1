/**
 * THE REVOCATION ROUND TRIP — TESTING_MANUAL.md §5.2, "the load-bearing test".
 *
 *   1. present            → verified: true
 *   2. revoke             → status list republished to the ledger
 *   3. present again      → verified: false, WITH A PER-CREDENTIAL ERROR
 *
 * ---------------------------------------------------------------------------
 * WHY THE ERROR MATTERS MORE THAN THE `false`
 * ---------------------------------------------------------------------------
 * An empty `errors` array alongside `verified:false` is A FALSE PASS, and this
 * project has already shipped exactly that bug: the presentation was nested
 * under `vp`, so the per-credential loop iterated nothing and returned
 * `verified:true` with an empty error list. Expiry, type, signature AND
 * revocation were all silently skipped. A test asserting only `isValid ===
 * false` would have passed against a build where the verification loop never
 * executed at all.
 *
 * So the assertion that carries the weight is the PRESENCE of a named,
 * attributable, per-credential revocation error — that is the only evidence
 * the loop actually ran.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS CANNOT BE FAST
 * ---------------------------------------------------------------------------
 * The status list is a BitstringStatusList published as a DID-linked resource
 * ON THE LEDGER, and `checkStatusOnLedger()` dereferences it. Mocking the
 * resolver would replace the one thing under test. It also has to survive the
 * CheckTx trap: Cosmos SDK v0.50 does not execute the message in CheckTx, so a
 * sync broadcast returns code 0 for transactions the module will reject.
 * `statusListPublished` is asserted separately from the verification result for
 * that reason — a revocation that only succeeded at broadcast is not a
 * revocation.
 *
 * This test REVOKES A REAL CREDENTIAL on a real ledger. It issues its own,
 * every run, and never touches pre-existing rows.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { CREDENTIAL_FORMATS, HealthcareCredentialCategory } from '@ssi-healthcare/shared';
import { createAgent, shutdownAgent } from '../../src/agent/index.js';
import {
  issueCredential,
  verifyCredential,
  revokeCredential,
} from '../../src/services/credentialService.js';
import { presentSdJwtCredential, sdJwtVcToW3cJson } from '../../src/services/sdJwtVc.js';
import { db } from '../../src/db/index.js';
import { ISSUER, HOLDER, CLAIMS } from './helpers/liveSdJwt.js';

/** The row this test issued, so teardown and assertions target it precisely. */
let credentialRowId: string;
/** The selectively-disclosed artifact a verifier would actually receive. */
let disclosedCompact: string;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let seenByVerifier: any;

beforeAll(async () => {
  const agent = await createAgent();

  await issueCredential({
    issuerDid: ISSUER,
    subjectDid: HOLDER,
    credentialType: 'LabResultCredential',
    category: HealthcareCredentialCategory.LAB_RESULTS,
    claims: CLAIMS,
    format: CREDENTIAL_FORMATS.SD_JWT_VC,
  });

  const row = await db.credential.findFirst({
    where: { holderDid: HOLDER, issuerDid: ISSUER },
    orderBy: { createdAt: 'desc' },
  });
  credentialRowId = row!.id;

  // Revocation must bite a SELECTIVELY DISCLOSED credential, not just a full
  // one. `credentialStatus` staying outside the disclosure frame is what makes
  // that possible, and is the property this indirectly pins.
  const disclosed = await presentSdJwtCredential(agent, row!.credentialJwt!, {
    credentialSubject: { hivStatus: true, medications: { 1: true } },
  });
  disclosedCompact = disclosed.encoded;
  seenByVerifier = sdJwtVcToW3cJson(disclosedCompact)!;
});

afterAll(async () => {
  await shutdownAgent();
});

describe('revocation round trip', () => {
  it('STEP 1 — a live, selectively disclosed credential verifies, status checked ON LEDGER', async () => {
    const before = await verifyCredential(seenByVerifier, {
      envelopeJwt: disclosedCompact,
      envelopeFormat: CREDENTIAL_FORMATS.SD_JWT_VC,
    });

    expect(before.errors).toEqual([]);
    expect(before.isValid).toBe(true);
    // Not merely "did not fail" — the revocation check must have RUN and passed.
    expect(before.checks.revocation).toBe(true);
    expect(before.checks.signature).toBe(true);
  });

  it('STEP 2 — revoking publishes the status list to the ledger', async () => {
    const revoked = await revokeCredential(
      credentialRowId,
      ISSUER,
      'P8 regression suite: revocation must bite an SD-JWT',
    );

    // THE CHECKTX TRAP. `statusListPublished` must reflect the committed
    // result, not the broadcast acknowledgement. A `false` here with a
    // `publishError` means the revocation exists only in Postgres, and the
    // verification assertion below would then be testing the database rather
    // than the ledger.
    expect(revoked.publishError).toBeFalsy();
    expect(revoked.statusListPublished).toBe(true);
  });

  it('STEP 3 — the SAME artifact is now rejected, WITH a per-credential error', async () => {
    const after = await verifyCredential(seenByVerifier, {
      envelopeJwt: disclosedCompact,
      envelopeFormat: CREDENTIAL_FORMATS.SD_JWT_VC,
    });

    expect(after.isValid).toBe(false);

    // THE LOAD-BEARING ASSERTION. An empty error list alongside `false` is the
    // false pass this project has already shipped once. The error must exist
    // AND name revocation as the reason.
    expect(after.errors.length).toBeGreaterThan(0);
    expect(after.errors.some((error: string) => /revoked/i.test(error))).toBe(true);

    // ATTRIBUTION: rejected for revocation SPECIFICALLY.
    expect(after.checks.revocation).toBe(false);

    // And the credential is otherwise untouched — the signature still verifies.
    // This is what distinguishes "revoked" from "broken", and it is what proves
    // the loop evaluated the status rather than bailing out early.
    expect(after.checks.signature).toBe(true);
  });

  it('the revocation is recorded in the database as well as on the ledger', async () => {
    const row = await db.credential.findUnique({ where: { id: credentialRowId } });
    expect(row?.status).toBe('REVOKED');
  });
});
