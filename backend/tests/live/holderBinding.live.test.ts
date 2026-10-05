/**
 * HOLDER BINDING FAILS CLOSED — TESTING_MANUAL.md §4.2.
 *
 * Issuing to a holder DID that does not resolve must produce HTTP 503
 * `HOLDER_BINDING_UNAVAILABLE` and — the part that actually matters — ZERO ROWS
 * PERSISTED.
 *
 * ---------------------------------------------------------------------------
 * WHY THE ROW COUNT IS THE REAL ASSERTION
 * ---------------------------------------------------------------------------
 * An unbound VC 2.0 credential is not a slightly worse credential. Credo 0.6
 * refuses to place a credential with no `cnf` into a presentation at all, so it
 * cannot be used for the only thing a credential is for. A persisted row is
 * therefore a credential the holder believes they have and can never present —
 * a guaranteed future failure, surfacing at a moment and in a stack trace that
 * point nowhere near issuance.
 *
 * A test that asserted only "it threw" would pass against a build that threw
 * AFTER writing the row. Hence the before/after count.
 *
 * ---------------------------------------------------------------------------
 * TRANSIENT vs PERMANENT, AND WHY THE DISTINCTION IS LOAD-BEARING
 * ---------------------------------------------------------------------------
 * `notFound` from the resolver is treated as TRANSIENT (503, retryable),
 * because a stopped validator returns a byte-identical response to a genuinely
 * absent DID. A DID method we can never support is PERMANENT (400,
 * `HOLDER_BINDING_UNSUPPORTED`). Collapsing these two into one code would tell
 * a client to retry forever, or to give up on a DID that would have worked in
 * thirty seconds. Both codes are asserted here so the distinction cannot be
 * quietly simplified away.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS LIVE, AND WHY IT ASSERTS `statusCode` RATHER THAN AN HTTP RESPONSE
 * ---------------------------------------------------------------------------
 * The property is "the real resolver, talking to the real chain, failed to find
 * a DID, and the real database is still empty". A mocked resolver would decide
 * the outcome of the test by fiat.
 *
 * It calls `issueCredential` rather than driving OID4VCI over HTTP because the
 * fail-closed decision lives in `assertHolderBound`, shared by BOTH issuance
 * paths, and `AppError.statusCode` is what the error middleware turns into the
 * 503. Driving the full token flow would add a large amount of setup that tests
 * OAuth, not holder binding. The HTTP layer of this route family is covered by
 * `unsupportedFormat.live.test.ts`, which needs a running backend for a
 * refusal that genuinely lives in a route handler.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import { CREDENTIAL_FORMATS, HealthcareCredentialCategory } from '@ssi-healthcare/shared';
import { createAgent, shutdownAgent } from '../../src/agent/index.js';
import { issueCredential } from '../../src/services/credentialService.js';
import { AppError } from '../../src/middleware/errorHandler.js';
import { db } from '../../src/db/index.js';
import { ISSUER, CLAIMS } from './helpers/liveSdJwt.js';

/**
 * A syntactically valid `did:cheqd` on OUR namespace that has never been
 * written to the ledger. The resolver must genuinely fail to find it — this is
 * not a malformed string that would be rejected by parsing before any lookup
 * happens.
 */
const UNRESOLVABLE_HOLDER = `did:cheqd:bdhealthtestnet:${randomUUID()}`;

/** A DID method this system can never support, for the permanent-failure case. */
const UNSUPPORTED_HOLDER = `did:example:${randomUUID()}`;

beforeAll(async () => {
  await createAgent();
});

afterAll(async () => {
  await shutdownAgent();
});

async function issueTo(subjectDid: string): Promise<unknown> {
  return issueCredential({
    issuerDid: ISSUER,
    subjectDid,
    credentialType: 'LabResultCredential',
    category: HealthcareCredentialCategory.LAB_RESULTS,
    claims: CLAIMS,
    format: CREDENTIAL_FORMATS.SD_JWT_VC,
  });
}

describe('an unresolvable holder DID fails closed', () => {
  it('refuses with 503 HOLDER_BINDING_UNAVAILABLE and persists NOTHING', async () => {
    const before = await db.credential.count();

    let thrown: unknown;
    try {
      await issueTo(UNRESOLVABLE_HOLDER);
    } catch (error) {
      thrown = error;
    }

    // It must have refused at all.
    expect(thrown, 'issuance SUCCEEDED for an unresolvable holder').toBeInstanceOf(AppError);

    const error = thrown as AppError;
    // 503 invites a retry; the resolver may simply have been unreachable.
    expect(error.statusCode).toBe(503);
    expect(error.code).toBe('HOLDER_BINDING_UNAVAILABLE');
    expect(error.details?.holderDid).toBe(UNRESOLVABLE_HOLDER);

    // THE ASSERTION THAT MATTERS: no row leaked past the guard.
    const after = await db.credential.count();
    expect(after).toBe(before);

    // And specifically nothing for this holder, in case another test in the
    // fork issued concurrently and made the totals coincidentally equal.
    const rows = await db.credential.count({ where: { holderDid: UNRESOLVABLE_HOLDER } });
    expect(rows).toBe(0);
  });

  it('leaves no partially-written row under any status', async () => {
    // A row created and then marked FAILED is still a row the holder can see.
    // The guard runs BEFORE `db.credential.create`, and this pins that ordering.
    const any = await db.credential.findFirst({ where: { holderDid: UNRESOLVABLE_HOLDER } });
    expect(any).toBeNull();
  });
});

describe('a permanently unsupportable holder DID is distinguished from a transient one', () => {
  it('a string that is not a DID at all gets 400 HOLDER_BINDING_UNSUPPORTED', async () => {
    // The permanent branch IS reachable — established by measuring the resolver
    // rather than by reading the code. `not-even-a-did` produces
    // `{ error: 'invalidDid' }`, which is in DEFINITIVE_RESOLUTION_ERRORS, so
    // it is classified `no-binding-key` and surfaces as a non-retryable 400.
    //
    // This matters because if NO input reached the permanent branch, the whole
    // transient/permanent split would be dead code dressed up as a safety
    // property.
    let thrown: unknown;
    try {
      await issueTo('not-even-a-did');
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(AppError);
    const error = thrown as AppError;

    expect(error.statusCode).toBe(400);
    expect(error.code).toBe('HOLDER_BINDING_UNSUPPORTED');
    expect(await db.credential.count({ where: { holderDid: 'not-even-a-did' } })).toBe(0);
  });

  it('an unsupported DID METHOD is permanent (400), not retryable', async () => {
    // Credo 0.6 emits `unsupportedDidMethod`; the W3C spelling is `methodNotSupported`.
    // Only the W3C one was in DEFINITIVE_RESOLUTION_ERRORS, so this fell through to a
    // 503 "please retry" for a request that can never succeed (steno #245, fixed #248).
    let thrown: unknown;
    try {
      await issueTo(UNSUPPORTED_HOLDER);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(AppError);
    const error = thrown as AppError;

    expect(error.statusCode).toBe(400);
    expect(error.code).toBe('HOLDER_BINDING_UNSUPPORTED');
    expect(await db.credential.count({ where: { holderDid: UNSUPPORTED_HOLDER } })).toBe(0);
  });
});
