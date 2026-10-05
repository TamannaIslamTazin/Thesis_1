/**
 * A JSON / `ldp_vp` PRESENTATION MUST BE REFUSED EXPLICITLY (P3, steno #234).
 *
 * The JSON-LD Data Integrity branch of `/oid4vp/response` was removed: our
 * `did:cheqd` documents declare a `jws-2020` context Credo 0.6's cached loader
 * does not carry, and they use `JsonWebKey2020` verification methods that no
 * Credo Data Integrity suite consumes. Reviving it is a feature, not a bug fix.
 * Until then a JSON VP is UNSUPPORTED and must be refused.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS TEST REJECTS BOTH A 2xx AND A `200 {verified:false}`
 * ---------------------------------------------------------------------------
 * The danger with a removed code path is not that it errors — it is that it
 * SILENTLY SUCCEEDS with an empty result. This route family has produced that
 * bug twice:
 *
 *   - a JWT VP nested under `vp` made the per-credential loop iterate nothing,
 *     and the route returned `verified: true` with an empty error list;
 *   - `vp+sd-jwt` fell through to a JWT reader that SUCCEEDED and returned a
 *     digest-only husk.
 *
 * Both looked like success. So "not a 2xx" is asserted separately from "carries
 * an attributable unsupported-format reason", and a `200` with
 * `verified:false` fails this test just as hard as a `200` with
 * `verified:true` — because the former would mean the request reached
 * verification logic it should never have reached.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS ONE NEEDS A RUNNING BACKEND WHEN THE OTHER LIVE TESTS DO NOT
 * ---------------------------------------------------------------------------
 * The refusal lives in the ROUTE HANDLER, not in a service. There is no
 * function to call: the property is "an HTTP request shaped like this gets a
 * 400 back", including the error middleware's status mapping and the fact that
 * the throw sits outside any try/catch that could swallow it. The other live
 * files exercise services directly and need only the agent, chain and database.
 *
 * Harvested from `packages/backend/scripts/probe-p3-jsonvp.mts`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import { db } from '../../src/db/index.js';

const BASE_URL = process.env.LIVE_TEST_BASE_URL ?? `http://localhost:${process.env.PORT ?? 3001}`;

/** Presentation rows this file created, cleaned up afterwards. */
const seededRowIds: string[] = [];

beforeAll(async () => {
  // Scoped to THIS file: the other live tests drive services directly and must
  // not be made to depend on a running HTTP server. Failing loudly rather than
  // skipping, for the reason given in setup/requireLiveStack.ts.
  let status: number;
  try {
    const response = await fetch(`${BASE_URL}/api/health`, {
      signal: AbortSignal.timeout(10_000),
    });
    status = response.status;
  } catch (error) {
    throw new Error(
      `LIVE HTTP PRECONDITION FAILED — the backend is not reachable at ${BASE_URL} ` +
        `(${error instanceof Error ? error.message : String(error)}).\n\n` +
        '  cd /home/ahsan/Work/Project/BDHealthTrust/SSI_healthcare && pnpm dev:backend\n\n' +
        'This test asserts on an HTTP status produced by a route handler and its ' +
        'error middleware. There is nothing meaningful to assert without them.',
    );
  }
  if (status !== 200) {
    throw new Error(`Backend at ${BASE_URL} answered /api/health with ${status}, expected 200`);
  }
});

afterAll(async () => {
  if (seededRowIds.length > 0) {
    await db.presentation.deleteMany({ where: { id: { in: seededRowIds } } });
  }
});

/** Seed a fresh REQUESTED presentation the way a real verifier would. */
async function seedRequest(): Promise<{ requestId: string; nonce: string; id: string }> {
  const requestId = randomUUID();
  const nonce = randomUUID();
  const row = await db.presentation.create({
    data: {
      verifierDid: 'did:cheqd:bdhealthtestnet:p8-regression-verifier',
      requestId,
      nonce,
      presentationType: 'FULL',
      requestedCredentials: { types: ['VaccinationCredential'] },
      status: 'REQUESTED',
      expiresAt: new Date(Date.now() + 15 * 60 * 1000),
    },
  });
  seededRowIds.push(row.id);
  return { requestId, nonce, id: row.id };
}

async function submit(vpToken: unknown, nonce?: string) {
  const { requestId, nonce: seededNonce, id } = await seedRequest();

  const body = {
    vp_token:
      nonce === 'MATCHING' && typeof vpToken === 'object' && vpToken !== null
        ? { ...(vpToken as Record<string, unknown>), nonce: seededNonce }
        : vpToken,
    presentation_submission: {
      id: randomUUID(),
      definition_id: requestId,
      descriptor_map: [{ id: 'p8', format: 'ldp_vp', path: '$.verifiableCredential[0]' }],
    },
    state: requestId,
  };

  const response = await fetch(`${BASE_URL}/oid4vp/response`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
    row: await db.presentation.findUnique({ where: { id } }),
  };
}

/** The shape the removed Data Integrity branch used to handle. */
const JSON_LD_VP = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiablePresentation'],
  holder: 'did:cheqd:bdhealthtestnet:attacker-controlled',
  verifiableCredential: [
    {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'VaccinationCredential'],
      issuer: 'did:cheqd:bdhealthtestnet:some-hospital',
      issuanceDate: '2026-01-01T00:00:00Z',
      credentialSubject: { id: 'did:cheqd:bdhealthtestnet:patient', vaccine: 'MMR' },
    },
  ],
  proof: {
    type: 'Ed25519Signature2020',
    created: '2026-08-20T00:00:00Z',
    verificationMethod: 'did:cheqd:bdhealthtestnet:attacker-controlled#key-1',
    proofPurpose: 'authentication',
    proofValue: 'z2c0ffee',
  },
};

const CASES: Array<[string, unknown]> = [
  ['a JSON-LD VP with a Data Integrity proof', JSON_LD_VP],
  ['a bare JSON object with no proof at all', { type: ['VerifiablePresentation'], holder: 'did:cheqd:bdhealthtestnet:whoever' }],
  ['an empty JSON object', {}],
];

describe('POST /oid4vp/response refuses JSON / ldp_vp presentations', () => {
  for (const [label, vpToken] of CASES) {
    it(`${label} → explicit 400, never a 2xx`, async () => {
      const { status, body, row } = await submit(vpToken);

      // 1. NOT a silent fall-through.
      expect(status, `expected a 4xx, got ${status}`).toBeGreaterThanOrEqual(400);
      expect(status).toBe(400);
      expect(body.success).toBe(false);

      // 2. Attributable, so an operator can tell WHY it was refused.
      const error = body.error as {
        code?: string;
        message?: string;
        details?: Record<string, unknown>;
      };
      expect(error).toBeDefined();
      expect(error.code).toBe('PRESENTATION_INVALID');
      expect(error.message).toMatch(/unsupported presentation format/i);
      expect(error.details?.reason).toBe('unsupported_presentation_format');

      // 3. Never recorded as verified.
      expect(row?.verifiedAt).toBeFalsy();
    });
  }

  it('refuses on FORMAT before nonce binding — a matching nonce does not buy a pass', async () => {
    // Ordering matters. If the format check sat after nonce binding, an
    // attacker who obtained a valid nonce would reach verification logic that
    // was deleted, which is the exact "silently succeeds with an empty result"
    // failure this route has already produced twice.
    const { status, body } = await submit(JSON_LD_VP, 'MATCHING');

    expect(status).toBe(400);
    const error = body.error as { details?: Record<string, unknown> };
    expect(error.details?.reason).toBe('unsupported_presentation_format');
  });

  it('never returns 200 with verified:false — that would mean it was verified and failed', async () => {
    // A 200 here is a DIFFERENT bug from a 500, and worse: it means the request
    // reached verification logic it should never have reached, and the result
    // is a statement about a presentation nobody checked.
    for (const [, vpToken] of CASES) {
      const { status, body } = await submit(vpToken);
      expect(status).not.toBe(200);
      expect(body.verified).toBeUndefined();
    }
  });
});
