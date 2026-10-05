/**
 * `createCheqdDID` REFUSES TO MINT WITHOUT A NAMED SHAPE ASSERTION — steno #313
 * follow-up.
 *
 * Phase 1 of the role-fusion audit found that `CreateCheqdDIDSpec.assertShape`
 * was OPTIONAL, and that the recovery-controller DID (`agentHeldRecoveryController`
 * / `deviceHeldRecoveryController`) was the one real call site that omitted it.
 * Patient and institutional DIDs already had dedicated, shape-locked
 * constructors that always supplied one, so this is the gap that actually
 * existed, not the one originally guessed at.
 *
 * FAST TIER, DELIBERATELY. This guard is checked as the FIRST statement of
 * `createCheqdDID`, before any KMS key is generated and before `agent` is
 * touched at all — so it can be exercised with no live chain and no real
 * agent. That ordering is itself part of the fix: a caller that cannot state
 * what shape it expects should not get as far as spending KMS work either.
 *
 * WHAT THIS DOES NOT PROVE: that a correctly-specced call actually reaches the
 * ledger. That is a live-chain property, exercised by
 * `tests/live/r5PatientEnrolment.live.test.ts`,
 * `tests/live/r5GuardianRecovery.live.test.ts`, and
 * `scripts/verify-cheqd-controller-shape.ts`, all of which now supply a real
 * `assertShape` at every call site. What this file proves is narrower and
 * belongs at this tier: the new required-ness of the field neither silently
 * accepts its absence, nor blocks a spec that legitimately supplies one.
 */
import { describe, it, expect } from 'vitest';
import type { Agent } from '@credo-ts/core';

import { createCheqdDID, ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL } from '../../src/services/cheqdDid.js';
import { SHAPE_ASSERTION_DELIBERATELY_OMITTED } from '@ssi-healthcare/sdk/ledger';

// Never dereferenced: the guard under test throws before `agent` is used.
const UNTOUCHED_AGENT = {} as unknown as Agent;

const SELF_GOVERNANCE = {
  kind: 'self' as const,
  acknowledgement: ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL,
  reason: 'fast-tier fixture',
};

describe('createCheqdDID refuses to mint without a named shape assertion', () => {
  it('REFUSES when assertShape is omitted entirely', async () => {
    await expect(
      createCheqdDID(UNTOUCHED_AGENT, {
        controllers: SELF_GOVERNANCE,
        verificationMethodControl: SELF_GOVERNANCE,
        signers: [],
      } as never),
    ).rejects.toThrowError(/No assertShape was supplied/);
  });

  it('REFUSES when assertShape is not a function', async () => {
    await expect(
      createCheqdDID(UNTOUCHED_AGENT, {
        controllers: SELF_GOVERNANCE,
        verificationMethodControl: SELF_GOVERNANCE,
        signers: [],
        assertShape: 'not-a-function' as never,
      }),
    ).rejects.toThrowError(/No assertShape was supplied/);
  });

  it('the SUCCESS path is reachable: a real assertShape gets PAST this guard', async () => {
    // Proves the guard is not swallowing every call. With `assertShape`
    // present, execution proceeds into key generation and reaches `kmsOf`,
    // which throws on `UNTOUCHED_AGENT.dependencyManager` being undefined —
    // a DIFFERENT failure than "No assertShape was supplied", and the
    // earliest point distinguishable without a real agent or a live chain.
    let sawAssertShapeInvoked = false;

    await expect(
      createCheqdDID(UNTOUCHED_AGENT, {
        controllers: SELF_GOVERNANCE,
        verificationMethodControl: SELF_GOVERNANCE,
        signers: [],
        assertShape: SHAPE_ASSERTION_DELIBERATELY_OMITTED,
      }),
    ).rejects.not.toThrowError(/No assertShape was supplied/);

    // Independently: SHAPE_ASSERTION_DELIBERATELY_OMITTED itself is callable
    // and a no-op, which is what every negative-control fixture in this repo
    // now relies on.
    expect(() => {
      SHAPE_ASSERTION_DELIBERATELY_OMITTED(undefined as never);
      sawAssertShapeInvoked = true;
    }).not.toThrow();
    expect(sawAssertShapeInvoked).toBe(true);
  });
});
