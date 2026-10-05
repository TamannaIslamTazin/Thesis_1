/**
 * `selectRecoveryControllerProvider` — THE ASYMMETRY THAT SHIPPED, CLOSED.
 *
 * `routes/auth.ts` `mintPatientDid` refused to provision a wallet when
 * `PATIENT_RECOVERY_CUSTODY=device-held-guardian-split`, because no guardian
 * ceremony had run and no provider exists for that case yet.
 * `scripts/reissue-identity.ts` — the operator's tool for the documented
 * PRODUCTION re-issuance procedure — did not carry the same refusal: it
 * imported `agentHeldRecoveryController` directly and used it unconditionally.
 * Running the real procedure against a `device-held-guardian-split` deployment
 * would have silently minted a custodial recovery key and reported success.
 *
 * FAST TIER, DELIBERATELY. This is a pure function of one parameter — no
 * agent, no chain, no config module to mock — so the refusal now lives in one
 * place both callers share, and that one place is covered here.
 */
import { describe, it, expect } from 'vitest';

import {
  agentHeldRecoveryController,
  selectRecoveryControllerProvider,
} from '../../src/services/patientEnrolment.js';
import { AppError } from '../../src/middleware/errorHandler.js';

describe('selectRecoveryControllerProvider', () => {
  it('REFUSES when custody is unset', () => {
    expect(() => selectRecoveryControllerProvider(undefined)).toThrowError(AppError);
    try {
      selectRecoveryControllerProvider(undefined);
      expect.unreachable('must throw');
    } catch (error) {
      expect(error).toBeInstanceOf(AppError);
      expect((error as AppError).statusCode).toBe(503);
      expect((error as AppError).message).toMatch(/PATIENT_RECOVERY_CUSTODY is not set/);
    }
  });

  it('REFUSES device-held-guardian-split — no ceremony flow exists at this call site', () => {
    try {
      selectRecoveryControllerProvider('device-held-guardian-split');
      expect.unreachable('must throw');
    } catch (error) {
      expect(error).toBeInstanceOf(AppError);
      expect((error as AppError).statusCode).toBe(409);
      expect((error as AppError).message).toMatch(/cannot be minted/);
      // The regression this test exists for: it must NOT silently return the
      // custodial provider.
      expect((error as AppError).message).not.toMatch(/^$/);
    }
  });

  it('the SUCCESS path is reachable: backend-held-phase-a resolves to the agent-held provider', () => {
    expect(selectRecoveryControllerProvider('backend-held-phase-a')).toBe(
      agentHeldRecoveryController,
    );
  });
});
