/**
 * WHICH CREDENTIALS A MIGRATION CARRIES FORWARD — R5, research question 1.
 *
 * This predicate decides what a patient walks out of the hospital holding after
 * an emergency identity migration. It is pure, so it is tested here rather than
 * behind a validator; getting it wrong does not throw, it quietly reinstates a
 * revoked credential or quietly extends an expiry.
 */
import { describe, it, expect } from 'vitest';

import {
  decideCredentialFate,
  summariseWorklist,
  type MigratableCredential,
} from '../../src/services/reissuance/worklist.js';

const NOW = new Date('2026-08-22T12:00:00.000Z');

function credential(overrides: Partial<MigratableCredential> = {}): MigratableCredential {
  return {
    id: 'cred-1',
    credentialHash: 'a'.repeat(64),
    status: 'ACTIVE',
    credentialFormat: 'vc+jwt',
    statusListId: 'list-1',
    statusListIndex: 42,
    expiresAt: new Date('2027-01-01T00:00:00.000Z'),
    ...overrides,
  };
}

describe('the migration set is not the credential set', () => {
  it('carries forward a live, tracked, unexpired credential', () => {
    expect(decideCredentialFate(credential(), NOW)).toEqual({ action: 'REISSUE' });
  });

  it('does NOT carry forward a revoked credential — migration is not revocation laundering', () => {
    const decision = decideCredentialFate(credential({ status: 'REVOKED' }), NOW);
    expect(decision.action).toBe('SKIP');
    expect(decision).toMatchObject({ outcome: 'SKIPPED_REVOKED' });
  });

  it('does NOT carry forward a suspended credential — that would silently lift the suspension', () => {
    expect(decideCredentialFate(credential({ status: 'SUSPENDED' }), NOW)).toMatchObject({
      action: 'SKIP',
      outcome: 'SKIPPED_REVOKED',
    });
  });

  it('does NOT carry forward an unaccepted offer', () => {
    expect(decideCredentialFate(credential({ status: 'PENDING' }), NOW)).toMatchObject({
      action: 'SKIP',
      outcome: 'SKIPPED_REVOKED',
    });
  });

  it('does NOT carry forward an expired credential — that would extend a validity never granted', () => {
    expect(
      decideCredentialFate(
        credential({ expiresAt: new Date('2026-08-22T11:59:59.000Z') }),
        NOW,
      ),
    ).toMatchObject({ action: 'SKIP', outcome: 'SKIPPED_EXPIRED' });
  });

  it('treats expiry as inclusive at the instant it expires', () => {
    expect(decideCredentialFate(credential({ expiresAt: NOW }), NOW)).toMatchObject({
      outcome: 'SKIPPED_EXPIRED',
    });
  });

  it('carries forward a credential with no expiry at all', () => {
    expect(decideCredentialFate(credential({ expiresAt: null }), NOW)).toEqual({
      action: 'REISSUE',
    });
  });
});

describe('the tracking gap is refused, not papered over', () => {
  it('marks a credential with no status-list index UNTRACKABLE rather than re-issuing it', () => {
    // The old copy could not be revoked, so issuing a replacement would leave
    // two live credentials asserting the same thing under two identifiers.
    const decision = decideCredentialFate(
      credential({ statusListId: null, statusListIndex: null, credentialFormat: null }),
      NOW,
    );
    expect(decision).toMatchObject({ action: 'SKIP', outcome: 'UNTRACKABLE' });
  });

  it('treats a half-populated status entry as untrackable too', () => {
    expect(
      decideCredentialFate(credential({ statusListIndex: null }), NOW),
    ).toMatchObject({ outcome: 'UNTRACKABLE' });
    expect(
      decideCredentialFate(credential({ statusListId: null }), NOW),
    ).toMatchObject({ outcome: 'UNTRACKABLE' });
  });

  it('index 0 is a valid bit position, not a missing one', () => {
    // The bug this guards against is `if (!statusListIndex)`, which would
    // declare the very first credential an issuer ever issued untrackable.
    expect(decideCredentialFate(credential({ statusListIndex: 0 }), NOW)).toEqual({
      action: 'REISSUE',
    });
  });

  it('reports an already-revoked untrackable credential as REVOKED, not as a tracking gap', () => {
    // The gap only matters for credentials we would otherwise have carried
    // forward; reporting it here would inflate the measured gap.
    expect(
      decideCredentialFate(
        credential({ status: 'REVOKED', statusListId: null, statusListIndex: null }),
        NOW,
      ),
    ).toMatchObject({ outcome: 'SKIPPED_REVOKED' });
  });
});

describe('the summary counts every credential exactly once', () => {
  it('accounts for skipped and carried-forward without double counting', () => {
    const decisions = [
      credential({ id: 'a' }),
      credential({ id: 'b', status: 'REVOKED' }),
      credential({ id: 'c', expiresAt: new Date('2020-01-01T00:00:00.000Z') }),
      credential({ id: 'd', statusListIndex: null }),
      credential({ id: 'e' }),
    ].map((c) => ({ decision: decideCredentialFate(c, NOW) }));

    const summary = summariseWorklist(decisions);

    expect(summary.found).toBe(5);
    expect(summary.toReissue).toBe(2);
    expect(summary.skipped).toBe(3);
    expect(summary.byOutcome).toEqual({
      PENDING: 2,
      SKIPPED_REVOKED: 1,
      SKIPPED_EXPIRED: 1,
      UNTRACKABLE: 1,
    });
    expect(Object.values(summary.byOutcome).reduce((a, b) => a + b, 0)).toBe(summary.found);
  });
});
