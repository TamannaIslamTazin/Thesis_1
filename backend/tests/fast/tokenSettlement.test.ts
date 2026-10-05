/**
 * The token settlement state machine.
 *
 * Every refusal here is paired with the success it refuses against, because a
 * suite of refusals alone passes perfectly against code that refuses everything.
 * The transition tests are then mutation-checked by hand: removing the terminal
 * guard must make them fail.
 */
import { describe, it, expect } from 'vitest';
import {
  tokenState,
  assertTransitionAllowed,
  isSettled,
  SettlementRefused,
  TOKEN_LIFETIME_MS,
} from '../../src/services/tokenSettlement.js';

const HOUR = 60 * 60 * 1000;
const ISSUED_AT = '2026-09-27T10:00:00.000Z';
const ISSUED_MS = Date.parse(ISSUED_AT);

describe('tokenState — the happy paths each refusal is measured against', () => {
  it('is ISSUED while young and unsettled', () => {
    expect(tokenState({ queueToken: 42 }, ISSUED_AT, ISSUED_MS + HOUR)).toBe('ISSUED');
  });

  it('is SETTLED once paid, whatever the age', () => {
    expect(
      tokenState({ queueToken: 42, settledAt: '2026-09-27T10:30:00.000Z' }, ISSUED_AT, ISSUED_MS + 48 * HOUR),
    ).toBe('SETTLED');
  });

  it('is ABANDONED when the counter declared it not collected', () => {
    expect(tokenState({ queueToken: 42, abandonedReason: 'declined' }, ISSUED_AT, ISSUED_MS + HOUR)).toBe('ABANDONED');
  });
});

describe('tokenState — the 24-hour read-time rule', () => {
  it('is still ISSUED one millisecond before the boundary', () => {
    expect(tokenState({ queueToken: 1 }, ISSUED_AT, ISSUED_MS + TOKEN_LIFETIME_MS - 1)).toBe('ISSUED');
  });

  it('reads as ABANDONED_EXPIRED exactly at the boundary', () => {
    expect(tokenState({ queueToken: 1 }, ISSUED_AT, ISSUED_MS + TOKEN_LIFETIME_MS)).toBe('ABANDONED_EXPIRED');
  });

  it('reads as ABANDONED_EXPIRED long after it', () => {
    expect(tokenState({ queueToken: 1 }, ISSUED_AT, ISSUED_MS + 30 * 24 * HOUR)).toBe('ABANDONED_EXPIRED');
  });

  it('fails closed on an unparseable issued-at rather than keeping the token alive forever', () => {
    expect(tokenState({ queueToken: 1 }, 'not-a-date', ISSUED_MS)).toBe('ABANDONED_EXPIRED');
  });

  it('prefers a settlement over expiry — a paid token past 24h is SETTLED, not expired', () => {
    expect(
      tokenState({ queueToken: 1, settledAt: '2026-09-28T11:00:00.000Z' }, ISSUED_AT, ISSUED_MS + 25 * HOUR),
    ).toBe('SETTLED');
  });
});

describe('assertTransitionAllowed — terminal means terminal', () => {
  it('allows a transition from ISSUED (the success the refusals are paired against)', () => {
    expect(() => assertTransitionAllowed('ISSUED')).not.toThrow();
  });

  it('refuses a second settle, so a double-click cannot reverse a payment', () => {
    expect(() => assertTransitionAllowed('SETTLED')).toThrow(SettlementRefused);
    try {
      assertTransitionAllowed('SETTLED');
    } catch (e) {
      expect((e as SettlementRefused).code).toBe('ALREADY_TERMINAL');
    }
  });

  it('refuses settle-after-decline', () => {
    expect(() => assertTransitionAllowed('ABANDONED')).toThrow(SettlementRefused);
  });

  it('refuses settle-after-expiry — the patient who pays at hour 25', () => {
    expect(() => assertTransitionAllowed('ABANDONED_EXPIRED')).toThrow(SettlementRefused);
  });

  it('refuses EVERY transition from every terminal state, and permits only ISSUED', () => {
    const states = ['SETTLED', 'ABANDONED', 'ABANDONED_EXPIRED'] as const;
    for (const s of states) {
      expect(() => assertTransitionAllowed(s), `expected ${s} to refuse`).toThrow(SettlementRefused);
    }
  });
});

describe('isSettled — the only state that may move a balance', () => {
  it('is true only for SETTLED', () => {
    expect(isSettled('SETTLED')).toBe(true);
    for (const s of ['ISSUED', 'ABANDONED', 'ABANDONED_EXPIRED'] as const) {
      expect(isSettled(s), `${s} must not move a balance`).toBe(false);
    }
  });
});
