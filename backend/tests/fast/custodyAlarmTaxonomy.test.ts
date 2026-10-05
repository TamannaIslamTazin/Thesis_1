/**
 * R5 — THE ALARM TAXONOMY.
 *
 * Two properties, both of which a plausible "cleanup" refactor would break:
 *
 *   1. AN UNMATCHED CHAIN EVENT IS NEVER FILED BELOW A MATCHED ONE. The
 *      tempting simplification is "we have an audit entry for it, so it is
 *      routine" — and its mirror, "no audit entry, probably a race, downgrade
 *      it". Either turns the single loudest available signal into noise.
 *
 *   2. EVICTION AND DEACTIVATION ARE NOT ROTATION. All three arrive as
 *      `MsgUpdateDidDoc`-shaped traffic. Under 1-of-N the difference decides
 *      whether the other officers still have a remedy: after enough evictions
 *      the institution holds no key and cannot rotate at all (S-4 H1, #291),
 *      and deactivation has no on-chain remedy whatsoever (code 1207).
 *
 * Pure module, so this runs with nothing installed and nothing running.
 */
import { describe, expect, it } from 'vitest';

import {
  AlarmAttribution,
  AlarmKind,
  AlarmSeverity,
  baseSeverityFor,
  headlineFor,
  severityFor,
  strongerOf,
} from '../../src/services/custody/alarmSeverity.js';

const ALL_KINDS = Object.values(AlarmKind);
const RANK = { INFO: 0, WARNING: 1, CRITICAL: 2 } as const;

describe('unmatched is never less serious than matched', () => {
  it.each(ALL_KINDS)('%s: UNMATCHED >= MATCHED, for every kind', (kind) => {
    const matched = severityFor(kind, AlarmAttribution.MATCHED);
    const unmatched = severityFor(kind, AlarmAttribution.UNMATCHED);
    expect(RANK[unmatched]).toBeGreaterThanOrEqual(RANK[matched]);
  });

  it.each(ALL_KINDS)('%s: an unaccounted-for chain event is always CRITICAL', (kind) => {
    // There is no chain event we cannot account for that is merely interesting.
    // Whoever produced it holds an officer key and is not using our signing path.
    expect(severityFor(kind, AlarmAttribution.UNMATCHED)).toBe(AlarmSeverity.CRITICAL);
  });

  it.each(ALL_KINDS)('%s: attribution never LOWERS the base severity', (kind) => {
    const base = baseSeverityFor(kind);
    for (const attribution of Object.values(AlarmAttribution)) {
      expect(RANK[severityFor(kind, attribution)]).toBeGreaterThanOrEqual(RANK[base]);
    }
  });
});

describe('eviction and deactivation are distinguished from routine rotation', () => {
  it('files an authorised rotation as routine', () => {
    // This is the operation 1-of-N exists to make possible. If it paged
    // somebody, nothing else here would get read.
    expect(severityFor(AlarmKind.OFFICER_ROTATED, AlarmAttribution.MATCHED)).toBe(
      AlarmSeverity.INFO,
    );
    expect(severityFor(AlarmKind.OFFICER_ADDED, AlarmAttribution.MATCHED)).toBe(AlarmSeverity.INFO);
  });

  it('files an AUTHORISED eviction as CRITICAL anyway', () => {
    // Attributable is not the same as safe. A matched eviction still narrows
    // the officer set toward the state where rotation is impossible.
    expect(severityFor(AlarmKind.OFFICER_EVICTED, AlarmAttribution.MATCHED)).toBe(
      AlarmSeverity.CRITICAL,
    );
  });

  it('files an AUTHORISED deactivation as CRITICAL anyway', () => {
    expect(severityFor(AlarmKind.DID_DEACTIVATED, AlarmAttribution.MATCHED)).toBe(
      AlarmSeverity.CRITICAL,
    );
  });

  it('treats a lost watch window as CRITICAL, because silence there proves nothing', () => {
    expect(severityFor(AlarmKind.WATCH_GAP_UNRECOVERABLE, AlarmAttribution.NOT_APPLICABLE)).toBe(
      AlarmSeverity.CRITICAL,
    );
  });

  it('ranks a stalled watcher below an actual key change', () => {
    // A degraded control, not evidence that anything happened.
    expect(
      RANK[severityFor(AlarmKind.WATCHER_STALLED, AlarmAttribution.NOT_APPLICABLE)],
    ).toBeLessThan(RANK[severityFor(AlarmKind.OFFICER_EVICTED, AlarmAttribution.MATCHED)]);
  });

  it('strongerOf never returns the weaker of the two', () => {
    expect(strongerOf(AlarmSeverity.INFO, AlarmSeverity.CRITICAL)).toBe(AlarmSeverity.CRITICAL);
    expect(strongerOf(AlarmSeverity.CRITICAL, AlarmSeverity.WARNING)).toBe(AlarmSeverity.CRITICAL);
    expect(strongerOf(AlarmSeverity.WARNING, AlarmSeverity.WARNING)).toBe(AlarmSeverity.WARNING);
  });
});

describe('the headline tells an operator what they cannot undo', () => {
  const base = { subjectDid: 'did:cheqd:bdhealthtestnet:hospital', detail: {} };

  it('says irreversible for a deactivation', () => {
    const text = headlineFor({
      ...base,
      kind: AlarmKind.DID_DEACTIVATED,
      attribution: AlarmAttribution.MATCHED,
      signerVerificationMethodIds: ['did:cheqd:bdhealthtestnet:hospital#key-officer-1'],
    });
    expect(text).toMatch(/irreversible/i);
    expect(text).toContain('1207');
  });

  it('says rotation becomes impossible for an eviction', () => {
    const text = headlineFor({
      ...base,
      kind: AlarmKind.OFFICER_EVICTED,
      attribution: AlarmAttribution.MATCHED,
    });
    expect(text).toMatch(/impossible|no key/i);
  });

  it.each(ALL_KINDS)('%s: an unmatched event says so in the headline itself', (kind) => {
    // Not only in a `detail` field somebody has to expand. The operator reading
    // one line must learn that nothing in our records accounts for this.
    const text = headlineFor({ ...base, kind, attribution: AlarmAttribution.UNMATCHED });
    expect(text).toContain('NO SIGNING AUDIT ENTRY ACCOUNTS FOR THIS');
  });

  it('names the signing verification method, because that is all attribution is', () => {
    const text = headlineFor({
      ...base,
      kind: AlarmKind.OFFICER_EVICTED,
      attribution: AlarmAttribution.MATCHED,
      signerVerificationMethodIds: ['did:cheqd:bdhealthtestnet:hospital#key-officer-3'],
    });
    expect(text).toContain('#key-officer-3');
  });
});
