/**
 * THE ISSUANCE-SIDE DISCLOSURE POLICY.
 *
 * `buildDisclosureFrame` decides what a credential is *capable* of hiding, for
 * the rest of its life — the frame is baked into the issuer's signature and
 * there is no remedy but reissuance. `assertNothingDisclosableLeaked` is the
 * check that refuses to issue when the frame did not take effect.
 *
 * Both are pure functions over plain JSON, so they are tested here rather than
 * against the live stack. Their INTERACTION with `@sd-jwt/core` — the part that
 * cannot be established by reading either one — is in
 * `disclosureFrameLeak.test.ts`.
 *
 * The `credentialSubject.id` carve-out is asserted here as a locked decision,
 * not a preference. OpenDiscussion.md records it as measured: with `id` inside
 * the frame a holder can withhold it, Credo's `credentialSubjectAuthentication`
 * then skips its check because `credentialSubjectIds` is empty, and a captured
 * credential can be re-presented under an attacker's DID. The identical theft
 * was rejected with `id` outside the frame.
 */
import { describe, it, expect } from 'vitest';
import { statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  buildDisclosureFrame,
  disclosableSubjectKeys,
  assertNothingDisclosableLeaked,
  DisclosurePolicyError,
  MAXIMAL_DISCLOSABILITY,
} from '@ssi-healthcare/shared';

const HOLDER = 'did:cheqd:bdhealthtestnet:00000000-0000-4000-8000-000000000001';

const SUBJECT = {
  id: HOLDER,
  patientName: 'Ahsan Rahman',
  hivStatus: 'negative',
  prescriber: { name: 'Dr Karim', licence: 'BMDC-4471' },
  medications: ['Metformin 500mg', 'Lisinopril 10mg'],
};

/** `_sd` at a given frame level, as a plain array. */
const sdOf = (frame: unknown): Array<string | number> =>
  (frame as { _sd?: Array<string | number> })._sd ?? [];

describe('the fixture the fast tier is asserting against is current', () => {
  /**
   * WHY THIS TEST EXISTS. The backend imports `@ssi-healthcare/shared` through
   * its BUILT `dist/index.mjs`, so that is what these tests exercise — which is
   * correct, because it is what production loads. The hazard is that a stale
   * `dist` would make every assertion in this file a statement about code that
   * is no longer the source. That is not a hypothetical failure mode in a repo
   * whose stated position is that only execution is trusted.
   *
   * If this fails, run `pnpm --filter @ssi-healthcare/shared build`. Do not
   * skip it: a green fast suite over a stale artifact is worse than no suite.
   */
  it('packages/shared/dist is not older than packages/shared/src', () => {
    // From packages/backend/tests/fast/ up three levels is packages/.
    const sharedRoot = fileURLToPath(new URL('../../../shared/', import.meta.url));

    const dist = statSync(`${sharedRoot}dist/index.mjs`).mtimeMs;
    const src = statSync(`${sharedRoot}src/disclosure/index.ts`).mtimeMs;

    expect(
      dist >= src,
      'packages/shared/dist is older than its source — rebuild it before trusting this suite',
    ).toBe(true);
  });
});

describe('buildDisclosureFrame', () => {
  it('never makes credentialSubject.id disclosable', () => {
    const frame = buildDisclosureFrame(SUBJECT)!;
    expect(sdOf(frame.credentialSubject)).not.toContain('id');
  });

  it('makes every other subject key disclosable', () => {
    const frame = buildDisclosureFrame(SUBJECT)!;
    const disclosable = sdOf(frame.credentialSubject);
    expect([...disclosable].sort()).toEqual(
      ['patientName', 'hivStatus', 'prescriber', 'medications'].sort(),
    );
  });

  it('frames only credentialSubject, never the fields that keep a credential checkable', () => {
    // `credentialStatus` staying in cleartext is load-bearing: it is what keeps
    // BitstringStatusList revocation working on a selectively disclosed
    // credential. `issuer` / `validFrom` / `validUntil` are what make it
    // verifiable at all.
    const frame = buildDisclosureFrame(SUBJECT)!;
    expect(Object.keys(frame)).toEqual(['credentialSubject']);
  });

  it('makes a nested container hideable AND its members individually disclosable', () => {
    // Hiding "there is a prescriber at all" is a distinct privacy property from
    // hiding the two leaves under it, so the container must appear in its
    // parent's `_sd` *and* carry a frame of its own.
    const frame = buildDisclosureFrame(SUBJECT)!;
    const subjectFrame = frame.credentialSubject as Record<string, unknown>;

    expect(sdOf(subjectFrame)).toContain('prescriber');
    expect([...sdOf(subjectFrame.prescriber)].sort()).toEqual(['licence', 'name']);
  });

  it('returns undefined — not {} — when nothing is eligible', () => {
    // Credo reads a missing frame as "disclose nothing selectively", which is
    // the correct reading of "there was nothing eligible". An empty object is
    // not the same statement and callers must pass the undefined through.
    expect(buildDisclosureFrame({ id: HOLDER })).toBeUndefined();
  });

  it('ignores undefined members rather than naming absent keys in _sd', () => {
    // A key whose value is `undefined` is absent from the signed payload, so
    // listing it is a directive @sd-jwt has nothing to apply.
    const frame = buildDisclosureFrame({ id: HOLDER, present: 'yes', missing: undefined })!;
    expect(sdOf(frame.credentialSubject)).toEqual(['present']);
  });

  it('REFUSES a subject nested past the policy depth instead of framing it partially', () => {
    // A partially framed subject is precisely the silent leak this module
    // exists to prevent, so an over-deep subject is refused outright.
    let deep: Record<string, unknown> = { leaf: 'value' };
    for (let i = 0; i < MAXIMAL_DISCLOSABILITY.maxDepth + 2; i += 1) {
      deep = { nested: deep };
    }
    expect(() => buildDisclosureFrame({ id: HOLDER, ...deep })).toThrow(DisclosurePolicyError);
  });

  it('refuses a non-object credentialSubject', () => {
    expect(() => buildDisclosureFrame('not an object')).toThrow(DisclosurePolicyError);
    expect(() => buildDisclosureFrame(null)).toThrow(DisclosurePolicyError);
    expect(() => buildDisclosureFrame(['array'])).toThrow(DisclosurePolicyError);
  });
});

describe('assertNothingDisclosableLeaked', () => {
  const signedCorrectly = { id: HOLDER, _sd: ['digest-a', 'digest-b'] };

  it('passes when every disclosable key is gone from the signed payload', () => {
    expect(() => assertNothingDisclosableLeaked(SUBJECT, signedCorrectly)).not.toThrow();
  });

  it('FAILS ISSUANCE when a disclosable claim survived in cleartext', () => {
    // The scenario from TESTING_MANUAL §6.4: deliberately break the frame and
    // confirm issuance is refused. If a malformed frame issues successfully,
    // the guard is not wired in.
    const leaked = { id: HOLDER, hivStatus: 'negative', _sd: ['digest-a'] };
    expect(() => assertNothingDisclosableLeaked(SUBJECT, leaked)).toThrow(DisclosurePolicyError);
    expect(() => assertNothingDisclosableLeaked(SUBJECT, leaked)).toThrow(/hivStatus/);
  });

  it('names every leaked claim, not just the first', () => {
    const leaked = { id: HOLDER, hivStatus: 'negative', patientName: 'Ahsan Rahman' };
    try {
      assertNothingDisclosableLeaked(SUBJECT, leaked);
      expect.unreachable('expected a DisclosurePolicyError');
    } catch (error) {
      expect((error as Error).message).toMatch(/hivStatus/);
      expect((error as Error).message).toMatch(/patientName/);
    }
  });

  it('FAILS CLOSED on an unreadable signed subject', () => {
    // "There was nothing to check" is the shape every fail-open bug in this
    // codebase has taken. It is not available here.
    expect(() => assertNothingDisclosableLeaked(SUBJECT, undefined)).toThrow(
      DisclosurePolicyError,
    );
    expect(() => assertNothingDisclosableLeaked(SUBJECT, 'garbage')).toThrow(
      DisclosurePolicyError,
    );
  });

  it('tolerates a subject with nothing disclosable', () => {
    // Nothing was expected to be hidden, so nothing can have leaked.
    expect(() => assertNothingDisclosableLeaked({ id: HOLDER }, { id: HOLDER })).not.toThrow();
  });

  it('agrees with disclosableSubjectKeys about what should be absent', () => {
    // The checker and the list it checks against must not drift apart.
    const expected = disclosableSubjectKeys(SUBJECT);
    expect([...expected].sort()).toEqual(
      ['patientName', 'hivStatus', 'prescriber', 'medications'].sort(),
    );
    for (const key of expected) {
      expect(() => assertNothingDisclosableLeaked(SUBJECT, { id: HOLDER, [key]: 'leaked' })).toThrow(
        DisclosurePolicyError,
      );
    }
  });
});
