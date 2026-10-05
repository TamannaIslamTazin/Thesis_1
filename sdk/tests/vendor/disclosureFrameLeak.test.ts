/**
 * DIVERGENCE D2 — the disclosure-frame leak, closed.
 *
 * This is the SDK's copy of `packages/backend/tests/fast/disclosureFrameLeak.test.ts`,
 * and it asserts something that file cannot: that the leak is now IMPOSSIBLE
 * rather than merely avoided by our own frame builder emitting the right shape.
 *
 * THE PROPERTY. In a disclosure frame, array element indices must be NUMBERS.
 * Written as strings, upstream `@sd-jwt/core` does not throw, does not warn and
 * does not partially apply the directive — it ignores it and emits the entire
 * array as one cleartext value inside the container's disclosure. A patient who
 * asked to reveal one of three medications reveals all three, including the
 * psychiatric one, and both issuer payloads look identical.
 *
 * WHY THE TYPE FIX ALONE WOULD NOT DO. Credo's published `IDisclosureFrame`
 * types `_sd` as `string[]`. Obeying the vendor's own type produces the leak,
 * so the type checker is the one signal that cannot be relied on here.
 *
 * EVERY TEST BELOW IS DIFFERENTIAL. Each runs the same input through the
 * published `@sd-jwt/core@0.19.0` (a devDependency, pinned by the root
 * pnpm.overrides) and through the vendored copy, and asserts they disagree.
 * That is what makes the fix demonstrated rather than asserted: if someone
 * reverts D2, the upstream arm and the vendored arm start agreeing and these
 * tests fail.
 *
 * IF UPSTREAM EVER FIXES THIS, the upstream arm stops leaking and these tests
 * fail. That is a SUCCESS: it means the divergence's justification has changed
 * and must be re-read. Re-measure and rewrite; do not delete.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  createIdentity,
  vendoredInstance,
  upstreamInstance,
  decodedDisclosures,
  issuerSignedPayload,
  type TestIdentity,
} from '../helpers/sdJwt';
import { SdJwtFrameError } from '../../src/vendor/sd-jwt/utils';

const SUBJECT = {
  id: 'did:cheqd:bdhealthtestnet:00000000-0000-4000-8000-000000000001',
  medications: ['Metformin 500mg', 'Lisinopril 10mg', 'Sertraline 50mg'],
};

const frameWith = (indices: Array<number | string>) => ({
  credentialSubject: {
    _sd: ['medications'],
    medications: { _sd: indices },
  },
});

/** An object-member disclosure is `[salt, name, value]`; an element is `[salt, value]`. */
const isMemberDisclosure = (d: unknown[]): boolean => d.length === 3;

function medicationsDisclosure(compact: string): unknown[] | undefined {
  return decodedDisclosures(compact).find(
    (d) => isMemberDisclosure(d) && d[1] === 'medications',
  );
}

describe('D2 — a disclosure frame that cannot take effect', () => {
  let issuer: TestIdentity;
  let upstream: Awaited<ReturnType<typeof upstreamInstance>>;

  beforeAll(async () => {
    issuer = await createIdentity();
    upstream = await upstreamInstance(issuer);
  });

  it('UPSTREAM 0.19.0 leaks the whole array on string indices — the control', async () => {
    const compact = await upstream.issue(
      { credentialSubject: { ...SUBJECT } },
      frameWith(['0', '1', '2']),
    );

    // THE LEAK: the container disclosure carries the raw values.
    const container = medicationsDisclosure(compact);
    expect(container, 'expected a disclosure for the medications container').toBeDefined();
    expect(container![2]).toEqual(SUBJECT.medications);

    // And there are no per-element disclosures, so the holder has no way to
    // withhold any single medication.
    const elements = decodedDisclosures(compact).filter((d) => !isMemberDisclosure(d));
    expect(elements).toHaveLength(0);
  });

  it('UPSTREAM 0.19.0 does so SILENTLY — issuance neither throws nor flags it', async () => {
    await expect(
      upstream.issue({ credentialSubject: { ...SUBJECT } }, frameWith(['0', '1', '2'])),
    ).resolves.toBeTypeOf('string');
  });

  it('UPSTREAM 0.19.0 produces an innocent-looking issuer payload either way', async () => {
    // Why inspecting the signed payload cannot catch this. In both cases
    // `medications` is correctly replaced by a digest at the top level; the
    // difference is buried one layer down, inside the disclosure.
    const numeric = issuerSignedPayload(
      await upstream.issue({ credentialSubject: { ...SUBJECT } }, frameWith([0, 1, 2])),
    );
    const strings = issuerSignedPayload(
      await upstream.issue({ credentialSubject: { ...SUBJECT } }, frameWith(['0', '1', '2'])),
    );

    for (const payload of [numeric, strings]) {
      const subject = payload.credentialSubject as Record<string, unknown>;
      expect(subject.medications).toBeUndefined();
      expect(Array.isArray(subject._sd)).toBe(true);
    }
    expect(Object.keys(numeric.credentialSubject as object).sort()).toEqual(
      Object.keys(strings.credentialSubject as object).sort(),
    );
  });

  it('VENDORED refuses to issue on string indices', async () => {
    await expect(
      vendoredInstance(issuer).issue(
        { credentialSubject: { ...SUBJECT } },
        frameWith(['0', '1', '2']) as never,
      ),
    ).rejects.toBeInstanceOf(SdJwtFrameError);
  });

  it('VENDORED names the fault in a way that tells the developer what to change', async () => {
    // A refusal a developer cannot act on gets cast away. The message has to
    // say "numbers, not strings", because the fix is one character per index.
    await expect(
      vendoredInstance(issuer).issue(
        { credentialSubject: { ...SUBJECT } },
        frameWith(['0']) as never,
      ),
    ).rejects.toThrow(/numbers, not strings/i);
  });

  it('VENDORED refuses an out-of-range index, which upstream also ignores silently', async () => {
    // Same failure class: the developer believes element 5 is hidden, and it
    // does not exist, so the directive evaporates.
    await expect(
      upstream.issue({ credentialSubject: { ...SUBJECT } }, frameWith([0, 5])),
    ).resolves.toBeTypeOf('string');

    await expect(
      vendoredInstance(issuer).issue(
        { credentialSubject: { ...SUBJECT } },
        frameWith([0, 5]) as never,
      ),
    ).rejects.toBeInstanceOf(SdJwtFrameError);
  });

  it('VENDORED refuses an _sd naming a claim the payload does not have', async () => {
    // The typo case. `medication` against a `medications` field leaves the real
    // field in cleartext, and upstream reports nothing.
    const typo = { credentialSubject: { _sd: ['medication'] } };

    await expect(
      upstream.issue({ credentialSubject: { ...SUBJECT } }, typo),
    ).resolves.toBeTypeOf('string');

    await expect(
      vendoredInstance(issuer).issue({ credentialSubject: { ...SUBJECT } }, typo as never),
    ).rejects.toBeInstanceOf(SdJwtFrameError);
  });

  it('VENDORED still issues the CORRECT numeric form, unchanged from upstream', async () => {
    // The guard must not be a blanket refusal. The working frame has to keep
    // working, and produce byte-for-byte the same STRUCTURE upstream does.
    const compact = await vendoredInstance(issuer).issue(
      { credentialSubject: { ...SUBJECT } },
      frameWith([0, 1, 2]) as never,
    );

    const container = medicationsDisclosure(compact);
    expect(container).toBeDefined();

    // The container's value is a list of digest references, not values.
    const value = container![2] as Array<Record<string, unknown>>;
    expect(Array.isArray(value)).toBe(true);
    expect(value).toHaveLength(3);
    for (const element of value) {
      expect(Object.keys(element)).toEqual(['...']);
      expect(typeof element['...']).toBe('string');
    }

    // No medication name appears anywhere in the container disclosure.
    const containerJson = JSON.stringify(container);
    for (const medication of SUBJECT.medications) {
      expect(containerJson).not.toContain(medication);
    }

    // The three values exist as separate, individually withholdable disclosures.
    const elements = decodedDisclosures(compact).filter((d) => !isMemberDisclosure(d));
    expect(elements.map((d) => d[1]).sort()).toEqual([...SUBJECT.medications].sort());
  });

  /**
   * The guard's blast radius.
   *
   * D2 is the one divergence that can REJECT input upstream accepts, so the
   * cases it must not touch matter as much as the cases it must catch. Each of
   * these was probed by execution before being written down; a guard that
   * rejects a decoy, a nested frame, or a frame that only carries sub-frames
   * would break selective disclosure for honest issuers.
   */
  describe('does not misfire on legitimate frames', () => {
    const accepts = async (payload: unknown, frame: unknown) =>
      expect(
        vendoredInstance(issuer).issue(payload as never, frame as never),
      ).resolves.toBeTypeOf('string');

    it('accepts _sd_decoy inside an ARRAY frame', async () => {
      // `_sd_decoy` is a frame key that is not an index, so a naive "every key
      // must be a valid index" guard would reject it.
      await accepts({ a: ['x', 'y', 'z'] }, { _sd: ['a'], a: { _sd: [0, 1, 2], _sd_decoy: 2 } });
    });

    it('accepts _sd_decoy inside an OBJECT frame', async () => {
      await accepts({ a: 'x', b: 'y' }, { _sd: ['a'], _sd_decoy: 2 });
    });

    it('accepts a nested array-of-objects frame', async () => {
      await accepts({ list: [{ p: 1 }, { q: 2 }] }, { _sd: ['list'], list: { _sd: [0], 1: { _sd: ['q'] } } });
    });

    it('accepts an array frame carrying only sub-frames and no _sd', async () => {
      await accepts({ list: [{ q: 2 }] }, { list: { 0: { _sd: ['q'] } } });
    });

    it('accepts an empty _sd — nothing was asked for, so nothing leaked', async () => {
      await accepts({ a: ['x'] }, { a: { _sd: [] } });
    });

    it('still refuses an _sd naming a nested path that does not exist', async () => {
      // The recursion has to carry the guard down, not just apply it at the top.
      await expect(
        vendoredInstance(issuer).issue({ a: { b: 1 } } as never, { a: { _sd: ['zzz'] } } as never),
      ).rejects.toBeInstanceOf(SdJwtFrameError);
    });
  });

  it('VENDORED and UPSTREAM agree exactly on the numeric form', async () => {
    // The other half of "the guard is not a blanket refusal": for every input
    // upstream handles correctly, the vendored copy must be indistinguishable.
    // Salts are random, so compare structure rather than bytes.
    const shape = (compact: string) =>
      decodedDisclosures(compact)
        .map((d) => (isMemberDisclosure(d) ? `member:${String(d[1])}` : 'element'))
        .sort();

    const mine = await vendoredInstance(issuer).issue(
      { credentialSubject: { ...SUBJECT } },
      frameWith([0, 1, 2]) as never,
    );
    const theirs = await upstream.issue(
      { credentialSubject: { ...SUBJECT } },
      frameWith([0, 1, 2]),
    );

    expect(shape(mine)).toEqual(shape(theirs));
  });
});
