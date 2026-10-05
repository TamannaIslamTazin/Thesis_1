/**
 * THE SHIM THAT LETS GUARDIAN RECOVERY RUN ON A HANDSET (#355).
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ACTUALLY AT RISK, AND WHY IT IS TESTED HERE RATHER THAN ASSUMED
 * ---------------------------------------------------------------------------
 * `slip39@0.1.9` needs `pbkdf2Sync`, `randomBytes` and `createHmac` from Node's
 * `crypto`, which does not exist on React Native. `packages/mobile/metro.config.js`
 * substitutes `shared/src/recovery/nodeCryptoShim.ts` for that one library, so
 * on a device the SLIP-39 arithmetic runs over `@noble/hashes` instead.
 *
 * The library itself is UNCHANGED, so the only way this can invalidate an
 * already-issued guardian share is if the shim's primitives disagree with
 * Node's by even one bit. That is what these tests exist to rule out, and they
 * rule it out DIFFERENTIALLY: every case is computed both ways and compared,
 * with `node:crypto` as the reference — the same technique used when vendoring
 * `@sd-jwt`.
 *
 * The end-to-end half of this claim is in `packages/mobile/tools/`: the probe
 * there runs the 45 official Trezor vectors through the real Metro bundle in a
 * host with no Node crypto at all. This file is the unit-level companion, and
 * it also covers the refusals, which the probe cannot reach.
 *
 * ---------------------------------------------------------------------------
 * WHY THE SHIM COMES FROM A SUBPATH AND NOT THE BARREL
 * ---------------------------------------------------------------------------
 * `randomBytes` / `createHmac` / `pbkdf2Sync` are generic enough that exporting
 * them through `@ssi-healthcare/shared` — and therefore through
 * `@ssi-healthcare/sdk/shared` — would drop three colliding names into an
 * integrator's namespace to serve one library's private need. So the shim has
 * its own entry point instead. The first draft reached it by a relative path
 * into `shared/src`, which `typecheck:tests` correctly rejected as crossing the
 * package boundary; the named subpath is the fix, rather than widening rootDir.
 */
import { createHmac as nodeCreateHmac, pbkdf2Sync as nodePbkdf2Sync } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { withSlip39Runtime } from '@ssi-healthcare/shared';
import {
  NodeCryptoShimError,
  createHmac,
  pbkdf2Sync,
  randomBytes,
} from '@ssi-healthcare/shared/recovery/node-crypto-shim';

/**
 * Deliberately not `Buffer.from(...).toString('hex')`: several tests below remove
 * the `Buffer` global to exercise the React Native case, and a helper that needed
 * it would fail inside them. The first draft did exactly that, which is a small
 * live demonstration of why the polyfill is scoped to one call rather than
 * installed process-wide.
 */
const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

/** The exact shape `slip39_helper.js:183` calls with: 4 rounds of 2500 iterations. */
const SLIP39_ITERATIONS = 2500;

function randomNumberArray(length: number): number[] {
  return Array.from({ length }, () => Math.floor(Math.random() * 256));
}

describe('the node crypto shim, against node:crypto itself', () => {
  it('derives the same key as pbkdf2Sync at the settings SLIP-39 uses', () => {
    // dkLen 16 and 32 are the two master-secret halves SLIP-39 actually feeds in.
    for (const keylen of [16, 32]) {
      for (let trial = 0; trial < 8; trial += 1) {
        const password = randomNumberArray(1 + keylen);
        const salt = randomNumberArray(6 + keylen);

        const ours = pbkdf2Sync(password, salt, SLIP39_ITERATIONS, keylen, 'sha256');
        const theirs = nodePbkdf2Sync(
          Buffer.from(password),
          Buffer.from(salt),
          SLIP39_ITERATIONS,
          keylen,
          'sha256',
        );

        expect(hex(ours)).toBe(hex(new Uint8Array(theirs)));
      }
    }
  });

  it('derives the same key across iteration counts and lengths', () => {
    for (const [iterations, keylen] of [
      [1, 1],
      [1, 64],
      [2, 32],
      [1000, 20],
    ] as const) {
      const password = randomNumberArray(9);
      const salt = randomNumberArray(13);

      expect(hex(pbkdf2Sync(password, salt, iterations, keylen, 'sha256'))).toBe(
        hex(new Uint8Array(nodePbkdf2Sync(Buffer.from(password), Buffer.from(salt), iterations, keylen, 'sha256'))),
      );
    }
  });

  it('computes the same HMAC, including the chained update SLIP-39 uses', () => {
    for (let trial = 0; trial < 16; trial += 1) {
      const key = randomNumberArray(1 + Math.floor(Math.random() * 80));
      const first = randomNumberArray(1 + Math.floor(Math.random() * 80));
      const second = randomNumberArray(Math.floor(Math.random() * 40));

      const ours = createHmac('sha256', key).update(first).update(second).digest();
      const theirs = nodeCreateHmac('sha256', Buffer.from(key))
        .update(Buffer.from(first))
        .update(Buffer.from(second))
        .digest();

      expect(hex(ours)).toBe(hex(new Uint8Array(theirs)));
    }
  });

  it('matches on the empty-message and long-key edges', () => {
    const longKey = randomNumberArray(100); // longer than SHA-256's 64-byte block
    expect(hex(createHmac('sha256', longKey).update([]).digest())).toBe(
      hex(new Uint8Array(nodeCreateHmac('sha256', Buffer.from(longKey)).update(Buffer.from([])).digest())),
    );

    expect(hex(createHmac('sha256', []).update([1, 2, 3]).digest())).toBe(
      hex(new Uint8Array(nodeCreateHmac('sha256', Buffer.from([])).update(Buffer.from([1, 2, 3])).digest())),
    );
  });

  it('accepts Buffers and Uint8Arrays identically, since slip39 passes Buffers', () => {
    const bytes = randomNumberArray(40);
    expect(hex(createHmac('sha256', Buffer.from(bytes)).update(Buffer.from(bytes)).digest())).toBe(
      hex(createHmac('sha256', Uint8Array.from(bytes)).update(Uint8Array.from(bytes)).digest()),
    );
  });
});

describe('the shim refuses rather than approximating', () => {
  it('will not substitute a different digest', () => {
    // Silently hashing with SHA-256 when asked for SHA-512 would produce shares
    // that look perfect and cannot be recovered by anything else.
    expect(() => pbkdf2Sync([1], [2], 1, 16, 'sha512')).toThrow(NodeCryptoShimError);
    expect(() => createHmac('sha512', [1])).toThrow(NodeCryptoShimError);
    expect(() => createHmac('SHA256', [1])).toThrow(NodeCryptoShimError);
  });

  it('will not take a string, because that would be an implicit encoding choice', () => {
    expect(() => createHmac('sha256', 'secret' as unknown as number[])).toThrow(NodeCryptoShimError);
  });

  it('will not accept a nonsensical iteration count or key length', () => {
    expect(() => pbkdf2Sync([1], [2], 0, 16, 'sha256')).toThrow(NodeCryptoShimError);
    expect(() => pbkdf2Sync([1], [2], 1.5, 16, 'sha256')).toThrow(NodeCryptoShimError);
    expect(() => pbkdf2Sync([1], [2], 1, 0, 'sha256')).toThrow(NodeCryptoShimError);
  });

  it('will not let a finalised HMAC be reused', () => {
    const mac = createHmac('sha256', [1, 2, 3]);
    mac.update([4]).digest();
    expect(() => mac.digest()).toThrow(NodeCryptoShimError);
    expect(() => mac.update([5])).toThrow(NodeCryptoShimError);
  });
});

describe('randomBytes fails closed', () => {
  it('returns the requested number of distinct bytes', () => {
    expect(randomBytes(32)).toHaveLength(32);
    expect(randomBytes()).toHaveLength(32);
    expect(hex(randomBytes(32))).not.toBe(hex(randomBytes(32)));
  });

  it('REFUSES when there is no CSPRNG, rather than falling back to Math.random', () => {
    // The property under test is the absence of a fallback. A shim that quietly
    // used Math.random would produce a share set that looks completely normal
    // and is completely worthless, with nothing downstream able to notice.
    const globals = globalThis as { crypto?: unknown };
    const real = globals.crypto;
    try {
      delete globals.crypto;
      expect(() => randomBytes(32)).toThrow(NodeCryptoShimError);
    } finally {
      globals.crypto = real;
    }
  });

  it('rejects a negative or fractional length', () => {
    expect(() => randomBytes(-1)).toThrow(NodeCryptoShimError);
    expect(() => randomBytes(1.5)).toThrow(NodeCryptoShimError);
  });
});

describe('the slip39 runtime scope', () => {
  it('is a no-op where Buffer already exists, so the backend is unchanged', () => {
    const before = globalThis.Buffer;
    expect(withSlip39Runtime(() => globalThis.Buffer)).toBe(before);
    expect(globalThis.Buffer).toBe(before);
  });

  it('installs Buffer.from only for the duration of the call, and removes it after', () => {
    const globals = globalThis as { Buffer?: unknown };
    const real = globals.Buffer;
    try {
      delete globals.Buffer;
      expect(typeof globals.Buffer).toBe('undefined');

      const inside = withSlip39Runtime(() => {
        // The one operation slip39 performs on it.
        return (globalThis as unknown as { Buffer: { from(v: number[]): Uint8Array } }).Buffer.from([
          1, 2, 3,
        ]);
      });

      expect(hex(inside)).toBe('010203');
      expect(typeof globals.Buffer).toBe('undefined');
    } finally {
      globals.Buffer = real;
    }
  });

  it('removes Buffer even when the operation throws', () => {
    const globals = globalThis as { Buffer?: unknown };
    const real = globals.Buffer;
    try {
      delete globals.Buffer;
      expect(() =>
        withSlip39Runtime(() => {
          throw new Error('boom');
        }),
      ).toThrow('boom');
      expect(typeof globals.Buffer).toBe('undefined');
    } finally {
      globals.Buffer = real;
    }
  });

  it('refuses anything on the polyfill other than from, by name', () => {
    const globals = globalThis as { Buffer?: unknown };
    const real = globals.Buffer;
    try {
      delete globals.Buffer;
      withSlip39Runtime(() => {
        const stub = (globalThis as unknown as { Buffer: Record<string, unknown> }).Buffer;
        expect(() => stub.alloc).toThrow(/slip39Runtime/);
        // Silent for the keys engines and debuggers touch incidentally.
        expect(stub.then).toBeUndefined();
      });
    } finally {
      globals.Buffer = real;
    }
  });

  it('refuses an async operation, whose continuation would run unpolyfilled', () => {
    const globals = globalThis as { Buffer?: unknown };
    const real = globals.Buffer;
    try {
      delete globals.Buffer;
      expect(() => withSlip39Runtime(async () => 1)).toThrow(/async operation/);
    } finally {
      globals.Buffer = real;
    }
  });
});
