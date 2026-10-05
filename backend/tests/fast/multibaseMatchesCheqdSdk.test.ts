/**
 * The wallet's `publicKeyMultibase` must be byte-identical to what the chain
 * writes, because it is anchored as a verification method and a verification
 * method cannot be corrected without the key it names (S-1 §8.4). A silently
 * wrong encoding here produces a DID nobody can ever sign for.
 *
 * The wallet cannot import `@cheqd/sdk/utils` — it is far too heavy for the
 * bundle — so `packages/shared/src/recovery/multibase.ts` reimplements the
 * encoding. This test is the join: it holds that reimplementation against the
 * SDK the backend actually uses, including the leading-zero cases where base58
 * implementations usually diverge.
 */
import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { toMultibaseRaw } from '@cheqd/sdk/utils';

import { ed25519PublicKeyToMultibase } from '@ssi-healthcare/shared';

describe('ed25519PublicKeyToMultibase agrees with @cheqd/sdk', () => {
  it('matches across random keys', () => {
    for (let i = 0; i < 200; i++) {
      const publicKey = new Uint8Array(randomBytes(32));
      expect(ed25519PublicKeyToMultibase(publicKey)).toBe(toMultibaseRaw(publicKey));
    }
  });

  it('matches when the key has leading zero bytes', () => {
    // base58 encodes each leading zero as a separate '1'; an implementation
    // that converts numerically without handling them loses length silently.
    for (const zeros of [1, 2, 5, 31]) {
      const publicKey = new Uint8Array(32);
      publicKey.set(new Uint8Array(randomBytes(32 - zeros)), zeros);
      expect(ed25519PublicKeyToMultibase(publicKey)).toBe(toMultibaseRaw(publicKey));
    }
  });

  it('matches for an all-zero key', () => {
    const publicKey = new Uint8Array(32);
    expect(ed25519PublicKeyToMultibase(publicKey)).toBe(toMultibaseRaw(publicKey));
  });

  it('refuses a key of the wrong length instead of encoding it', () => {
    // Encoding a short key would anchor an unusable verification method.
    expect(() => ed25519PublicKeyToMultibase(new Uint8Array(31))).toThrow(/32-byte/);
    expect(() => ed25519PublicKeyToMultibase(new Uint8Array(33))).toThrow(/32-byte/);
  });
});
