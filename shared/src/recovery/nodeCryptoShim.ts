/**
 * The three Node `crypto` functions `slip39@0.1.9` needs, over `@noble/hashes`.
 *
 * ===========================================================================
 * WHY A SHIM AND NOT A REPLACEMENT LIBRARY (#355)
 * ===========================================================================
 * `node_modules/slip39/src/slip39_helper.js:4` does `require("crypto")` inside a
 * try/catch. Metro reads that shape as an optional dependency, so it bundles the
 * module and emits a RUNTIME throw instead of failing the build — guardian
 * recovery therefore ships to the handset and dies at first use, invisibly.
 *
 * The obvious repair is to reimplement SLIP-39 over noble. That is the dangerous
 * one. Every guardian share this system has ever issued was produced by
 * `slip39@0.1.9`, and a reimplementation that is one byte off in its KDF
 * silently invalidates all of them — a failure that surfaces years later, at the
 * only moment the shares are ever used. Substituting the primitives underneath
 * an UNCHANGED library cannot have that failure mode: the Shamir arithmetic, the
 * RS1024 checksum, the word list and the Feistel construction are untouched, and
 * the only claim to prove is that these three functions agree bit-for-bit with
 * Node's. That claim is cheap to test and is tested — see
 * `packages/backend/tests/fast/nodeCryptoShim.test.ts`.
 *
 * ===========================================================================
 * WHY IT LIVES IN `shared` AND NOT IN `packages/mobile`
 * ===========================================================================
 * It is only ever substituted on the mobile platform, so mobile looks like its
 * home. It is here instead because of dependency RESOLUTION, checked rather than
 * assumed: `packages/mobile/node_modules` carries an undeclared `@noble/hashes`
 * 2.0.1 (pulled in for `@toruslabs/eccrypto`) while `shared` declares ^1.8.0, and
 * a clean install on EAS reproduces neither arrangement. A shim resolving a
 * different hash implementation locally than in CI is precisely the class of bug
 * this file exists to avoid. `shared` declares the dependency, so the version is
 * the same everywhere, and the device bundles ONE copy of noble rather than two.
 *
 * ===========================================================================
 * WHAT IT DELIBERATELY DOES NOT DO
 * ===========================================================================
 * This is not a general `crypto` polyfill and must never be installed as one.
 * It implements exactly the surface `slip39_helper.js` calls, and refuses
 * everything else rather than approximating it — an unrecognised digest throws
 * instead of quietly hashing with SHA-256. `packages/mobile/metro.config.js`
 * substitutes it only for requests originating inside `node_modules/slip39`, so
 * any other module asking for `crypto` still fails loudly, as it should.
 */

import { hmac } from '@noble/hashes/hmac.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';

/** The only digest SLIP-39 uses. Anything else is a caller we have not vetted. */
const SUPPORTED_DIGEST = 'sha256';

export class NodeCryptoShimError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NodeCryptoShimError';
  }
}

function assertSupportedDigest(digest: string): void {
  if (digest !== SUPPORTED_DIGEST) {
    throw new NodeCryptoShimError(
      `This shim implements ${SUPPORTED_DIGEST} only, and was asked for '${digest}'. ` +
        'Refusing rather than substituting a different hash — silently returning the ' +
        'wrong digest would corrupt every share derived from it.',
    );
  }
}

/**
 * `Buffer.from(...)` results, plain number arrays and Uint8Arrays all arrive here.
 * Normalise without copying when we already have bytes.
 */
function toBytes(value: ArrayLike<number>, what: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (typeof value === 'string') {
    throw new NodeCryptoShimError(
      `${what} was a string. This shim takes bytes only; an implicit encoding choice is ` +
        'exactly the kind of guess that produces shares nobody can recover.',
    );
  }
  if (value == null || typeof value.length !== 'number') {
    throw new NodeCryptoShimError(`${what} is not an array of bytes.`);
  }
  return Uint8Array.from(value as ArrayLike<number>);
}

/**
 * Fails closed if there is no CSPRNG.
 *
 * `globalThis.crypto.getRandomValues` is the one generator present in both Node
 * and Hermes, and `recoveryKey.ts` already depends on exactly it. There is no
 * `Math.random` fallback on purpose: a share set built from predictable entropy
 * looks completely normal and is completely worthless.
 */
export function randomBytes(length = 32): Uint8Array {
  if (!Number.isInteger(length) || length < 0) {
    throw new NodeCryptoShimError(`randomBytes needs a non-negative integer, got ${length}.`);
  }
  const source = globalThis.crypto;
  if (typeof source?.getRandomValues !== 'function') {
    throw new NodeCryptoShimError(
      'No crypto.getRandomValues in this runtime. Refusing to generate guardian shares ' +
        'from a non-cryptographic source.',
    );
  }
  return source.getRandomValues(new Uint8Array(length));
}

export function pbkdf2Sync(
  password: ArrayLike<number>,
  salt: ArrayLike<number>,
  iterations: number,
  keylen: number,
  digest: string,
): Uint8Array {
  assertSupportedDigest(digest);
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new NodeCryptoShimError(`pbkdf2 iteration count must be a positive integer, got ${iterations}.`);
  }
  if (!Number.isInteger(keylen) || keylen < 1) {
    throw new NodeCryptoShimError(`pbkdf2 key length must be a positive integer, got ${keylen}.`);
  }
  return pbkdf2(sha256, toBytes(password, 'pbkdf2 password'), toBytes(salt, 'pbkdf2 salt'), {
    c: iterations,
    dkLen: keylen,
  });
}

/**
 * Node's streaming HMAC surface, narrowed to what `createDigest` uses:
 * `createHmac(alg, key).update(data).digest()`.
 *
 * Single-use by construction. Node lets a finalised HMAC be re-updated and gives
 * back nonsense; making that unconstructable here costs one boolean.
 */
export interface Hmac {
  update(data: ArrayLike<number>): Hmac;
  digest(): Uint8Array;
}

export function createHmac(algorithm: string, key: ArrayLike<number>): Hmac {
  assertSupportedDigest(algorithm);
  const mac = hmac.create(sha256, toBytes(key, 'hmac key'));
  let finalised = false;

  const handle: Hmac = {
    update(data) {
      if (finalised) {
        throw new NodeCryptoShimError('This HMAC has already been finalised by digest().');
      }
      mac.update(toBytes(data, 'hmac data'));
      return handle;
    },
    digest() {
      if (finalised) {
        throw new NodeCryptoShimError('This HMAC has already been finalised by digest().');
      }
      finalised = true;
      return mac.digest();
    },
  };

  return handle;
}
