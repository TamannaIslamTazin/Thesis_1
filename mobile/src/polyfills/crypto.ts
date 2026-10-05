/**
 * Installs `globalThis.crypto.getRandomValues` on Hermes.
 *
 * `@ssi-healthcare/shared` calls it directly to mint recovery key seeds. Hermes
 * does not provide it: on device the call threw "Cannot read property
 * 'getRandomValues' of undefined" and recovery enrolment could not complete.
 * Node has it, so every test and every backend path passed.
 *
 * This is the same shape as the btoa/atob gap in `recovery/base64Url.ts` — a
 * global that exists in Node, is assumed by shared code, and is absent from the
 * runtime the wallet actually runs on.
 *
 * Deliberately throws when the native module is missing. A silent fallback to
 * Math.random would produce seeds that look well-formed and are predictable,
 * which is the one failure here that would not announce itself.
 */
import { getRandomValues } from 'expo-crypto';

const existing = (globalThis as { crypto?: Partial<Crypto> }).crypto;

if (typeof existing?.getRandomValues !== 'function') {
  const shim = {
    ...(existing ?? {}),
    getRandomValues<T extends ArrayBufferView | null>(array: T): T {
      if (array === null) return array;
      if (typeof getRandomValues !== 'function') {
        throw new Error(
          'expo-crypto.getRandomValues is unavailable; refusing to generate key material.',
        );
      }
      return getRandomValues(array as never) as T;
    },
  };

  Object.defineProperty(globalThis, 'crypto', {
    value: shim,
    configurable: true,
    writable: true,
  });
}
