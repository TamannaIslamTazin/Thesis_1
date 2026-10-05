/**
 * Crypto that runs on a WORKLET RUNTIME's thread — the wallet's port of the
 * necessary @noble/hashes primitives.
 *
 * WHY A PORT. Worklet serialization drops function properties and cannot
 * resolve module-scoped class factories, so noble's createHasher wrappers and
 * its Hash classes cannot run in a worklet runtime at all; both failures were
 * measured on the handset (20 Sep 2026) and are recorded in the owner's log
 * (#459). Bundle Mode would fix them, but it is experimental and sits under
 * Reanimated's UI worklets.
 *
 * WHAT REPLACES THEM. `core.ts`: SHA-256 as a factory-created plain object,
 * HMAC and PBKDF2 built over it, and scrypt's Salsa/BlockMix/ROMix transcribed
 * from noble (MIT, attributed). Everything is a plain function or a plain
 * object created inside the runtime, so nothing depends on module scope.
 *
 * SAFETY. Every primitive is verified bit-for-bit against @noble/hashes — RFC
 * vectors plus random cross-checks — in Node (tools/verifyWorkletSubset.ts)
 * and again ON DEVICE against the RN-side implementation before any caller
 * switches over. A KDF that is one bit off unwraps nothing.
 *
 * WHERE THIS MAY BE IMPORTED FROM. Only through the Metro pipeline, which
 * compiles these sources with the app's Babel config (the worklets plugin must
 * stamp each function); packages/mobile/metro.config.js redirects the import
 * here explicitly, and the package export for this subpath therefore points at
 * SOURCE. Node consumers use the KAT tool, which imports the file directly.
 */
export {
  sha256,
  sha256Init,
  sha256Update,
  sha256Digest,
  hmacSha256,
  pbkdf2Sha256,
  scrypt,
  type Sha256State,
  type ScryptOptions,
} from './core';
