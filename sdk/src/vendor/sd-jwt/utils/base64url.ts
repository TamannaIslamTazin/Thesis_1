/**
 * VENDORED from @sd-jwt/utils@0.19.0 — src/base64url.ts
 *
 * Apache-2.0. Copyright the sd-jwt-js authors. See ../LICENSE and ../NOTICE.
 * Upstream: https://github.com/openwallet-foundation/sd-jwt-js
 *
 * MODIFICATION NOTICE (Apache-2.0 §4(b)): REWRITTEN by BDHealthTrust — see divergence D1 (js-base64 removed) in
 *   ../NOTICE. The exported names and their behaviour are unchanged; the
 *   implementation behind them is ours.
 */

// ── BDHT DIVERGENCE D1 ──────────────────────────────────────────────────────
// Upstream is four re-exports of `js-base64`:
//
//     import { Base64 } from 'js-base64';
//     export const base64urlEncode = Base64.encodeURI;
//     export const base64urlDecode = Base64.decode;
//     export const uint8ArrayToBase64Url = (i) => Base64.fromUint8Array(i, true);
//     export const base64UrlToUint8Array = (i) => Base64.toUint8Array(i);
//
// `js-base64` was the only runtime dependency any of the five vendored packages
// had. Vendoring @sd-jwt/core to sever an upstream dependency while leaving a
// transitive one in place would move the risk down a level rather than remove
// it, so it is replaced here rather than vendored alongside.
//
// PLATFORM. `atob`/`btoa` and `TextEncoder`/`TextDecoder` are globals in every
// browser and in Node >= 16, so this is the one implementation that runs on
// both targets. It deliberately does not reach for `Buffer` (Node-only) or for
// any bundler shim.
//
// BEHAVIOUR IS MATCHED, NOT APPROXIMATED. The three properties that matter,
// each of which the upstream library provided and each of which something in
// this tree depends on:
//   1. `base64urlEncode` emits base64url (`-`/`_`) with NO padding. Disclosure
//      digests are computed over this exact string, so a stray `=` changes
//      every digest and nothing verifies.
//   2. `base64urlDecode` accepts padded or unpadded input in either alphabet.
//      Real-world JWTs arrive both ways.
//   3. Both round-trip non-ASCII correctly through UTF-8. Patient names in this
//      system are routinely Bengali; a latin1 round-trip corrupts them silently.
// `tests/vendor/base64url.test.ts` asserts all three against `js-base64` itself.
// ────────────────────────────────────────────────────────────────────────────

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** base64 -> base64url, padding stripped. */
const toUrlAlphabet = (base64: string): string =>
  base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** base64url -> base64, padding restored. Tolerates input already in base64. */
const toStandardAlphabet = (base64url: string): string => {
  const standard = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const remainder = standard.length % 4;
  return remainder === 0 ? standard : standard + '='.repeat(4 - remainder);
};

export const uint8ArrayToBase64Url = (input: Uint8Array): string => {
  // Chunked to stay clear of the argument-count limit on String.fromCharCode,
  // which a large credential payload can otherwise hit.
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < input.length; i += CHUNK) {
    binary += String.fromCharCode(...input.subarray(i, i + CHUNK));
  }
  return toUrlAlphabet(btoa(binary));
};

export const base64UrlToUint8Array = (input: string): Uint8Array => {
  const binary = atob(toStandardAlphabet(input));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

export const base64urlEncode = (input: string): string =>
  uint8ArrayToBase64Url(encoder.encode(input));

export const base64urlDecode = (input: string): string =>
  decoder.decode(base64UrlToUint8Array(input));
