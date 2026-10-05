/**
 * base64url encode/decode with no dependency on `btoa`/`atob`.
 *
 * ===========================================================================
 * WHY THIS EXISTS, MEASURED RATHER THAN ASSUMED
 * ===========================================================================
 * `keyEnvelope.ts` and `prfEnvelope.ts` each carried their own copy of this
 * pair, both built on `btoa`/`atob`. Those are DOM globals — not part of the
 * ECMAScript spec, not something Node or Hermes are obliged to provide.
 * `packages/mobile/tools/runPassphraseEnvelopeProbe.mjs` bundles this
 * envelope family through the app's real Metro config and runs it in a
 * context with the globals React Native's own `InitializeCore.js` actually
 * installs (checked: `node_modules/react-native/src/private/setup/*.js` and
 * `Libraries/Core/setUpGlobals.js` install neither `btoa` nor `atob`). That
 * run failed with `ReferenceError: btoa is not defined`.
 *
 * What this does NOT tell us: whether Hermes itself supplies `btoa`/`atob`
 * as an engine builtin outside of what React Native's JS-level polyfills
 * install — this probe runs the bundle in Node's V8 in a stripped `vm`
 * context, not in Hermes, so an engine-level builtin would not show up
 * either way. That distinction could not be resolved without a device or an
 * EAS build. Given a working, dependency-free implementation costs one
 * small file, the safer move is to stop depending on the answer.
 *
 * ===========================================================================
 * WIRE COMPATIBILITY, NOT JUST A REWRITE
 * ===========================================================================
 * This has to produce byte-IDENTICAL output to the `btoa`-based code it
 * replaces, or every envelope already written becomes unopenable. It is
 * standard base64 (RFC 4648 §5, unpadded, `-`/`_` in place of `+`/`/`) —
 * exactly what `btoa`/`atob` and Node's `Buffer...toString('base64url')`
 * already agree on. `keyEnvelope.test.ts`'s legacy-compatibility suite
 * round-trips through `Buffer.from(..., 'base64url')` against this code and
 * still passes, which is the check that would have caught a divergence.
 */

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function bytesToBase64Url(bytes: Uint8Array): string {
  let output = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const byte0 = bytes[i];
    const byte1 = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const byte2 = i + 2 < bytes.length ? bytes[i + 2] : undefined;

    output += BASE64URL_ALPHABET[byte0 >> 2];
    output += BASE64URL_ALPHABET[((byte0 & 0x03) << 4) | ((byte1 ?? 0) >> 4)];
    if (byte1 !== undefined) {
      output += BASE64URL_ALPHABET[((byte1 & 0x0f) << 2) | ((byte2 ?? 0) >> 6)];
    }
    if (byte2 !== undefined) {
      output += BASE64URL_ALPHABET[byte2 & 0x3f];
    }
  }
  return output;
}

export function base64UrlToBytes(value: string): Uint8Array {
  const cleaned = value.replace(/[^A-Za-z0-9\-_]/g, '');
  const byteLength = Math.floor((cleaned.length * 6) / 8);
  const bytes = new Uint8Array(byteLength);

  let buffer = 0;
  let bitsInBuffer = 0;
  let byteIndex = 0;

  for (let i = 0; i < cleaned.length; i += 1) {
    const charIndex = BASE64URL_ALPHABET.indexOf(cleaned[i]);
    if (charIndex === -1) continue;

    buffer = (buffer << 6) | charIndex;
    bitsInBuffer += 6;

    if (bitsInBuffer >= 8) {
      bitsInBuffer -= 8;
      bytes[byteIndex] = (buffer >> bitsInBuffer) & 0xff;
      byteIndex += 1;
    }
  }

  return bytes;
}
