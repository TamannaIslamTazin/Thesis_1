/**
 * base58btc and multibase, portably — the replacement for Credo's
 * `MultiBaseEncoder`.
 *
 * ===========================================================================
 * WHY THIS IS A COMPLETE REPLACEMENT AND NOT A SUBSET
 * ===========================================================================
 * Measured, not assumed. `@credo-ts/core`'s `MultiBaseEncoder` has exactly one
 * entry in each of its encoding and decoding maps:
 *
 *     const multibaseEncodingMap = { base58btc: ... }
 *     const multibaseDecodingMap = { z: ... }
 *
 * So "multibase" there means base58btc and nothing else, and its `BaseName` type
 * is the literal `'base58btc'`. Porting it therefore loses no capability. Every
 * `publicKeyMultibase` this system reads or writes is `z`-prefixed anyway —
 * Ed25519VerificationKey2020 mandates base58btc — so the narrow surface is the
 * correct one rather than a compromise.
 *
 * Any other multibase prefix is REFUSED, loudly, rather than guessed at. A key
 * encoding is written into an identifier that cannot be repaired afterwards.
 *
 * ===========================================================================
 * ONE DELIBERATE DIVERGENCE: NON-ASCII IS REJECTED
 * ===========================================================================
 * Credo decodes through `@multiformats/base-x`, which builds a 256-entry lookup
 * table and tests `if (carry === 255) return` to spot a non-alphabet character.
 * For a character above U+00FF the table lookup is `undefined`, not `255`, so
 * that test does not fire; the arithmetic then proceeds through `NaN` and the
 * input is silently accepted. Verified against the installed copy:
 *
 *     decode('中文')   -> Uint8Array(0)      // silently empty
 *     decode('abĀcd')  -> 0x14d72012         // silently wrong
 *     decode('0OIl')   -> throws             // ASCII case is handled correctly
 *
 * Both of those should be refusals. This implementation indexes a 128-entry
 * table and treats every code point at or above 128 as a non-digit, so the
 * refusal fires for all of them. The divergence only ever turns a silent
 * mis-decode into an error, which is the direction this project's rules require:
 * refuse rather than guess, and make a wrong state unconstructable.
 *
 * The algorithm below is otherwise a faithful port of the base58 in Bitcoin
 * Core's `base58.cpp`, which is what base-x itself is a port of.
 */

import { ERROR_CODES, SsiError } from '@ssi-healthcare/shared';

/** Bitcoin's ordering. Excludes `0`, `O`, `I` and `l` as visually ambiguous. */
export const BASE58BTC_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const BASE = BASE58BTC_ALPHABET.length;
/** base58btc's multibase prefix, per the multibase table. */
export const BASE58BTC_MULTIBASE_PREFIX = 'z';
/** The digit standing for zero; leading zero BYTES encode as leading `1`s. */
const LEADER = '1';
const NOT_A_DIGIT = 255;

/**
 * 128 entries, not 256: the alphabet is pure ASCII, so anything at or above 128
 * is a non-digit by construction and gets the same refusal as `0` or `O`.
 */
const DIGIT_VALUES = /* @__PURE__ */ (() => {
  const table = new Uint8Array(128).fill(NOT_A_DIGIT);
  for (let index = 0; index < BASE58BTC_ALPHABET.length; index++) {
    table[BASE58BTC_ALPHABET.charCodeAt(index)] = index;
  }
  return table;
})();

const LOG_58_OVER_LOG_256 = Math.log(BASE) / Math.log(256);
const LOG_256_OVER_LOG_58 = Math.log(256) / Math.log(BASE);

function refuse(message: string): never {
  throw new SsiError(ERROR_CODES.VALIDATION_ERROR, message, 400);
}

/** Lowercase hex, for error messages. `Buffer` is not available on a handset. */
export function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Decode base58btc WITHOUT a multibase prefix.
 *
 * Refuses any character outside the alphabet, including whitespace and any
 * non-ASCII code point. An empty string decodes to an empty array, matching the
 * implementation this replaces.
 */
export function base58btcDecode(text: string): Uint8Array {
  if (text.length === 0) return new Uint8Array(0);

  let zeroes = 0;
  let index = 0;
  while (index < text.length && text[index] === LEADER) {
    zeroes++;
    index++;
  }

  const size = ((text.length - index) * LOG_58_OVER_LOG_256 + 1) >>> 0;
  const bytes = new Uint8Array(size);
  let length = 0;

  for (; index < text.length; index++) {
    const code = text.charCodeAt(index);
    const digit = code < DIGIT_VALUES.length ? (DIGIT_VALUES[code] as number) : NOT_A_DIGIT;
    if (digit === NOT_A_DIGIT) {
      refuse(
        `'${text}' is not base58btc: ${JSON.stringify(text[index])} at position ${index} is ` +
          `not one of '${BASE58BTC_ALPHABET}'.`,
      );
    }

    let carry = digit;
    let written = 0;
    for (
      let position = size - 1;
      (carry !== 0 || written < length) && position !== -1;
      position--, written++
    ) {
      carry += BASE * (bytes[position] as number);
      bytes[position] = carry % 256;
      carry = (carry / 256) | 0;
    }
    // Unreachable while `size` is computed as above; kept because the
    // alternative to noticing here is a silently truncated key.
    if (carry !== 0) refuse('base58btc decoding overflowed its buffer.');
    length = written;
  }

  let start = size - length;
  while (start !== size && bytes[start] === 0) start++;

  const decoded = new Uint8Array(zeroes + (size - start));
  decoded.set(bytes.subarray(start), zeroes);
  return decoded;
}

/** Encode base58btc WITHOUT a multibase prefix. Empty input gives an empty string. */
export function base58btcEncode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  let zeroes = 0;
  let index = 0;
  while (index < bytes.length && bytes[index] === 0) {
    zeroes++;
    index++;
  }

  const size = ((bytes.length - index) * LOG_256_OVER_LOG_58 + 1) >>> 0;
  const digits = new Uint8Array(size);
  let length = 0;

  for (; index < bytes.length; index++) {
    let carry = bytes[index] as number;
    let written = 0;
    for (
      let position = size - 1;
      (carry !== 0 || written < length) && position !== -1;
      position--, written++
    ) {
      carry += 256 * (digits[position] as number);
      digits[position] = carry % BASE;
      carry = (carry / BASE) | 0;
    }
    if (carry !== 0) refuse('base58btc encoding overflowed its buffer.');
    length = written;
  }

  let start = size - length;
  while (start !== size && digits[start] === 0) start++;

  let encoded = LEADER.repeat(zeroes);
  for (; start < size; start++) encoded += BASE58BTC_ALPHABET[digits[start] as number];
  return encoded;
}

/** The only multibase encoding this system reads or writes. */
export type MultibaseName = 'base58btc';

export interface DecodedMultibase {
  readonly data: Uint8Array;
  readonly baseName: MultibaseName;
}

/**
 * Decode a multibase string, i.e. a base-identifying prefix then the payload.
 *
 * Shape-compatible with `MultiBaseEncoder.decode`, so a call site swaps the
 * import and nothing else.
 */
export function multibaseDecode(text: string): DecodedMultibase {
  if (text.length === 0) {
    refuse('An empty string carries no multibase prefix, so there is nothing to decode.');
  }
  const prefix = text[0] as string;
  if (prefix !== BASE58BTC_MULTIBASE_PREFIX) {
    refuse(
      `No decoder for multibase prefix ${JSON.stringify(prefix)}. Only ` +
        `'${BASE58BTC_MULTIBASE_PREFIX}' (base58btc) is supported, which is what ` +
        'Ed25519VerificationKey2020 mandates. Refusing to guess at the encoding.',
    );
  }
  return { data: base58btcDecode(text.slice(1)), baseName: 'base58btc' };
}

/** Encode to multibase. `baseName` is explicit so a call site states its intent. */
export function multibaseEncode(bytes: Uint8Array, baseName: MultibaseName): string {
  if (baseName !== 'base58btc') {
    refuse(`Unsupported multibase encoding ${JSON.stringify(baseName)}.`);
  }
  return BASE58BTC_MULTIBASE_PREFIX + base58btcEncode(bytes);
}
