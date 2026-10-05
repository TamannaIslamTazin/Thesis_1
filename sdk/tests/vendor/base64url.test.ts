/**
 * DIVERGENCE D1 — `js-base64` replaced, byte for byte.
 *
 * This is the one divergence where "behaviour is unchanged" is the WHOLE claim,
 * so asserting it against the real `js-base64` rather than against my own idea
 * of what it does is the only honest way to test it. `js-base64` is a
 * devDependency for exactly this reason and is never shipped.
 *
 * WHY IT MATTERS THAT THIS IS EXACT. A disclosure's digest is the hash of its
 * base64url-encoded form EXACTLY AS IT APPEARS ON THE WIRE. One stray `=` of
 * padding, or one byte of difference in how a non-ASCII string is encoded,
 * changes every digest — and the failure would not look like an encoding bug.
 * It would look like every credential this SDK touches being tampered with.
 */
import { describe, it, expect } from 'vitest';
import { Base64 } from 'js-base64';
import {
  base64urlEncode,
  base64urlDecode,
  uint8ArrayToBase64Url,
  base64UrlToUint8Array,
} from '../../src/vendor/sd-jwt/utils';

const SAMPLES = [
  '',
  'a',
  'ab',
  'abc',
  'abcd',
  '{"iss":"did:cheqd:bdhealthtestnet:abc","iat":1755000000}',
  // Bengali. Patient names in this system are routinely non-ASCII, and a
  // latin1 round-trip corrupts them silently rather than throwing.
  'আহসান রহমান',
  'Dr Karim — BMDC‑4471',
  '💊 Metformin 500mg',
  // Lengths that straddle every base64 padding boundary.
  ...Array.from({ length: 12 }, (_, i) => 'x'.repeat(i)),
];

describe('D1 — base64url without js-base64', () => {
  it('encodes identically to Base64.encodeURI for every sample', () => {
    for (const sample of SAMPLES) {
      expect(base64urlEncode(sample), `encoding ${JSON.stringify(sample)}`).toBe(
        Base64.encodeURI(sample),
      );
    }
  });

  it('emits NO padding — the property digests depend on', () => {
    for (const sample of SAMPLES) {
      expect(base64urlEncode(sample)).not.toContain('=');
    }
  });

  it('emits the url alphabet, never + or /', () => {
    // `?~?` and friends are chosen to force + and / in standard base64.
    for (const sample of ['??~?', 'ÿþý', '>>>???']) {
      const encoded = base64urlEncode(sample);
      expect(encoded).not.toMatch(/[+/]/);
      expect(encoded).toBe(Base64.encodeURI(sample));
    }
  });

  it('decodes identically to Base64.decode for every sample', () => {
    for (const sample of SAMPLES) {
      const encoded = Base64.encodeURI(sample);
      expect(base64urlDecode(encoded), `decoding ${JSON.stringify(sample)}`).toBe(
        Base64.decode(encoded),
      );
      expect(base64urlDecode(encoded)).toBe(sample);
    }
  });

  it('accepts PADDED input, and the standard alphabet, exactly as js-base64 did', () => {
    // Real JWTs arrive both ways. A decoder that only handles the unpadded url
    // form rejects honest input from other implementations.
    for (const sample of SAMPLES) {
      const standardPadded = Base64.encode(sample);
      expect(base64urlDecode(standardPadded)).toBe(Base64.decode(standardPadded));
      expect(base64urlDecode(standardPadded)).toBe(sample);
    }
  });

  it('round-trips bytes identically to fromUint8Array/toUint8Array', () => {
    for (let length = 0; length < 40; length++) {
      const bytes = new Uint8Array(length);
      for (let i = 0; i < length; i++) bytes[i] = (i * 37 + 11) % 256;

      expect(uint8ArrayToBase64Url(bytes)).toBe(Base64.fromUint8Array(bytes, true));
      expect(Array.from(base64UrlToUint8Array(uint8ArrayToBase64Url(bytes)))).toEqual(
        Array.from(bytes),
      );
    }
  });

  it('handles a payload large enough to exercise the chunked encoder', () => {
    // `String.fromCharCode(...bytes)` blows the argument limit somewhere around
    // 100k; a credential with an embedded image gets there. The chunking exists
    // for this, so it needs a test that would notice if it were removed.
    const big = new Uint8Array(300_000);
    for (let i = 0; i < big.length; i++) big[i] = i % 256;

    expect(uint8ArrayToBase64Url(big)).toBe(Base64.fromUint8Array(big, true));
  });

  /**
   * Vendor-tree source with comments stripped.
   *
   * COMMENTS MUST BE STRIPPED, not merely tolerated. The divergence notes quote
   * the upstream code they replaced — `import { Base64 } from 'js-base64';` —
   * so a naive grep for that string finds it in the very file that removed it.
   * That is the correct thing for the comment to say, so the scanner is what
   * has to be precise.
   */
  const vendorSources = async (): Promise<Array<{ path: string; code: string }>> => {
    const { readFileSync, readdirSync, statSync } = await import('node:fs');
    const { join } = await import('node:path');

    const walk = (dir: string): string[] =>
      readdirSync(dir).flatMap((entry) => {
        const path = join(dir, entry);
        return statSync(path).isDirectory() ? walk(path) : [path];
      });

    return walk('src/vendor/sd-jwt')
      .filter((path) => path.endsWith('.ts'))
      .map((path) => ({
        path,
        code: readFileSync(path, 'utf8')
          .replace(/\/\*[\s\S]*?\*\//g, '')
          .replace(/^\s*\/\/.*$/gm, ''),
      }));
  };

  it('leaves no import of js-base64 in the shipped vendor tree', async () => {
    // The point of D1. A test asserting behavioural equivalence would still
    // pass if the dependency crept back in, so assert its absence directly.
    const offenders = (await vendorSources())
      .filter(({ code }) => /from\s+['"]js-base64['"]/.test(code))
      .map(({ path }) => path);

    expect(offenders).toEqual([]);
  });

  it('leaves no @sd-jwt/* import in the shipped vendor tree — the severance itself', async () => {
    // This is the deliverable in one assertion: nothing under the vendored tree
    // resolves anything from node_modules. If it ever does, the fork is not a
    // fork.
    const offenders = (await vendorSources())
      .filter(({ code }) => /from\s+['"]@sd-jwt\//.test(code))
      .map(({ path }) => path);

    expect(offenders).toEqual([]);
  });

  it('the comment-stripping scanner is not vacuous', async () => {
    // A scanner that found nothing because it looked at nothing would pass both
    // tests above. Prove it still sees real imports.
    const sources = await vendorSources();
    expect(sources.length).toBeGreaterThan(10);
    expect(sources.some(({ code }) => /from\s+['"]\.\.\/types['"]/.test(code))).toBe(true);
  });
});
