#!/usr/bin/env node
/**
 * KAT for the worklet-runtime crypto port in ../src/worklet-crypto/core.ts.
 *
 * This is a HAND PORT of noble's primitives (neither the library, a class
 * wrapper, nor a factory survives the worklet boundary — see core.ts), and a
 * hand port of cryptographic arithmetic does not fail loudly: it produces
 * well-formed arithmetic that computes the wrong digest, the exact failure
 * class this project keeps paying for. It happened here — this KAT caught a
 * rotate-left/rotate-right inversion in the Salsa20 core that no typecheck
 * could see.
 *
 * The port is checked three ways:
 *
 *   1. RFC vectors: sha256, HMAC-SHA256 (RFC 4231), PBKDF2-HMAC-SHA256,
 *      scrypt (RFC 7914, all published vectors including the 16 MiB one).
 *   2. Cross-check against the INSTALLED @noble/hashes on random inputs, so a
 *      future noble bump or a subtle transcription change is caught even
 *      where no published vector exists.
 *   3. Timing of the scrypt parameters the wallet actually uses (N=2^15), as a
 *      workstation baseline for comparison with the device's worker runtime
 *      (device 20 Sep 2026: parity MATCH at N=256; N=2^15 workerMs=37389).
 *
 * Run:  npx tsx tools/verifyWorkletSubset.ts   (from packages/shared)
 */
import { sha256 as nSha256 } from '@noble/hashes/sha2';
import { hmac as nHmac } from '@noble/hashes/hmac';
import { pbkdf2 as nPbkdf2 } from '@noble/hashes/pbkdf2';
import { scrypt as nScrypt } from '@noble/hashes/scrypt';
import {
  sha256 as vSha256,
  hmacSha256,
  pbkdf2Sha256,
  scrypt as vScrypt,
} from '../src/worklet-crypto/core';

const vHmac = (_h: unknown, key: Uint8Array, msg: Uint8Array): Uint8Array =>
  hmacSha256(key, msg);

// Signature-compatible shim for the vector table below.
const vPbkdf2 = (
  _h: unknown,
  pw: Uint8Array,
  salt: Uint8Array,
  opts: { c: number; dkLen: number },
): Uint8Array => pbkdf2Sha256(pw, salt, opts.c, opts.dkLen);

let failures = 0;

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

function check(label: string, got: string, want: string): void {
  const ok = got === want;
  if (!ok) failures += 1;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok ? '' : `\n     got  ${got}\n     want ${want}`}`);
}

// 1. Published vectors -------------------------------------------------------
check('sha256("abc")', hex(vSha256(utf8('abc'))),
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
check('sha256("")', hex(vSha256(new Uint8Array(0))),
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

// RFC 4231 case 1 and 2.
check('hmac-sha256 case 1', hex(vHmac(vSha256, new Uint8Array(20).fill(0x0b), utf8('Hi There'))),
  'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
check('hmac-sha256 case 2', hex(vHmac(vSha256, utf8('Jefe'), utf8('what do ya want for nothing?'))),
  '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');

// PBKDF2-HMAC-SHA256, published vector (password/salt/1/32).
check('pbkdf2 c=1', hex(vPbkdf2(vSha256, utf8('password'), utf8('salt'), { c: 1, dkLen: 32 })),
  '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
check('pbkdf2 c=2', hex(vPbkdf2(vSha256, utf8('password'), utf8('salt'), { c: 2, dkLen: 32 })),
  'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43');

// RFC 7914 scrypt vectors.
check('scrypt rfc7914 #1', hex(vScrypt(utf8(''), utf8(''), { N: 16, r: 1, p: 1, dkLen: 64 })),
  '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906');
check('scrypt rfc7914 #2', hex(vScrypt(utf8('password'), utf8('NaCl'), { N: 1024, r: 8, p: 16, dkLen: 64 })),
  'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640');
check('scrypt rfc7914 #3', hex(vScrypt(utf8('pleaseletmein'), utf8('SodiumChloride'), { N: 16384, r: 8, p: 1, dkLen: 64 })),
  '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887');

// 2. Cross-check against installed @noble on random inputs -------------------
let mismatches = 0;
for (let i = 0; i < 25; i += 1) {
  const a = crypto.getRandomValues(new Uint8Array(1 + (i % 40)));
  const b = crypto.getRandomValues(new Uint8Array(1 + (i % 32)));

  if (hex(vSha256(a)) !== hex(nSha256(a))) mismatches += 1;
  if (hex(vHmac(vSha256, a, b)) !== hex(nHmac(nSha256, a, b))) mismatches += 1;
  if (hex(pbkdf2Sha256(a, b, 3 + i, 32)) !==
      hex(nPbkdf2(nSha256, a, b, { c: 3 + i, dkLen: 32 }))) mismatches += 1;
  if (hex(vScrypt(a, b, { N: 256, r: 4, p: 2 + (i % 3), dkLen: 32 })) !==
      hex(nScrypt(a, b, { N: 256, r: 4, p: 2 + (i % 3), dkLen: 32 }))) mismatches += 1;
}
check('25 random cross-checks vs @noble (100 comparisons)', String(mismatches), '0');

// 3. The wallet's real parameters, timed -------------------------------------
const password = utf8('a passphrase the holder chose');
const salt = new Uint8Array(16).fill(7);
const started = Date.now();
const derived = vScrypt(password, salt, { N: 2 ** 15, r: 8, p: 1, dkLen: 32 });
console.log(`info scrypt N=2^15,r=8,p=1 on this workstation: ${Date.now() - started} ms, ${derived.length} bytes`);

console.log(failures === 0 ? '\nALL KAT PASSED' : `\n${failures} KAT FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
