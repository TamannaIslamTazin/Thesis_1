/**
 * Worklet-runtime crypto: the wallet's KDF, as plain functions and objects.
 *
 * ===========================================================================
 * WHY THIS IS A PORT AND NOT THE VENDORED LIBRARY
 * ===========================================================================
 * Two properties of worklet serialization were measured on the handset
 * (20 Sep 2026) and between them rule out running noble unmodified:
 *
 *   1. FUNCTION PROPERTIES DO NOT CROSS. noble's `sha256` is a wrapper with
 *      `create`/`outputLen`/`blockLen` grafted on by createHasher. Inside the
 *      runtime the imported wrapper arrived as typeof=function with
 *      create=undefined, and `ahash` refuses exactly that shape:
 *      "Hash should be wrapped by utils.createHasher".
 *   2. CLASSES CANNOT REFERENCE THEIR MODULE SCOPE. Building the wrapper
 *      in-runtime moved the failure one level down: the plugin compiles
 *      `new SHA256()` into a call to a MODULE-SCOPED `SHA256__classFactory`,
 *      and a worklet runtime has no module scope for it:
 *      "SHA256__classFactory is not a function (it is undefined)".
 *
 *   3. A FACTORY RETURNING AN OBJECT WITH METHODS FAILS TOO. Its method
 *      closures captured the returned facade, and inside the runtime that
 *      binding arrived undefined on the next chained call:
 *      "Cannot read property 'update' of undefined". Hence state is passed in
 *      explicitly and nothing closes over a value a worklet creates.
 *
 * Bundle Mode would re-execute module code in the runtime and fix both, but it
 * is experimental and would sit under Reanimated's UI worklets. So the owner's
 * instruction is followed literally — "port the freaking js noble" — with the
 * property that makes the port safe: every primitive here is verified
 * bit-for-bit against @noble/hashes (RFC vectors plus random cross-checks) by
 * packages/shared/tools/verifyWorkletSubset.ts, and against the RN-side noble
 * implementation ON DEVICE through the worker runtime: 20 Sep 2026,
 * N=256 parity MATCH, N=2^15,r=8,p=1 in workerMs=37389 (see cryptoWorker.ts).
 *
 * Algorithmic code (Salsa20/8, BlockMix, ROMix) is transcribed from
 * @noble/hashes 1.8.0, MIT, Copyright (c) 2022 Paul Miller. The structural
 * changes are ours: classes became plain functions with explicit state, and
 * nothing relies on a function's own properties, on a closure over a returned
 * facade, or on module-scope state — none of those survive the boundary.
 *
 * RANDOMNESS: none is needed here and none is provided. scrypt, PBKDF2 and
 * HMAC are deterministic; entropy is drawn on the RN side and passed in.
 */

// ---------------------------------------------------------------------------
// Small helpers (all workletized; no module-scope state is read at runtime)
// ---------------------------------------------------------------------------

function rotr(word: number, shift: number): number {
  'worklet';
  return (word >>> shift) | (word << (32 - shift));
}

function rotl(word: number, shift: number): number {
  'worklet';
  return (word << shift) | (word >>> (32 - shift));
}

function isLittleEndian(): boolean {
  'worklet';
  const probe = new Uint8Array(4);
  new Uint32Array(probe.buffer)[0] = 1;
  return probe[0] === 1;
}

function u32View(bytes: Uint8Array): Uint32Array {
  'worklet';
  // Callers always pass fresh, 4-aligned arrays; a copy guards against a
  // non-aligned offset producing a silently empty view.
  return bytes.byteOffset % 4 === 0
    ? new Uint32Array(bytes.buffer, bytes.byteOffset, bytes.length >>> 2)
    : new Uint32Array(bytes.slice().buffer);
}

function wipe(...arrays: Array<Uint8Array | Uint32Array>): void {
  'worklet';
  for (const array of arrays) array.fill(0);
}

// ---------------------------------------------------------------------------
// SHA-256, as a factory-created plain object
// ---------------------------------------------------------------------------

/**
 * SHA-256 as plain state + stateless functions.
 *
 * A factory returning an object with methods was tried first and failed the
 * same way as noble's own wrappers: the method closure captured a variable
 * declared in the same scope (the returned facade), and inside the worklet
 * runtime that variable arrived undefined — "Cannot read property 'update' of
 * undefined". Nothing here closes over anything: state is passed in and out,
 * and every function reads only its parameters and its top-level siblings.
 */
export interface Sha256State {
  h: Uint32Array;
  w: Uint32Array;
  buffer: Uint8Array;
  bufferLength: number;
  totalLength: number;
  finished: boolean;
}

export function sha256Init(): Sha256State {
  'worklet';
  return {
    h: new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
      0x5be0cd19,
    ]),
    w: new Uint32Array(64),
    buffer: new Uint8Array(64),
    bufferLength: 0,
    totalLength: 0,
    finished: false,
  };
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256Compress(state: Sha256State, block: Uint8Array): void {
  'worklet';
  const { h, w } = state;
  for (let i = 0; i < 16; i += 1) {
    w[i] =
      (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
  }
  for (let i = 16; i < 64; i += 1) {
    const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
    const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
  }
  let a = h[0];
  let b = h[1];
  let c = h[2];
  let d = h[3];
  let e = h[4];
  let f = h[5];
  let g = h[6];
  let hh = h[7];
  for (let i = 0; i < 64; i += 1) {
    const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const ch = (e & f) ^ (~e & g);
    const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) | 0;
    const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) | 0;
    hh = g;
    g = f;
    f = e;
    e = (d + t1) | 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) | 0;
  }
  h[0] = (h[0] + a) | 0;
  h[1] = (h[1] + b) | 0;
  h[2] = (h[2] + c) | 0;
  h[3] = (h[3] + d) | 0;
  h[4] = (h[4] + e) | 0;
  h[5] = (h[5] + f) | 0;
  h[6] = (h[6] + g) | 0;
  h[7] = (h[7] + hh) | 0;
}

export function sha256Update(state: Sha256State, data: Uint8Array): void {
  'worklet';
  if (state.finished) throw new Error('sha256: digest already called');
  state.totalLength += data.length;
  let offset = 0;
  if (state.bufferLength > 0) {
    const take = Math.min(64 - state.bufferLength, data.length);
    state.buffer.set(data.subarray(0, take), state.bufferLength);
    state.bufferLength += take;
    offset = take;
    if (state.bufferLength === 64) {
      sha256Compress(state, state.buffer);
      state.bufferLength = 0;
    }
  }
  while (offset + 64 <= data.length) {
    sha256Compress(state, data.subarray(offset, offset + 64));
    offset += 64;
  }
  if (offset < data.length) {
    state.buffer.set(data.subarray(offset), 0);
    state.bufferLength = data.length - offset;
  }
}

export function sha256Digest(state: Sha256State): Uint8Array {
  'worklet';
  if (state.finished) throw new Error('sha256: digest already called');
  const bitLengthHigh = Math.floor(state.totalLength / 0x20000000);
  const bitLengthLow = (state.totalLength << 3) >>> 0;
  const padLength =
    state.bufferLength < 56 ? 64 - state.bufferLength : 128 - state.bufferLength;
  const pad = new Uint8Array(padLength);
  pad[0] = 0x80;
  pad[pad.length - 8] = (bitLengthHigh >>> 24) & 0xff;
  pad[pad.length - 7] = (bitLengthHigh >>> 16) & 0xff;
  pad[pad.length - 6] = (bitLengthHigh >>> 8) & 0xff;
  pad[pad.length - 5] = bitLengthHigh & 0xff;
  pad[pad.length - 4] = (bitLengthLow >>> 24) & 0xff;
  pad[pad.length - 3] = (bitLengthLow >>> 16) & 0xff;
  pad[pad.length - 2] = (bitLengthLow >>> 8) & 0xff;
  pad[pad.length - 1] = bitLengthLow & 0xff;
  sha256Update(state, pad);
  state.finished = true;
  wipe(pad);
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i += 1) {
    out[i * 4] = (state.h[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (state.h[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (state.h[i] >>> 8) & 0xff;
    out[i * 4 + 3] = state.h[i] & 0xff;
  }
  wipe(state.h, state.w, state.buffer);
  return out;
}

/** One-shot hash, for call sites that do not stream. */
export function sha256(data: Uint8Array): Uint8Array {
  'worklet';
  const state = sha256Init();
  sha256Update(state, data);
  return sha256Digest(state);
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 and PBKDF2-HMAC-SHA256
// ---------------------------------------------------------------------------

const SHA256_BLOCK = 64;

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  'worklet';
  const normalized = key.length > SHA256_BLOCK ? sha256(key) : key;
  const ipad = new Uint8Array(SHA256_BLOCK);
  const opad = new Uint8Array(SHA256_BLOCK);
  for (let i = 0; i < SHA256_BLOCK; i += 1) {
    const byte = i < normalized.length ? normalized[i] : 0;
    ipad[i] = byte ^ 0x36;
    opad[i] = byte ^ 0x5c;
  }
  const innerState = sha256Init();
  sha256Update(innerState, ipad);
  sha256Update(innerState, message);
  const inner = sha256Digest(innerState);
  const outerState = sha256Init();
  sha256Update(outerState, opad);
  sha256Update(outerState, inner);
  const result = sha256Digest(outerState);
  wipe(ipad, opad, inner);
  return result;
}

export function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Uint8Array {
  'worklet';
  if (iterations < 1) throw new Error('pbkdf2: iterations must be >= 1');
  const hLen = 32;
  const blocks = Math.ceil(dkLen / hLen);
  const derived = new Uint8Array(blocks * hLen);
  const counterBlock = new Uint8Array(salt.length + 4);
  counterBlock.set(salt, 0);
  for (let block = 1; block <= blocks; block += 1) {
    counterBlock[salt.length] = (block >>> 24) & 0xff;
    counterBlock[salt.length + 1] = (block >>> 16) & 0xff;
    counterBlock[salt.length + 2] = (block >>> 8) & 0xff;
    counterBlock[salt.length + 3] = block & 0xff;
    let u = hmacSha256(password, counterBlock);
    const acc = u.slice();
    for (let i = 1; i < iterations; i += 1) {
      u = hmacSha256(password, u);
      for (let j = 0; j < hLen; j += 1) acc[j] ^= u[j];
    }
    derived.set(acc, (block - 1) * hLen);
    wipe(u, acc);
  }
  wipe(counterBlock);
  return derived.subarray(0, dkLen);
}

// ---------------------------------------------------------------------------
// scrypt (RFC 7914) — Salsa20/8 core, BlockMix and ROMix transcribed from
// @noble/hashes 1.8.0 (MIT). pbkdf2 calls use the SHA-256 implementation above.
// ---------------------------------------------------------------------------

function xorAndSalsa(
  prev: Uint32Array,
  pi: number,
  input: Uint32Array,
  ii: number,
  out: Uint32Array,
  oi: number,
): void {
  'worklet';
  let y00 = prev[pi++] ^ input[ii++];
  let y01 = prev[pi++] ^ input[ii++];
  let y02 = prev[pi++] ^ input[ii++];
  let y03 = prev[pi++] ^ input[ii++];
  let y04 = prev[pi++] ^ input[ii++];
  let y05 = prev[pi++] ^ input[ii++];
  let y06 = prev[pi++] ^ input[ii++];
  let y07 = prev[pi++] ^ input[ii++];
  let y08 = prev[pi++] ^ input[ii++];
  let y09 = prev[pi++] ^ input[ii++];
  let y10 = prev[pi++] ^ input[ii++];
  let y11 = prev[pi++] ^ input[ii++];
  let y12 = prev[pi++] ^ input[ii++];
  let y13 = prev[pi++] ^ input[ii++];
  let y14 = prev[pi++] ^ input[ii++];
  let y15 = prev[pi++] ^ input[ii++];
  let x00 = y00;
  let x01 = y01;
  let x02 = y02;
  let x03 = y03;
  let x04 = y04;
  let x05 = y05;
  let x06 = y06;
  let x07 = y07;
  let x08 = y08;
  let x09 = y09;
  let x10 = y10;
  let x11 = y11;
  let x12 = y12;
  let x13 = y13;
  let x14 = y14;
  let x15 = y15;
  for (let i = 0; i < 8; i += 2) {
    x04 ^= rotl(x00 + x12, 7);
    x08 ^= rotl(x04 + x00, 9);
    x12 ^= rotl(x08 + x04, 13);
    x00 ^= rotl(x12 + x08, 18);
    x09 ^= rotl(x05 + x01, 7);
    x13 ^= rotl(x09 + x05, 9);
    x01 ^= rotl(x13 + x09, 13);
    x05 ^= rotl(x01 + x13, 18);
    x14 ^= rotl(x10 + x06, 7);
    x02 ^= rotl(x14 + x10, 9);
    x06 ^= rotl(x02 + x14, 13);
    x10 ^= rotl(x06 + x02, 18);
    x03 ^= rotl(x15 + x11, 7);
    x07 ^= rotl(x03 + x15, 9);
    x11 ^= rotl(x07 + x03, 13);
    x15 ^= rotl(x11 + x07, 18);
    x01 ^= rotl(x00 + x03, 7);
    x02 ^= rotl(x01 + x00, 9);
    x03 ^= rotl(x02 + x01, 13);
    x00 ^= rotl(x03 + x02, 18);
    x06 ^= rotl(x05 + x04, 7);
    x07 ^= rotl(x06 + x05, 9);
    x04 ^= rotl(x07 + x06, 13);
    x05 ^= rotl(x04 + x07, 18);
    x11 ^= rotl(x10 + x09, 7);
    x08 ^= rotl(x11 + x10, 9);
    x09 ^= rotl(x08 + x11, 13);
    x10 ^= rotl(x09 + x08, 18);
    x12 ^= rotl(x15 + x14, 7);
    x13 ^= rotl(x12 + x15, 9);
    x14 ^= rotl(x13 + x12, 13);
    x15 ^= rotl(x14 + x13, 18);
  }
  out[oi++] = (y00 + x00) | 0;
  out[oi++] = (y01 + x01) | 0;
  out[oi++] = (y02 + x02) | 0;
  out[oi++] = (y03 + x03) | 0;
  out[oi++] = (y04 + x04) | 0;
  out[oi++] = (y05 + x05) | 0;
  out[oi++] = (y06 + x06) | 0;
  out[oi++] = (y07 + x07) | 0;
  out[oi++] = (y08 + x08) | 0;
  out[oi++] = (y09 + x09) | 0;
  out[oi++] = (y10 + x10) | 0;
  out[oi++] = (y11 + x11) | 0;
  out[oi++] = (y12 + x12) | 0;
  out[oi++] = (y13 + x13) | 0;
  out[oi++] = (y14 + x14) | 0;
  out[oi++] = (y15 + x15) | 0;
}

function blockMix(input: Uint32Array, ii: number, out: Uint32Array, oi: number, r: number): void {
  'worklet';
  let head = oi + 0;
  let tail = oi + 16 * r;
  for (let i = 0; i < 16; i += 1) out[tail + i] = input[ii + (2 * r - 1) * 16 + i];
  for (let i = 0; i < r; i += 1, head += 16, ii += 16) {
    xorAndSalsa(out, tail, input, ii, out, head);
    if (i > 0) tail += 16;
    xorAndSalsa(out, head, input, (ii += 16), out, tail);
  }
}

export interface ScryptOptions {
  N: number;
  r: number;
  p: number;
  dkLen: number;
}

export function scrypt(
  password: Uint8Array,
  salt: Uint8Array,
  options: ScryptOptions,
): Uint8Array {
  'worklet';
  const { N, r, p, dkLen } = options;
  if (N <= 1 || (N & (N - 1)) !== 0) {
    throw new Error('scrypt: N must be a power of two greater than 1');
  }
  if (r < 1 || p < 1 || dkLen < 1) throw new Error('scrypt: r, p and dkLen must be positive');
  const blockSize = 128 * r;
  const blockSize32 = blockSize / 4;

  // B = PBKDF2(password, salt, 1, blockSize * p)
  const B = pbkdf2Sha256(password, salt, 1, blockSize * p);
  if (!isLittleEndian()) {
    // The algorithm reads u32s as little-endian; swap on a big-endian host
    // rather than assuming. Hermes on Android is little-endian, but a wrong
    // assumption here yields plausible garbage, so it is checked, not assumed.
    const words = u32View(B);
    for (let i = 0; i < words.length; i += 1) words[i] = byteSwap32(words[i]);
  }
  const b32 = u32View(B);
  const v = new Uint32Array(blockSize32 * N);
  const tmp = new Uint32Array(blockSize32);

  for (let pi = 0; pi < p; pi += 1) {
    const Pi = blockSize32 * pi;
    for (let i = 0; i < blockSize32; i += 1) v[i] = b32[Pi + i];
    for (let i = 0, pos = 0; i < N - 1; i += 1) {
      blockMix(v, pos, v, (pos += blockSize32), r);
    }
    blockMix(v, (N - 1) * blockSize32, b32, Pi, r);
    for (let i = 0; i < N; i += 1) {
      const j = b32[Pi + blockSize32 - 16] % N;
      for (let k = 0; k < blockSize32; k += 1) tmp[k] = b32[Pi + k] ^ v[j * blockSize32 + k];
      blockMix(tmp, 0, b32, Pi, r);
    }
  }

  const result = pbkdf2Sha256(password, B, 1, dkLen);
  wipe(B, v, tmp);
  return result;
}

function byteSwap32(value: number): number {
  'worklet';
  return (
    (((value & 0xff) << 24) |
      ((value & 0xff00) << 8) |
      ((value >>> 8) & 0xff00) |
      ((value >>> 24) & 0xff)) >>>
    0
  );
}
