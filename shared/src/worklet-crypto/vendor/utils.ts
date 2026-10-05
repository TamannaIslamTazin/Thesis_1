/**
 * VENDORED from @noble/hashes@1.8.0 (utils.ts).
 *
 * MIT licensed (see LICENSE in this directory). DO NOT EDIT BY HAND —
 * regenerate with `node tools/make-worklet-subset.mjs` from packages/shared.
 * The only changes are mechanical: a 'worklet'; directive in every function
 * body so the worklet runtime can execute this code, and (in utils) the
 * removal of the host-only helpers the closure never calls (randomBytes and
 * its crypto import, bytesToHex, hexToBytes, hasHexBuiltin). See NOTICE.md
 * for the full provenance.
 */
/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
export function isBytes(a: unknown): a is Uint8Array {
    "worklet";
    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}
/** Asserts something is positive integer. */
export function anumber(n: number): void {
    "worklet";
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error('positive integer expected, got ' + n);
}
/** Asserts something is Uint8Array. */
export function abytes(b: Uint8Array | undefined, ...lengths: number[]): void {
    "worklet";
    if (!isBytes(b))
        throw new Error('Uint8Array expected');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error('Uint8Array expected of length ' + lengths + ', got length=' + b.length);
}
/** Asserts something is hash */
export function ahash(h: IHash): void {
    "worklet";
    if (typeof h !== 'function' || typeof h.create !== 'function')
        throw new Error('Hash should be wrapped by utils.createHasher');
    anumber(h.outputLen);
    anumber(h.blockLen);
}
/** Asserts a hash instance has not been destroyed / finished */
export function aexists(instance: any, checkFinished = true): void {
    "worklet";
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
/** Asserts output is properly-sized byte array */
export function aoutput(out: any, instance: any): void {
    "worklet";
    abytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error('digestInto() expects output buffer of length at least ' + min);
    }
}
/** Generic type encompassing 8/16/32-byte arrays - but not 64-byte. */
// prettier-ignore
export type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array | Uint16Array | Int16Array | Uint32Array | Int32Array;
/** Cast u8 / u16 / u32 to u8. */
export function u8(arr: TypedArray): Uint8Array {
    "worklet";
    return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
/** Cast u8 / u16 / u32 to u32. */
export function u32(arr: TypedArray): Uint32Array {
    "worklet";
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
/** Zeroize a byte array. Warning: JS provides no guarantees. */
export function clean(...arrays: TypedArray[]): void {
    "worklet";
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
}
/** Create DataView of an array for easy byte-level manipulation. */
export function createView(arr: TypedArray): DataView {
    "worklet";
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
/** The rotate right (circular right shift) operation for uint32 */
export function rotr(word: number, shift: number): number {
    "worklet";
    return (word << (32 - shift)) | (word >>> shift);
}
/** The rotate left (circular left shift) operation for uint32 */
export function rotl(word: number, shift: number): number {
    "worklet";
    return (word << shift) | ((word >>> (32 - shift)) >>> 0);
}
/** Is current platform little-endian? Most are. Big-Endian platform: IBM */
export const isLE: boolean = /* @__PURE__ */ (() => {
    "worklet";
    return new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
})();
/** The byte swap operation for uint32 */
export function byteSwap(word: number): number {
    "worklet";
    return (((word << 24) & 0xff000000) |
        ((word << 8) & 0xff0000) |
        ((word >>> 8) & 0xff00) |
        ((word >>> 24) & 0xff));
}
/** Conditionally byte swap if on a big-endian platform */
export const swap8IfBE: (n: number) => number = isLE
    ? (n: number) => {
        "worklet";
        return n;
    }
    : (n: number) => {
        "worklet";
        return byteSwap(n);
    };
/** @deprecated */
export const byteSwapIfBE: typeof swap8IfBE = swap8IfBE;
/** In place byte swap for Uint32Array */
export function byteSwap32(arr: Uint32Array): Uint32Array {
    "worklet";
    for (let i = 0; i < arr.length; i++) {
        arr[i] = byteSwap(arr[i]);
    }
    return arr;
}
export const swap32IfBE: (u: Uint32Array) => Uint32Array = isLE
    ? (u: Uint32Array) => {
        "worklet";
        return u;
    }
    : byteSwap32;
/**
 * There is no setImmediate in browser and setTimeout is slow.
 * Call of async fn will return Promise, which will be fullfiled only on
 * next scheduler queue processing step and this is exactly what we need.
 */
export const nextTick = async (): Promise<void> => {
    "worklet";
};
/** Returns control to thread each 'tick' ms to avoid blocking. */
export async function asyncLoop(iters: number, tick: number, cb: (i: number) => void): Promise<void> {
    "worklet";
    let ts = Date.now();
    for (let i = 0; i < iters; i++) {
        cb(i);
        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
            continue;
        await nextTick();
        ts += diff;
    }
}
// Global symbols, but ts doesn't see them: https://github.com/microsoft/TypeScript/issues/31535
declare const TextEncoder: any;
declare const TextDecoder: any;
/**
 * Converts string to bytes using UTF8 encoding.
 * @example utf8ToBytes('abc') // Uint8Array.from([97, 98, 99])
 */
export function utf8ToBytes(str: string): Uint8Array {
    "worklet";
    if (typeof str !== 'string')
        throw new Error('string expected');
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
/**
 * Converts bytes to string using UTF8 encoding.
 * @example bytesToUtf8(Uint8Array.from([97, 98, 99])) // 'abc'
 */
export function bytesToUtf8(bytes: Uint8Array): string {
    "worklet";
    return new TextDecoder().decode(bytes);
}
/** Accepted input of hash functions. Strings are converted to byte arrays. */
export type Input = string | Uint8Array;
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
export function toBytes(data: Input): Uint8Array {
    "worklet";
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    abytes(data);
    return data;
}
/** KDFs can accept string or Uint8Array for user convenience. */
export type KDFInput = string | Uint8Array;
/**
 * Helper for KDFs: consumes uint8array or string.
 * When string is passed, does utf8 decoding, using TextDecoder.
 */
export function kdfInputToBytes(data: KDFInput): Uint8Array {
    "worklet";
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    abytes(data);
    return data;
}
/** Copies several Uint8Arrays into one. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    "worklet";
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        abytes(a);
        sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
    }
    return res;
}
type EmptyObj = {};
export function checkOpts<T1 extends EmptyObj, T2 extends EmptyObj>(defaults: T1, opts?: T2): T1 & T2 {
    "worklet";
    if (opts !== undefined && {}.toString.call(opts) !== '[object Object]')
        throw new Error('options should be object or undefined');
    const merged = Object.assign(defaults, opts);
    return merged as T1 & T2;
}
/** Hash interface. */
export type IHash = {
    (data: Uint8Array): Uint8Array;
    blockLen: number;
    outputLen: number;
    create: any;
};
/** For runtime check if class implements interface */
export abstract class Hash<T extends Hash<T>> {
    abstract blockLen: number; // Bytes per block
    abstract outputLen: number; // Bytes in output
    abstract update(buf: Input): this;
    // Writes digest into buf
    abstract digestInto(buf: Uint8Array): void;
    abstract digest(): Uint8Array;
    /**
     * Resets internal state. Makes Hash instance unusable.
     * Reset is impossible for keyed hashes if key is consumed into state. If digest is not consumed
     * by user, they will need to manually call `destroy()` when zeroing is necessary.
     */
    abstract destroy(): void;
    /**
     * Clones hash instance. Unsafe: doesn't check whether `to` is valid. Can be used as `clone()`
     * when no options are passed.
     * Reasons to use `_cloneInto` instead of clone: 1) performance 2) reuse instance => all internal
     * buffers are overwritten => causes buffer overwrite which is used for digest in some cases.
     * There are no guarantees for clean-up because it's impossible in JS.
     */
    abstract _cloneInto(to?: T): T;
    // Safe version that clones internal state
    abstract clone(): T;
}
/**
 * XOF: streaming API to read digest in chunks.
 * Same as 'squeeze' in keccak/k12 and 'seek' in blake3, but more generic name.
 * When hash used in XOF mode it is up to user to call '.destroy' afterwards, since we cannot
 * destroy state, next call can require more bytes.
 */
export type HashXOF<T extends Hash<T>> = Hash<T> & {
    xof(bytes: number): Uint8Array; // Read 'bytes' bytes from digest stream
    xofInto(buf: Uint8Array): Uint8Array; // read buf.length bytes from digest stream into buf
};
/** Hash function */
export type CHash = ReturnType<typeof createHasher>;
/** Hash function with output */
export type CHashO = ReturnType<typeof createOptHasher>;
/** XOF with output */
export type CHashXO = ReturnType<typeof createXOFer>;
/** Wraps hash function, creating an interface on top of it */
export function createHasher<T extends Hash<T>>(hashCons: () => Hash<T>): {
    (msg: Input): Uint8Array;
    outputLen: number;
    blockLen: number;
    create(): Hash<T>;
} {
    "worklet";
    const hashC = (msg: Input): Uint8Array => {
        "worklet";
        return hashCons().update(toBytes(msg)).digest();
    };
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => {
        "worklet";
        return hashCons();
    };
    return hashC;
}
export function createOptHasher<H extends Hash<H>, T extends Object>(hashCons: (opts?: T) => Hash<H>): {
    (msg: Input, opts?: T): Uint8Array;
    outputLen: number;
    blockLen: number;
    create(opts?: T): Hash<H>;
} {
    "worklet";
    const hashC = (msg: Input, opts?: T): Uint8Array => {
        "worklet";
        return hashCons(opts).update(toBytes(msg)).digest();
    };
    const tmp = hashCons({} as T);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts?: T) => {
        "worklet";
        return hashCons(opts);
    };
    return hashC;
}
export function createXOFer<H extends HashXOF<H>, T extends Object>(hashCons: (opts?: T) => HashXOF<H>): {
    (msg: Input, opts?: T): Uint8Array;
    outputLen: number;
    blockLen: number;
    create(opts?: T): HashXOF<H>;
} {
    "worklet";
    const hashC = (msg: Input, opts?: T): Uint8Array => {
        "worklet";
        return hashCons(opts).update(toBytes(msg)).digest();
    };
    const tmp = hashCons({} as T);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts?: T) => {
        "worklet";
        return hashCons(opts);
    };
    return hashC;
}
export const wrapConstructor: typeof createHasher = createHasher;
export const wrapConstructorWithOpts: typeof createOptHasher = createOptHasher;
export const wrapXOFConstructorWithOpts: typeof createXOFer = createXOFer;
