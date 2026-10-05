/**
 * The user passphrase as an envelope over the RCK, parallel to `prfEnvelope.ts`.
 *
 * ===========================================================================
 * WHY A SEPARATE MODULE, NOT A THIRD ARGUMENT ON THE PRF ONE
 * ===========================================================================
 * A PRF output already IS 32 bytes of high-entropy key material; it goes into
 * `sealKey` unmodified. A passphrase is neither 32 bytes nor high-entropy, so
 * a wrapping key has to be derived from it first, and that derivation is the
 * one property this module owns end to end: the KDF, its parameters, and the
 * salt that makes two envelopes of the same passphrase unlinkable.
 *
 * `wrapRecoveryKeyWithPassphrase` / `unwrapRecoveryKeyWithPassphrase` still
 * finish by calling the shared `sealKey` / `openKey` primitive, so the AEAD
 * half of this envelope is identical in shape to the PRF one and to the
 * locker's device/guardian envelopes (#340) — only the key-derivation step
 * differs, which is the whole point of factoring `keyEnvelope.ts` out.
 *
 * ===========================================================================
 * WHY SCRYPT, WHAT PARAMETERS, AND WHERE THAT NUMBER CAME FROM
 * ===========================================================================
 * `@noble/hashes` ships both scrypt and Argon2id in pure JS; on a React
 * Native / Hermes runtime neither gets the SIMD or native-code speedup a
 * server would have. Benchmarked here (Node, not a device — see the caveat
 * below) with `dkLen=32`, three runs each, warmed:
 *
 *   scrypt   N=2^15,r=8,p=1  (32 MiB)   113-134 ms
 *   scrypt   N=2^16,r=8,p=1  (64 MiB)   230-233 ms
 *   argon2id t=2,m=19 MiB,p=1           974 ms
 *   argon2id t=3,m=12 MiB,p=1           431 ms
 *   argon2id t=2,m=64 MiB,p=1          1706 ms
 *
 * scrypt is 3-7x faster than argon2id at comparable memory in this pure-JS
 * implementation, which is the deciding factor for a budget Android device
 * with no crypto-accelerated JS engine. `N=2^15, r=8, p=1` was chosen: ~32
 * MiB peak memory (`128 * N * r` bytes), a number a 2-3 GB budget phone can
 * allocate for the few hundred milliseconds this runs without pressuring the
 * rest of the app, and a runtime that stayed under 150 ms on a desktop V8.
 *
 * THE CAVEAT THIS NUMBER CARRIES. The benchmark above ran on the development
 * machine's Node/V8, not on Hermes on a low-end handset. Hermes has no JIT
 * comparable to V8's; a budget Android CPU is slower again. This module does
 * not know, and has not measured, what N=2^15 costs on an actual device —
 * that is the "what you could not verify" this round's report says plainly.
 * `scryptAsync` is used rather than the synchronous `scrypt` specifically so
 * that if it does run long on a slow device, it yields the JS thread instead
 * of freezing the UI outright (`asyncTick`, default 10 ms, controls that).
 *
 * ===========================================================================
 * SELF-DESCRIBING, ON PURPOSE
 * ===========================================================================
 * The KDF name, N, r, p and salt travel inside the envelope. A parameter
 * change later (raising N once real device timings are in) does not strand
 * envelopes written under the old ones — each envelope carries what it needs
 * to be opened, and `deriveScryptKey` is exported precisely so a known-answer
 * test can pin today's parameters and catch silent drift.
 */

import { scryptAsync, type ScryptOpts } from '@noble/hashes/scrypt';

import { RECOVERY_KEY_SEED_BYTES, assertWellFormedSeed } from './recoveryKey.js';
import {
  EMPTY_AAD,
  KeyEnvelopeError,
  type EnvelopeContext,
  type KeyEnvelope,
  openKey,
  sealKey,
} from './keyEnvelope.js';
import { base64UrlToBytes, bytesToBase64Url } from './base64Url.js';

/** `128 * N * r` bytes peak memory. 2^15 * 8 -> ~32 MiB. See the module docblock. */
export const PASSPHRASE_KDF_N = 2 ** 15;
export const PASSPHRASE_KDF_R = 8;
export const PASSPHRASE_KDF_P = 1;
export const PASSPHRASE_KDF_DKLEN = 32;
export const PASSPHRASE_KDF_SALT_BYTES = 16;

const ENVELOPE_HKDF_INFO = 'bdhealthtrust/rck-passphrase-envelope/v1';
const PASSPHRASE_ENVELOPE_CONTEXT: EnvelopeContext = { info: ENVELOPE_HKDF_INFO, aad: EMPTY_AAD };

export class PassphraseEnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PassphraseEnvelopeError';
  }
}

export interface PassphraseKdfParams {
  readonly name: 'scrypt';
  readonly N: number;
  readonly r: number;
  readonly p: number;
  readonly dkLen: number;
  /** base64url */
  readonly salt: string;
}

export interface PassphraseEnvelope {
  readonly version: 1;
  readonly kdf: PassphraseKdfParams;
  readonly envelope: KeyEnvelope;
  /**
   * How to open the wallet's database snapshot, if one was backed up at the time
   * this envelope was sealed.
   *
   * It lives INSIDE the sealed envelope on purpose. The snapshot is encrypted
   * with those two values as additional authenticated data, so a device that has
   * never held the database cannot derive either of them — the version is a
   * timestamp from the uploading device and the hash is of a plaintext the
   * restorer has not yet decrypted. Carrying them here means the same factor
   * that releases the key also releases what is needed to use it, and nobody who
   * cannot open the envelope learns anything from its presence.
   *
   * Optional: envelopes sealed before this existed, and wallets that had not yet
   * backed up, are both legitimate and both restore to "no data to fetch".
   */
  readonly backupBinding?: {
    readonly version: number;
    readonly contentHash: string;
  };
}

function assertUsablePassphrase(passphrase: string): void {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new PassphraseEnvelopeError(
      `A passphrase must be a non-empty string, got ${
        typeof passphrase === 'string' ? 'an empty string' : typeof passphrase
      }.`,
    );
  }
}

/**
 * Derive the 32-byte wrapping key for a given passphrase and KDF parameters.
 *
 * Exported so the known-answer test can call it directly: the AEAD half of
 * the envelope already has round-trip and tamper coverage on the shared
 * primitive, so what needs its own fixed-input, fixed-output test is this
 * derivation, which is the piece that silently drifts if `N`, `r`, `p` or the
 * `dkLen` ever change without anyone noticing.
 */
export async function deriveScryptKey(
  passphrase: string,
  salt: Uint8Array,
  params: Pick<PassphraseKdfParams, 'N' | 'r' | 'p' | 'dkLen'> = {
    N: PASSPHRASE_KDF_N,
    r: PASSPHRASE_KDF_R,
    p: PASSPHRASE_KDF_P,
    dkLen: PASSPHRASE_KDF_DKLEN,
  },
): Promise<Uint8Array> {
  assertUsablePassphrase(passphrase);
  if (!(salt instanceof Uint8Array) || salt.length === 0) {
    throw new PassphraseEnvelopeError(
      `The KDF salt must be a non-empty Uint8Array, got ${
        salt instanceof Uint8Array ? `${salt.length} bytes` : typeof salt
      }.`,
    );
  }

  const opts: ScryptOpts = { N: params.N, r: params.r, p: params.p, dkLen: params.dkLen };
  const key = await scryptAsync(passphrase.normalize('NFKC'), salt, opts);

  if (key.length !== params.dkLen) {
    throw new PassphraseEnvelopeError(
      `scrypt returned ${key.length} bytes, expected ${params.dkLen}.`,
    );
  }
  return key;
}

/**
 * Wrap the RCK seed under a passphrase.
 *
 * A fresh KDF salt is drawn per call, so wrapping the same seed under the
 * same passphrase twice produces two unlinkable envelopes — the same
 * property `sealKey` already gives the AEAD salt and nonce.
 */
export async function wrapRecoveryKeyWithPassphrase(
  seed: Uint8Array,
  passphrase: string,
  backupBinding?: { readonly version: number; readonly contentHash: string },
): Promise<PassphraseEnvelope> {
  assertWellFormedSeed(seed);
  assertUsablePassphrase(passphrase);

  const kdfSalt = new Uint8Array(PASSPHRASE_KDF_SALT_BYTES);
  globalThis.crypto.getRandomValues(kdfSalt);

  const wrappingKey = await deriveScryptKey(passphrase, kdfSalt);
  try {
    const envelope = sealKey(seed, wrappingKey, PASSPHRASE_ENVELOPE_CONTEXT);
    return {
      version: 1,
      kdf: {
        name: 'scrypt',
        N: PASSPHRASE_KDF_N,
        r: PASSPHRASE_KDF_R,
        p: PASSPHRASE_KDF_P,
        dkLen: PASSPHRASE_KDF_DKLEN,
        salt: bytesToBase64Url(kdfSalt),
      },
      envelope,
      ...(backupBinding
        ? {
            backupBinding: {
              version: backupBinding.version,
              contentHash: backupBinding.contentHash,
            },
          }
        : {}),
    };
  } catch (error) {
    throw asPassphraseEnvelopeError(error);
  } finally {
    wrappingKey.fill(0);
  }
}

/**
 * Open a passphrase envelope.
 *
 * AES-GCM authenticates, so a wrong passphrase and a tampered ciphertext both
 * fail on the tag rather than returning plausible garbage — there is no
 * silent-wrong-key outcome, same as `unwrapRecoveryKeyWithPrf`.
 */
export async function unwrapRecoveryKeyWithPassphrase(
  envelope: PassphraseEnvelope,
  passphrase: string,
): Promise<Uint8Array> {
  if (envelope?.version !== 1) {
    throw new PassphraseEnvelopeError(
      `Unknown passphrase envelope version ${String(envelope?.version)}. Refusing to guess its layout.`,
    );
  }
  if (envelope.kdf?.name !== 'scrypt') {
    throw new PassphraseEnvelopeError(
      `Unknown KDF '${String(envelope.kdf?.name)}' in a passphrase envelope. Refusing to guess its layout.`,
    );
  }
  assertUsablePassphrase(passphrase);

  const kdfSalt = base64UrlToBytes(envelope.kdf.salt);
  const wrappingKey = await deriveScryptKey(passphrase, kdfSalt, {
    N: envelope.kdf.N,
    r: envelope.kdf.r,
    p: envelope.kdf.p,
    dkLen: envelope.kdf.dkLen,
  });

  let seed: Uint8Array;
  try {
    seed = openKey(envelope.envelope, wrappingKey, PASSPHRASE_ENVELOPE_CONTEXT);
  } catch (error) {
    if (error instanceof KeyEnvelopeError) {
      throw new PassphraseEnvelopeError(
        'The passphrase envelope did not authenticate. The passphrase is wrong, or the ' +
          `envelope was altered: ${error.message}`,
      );
    }
    throw asPassphraseEnvelopeError(error);
  } finally {
    wrappingKey.fill(0);
  }

  if (seed.length !== RECOVERY_KEY_SEED_BYTES) {
    throw new PassphraseEnvelopeError(
      `The passphrase envelope opened to ${seed.length} bytes, expected ${RECOVERY_KEY_SEED_BYTES}.`,
    );
  }
  return seed;
}

function asPassphraseEnvelopeError(error: unknown): Error {
  if (error instanceof KeyEnvelopeError) return new PassphraseEnvelopeError(error.message);
  return error instanceof Error ? error : new PassphraseEnvelopeError(String(error));
}
