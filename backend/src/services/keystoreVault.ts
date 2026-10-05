/**
 * The keystore vault — PUT/fetch for the passphrase-wrapped recovery envelope
 * (AUTH-AND-KEYSTORE-API.md §2-4).
 *
 * ===========================================================================
 * WHAT "OPAQUE" MEANS HERE, AND WHAT IT DOES NOT
 * ===========================================================================
 * The envelope is produced by `packages/shared/src/recovery/passphraseEnvelope.ts`,
 * sealed under a scrypt-derived key from the user's passphrase. This module
 * never imports that file's `unwrapRecoveryKeyWithPassphrase`, never derives a
 * key, and never sees a passphrase — that is what "opaque" is protecting.
 *
 * It DOES validate the envelope's JSON SHAPE (`passphraseEnvelopeShape` below)
 * before storing it. That is ordinary input validation at a trust boundary,
 * not a cryptographic operation: rejecting a body that is not even
 * well-formed JSON in the expected shape is a bound on what an authenticated
 * caller can make this row hold, not an attempt to understand what the
 * ciphertext says.
 *
 * ===========================================================================
 * WHY THE ROW NAMES NEITHER A USER NOR A DID
 * ===========================================================================
 * AUTH-AND-KEYSTORE-API.md §4: "No plaintext list of enrolled numbers linked
 * to DIDs may exist at rest." `KeystoreEnvelope.handleHmac` is an HMAC of the
 * phone handle; `ownerTag` is an HMAC of the authenticated userId, under a
 * SEPARATE pepper. Neither is reversible without its own pepper, and knowing
 * one derivation's pepper does not help invert the other. A leak of this
 * table, on its own, cannot produce "which phone numbers are enrolled" or
 * "which account owns this number" — only "these two opaque tags co-occurred
 * in one row", which is not the same claim.
 *
 * `ownerTag` exists so PUT can be idempotent PER ACCOUNT without that
 * requiring a userId column: the same account may replace its own envelope
 * (matching tag), and a different account may not silently overwrite it
 * (mismatched tag is refused, never merged) — see `putEnvelope` below. The
 * phone handle is not a secret (spec §4's named weakness), so leaving REPLACE
 * open to "whoever knows the number" would let anyone who knows a victim's
 * phone number brick their recovery path.
 *
 * ===========================================================================
 * TIMING, AND WHAT THE OWNER ALREADY NAMED AS UNSOLVED
 * ===========================================================================
 * `withTimingFloor` narrows the gap between "handle enrolled" and "handle
 * unknown" by padding every fetch to a fixed minimum wall-clock time. It does
 * NOT make the two cases indistinguishable — the response body still differs,
 * because the wallet legitimately needs to know which case it is in. What it
 * removes is the cheap, scriptable timing oracle a naive implementation would
 * otherwise hand an attacker probing many numbers. The owner's own framing
 * stands: "the handle is not a secret, so the passphrase is doing all the
 * work" — this reduces one contributing signal, it does not remove the one
 * named weakness.
 */

import { createHmac } from 'node:crypto';
import { z } from 'zod';

import { config } from '../config/index.js';
import { db } from '../db/index.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import type { Prisma } from '../../prisma/generated/client/index.js';

// ---------------------------------------------------------------------------
// Handle format and HMAC derivation
// ---------------------------------------------------------------------------

/**
 * E.164, required rather than guessed at. Two spellings of the same number
 * ("+8801711000000" vs "01711000000") would HMAC to two different keys and
 * the enrolment would silently appear unknown at fetch time on a differently
 * formatted retry. Rather than a normalisation heuristic this module cannot
 * verify is correct for every entered format, malformed input is refused —
 * canonicalising to E.164 BEFORE this call is the wallet's job, since only the
 * client has the country context to do it correctly. See the round report for
 * what this means for the wallet screen that collects the handle.
 */
const E164_PATTERN = /^\+[1-9]\d{6,14}$/;

export function assertE164Handle(handle: unknown): string {
  if (typeof handle !== 'string' || !E164_PATTERN.test(handle)) {
    throw new AppError(
      ERROR_CODES.VALIDATION_FAILED,
      'handle must be an E.164 phone number (leading +, country code, digits only, no spaces ' +
        'or separators). This server does not attempt to normalise other formats.',
      400,
    );
  }
  return handle;
}

export function handleHmac(handle: string): string {
  return createHmac('sha256', config.keystoreHandlePepper).update(handle, 'utf8').digest('hex');
}

export function ownerTag(userId: string): string {
  return createHmac('sha256', config.keystoreOwnerPepper).update(userId, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Envelope shape — validated, never interpreted
// ---------------------------------------------------------------------------

const keyEnvelopeShape = z.object({
  version: z.literal(1),
  salt: z.string().min(1),
  nonce: z.string().min(1),
  ciphertext: z.string().min(1),
});

/** Mirrors `PassphraseEnvelope` in `packages/shared/src/recovery/passphraseEnvelope.ts`. */
export const passphraseEnvelopeShape = z.object({
  version: z.literal(1),
  kdf: z.object({
    name: z.literal('scrypt'),
    N: z.number().int().positive(),
    r: z.number().int().positive(),
    p: z.number().int().positive(),
    dkLen: z.number().int().positive(),
    salt: z.string().min(1),
  }),
  envelope: keyEnvelopeShape,
});

export type ValidatedPassphraseEnvelope = z.infer<typeof passphraseEnvelopeShape>;

// ---------------------------------------------------------------------------
// Store — Prisma-backed, and an interface a fast test can substitute
// ---------------------------------------------------------------------------

export interface KeystoreEnvelopeRecord {
  readonly ownerTag: string;
  readonly envelope: ValidatedPassphraseEnvelope;
}

export type PutOutcome = 'created' | 'replaced' | 'conflict';

export interface KeystoreEnvelopeStore {
  find(handleHmac: string): Promise<KeystoreEnvelopeRecord | null>;
  /**
   * Create-or-replace. `conflict` means a row already exists under a
   * DIFFERENT owner tag, or a concurrent create by a different owner won a
   * race for the same handle — either way, refused rather than merged.
   */
  put(args: {
    readonly handleHmac: string;
    readonly ownerTag: string;
    readonly envelope: ValidatedPassphraseEnvelope;
  }): Promise<PutOutcome>;
}

/** Prisma's error shape for a unique-constraint violation (P2002), without importing the runtime class just to narrow one field. */
function isUniqueConstraintViolation(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { code?: unknown }).code === 'P2002'
  );
}

export const prismaKeystoreEnvelopeStore: KeystoreEnvelopeStore = {
  async find(handleHmacValue) {
    const row = await db.keystoreEnvelope.findUnique({ where: { handleHmac: handleHmacValue } });
    if (!row) return null;
    return { ownerTag: row.ownerTag, envelope: row.envelope as unknown as ValidatedPassphraseEnvelope };
  },

  async put({ handleHmac: handleHmacValue, ownerTag: ownerTagValue, envelope }) {
    const existing = await db.keystoreEnvelope.findUnique({ where: { handleHmac: handleHmacValue } });

    if (!existing) {
      try {
        await db.keystoreEnvelope.create({
          data: {
            handleHmac: handleHmacValue,
            ownerTag: ownerTagValue,
            envelope: envelope as unknown as Prisma.InputJsonValue,
          },
        });
        return 'created';
      } catch (error) {
        // Lost a create race to a different PUT for the same handle between
        // our read and our write. From this caller's perspective that is
        // indistinguishable from "someone else already owns this slot".
        if (isUniqueConstraintViolation(error)) return 'conflict';
        throw error;
      }
    }

    if (existing.ownerTag !== ownerTagValue) {
      return 'conflict';
    }

    await db.keystoreEnvelope.update({
      where: { handleHmac: handleHmacValue },
      data: { envelope: envelope as unknown as Prisma.InputJsonValue },
    });
    return 'replaced';
  },
};

// ---------------------------------------------------------------------------
// Timing-floor wrapper for the unauthenticated fetch path
// ---------------------------------------------------------------------------

/**
 * A fetch for an enrolled handle and a fetch for an unknown one must not be
 * separable by wall-clock time alone. `floorMs` is not measured against this
 * deployment's real latency percentiles — it is a fixed pad chosen to exceed
 * a comfortable multiple of an indexed lookup's expected cost. Recorded as
 * unverified rather than asserted as sufficient.
 */
export const KEYSTORE_FETCH_TIMING_FLOOR_MS = 150;

export async function withTimingFloor<T>(floorMs: number, work: () => Promise<T>): Promise<T> {
  const startedAt = process.hrtime.bigint();
  const result = await work();
  const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
  const remaining = floorMs - elapsedMs;
  if (remaining > 0) {
    await new Promise((resolve) => setTimeout(resolve, remaining));
  }
  return result;
}

/**
 * Fetch by handle, padded to a uniform floor. Returns `null` for an unknown
 * handle — same 200 response shape as a found one; see the route handler.
 */
export async function fetchEnvelopeUniform(
  handle: string,
  store: KeystoreEnvelopeStore = prismaKeystoreEnvelopeStore,
  floorMs: number = KEYSTORE_FETCH_TIMING_FLOOR_MS,
): Promise<ValidatedPassphraseEnvelope | null> {
  return withTimingFloor(floorMs, async () => {
    const record = await store.find(handleHmac(handle));
    return record ? record.envelope : null;
  });
}

/** Store-or-replace, scoped to the authenticated caller's own slot. */
export async function putEnvelope(
  args: { readonly handle: string; readonly userId: string; readonly envelope: ValidatedPassphraseEnvelope },
  store: KeystoreEnvelopeStore = prismaKeystoreEnvelopeStore,
): Promise<PutOutcome> {
  return store.put({
    handleHmac: handleHmac(args.handle),
    ownerTag: ownerTag(args.userId),
    envelope: args.envelope,
  });
}
