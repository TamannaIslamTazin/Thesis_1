/**
 * WebAuthn PRF as an ENVELOPE over the RCK — never as its derivation (#240).
 *
 * ===========================================================================
 * THE MEASUREMENT THIS MODULE EXISTS TO SURVIVE (S-2 §3.3, §3.4)
 * ===========================================================================
 * `androidx.credentials` picks one of two code paths on a Play services version
 * check, `PRE_U_MIN_GMS_APK_VERSION = 252400000`:
 *
 *   >= 252400000  ->  pre-U credman flow. The request JSON reaches the provider
 *                     intact and PRF SURVIVES.
 *   <  252400000  ->  legacy GIS FIDO2 flow, which rebuilds the request field by
 *                     field into typed objects and handles only `uvm` and
 *                     `credProps`. PRF IS SILENTLY DROPPED.
 *
 * On the second path THE CEREMONY STILL SUCCEEDS. The user authenticates, a
 * cryptographically valid assertion comes back, and `clientExtensionResults`
 * simply has no `prf` member. Code that does not explicitly check derives a key
 * from `undefined`.
 *
 * 56% of Bangladeshi Android traffic is Android <= 13, which is the tier where
 * this shim is on the path at all. So this is not an edge case; it is the
 * modal device.
 *
 * ===========================================================================
 * WHY DETECTION IS LOUD BUT THE RESPONSE IS GRACEFUL
 * ===========================================================================
 * Two different obligations, easily confused:
 *
 *   - AT THE CRYPTO BOUNDARY, absence must be LOUD. There is deliberately NO
 *     code path in this module from "PRF was absent" to "here is a key".
 *     {@link deriveEnvelopeKey} throws rather than accepting a short, empty or
 *     absent output, because a key derived from nothing is unrecoverable on the
 *     56% and looks identical to success on the rest.
 *
 *   - AT THE POLICY BOUNDARY, absence must DEGRADE. {@link probePrfOutput}
 *     returns a structured outcome instead of throwing, so enrolment can carry
 *     on with the guardian path. A device without PRF must still be able to
 *     enrol — that is reason 2 in #240 for making PRF an envelope at all.
 *
 * Losing PRF must cost an ENVELOPE, never an IDENTITY. The guardian split is
 * the universal path; this is a one-tap convenience layered over it.
 */

import { RECOVERY_KEY_SEED_BYTES, assertWellFormedSeed } from './recoveryKey.js';
import {
  EMPTY_AAD,
  KeyEnvelopeError,
  type EnvelopeContext,
  type KeyEnvelope,
  openKey,
  sealKey,
} from './keyEnvelope.js';
import { base64UrlToBytes } from './base64Url.js';

/** WebAuthn PRF outputs are HMAC-SHA-256 sized. Anything else is not a PRF output. */
export const PRF_OUTPUT_BYTES = 32;

/**
 * Domain separation, so this key can never collide with another HKDF use.
 *
 * This string is now passed to the shared primitive rather than baked into it.
 * The locker (#340) wraps its KEK through the same code with
 * 'bdhealthtrust/locker-kek-device/v1' and '.../locker-kek-recovery/v1'; had
 * they all shared THIS label, three distinct key purposes would derive
 * identically and the separation would be decorative.
 */
const ENVELOPE_HKDF_INFO = 'bdhealthtrust/rck-prf-envelope/v1';

/**
 * No AAD, and that is wire-compatible with every envelope written before the
 * shared primitive existed. Verified rather than assumed: AES-GCM over a
 * zero-length AAD is byte-identical to AES-GCM with no AAD argument, and each
 * form opens the other's ciphertext. There is no slot identity to bind here —
 * an RCK envelope belongs to exactly one key on one device.
 */
const PRF_ENVELOPE_CONTEXT: EnvelopeContext = { info: ENVELOPE_HKDF_INFO, aad: EMPTY_AAD };

export class PrfEnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PrfEnvelopeError';
  }
}

/**
 * Every way a PRF output can fail to arrive, named.
 *
 * These are reported and counted rather than collapsed into a boolean, because
 * they mean different things operationally: `EXTENSION_DROPPED` is the expected
 * S-2 §3.4 outcome on a below-floor device and is not a defect, whereas
 * `WRONG_LENGTH` means something produced a value we do not understand and is.
 */
export type PrfAbsenceReason =
  | 'NO_CLIENT_EXTENSION_RESULTS'
  | 'EXTENSION_DROPPED'
  | 'NO_RESULTS_FIRST'
  | 'WRONG_LENGTH'
  | 'NOT_DECODABLE'
  | 'ALL_ZEROES';

export type PrfOutcome =
  | { readonly available: true; readonly output: Uint8Array }
  | { readonly available: false; readonly reason: PrfAbsenceReason; readonly detail: string };

/**
 * The untyped shape a ceremony actually returns.
 *
 * Deliberately `unknown`-ish: S-2 §3.2 established there is no typed PRF API on
 * Android at all — `androidx` models PRF nowhere and the request/response are
 * opaque JSON passthrough. Typing this as a known interface would be inventing
 * a guarantee the platform does not give.
 */
export interface WebAuthnAssertionLike {
  readonly clientExtensionResults?: unknown;
}

/**
 * Extract a PRF output, or say precisely why there is not one.
 *
 * The four shapes S-2 §3.4 requires be distinguished are the first four
 * branches. Two more are checked because they are cheap and would otherwise
 * produce a usable-looking key from unusable material.
 */
export function probePrfOutput(assertion: WebAuthnAssertionLike | null | undefined): PrfOutcome {
  if (!assertion || typeof assertion !== 'object') {
    return {
      available: false,
      reason: 'NO_CLIENT_EXTENSION_RESULTS',
      detail: 'No assertion object was returned by the ceremony.',
    };
  }

  const extensions = (assertion as { clientExtensionResults?: unknown }).clientExtensionResults;
  if (!extensions || typeof extensions !== 'object') {
    return {
      available: false,
      reason: 'NO_CLIENT_EXTENSION_RESULTS',
      detail:
        'The assertion carries no clientExtensionResults at all. The ceremony succeeded ' +
        'without reporting any extension outcome.',
    };
  }

  const prf = (extensions as { prf?: unknown }).prf;
  if (!prf || typeof prf !== 'object') {
    return {
      available: false,
      reason: 'EXTENSION_DROPPED',
      detail:
        'The ceremony SUCCEEDED but clientExtensionResults has no `prf` member. This is the ' +
        'S-2 §3.4 silent drop: below Play services 252400000 the legacy GIS FIDO2 path ' +
        'rebuilds the request and carries only uvm and credProps. Not a defect — degrade ' +
        'to the guardian path.',
    };
  }

  const first = (prf as { results?: { first?: unknown } }).results?.first;
  if (first === undefined || first === null) {
    return {
      available: false,
      reason: 'NO_RESULTS_FIRST',
      detail: 'clientExtensionResults.prf exists but carries no results.first value.',
    };
  }

  let bytes: Uint8Array;
  if (first instanceof Uint8Array) {
    bytes = first;
  } else if (first instanceof ArrayBuffer) {
    bytes = new Uint8Array(first);
  } else if (typeof first === 'string') {
    try {
      bytes = base64UrlToBytes(first);
    } catch (error) {
      return {
        available: false,
        reason: 'NOT_DECODABLE',
        detail: `results.first is a string that is not base64url: ${
          error instanceof Error ? error.message : String(error)
        }`,
      };
    }
  } else {
    return {
      available: false,
      reason: 'NOT_DECODABLE',
      detail: `results.first is a ${typeof first}, which is not a PRF output.`,
    };
  }

  if (bytes.length !== PRF_OUTPUT_BYTES) {
    return {
      available: false,
      reason: 'WRONG_LENGTH',
      detail:
        `results.first decoded to ${bytes.length} bytes, expected ${PRF_OUTPUT_BYTES}. ` +
        'Something produced a value we do not understand; refusing to key from it.',
    };
  }

  if (bytes.every((byte) => byte === 0)) {
    return {
      available: false,
      reason: 'ALL_ZEROES',
      detail: 'results.first is all zeroes, which is an uninitialised buffer rather than a PRF output.',
    };
  }

  return { available: true, output: bytes };
}

/**
 * There is intentionally no way to reach the cipher with an absent PRF output.
 * {@link probePrfOutput} returns a discriminated union precisely so that the
 * absent case cannot be passed here without the caller narrowing it first.
 *
 * The shared primitive would also refuse a wrong-length or all-zero wrapping
 * key, but this guard stays and runs FIRST because its message is the one that
 * explains the actual failure — a dropped PRF extension on a below-floor
 * Android — rather than a generic "wrapping key must be 32 bytes".
 */
function assertUsablePrfOutput(prfOutput: Uint8Array): void {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length !== PRF_OUTPUT_BYTES) {
    throw new PrfEnvelopeError(
      `Refusing to derive an envelope key from ${
        prfOutput instanceof Uint8Array ? `${prfOutput.length} bytes` : typeof prfOutput
      }. A key derived from an absent PRF output is unrecoverable on every device below ` +
        'the Play services floor, and indistinguishable from success on every device above it.',
    );
  }
}

/**
 * Structurally the shared {@link KeyEnvelope}. Kept as a named export because
 * callers and stored JSON refer to it by this name, and because the PRF
 * envelope is a distinct concept even where the bytes are the same shape.
 */
export type PrfEnvelope = KeyEnvelope;

/**
 * Wrap the RCK seed under a PRF-derived key.
 *
 * The envelope is disposable BY DESIGN: salt, KDF and even the provider can all
 * be changed later by re-wrapping, and the on-chain key never moves. That is
 * reason 1 in #240 for this layering, and it is what makes a lost or rotated
 * passkey a recoverable inconvenience rather than an unrepairable dependency of
 * an unrepairable identifier.
 */
export function wrapRecoveryKeyWithPrf(seed: Uint8Array, prfOutput: Uint8Array): PrfEnvelope {
  assertWellFormedSeed(seed);
  assertUsablePrfOutput(prfOutput);

  // The primitive reopens and compares before returning, so the "an envelope
  // that does not open is a silent, terminal failure" check still happens —
  // it now happens in one place for all three callers instead of here.
  try {
    return sealKey(seed, prfOutput, PRF_ENVELOPE_CONTEXT);
  } catch (error) {
    throw asPrfEnvelopeError(error);
  }
}

/**
 * Keep this module's error type at its own boundary. Callers catch
 * `PrfEnvelopeError`; leaking `KeyEnvelopeError` through would break them and
 * would report a shared-primitive failure as though it were unrelated to PRF.
 */
function asPrfEnvelopeError(error: unknown): Error {
  if (error instanceof KeyEnvelopeError) return new PrfEnvelopeError(error.message);
  return error instanceof Error ? error : new PrfEnvelopeError(String(error));
}

/**
 * Open a PRF envelope.
 *
 * AES-GCM authenticates, so a wrong PRF output — a different passkey, a
 * different device, a tampered envelope — fails on the tag rather than
 * returning plausible garbage. There is no silent-wrong-key outcome here.
 */
export function unwrapRecoveryKeyWithPrf(
  envelope: PrfEnvelope,
  prfOutput: Uint8Array,
): Uint8Array {
  // Version is checked before the PRF guard so that an unknown layout reports
  // as an unknown layout, not as a bad passkey.
  if (envelope?.version !== 1) {
    throw new PrfEnvelopeError(
      `Unknown PRF envelope version ${String(envelope?.version)}. Refusing to guess its layout.`,
    );
  }
  assertUsablePrfOutput(prfOutput);

  let seed: Uint8Array;
  try {
    seed = openKey(envelope, prfOutput, PRF_ENVELOPE_CONTEXT);
  } catch (error) {
    if (error instanceof KeyEnvelopeError) {
      throw new PrfEnvelopeError(
        'The PRF envelope did not authenticate. The passkey that opens it is not the one ' +
          `that sealed it, or the envelope was altered: ${error.message}`,
      );
    }
    throw asPrfEnvelopeError(error);
  }

  if (seed.length !== RECOVERY_KEY_SEED_BYTES) {
    throw new PrfEnvelopeError(
      `The PRF envelope opened to ${seed.length} bytes, expected ${RECOVERY_KEY_SEED_BYTES}.`,
    );
  }

  return seed;
}
