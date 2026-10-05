/**
 * The error seam that lets refusing logic leave the backend.
 *
 * WHY THIS EXISTS. Every shape assertion, signer-set rule and verification check
 * being moved into the SDK refuses by throwing the backend's `AppError`, which
 * lives in `middleware/errorHandler.ts` and therefore drags Express and winston
 * behind it. `AppError` carries three things the SDK genuinely needs — a stable
 * machine-readable `code`, a human `message`, and structured `details` — plus one
 * it does not: an HTTP status. The status is kept anyway rather than dropped,
 * because it is the accumulated judgement of which refusals are the caller's
 * fault (400) and which are ours (500), and re-deriving that at the boundary
 * would mean guessing it back.
 *
 * =========================================================================
 * WHY IT IS IN `shared` AND NOT IN THE SDK
 * =========================================================================
 * `packages/sdk/tsup.config.ts` sets `splitting: false`, so every entry point
 * — `/ledger`, `/verify`, `/issuer` — is bundled as a self-contained file. A
 * class declared in an SDK-internal module is therefore COPIED into each of
 * them, and `instanceof` between two of those copies is FALSE. An error thrown
 * by `@ssi-healthcare/sdk/ledger` would not be recognised by a handler that
 * imported the class from `@ssi-healthcare/sdk/verify`, silently, at runtime
 * only, with the failure appearing as a generic 500 far from its cause.
 *
 * `@ssi-healthcare/shared` is listed in that config's `external`, precisely so
 * this cannot happen — the comment there already says inlining it "would put a
 * second copy of every shared constant in the bundle and break identity
 * comparisons against the first". One module instance, so one class identity,
 * so `instanceof` holds across every entry point and across the backend, which
 * already depends on `shared` directly.
 *
 * =========================================================================
 * THE BRAND IS THE FAILSAFE, NOT THE PRIMARY MECHANISM
 * =========================================================================
 * The reasoning above is a property of the CURRENT bundler configuration, and a
 * bundler configuration is exactly the kind of thing that changes without anyone
 * connecting it to error handling four packages away. If `shared` ever stops
 * being external — or the SDK is published to a registry and a consumer ends up
 * with two copies of it — `instanceof` starts returning false and every refusal
 * degrades to an unexplained 500.
 *
 * So identity is ALSO carried by a `Symbol.for` brand, which is looked up in the
 * cross-realm global registry and is therefore identical between duplicated
 * copies of this module. {@link isSsiError} checks the brand, never `instanceof`.
 * Use it. It is a superset of `instanceof SsiError`, it cannot be weakened by a
 * bundler, and a duplicated-module regression becomes a non-event instead of an
 * outage.
 */

/**
 * Registry-global, so it is the same symbol in every copy of this module.
 * `Symbol('...')` would defeat the entire point — it would be a fresh symbol per
 * copy and the brand would be exactly as fragile as `instanceof`.
 */
const SSI_ERROR_BRAND: unique symbol = Symbol.for(
  '@ssi-healthcare/shared#SsiError',
) as never;

/**
 * A refusal that carries a machine-readable reason, thrown by logic that must
 * run on a handset, in a browser and on a server alike.
 *
 * The constructor's parameter list is deliberately identical to the backend's
 * `AppError` — `(code, message, statusCode, details)` — so porting a throw site
 * is a rename and never a re-argument. `AppError` now extends this class, so the
 * backend keeps one error hierarchy rather than gaining a second.
 */
export class SsiError extends Error {
  /** @see isSsiError — brand-based identity, immune to module duplication. */
  readonly [SSI_ERROR_BRAND] = true as const;

  constructor(
    /** Stable and machine-readable; `ERROR_CODES` holds the ones we define. */
    public readonly code: string,
    message: string,
    /**
     * The HTTP status a server boundary should answer with. Meaningless on a
     * handset and harmless there; it exists so the backend's boundary does not
     * have to re-derive which refusals are the caller's fault.
     */
    public readonly statusCode: number = 500,
    public readonly details?: Readonly<Record<string, unknown>>,
    options?: { readonly cause?: unknown },
  ) {
    super(message);
    this.name = new.target.name;
    if (options && 'cause' in options) {
      // Assigned rather than passed to `super`: `cause` is ES2022 and the RN
      // engines this ships to do not all implement it in the Error constructor.
      Object.defineProperty(this, 'cause', {
        value: options.cause,
        configurable: true,
        writable: true,
      });
    }
    // Restores the prototype chain when this is compiled down to ES5 by a
    // consumer's toolchain, where extending a builtin otherwise breaks
    // `instanceof` for reasons unrelated to bundling.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Whether a caught value is one of our refusals.
 *
 * PREFER THIS TO `instanceof` EVERYWHERE, including inside this repository. It
 * is true for `SsiError`, for the backend's `AppError`, and for an `SsiError`
 * that arrived from a duplicated copy of this module — that last case is the one
 * `instanceof` gets wrong, silently, and only in a bundled build.
 *
 * Fails closed: anything that is not an object carrying the brand is treated as
 * an unknown error, which is the branch that logs a stack trace and answers 500.
 */
export function isSsiError(value: unknown): value is SsiError {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<PropertyKey, unknown>)[SSI_ERROR_BRAND] === true
  );
}

/**
 * The wire shape of a refusal: what a client is allowed to be told.
 *
 * Deliberately omits `stack` and `cause`. Both routinely contain absolute paths,
 * DIDs and, via `cause`, whole upstream response bodies; a serialiser that
 * included them by default would leak them the first time someone returned this
 * object straight from a route.
 */
export interface SerialisedSsiError {
  readonly code: string;
  readonly message: string;
  readonly details?: Readonly<Record<string, unknown>>;
}

/**
 * Narrow any caught value to something safe to hand a client.
 *
 * Unrecognised errors collapse to `INTERNAL_ERROR` with a fixed message rather
 * than their own: an arbitrary thrown value's message is attacker-influenced and
 * frequently contains a query, a path or a driver's view of the schema.
 */
export function serialiseError(value: unknown): SerialisedSsiError {
  if (isSsiError(value)) {
    return value.details === undefined
      ? { code: value.code, message: value.message }
      : { code: value.code, message: value.message, details: value.details };
  }
  return { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred.' };
}
