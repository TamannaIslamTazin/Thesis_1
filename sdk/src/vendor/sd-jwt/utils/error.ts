/**
 * VENDORED from @sd-jwt/utils@0.19.0 — src/error.ts
 *
 * Apache-2.0. Copyright the sd-jwt-js authors. See ../LICENSE and ../NOTICE.
 * Upstream: https://github.com/openwallet-foundation/sd-jwt-js
 *
 * MODIFICATION NOTICE (Apache-2.0 §4(b)): CHANGED by BDHealthTrust — see divergence D5 (named error subclasses)
 *   in ../NOTICE.
 */
export class SDJWTException extends Error {
  public details?: unknown;

  constructor(message: string, details?: unknown) {
    super(message);
    Object.setPrototypeOf(this, SDJWTException.prototype);
    this.name = 'SDJWTException';
    this.details = details;
  }

  getFullMessage(): string {
    return `${this.name}: ${this.message} ${
      this.details ? `- ${JSON.stringify(this.details)}` : ''
    }`;
  }
}

// ── BDHT DIVERGENCE D5 ──────────────────────────────────────────────────────
// Two named subclasses, added for the failures divergences D2 and D3 introduce.
//
// They extend `SDJWTException` so every existing `catch` keeps working and
// nothing upstream needs to know they exist. They are separate types because
// every other exception this library raises is a CONFIGURATION error — "Hasher
// not found", "Verifier not found" — which a relying party should treat as its
// own bug, whereas these two are SECURITY refusals about the artifact it was
// handed. Collapsing both into one type would force callers to match on
// message strings to tell "I wired the SDK up wrong" apart from "this
// presentation has been tampered with".
// ────────────────────────────────────────────────────────────────────────────

/** A disclosure frame that cannot take effect against the payload being signed. */
export class SdJwtFrameError extends SDJWTException {
  constructor(message: string, details?: unknown) {
    super(message, details);
    Object.setPrototypeOf(this, SdJwtFrameError.prototype);
    this.name = 'SdJwtFrameError';
  }
}

/** A disclosure on the wire that the issuer never committed to. RFC 9807 §7.3. */
export class SdJwtDisclosureError extends SDJWTException {
  constructor(message: string, details?: unknown) {
    super(message, details);
    Object.setPrototypeOf(this, SdJwtDisclosureError.prototype);
    this.name = 'SdJwtDisclosureError';
  }
}
// ── END BDHT DIVERGENCE D5 ──────────────────────────────────────────────────
