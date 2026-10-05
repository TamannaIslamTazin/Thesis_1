/**
 * Narrow a held `vc+sd-jwt` to exactly what the holder agreed to disclose.
 *
 * ===========================================================================
 * WHY THIS EXISTS
 * ===========================================================================
 * Until this module the disclosure sheet was a preference, not a control. The
 * wallet presented the credential WHOLE and recorded which switches the holder
 * had left on, so a pharmacy that asked for one claim received three while the
 * holder was shown "Share 1 item". A consent system that discloses unconsented
 * claims refutes itself; labelling the gap honestly is a mitigation, and this
 * is the fix.
 *
 * The narrowing is cryptographic, not editorial. An SD-JWT's disclosable claims
 * are present in the issuer-signed payload only as SALTED DIGESTS; the values
 * live in disclosure segments appended after the JWT. Dropping a segment
 * removes the value from the artifact entirely — the verifier receives a digest
 * it cannot invert and never learns the claim existed with any particular
 * value. Nothing is redacted after the fact and nothing is re-signed: the
 * issuer's signature still covers exactly what it covered.
 *
 * ===========================================================================
 * WHAT THIS MODULE REFUSES TO DO
 * ===========================================================================
 * It will not silently pass a credential through unnarrowed. A `vc+jwt` has no
 * disclosures to drop, so honouring a selection over one is impossible — and
 * the dangerous outcome is not an error, it is a well-formed presentation that
 * discloses everything while the receipt says otherwise. So the caller is told
 * which happened, explicitly, and the consent receipt records it (#360).
 *
 * The counterpart on the issuing side is `buildDisclosureFrame`, which makes
 * every claim except `credentialSubject.id` disclosable at issuance (#194) —
 * maximal disclosability there is what leaves this decision available here.
 * `id` is deliberately NOT disclosable: with it withheld, a thief can present a
 * stolen credential under their own DID and Credo returns isValid (#195).
 */
import { presentSync } from '@ssi-healthcare/sdk/sd-jwt';
import { buildPresentationFrame } from '@ssi-healthcare/shared';
import { sha256 } from '@noble/hashes/sha256';

/** The `_sd_alg` this issuer uses. Anything else is refused rather than guessed. */
const SUPPORTED_HASH_ALG = 'sha-256';

/**
 * A compact SD-JWT carries `~`-separated disclosures after the JWT. A plain
 * `vc+jwt` has none, and that is exactly the case that must not pass silently.
 */
export function isSdJwtCredential(compact: string): boolean {
  return compact.includes('~');
}

export class SelectiveDisclosureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SelectiveDisclosureError';
  }
}

const hasher = (data: string, alg: string): Uint8Array => {
  if (alg.toLowerCase() !== SUPPORTED_HASH_ALG) {
    // Refuse rather than hash with the wrong algorithm. Producing digests under
    // a different algorithm than the issuer used yields a presentation whose
    // disclosures match nothing — which RFC 9807 §7.3 requires be REJECTED, and
    // which Credo instead drops silently (#196, hole 3). Failing here makes it
    // a visible refusal instead of a quiet under-disclosure.
    throw new SelectiveDisclosureError(
      `This credential uses hash algorithm '${alg}', which this wallet cannot compute.`,
    );
  }
  return sha256(new TextEncoder().encode(data));
};

export interface NarrowedCredential {
  /** The artifact to present. */
  compact: string;
  /** Whether the holder's selection was actually enforced on it. */
  minimisationEnforced: boolean;
  /** Claim paths readable in `compact`, derived from the artifact itself. */
  disclosedClaims: string[];
}

/**
 * Read the claim paths a compact SD-JWT actually reveals.
 *
 * Derived from the ARTIFACT, never from the selection that produced it. The
 * whole failure being corrected here was a wallet that reported its intent as
 * though it were the outcome, so the check that the narrowing worked must not
 * consult the same value that asked for it.
 *
 * A disclosure segment is base64url of `[salt, claimName, value]`.
 */
export function claimsRevealedBy(compact: string): string[] {
  const [, ...rest] = compact.split('~');
  const revealed: string[] = [];
  for (const segment of rest) {
    if (!segment) continue;
    try {
      const json = JSON.parse(
        new TextDecoder().decode(
          Uint8Array.from(
            atobCompat(segment.replace(/-/g, '+').replace(/_/g, '/')),
            (c) => c.charCodeAt(0),
          ),
        ),
      );
      if (Array.isArray(json) && json.length >= 2 && typeof json[1] === 'string') {
        revealed.push(json[1]);
      }
    } catch {
      // A segment we cannot read is not a claim we can promise was disclosed.
    }
  }
  return revealed;
}

/** `atob` is absent from RN 0.83's polyfills (steno #376). */
function atobCompat(b64: string): string {
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const input = `${b64}${pad}`.replace(/=+$/, '');
  let out = '';
  let bits = 0;
  let acc = 0;
  for (const ch of input) {
    const idx = chars.indexOf(ch);
    if (idx === -1) continue;
    acc = (acc << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += String.fromCharCode((acc >> bits) & 0xff);
    }
  }
  return out;
}

/**
 * Narrow `compact` to `selectedPaths`.
 *
 * Always returns something presentable. When the credential cannot carry a
 * selection the original is returned with `minimisationEnforced: false`, so the
 * caller can record the truth rather than the intention.
 */
export function narrowToSelection(
  compact: string,
  selectedPaths: readonly string[],
): NarrowedCredential {
  if (!isSdJwtCredential(compact)) {
    return {
      compact,
      minimisationEnforced: false,
      // Not `selectedPaths`. What travels is whatever the credential contains,
      // and the caller reads that from the artifact.
      disclosedClaims: [],
    };
  }

  const frame = buildPresentationFrame(selectedPaths);
  const narrowed = presentSync(compact, frame as never, hasher);
  const disclosedClaims = claimsRevealedBy(narrowed);

  // POST-CONDITION, asserted against the produced bytes.
  //
  // A frame that does not take effect produces a well-formed, correctly-signed
  // artifact that simply asserts the wrong thing — silently, and toward
  // exposure. That is the exact failure class of #203, where obeying Credo's
  // published `_sd: string[]` type shipped a patient's medications in cleartext.
  // The only defence is to read the output and refuse if it disagrees.
  const leaked = disclosedClaims.filter(
    (claim) => !selectedPaths.some((p) => p === claim || p.startsWith(`${claim}.`) || p.startsWith(`${claim}[`)),
  );
  if (leaked.length > 0) {
    throw new SelectiveDisclosureError(
      `Refusing to present: the narrowed credential still reveals ${leaked.join(', ')}, ` +
        'which the holder did not agree to share.',
    );
  }

  return { compact: narrowed, minimisationEnforced: true, disclosedClaims };
}
