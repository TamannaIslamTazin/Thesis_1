/**
 * SSI Healthcare - SD-JWT Disclosure Frame Policy
 *
 * THE ONE PLACE THAT DECIDES WHAT A CREDENTIAL CAN EVER DISCLOSE.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A POLICY MODULE AND NOT A FEW LINES AT THE ISSUANCE CALL SITE
 * ---------------------------------------------------------------------------
 * An SD-JWT has two frames and they belong to different parties at different
 * times:
 *
 *   disclosureFrame    chosen by the ISSUER, at issuance, and BAKED INTO THE
 *                      SIGNATURE. It decides what the credential is even
 *                      *capable* of hiding, forever.
 *   presentationFrame  chosen by the HOLDER, at presentation. It decides what
 *                      is actually revealed this time.
 *
 * Only the first is irreversible. A claim the issuer did not make selectively
 * disclosable is in cleartext in every presentation of that credential for the
 * rest of its life, and the only remedy is reissuance — which, for a lab result
 * from a hospital the patient has since left, is no remedy at all.
 *
 * That asymmetry is why the policy lives in one module with one name rather
 * than being spelled out at each `signCredential` call. Changing what this
 * system is willing to hide must be one edit, reviewable on its own, not a hunt
 * through issuance code in two packages.
 *
 * ---------------------------------------------------------------------------
 * THE POLICY: MAXIMAL DISCLOSABILITY
 * ---------------------------------------------------------------------------
 * Every value under `credentialSubject` is selectively disclosable, except what
 * is structurally required for the credential to remain a valid, verifiable W3C
 * credential.
 *
 * The reasoning is about where recourse exists. If the ISSUER withholds
 * disclosability, the holder has no recourse: they cannot hide a claim the
 * issuer nailed down, and the verifier sees it whether or not it was needed. If
 * the ISSUER grants disclosability too freely, the VERIFIER still has complete
 * recourse: it refuses any presentation missing a field it requires. Required-
 * field enforcement is therefore the verifier's job, and this module's job is to
 * leave the holder as many choices as the format allows.
 *
 * "Maximal" here is stronger than "every leaf":
 *
 *   - Leaves are disclosable.
 *   - CONTAINERS are disclosable too, so a holder can hide the very existence
 *     of a group. `{ prescriber: { name, licence } }` yields a frame where
 *     `prescriber` itself is hidden *and* its members are individually
 *     disclosable — hiding "there is a prescriber at all" is a real privacy
 *     property that hiding only the two leaves does not give you.
 *   - ARRAY ELEMENTS are individually disclosable, so a holder can reveal one
 *     medication out of three without revealing that there are three.
 *
 * ---------------------------------------------------------------------------
 * THE ONE CARVE-OUT: `credentialSubject.id`, AND WHY IT IS NOT NEGOTIABLE
 * ---------------------------------------------------------------------------
 * `credentialSubject.id` is CAN be made disclosable — Credo signs such a
 * credential without complaint — and doing so is a measured, exploitable
 * vulnerability rather than a theoretical one. Observed against Credo 0.6:
 *
 *   `W3cV2SdJwtCredentialService.verifyPresentation` authenticates the holder
 *   by comparing `credentialSubjectIds` against the presentation signer, and
 *   SKIPS that check entirely when `credentialSubjectIds` is empty. If `id` is
 *   disclosable, a holder can withhold it; then anyone who captures the
 *   disclosed credential can wrap it in their own presentation, signed with
 *   their own key under their own DID, and Credo returns `isValid: true`.
 *   The identical attack against a credential whose `id` was outside the
 *   disclosure frame is rejected.
 *
 * So `id` stays outside the frame. Note this is DEFENCE IN DEPTH, not the
 * defence: the verification boundary independently binds the credential's `cnf`
 * to the presentation signer, unconditionally, precisely so that this policy is
 * not the only thing standing between a captured credential and a successful
 * theft. See `assertPresentationHolderBinding` in the backend's `sdJwtVc`
 * service. Relying on Credo's `credentialSubjectAuthentication` alone would be
 * an implicit dependency on third-party behaviour that can change on upgrade.
 *
 * `credentialSubject` itself is likewise never disclosable: hiding it would
 * take `id` with it and reopen exactly that hole.
 *
 * Everything ABOVE `credentialSubject` — `@context`, `type`, `credentialStatus`,
 * `credentialSchema`, `relatedResource` — is refused by Credo itself and is not
 * this module's concern. `credentialStatus` staying in the clear is load
 * bearing and desirable: it is what keeps BitstringStatusList revocation
 * working on a selectively disclosed credential.
 *
 * ---------------------------------------------------------------------------
 * A MALFORMED FRAME FAILS **OPEN**. THIS IS THE DANGEROUS PART.
 * ---------------------------------------------------------------------------
 * `@sd-jwt/core` silently ignores frame directives it does not understand. The
 * measured example: array element indices must be NUMBERS. Writing
 * `{ _sd: ['0', '1', '2'] }` instead of `{ _sd: [0, 1, 2] }` produces no error
 * at issuance and no error at presentation — it emits the entire array in
 * cleartext, and a holder who asks to disclose one element gets all of them.
 *
 * That is why this module builds the frame PROGRAMMATICALLY from the actual
 * credential subject rather than from a hardcoded field list (which would go
 * stale the moment a credential type gains a field), and why issuance calls
 * {@link assertNothingDisclosableLeaked} against the signed payload afterwards.
 * A frame you cannot verify is a frame you cannot trust.
 */

/**
 * A disclosure frame in the shape `@sd-jwt/core` consumes.
 *
 * Structurally identical to Credo's `IDisclosureFrame`, declared here rather
 * than imported so this package keeps its zero-dependency footprint and can be
 * consumed by the SDK, which has no Credo dependency at all.
 *
 * `_sd` holds the keys (object) or indices (array) made selectively disclosable
 * at this level. Indices MUST be numbers — see the warning above.
 */
export interface SdJwtDisclosureFrame {
  _sd?: Array<string | number>;
  _sd_decoy?: number;
  [key: string]: Array<string | number> | number | SdJwtDisclosureFrame | undefined;
}

/**
 * The knobs. Override these to change what the system is willing to hide;
 * everything else about frame construction is derived.
 */
export interface DisclosurePolicy {
  /**
   * Property names under `credentialSubject` that are NEVER made disclosable,
   * expressed as dot paths relative to `credentialSubject` itself.
   *
   * Adding to this set makes the system LESS private and should be justified in
   * the same terms as the `id` carve-out above: name the specific verification
   * step that breaks when the claim is absent.
   */
  readonly alwaysDisclosed: readonly string[];
  /**
   * Recursion limit for walking the subject.
   *
   * A credential subject is issuer-supplied data. Without a bound, a
   * pathologically nested (or cyclic) subject would recurse until the stack
   * gives out, turning a malformed input into a process-level failure. The
   * limit is a safety bound rather than a modelling statement: subjects this
   * deep are refused outright rather than partially framed, because a
   * PARTIALLY framed subject is precisely the silent leak described above.
   */
  readonly maxDepth: number;
}

/**
 * The policy this system issues under. See the module docstring for the
 * reasoning; overriding it is a single edit here.
 */
export const MAXIMAL_DISCLOSABILITY: DisclosurePolicy = {
  alwaysDisclosed: ['id'],
  maxDepth: 12,
};

/** Thrown when a credential subject cannot be framed safely. */
export class DisclosurePolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DisclosurePolicyError';
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Build the frame for one value, returning `undefined` for a leaf.
 *
 * A leaf needs no sub-frame: it is made disclosable by its PARENT listing its
 * key. Only containers produce a frame of their own, and they always also
 * appear in their parent's `_sd`, which is what makes the container's existence
 * hideable as well as its contents.
 */
function frameForValue(
  value: unknown,
  path: string,
  policy: DisclosurePolicy,
  depth: number,
): SdJwtDisclosureFrame | undefined {
  if (depth > policy.maxDepth) {
    throw new DisclosurePolicyError(
      `credentialSubject nests deeper than the policy limit of ${policy.maxDepth} at '${path}'. ` +
        'Refusing to build a partial disclosure frame: an unframed branch is emitted in cleartext.',
    );
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return undefined;
    const frame: SdJwtDisclosureFrame = {
      // NUMBERS, not strings. String indices are silently ignored by
      // @sd-jwt/core and the whole array ends up in cleartext.
      _sd: value.map((_, index) => index),
    };
    value.forEach((element, index) => {
      const sub = frameForValue(element, `${path}[${index}]`, policy, depth + 1);
      if (sub) frame[String(index)] = sub;
    });
    return frame;
  }

  if (isPlainObject(value)) {
    const disclosable: string[] = [];
    const frame: SdJwtDisclosureFrame = {};

    for (const [key, child] of Object.entries(value)) {
      // Skip `undefined` members outright: they are absent from the signed
      // payload, and naming an absent key in `_sd` is a directive @sd-jwt has
      // nothing to apply.
      if (child === undefined) continue;
      disclosable.push(key);
      const sub = frameForValue(child, path ? `${path}.${key}` : key, policy, depth + 1);
      if (sub) frame[key] = sub;
    }

    if (disclosable.length === 0) return undefined;
    frame._sd = disclosable;
    return frame;
  }

  // Leaf (string, number, boolean, null). The parent makes it disclosable.
  return undefined;
}

/**
 * Build the disclosure frame for a credential, from the credential's own
 * subject shape.
 *
 * Returns `undefined` when there is nothing to make disclosable — a subject
 * carrying only `id`, for instance. Callers must pass `undefined` through
 * rather than substituting an empty object: Credo treats a missing frame as
 * "disclose nothing selectively", which is the correct reading of "there was
 * nothing eligible".
 *
 * The returned frame is rooted at the credential, so it can be handed to
 * `signCredential({ disclosureFrame })` unchanged.
 */
export function buildDisclosureFrame(
  credentialSubject: unknown,
  policy: DisclosurePolicy = MAXIMAL_DISCLOSABILITY,
): SdJwtDisclosureFrame | undefined {
  if (!isPlainObject(credentialSubject)) {
    throw new DisclosurePolicyError(
      'credentialSubject must be a JSON object to build a disclosure frame from it',
    );
  }

  const alwaysDisclosed = new Set(policy.alwaysDisclosed);
  const disclosable: string[] = [];
  const subjectFrame: SdJwtDisclosureFrame = {};

  for (const [key, child] of Object.entries(credentialSubject)) {
    if (alwaysDisclosed.has(key) || child === undefined) continue;
    disclosable.push(key);
    const sub = frameForValue(child, key, policy, 1);
    if (sub) subjectFrame[key] = sub;
  }

  if (disclosable.length === 0) return undefined;
  subjectFrame._sd = disclosable;

  // Only `credentialSubject` is ever framed. Credo refuses `@context`, `type`,
  // `credentialStatus`, `credentialSchema` and `relatedResource` outright, and
  // `issuer` / `validFrom` / `validUntil` are what make the credential
  // checkable at all.
  return { credentialSubject: subjectFrame };
}

/**
 * Names of the claims this policy expects to be ABSENT from the issuer-signed
 * payload of a freshly signed credential.
 *
 * Used by {@link assertNothingDisclosableLeaked}; exported so tests and probes
 * can assert against the same list the checker uses.
 */
export function disclosableSubjectKeys(
  credentialSubject: unknown,
  policy: DisclosurePolicy = MAXIMAL_DISCLOSABILITY,
): string[] {
  if (!isPlainObject(credentialSubject)) return [];
  const alwaysDisclosed = new Set(policy.alwaysDisclosed);
  return Object.keys(credentialSubject).filter(
    (key) => !alwaysDisclosed.has(key) && credentialSubject[key] !== undefined,
  );
}

/**
 * Fail issuance if the disclosure frame did not actually take effect.
 *
 * THE REASON THIS EXISTS is at the top of this file: `@sd-jwt/core` ignores
 * frame directives it does not understand, silently, so a frame bug shows up
 * not as an exception but as patient data in cleartext. Nothing about the
 * signing call reports it, and the credential is signed and valid — just not
 * private.
 *
 * The check is cheap and total: after signing, every key the policy said should
 * be disclosable must be GONE from `credentialSubject` in the issuer-signed
 * payload, replaced by a digest in `_sd`. If any survives, the credential
 * cannot be issued, because issuing it would hand the holder a credential they
 * believe hides their diagnosis and which does not.
 *
 * @param signedSubject `credentialSubject` as it appears in the ISSUER-SIGNED
 *   JWT payload — NOT `prettyClaims`, which is the fully re-disclosed view and
 *   would always contain every claim.
 */
export function assertNothingDisclosableLeaked(
  originalSubject: unknown,
  signedSubject: unknown,
  policy: DisclosurePolicy = MAXIMAL_DISCLOSABILITY,
): void {
  const expectedAbsent = disclosableSubjectKeys(originalSubject, policy);
  if (expectedAbsent.length === 0) return;

  if (!isPlainObject(signedSubject)) {
    throw new DisclosurePolicyError(
      'Signed credential has no readable credentialSubject to verify the disclosure frame against',
    );
  }

  const leaked = expectedAbsent.filter((key) => key in signedSubject);
  if (leaked.length > 0) {
    throw new DisclosurePolicyError(
      `Disclosure frame did not take effect: ${leaked.join(', ')} ${
        leaked.length === 1 ? 'is' : 'are'
      } still in cleartext in the issuer-signed payload. ` +
        'Refusing to issue a credential that claims selective disclosure it does not have.',
    );
  }
}

// ===========================================================================
// THE HOLDER'S HALF: PRESENTATION FRAMES
// ===========================================================================
/**
 * Everything above decides what a credential is CAPABLE of hiding, once, at
 * issuance. Everything below decides what is ACTUALLY hidden, per presentation,
 * by the holder. The two frames are different shapes consumed by different
 * `@sd-jwt` entry points, and the rules for one DO NOT transfer to the other:
 *
 *   disclosureFrame    `{ _sd: ['a','b'], meds: { _sd: [0,1,2] } }`
 *                      array indices are NUMBERS inside an `_sd` array.
 *                      Strings are silently ignored — see the warning above.
 *   presentationFrame  `{ a: true, meds: { 1: true } }`
 *                      array indices are OBJECT KEYS, and therefore strings.
 *
 * Both live in this module for the same reason: a frame constructed at a call
 * site is a frame nobody reviews, and both of these fail silently rather than
 * loudly when they are wrong.
 *
 * ---------------------------------------------------------------------------
 * MEASURED SEMANTICS — why this takes LEAF paths and not "fields"
 * ---------------------------------------------------------------------------
 * Observed against `@sd-jwt/core` 0.19 on 2026-08-20, not inferred:
 *
 *   `{ prescriber: { name: true } }`  ->  `prescriber: { name: 'Dr Karim' }`
 *       Naming a member IMPLIES its container. Ancestors never need spelling
 *       out, so this builder does not emit them.
 *
 *   `{ prescriber: true }`            ->  `prescriber: {}`
 *       Naming a container ALONE discloses it as an EMPTY OBJECT. It proves a
 *       prescriber EXISTS and reveals no member of it.
 *
 * That second result is the trap this API is shaped to avoid. "Disclose the
 * prescriber" and "admit that a prescriber exists" are different acts with
 * different privacy consequences, and a sheet that maps a container toggle
 * straight to `true` would silently perform the second while the holder
 * believed they had done the first — sharing an empty object, which is both a
 * privacy leak and a broken presentation.
 *
 * So {@link buildPresentationFrame} consumes LEAF paths only. A container is
 * disclosed by disclosing its leaves. Existence-only disclosure is a real
 * capability of the format, but it is not reachable by accident from here.
 */

/**
 * A holder's choice of what to reveal, in the shape `@sd-jwt/present` consumes.
 *
 * `true` at a key reveals it; a nested object reveals selected members. Anything
 * NOT mentioned is withheld — the frame is an ALLOWLIST, so a typo hides a claim
 * rather than revealing one, which is the safe direction to fail.
 */
export interface SdJwtPresentationFrame {
  [key: string]: boolean | SdJwtPresentationFrame;
}

/** One step of a claim path: an object key, or an array index. */
export type ClaimPathSegment = string | number;

/**
 * Split a claim path into segments.
 *
 * The path syntax is the one {@link buildDisclosureFrame} already reports in its
 * error messages — `prescriber.name`, `medications[1]`, `a[0].b` — so the two
 * halves of this module speak about claims in one vocabulary. Paths are
 * relative to `credentialSubject`, which is the only part of a credential this
 * system ever makes disclosable.
 */
export function parseClaimPath(path: string): ClaimPathSegment[] {
  const segments: ClaimPathSegment[] = [];
  // Matches either a bracketed array index or a dot-delimited property name.
  const pattern = /\[(\d+)\]|([^.[\]]+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(path)) !== null) {
    if (match[1] !== undefined) segments.push(Number(match[1]));
    else if (match[2] !== undefined && match[2].length > 0) segments.push(match[2]);
  }
  return segments;
}

/** Render segments back into the path syntax {@link parseClaimPath} accepts. */
export function formatClaimPath(segments: readonly ClaimPathSegment[]): string {
  return segments.reduce<string>(
    (acc, segment) =>
      typeof segment === 'number' ? `${acc}[${segment}]` : acc ? `${acc}.${segment}` : String(segment),
    '',
  );
}

/**
 * One claim a holder can independently choose to reveal or withhold.
 *
 * These are LEAVES. A container is represented by its leaves rather than by
 * itself, for the reason in the section header: selecting a container is not
 * the same act as selecting its contents, and conflating them over-discloses.
 */
export interface DisclosableClaim {
  /** Path relative to `credentialSubject`, e.g. `prescriber.name`. */
  path: string;
  /** The claim's value, for showing the holder what they are about to reveal. */
  value: unknown;
}

/**
 * Enumerate every claim a holder can independently withhold, from the credential
 * as they hold it (fully disclosed).
 *
 * This is the sheet's row source, and it is derived from the SAME policy that
 * built the issuance frame — so a claim the issuer never made disclosable can
 * never appear as a choice. Offering a toggle that cannot take effect is the
 * disclosure-sheet version of a fail-open: the holder would believe they had
 * withheld something that is in cleartext in every presentation.
 */
export function enumerateDisclosableClaims(
  credentialSubject: unknown,
  policy: DisclosurePolicy = MAXIMAL_DISCLOSABILITY,
): DisclosableClaim[] {
  if (!isPlainObject(credentialSubject)) return [];

  const alwaysDisclosed = new Set(policy.alwaysDisclosed);
  const claims: DisclosableClaim[] = [];

  const walk = (value: unknown, segments: ClaimPathSegment[], depth: number): void => {
    if (depth > policy.maxDepth) return;

    if (Array.isArray(value)) {
      value.forEach((element, index) => walk(element, [...segments, index], depth + 1));
      return;
    }
    if (isPlainObject(value)) {
      for (const [key, child] of Object.entries(value)) {
        if (child === undefined) continue;
        walk(child, [...segments, key], depth + 1);
      }
      return;
    }
    // Leaf.
    claims.push({ path: formatClaimPath(segments), value });
  };

  for (const [key, child] of Object.entries(credentialSubject)) {
    if (alwaysDisclosed.has(key) || child === undefined) continue;
    walk(child, [key], 1);
  }

  return claims;
}

/**
 * Build the presentation frame for a chosen set of leaf paths.
 *
 * Returns a frame rooted at the CREDENTIAL, so it can be handed to
 * `presentSdJwtCredential` unchanged, matching {@link buildDisclosureFrame}'s
 * rooting on the issuance side.
 *
 * Selecting NOTHING is legal and meaningful: it yields a presentation carrying
 * only the claims the issuer left outside the frame (`credentialSubject.id`,
 * `credentialStatus`, the validity window) — enough to prove the credential is
 * genuine, unrevoked and bound to this holder, and nothing about its subject.
 * That is a real and useful disclosure level, not a degenerate one, so it is
 * not an error.
 *
 * Paths naming an always-disclosed claim are dropped rather than rejected: such
 * a claim is outside the issuer's frame and is present in every presentation
 * regardless, so naming it in a presentation frame is a directive with nothing
 * to apply.
 */
export function buildPresentationFrame(
  selectedPaths: readonly string[],
  policy: DisclosurePolicy = MAXIMAL_DISCLOSABILITY,
): SdJwtPresentationFrame {
  const alwaysDisclosed = new Set(policy.alwaysDisclosed);
  const subjectFrame: SdJwtPresentationFrame = {};

  for (const path of selectedPaths) {
    const segments = parseClaimPath(path);
    if (segments.length === 0) continue;
    if (alwaysDisclosed.has(String(segments[0]))) continue;

    let cursor = subjectFrame;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const key = String(segments[i]);
      const existing = cursor[key];
      // A path may not both name a leaf and be a prefix of another path in a
      // well-formed selection, but the input comes from a UI. Prefer the
      // container reading: it is the one that can still carry both.
      if (typeof existing !== 'object' || existing === null) {
        cursor[key] = {};
      }
      cursor = cursor[key] as SdJwtPresentationFrame;
    }

    const leaf = String(segments[segments.length - 1]);
    // Do not overwrite an existing sub-frame with `true`: that would replace
    // "these members" with "the container, empty" — the measured footgun in the
    // section header, in its most damaging direction.
    if (typeof cursor[leaf] !== 'object') cursor[leaf] = true;
  }

  return { credentialSubject: subjectFrame };
}

// ---------------------------------------------------------------------------
// WHAT THE VERIFIER ASKED FOR
// ---------------------------------------------------------------------------

/**
 * How badly a verifier wants a claim.
 *
 * There are only two states a verifier can put a claim in, and a third that it
 * cannot: a claim it did not mention at all is `null` here, never `'optional'`.
 * The distinction matters to the holder — "they asked and I may decline" and
 * "they never asked" are different situations — and collapsing them is how a
 * sheet ends up presenting volunteered data as though it had been requested.
 */
export type ClaimRequirement = 'required' | 'optional';

/** One claim a verifier states it needs, as it travels on the wire. */
export interface VerifierClaimRequest {
  /** Path relative to `credentialSubject`, in {@link parseClaimPath} syntax. */
  path: string;
  requirement: ClaimRequirement;
  /** Why this verifier needs this claim, in the holder's language. */
  purpose?: string;
}

/**
 * One row of the disclosure sheet: a claim, what the verifier said about it, and
 * whether it starts out selected.
 */
export interface DisclosureChoice {
  path: string;
  value: unknown;
  /** `null` when this verifier did not ask for this claim at all. */
  requirement: ClaimRequirement | null;
  purpose?: string;
  /** Whether this claim is disclosed in the CURRENT selection. */
  disclosed: boolean;
  /**
   * Whether the holder may change {@link disclosed}.
   *
   * Only ever `true` for a REQUIRED claim, and it means "not individually
   * refusable", never "not refusable". Withholding a required claim produces a
   * presentation the verifier will reject by definition, and a control whose
   * only outcome is guaranteed failure is a false choice — worse than no
   * control, because it implies a possibility that does not exist. The real
   * decision at that point is whether to share at all, which is why declining
   * the whole exchange is a peer of confirming it.
   */
  locked: boolean;
}

/**
 * Build the sheet's initial state: every disclosable claim, annotated with what
 * this verifier asked for, and PRE-SELECTED AT THE MINIMUM THAT SATISFIES THEM.
 *
 * ===========================================================================
 * THIS DEFAULT IS THE WHOLE PRIVACY PROPERTY. IT IS NOT A UI PREFERENCE.
 * ===========================================================================
 * A disclosure sheet is where a privacy feature turns into a dark pattern, and
 * the mechanism is entirely the default. Selective disclosure that opens with
 * everything switched on does not produce less disclosure — it produces exactly
 * as much disclosure as before, plus a consent record saying the holder chose
 * it. That is worse than not shipping the feature, because it MANUFACTURES
 * CONSENT for full disclosure and makes the resulting over-disclosure look
 * deliberate.
 *
 * The default is therefore the required set and nothing else:
 *
 *   - required   -> selected, and locked (see {@link DisclosureChoice.locked})
 *   - optional   -> NOT selected. The verifier said it could proceed without
 *                   this, and took the trouble to say so; honour that rather
 *                   than treating "optional" as "yes by default".
 *   - not asked  -> NOT selected.
 *
 * The asymmetry is deliberate and it is the enforcement mechanism: the minimal
 * disclosure costs the holder ZERO taps and leaves the confirm button live
 * immediately, while every claim beyond it costs one deliberate tap. Nothing
 * anywhere offers "disclose everything" in one action. Over-disclosure remains
 * possible — refusing it would be paternalistic, and a holder may have good
 * reason — but it cannot happen inattentively, which is the only failure mode
 * that scales to every user.
 *
 * Note what this does NOT do: it does not decide anything about what the ISSUER
 * made disclosable. `disclosable` is derived from the credential as issued, so a
 * claim the issuer nailed down never appears here as a choice at all.
 */
export function buildDisclosureChoices(
  disclosable: readonly DisclosableClaim[],
  requests: readonly VerifierClaimRequest[],
): DisclosureChoice[] {
  const byPath = new Map(requests.map((request) => [request.path, request]));

  return disclosable.map((claim) => {
    const request = byPath.get(claim.path);
    const requirement = request?.requirement ?? null;
    return {
      path: claim.path,
      value: claim.value,
      requirement,
      ...(request?.purpose ? { purpose: request.purpose } : {}),
      // The default. See the docstring — this line is the privacy property.
      disclosed: requirement === 'required',
      locked: requirement === 'required',
    };
  });
}

/**
 * The claims a verifier required but this credential cannot supply.
 *
 * A verifier can ask for a claim the credential simply does not carry. The
 * holder must be told that BEFORE they confirm, because otherwise they consent
 * to a disclosure, hand over real claims, and receive a rejection anyway —
 * paying the privacy cost for none of the benefit.
 */
export function unsatisfiableRequirements(
  disclosable: readonly DisclosableClaim[],
  requests: readonly VerifierClaimRequest[],
  policy: DisclosurePolicy = MAXIMAL_DISCLOSABILITY,
): string[] {
  const available = new Set(disclosable.map((claim) => claim.path));
  const alwaysDisclosed = new Set(policy.alwaysDisclosed);
  return requests
    .filter((request) => request.requirement === 'required')
    .map((request) => request.path)
    .filter((path) => !available.has(path) && !alwaysDisclosed.has(String(parseClaimPath(path)[0])));
}

/**
 * The selected paths that go BEYOND what the verifier asked for.
 *
 * Surfaced so the sheet can say so plainly at the moment it becomes true. Not to
 * block it — see {@link buildDisclosureChoices} — but because over-disclosure
 * that is never named is over-disclosure the holder cannot notice they are
 * doing.
 */
export function volunteeredClaims(choices: readonly DisclosureChoice[]): string[] {
  return choices
    .filter((choice) => choice.disclosed && choice.requirement !== 'required')
    .map((choice) => choice.path);
}

/** The presentation frame for the current sheet state. */
export function presentationFrameForChoices(
  choices: readonly DisclosureChoice[],
  policy: DisclosurePolicy = MAXIMAL_DISCLOSABILITY,
): SdJwtPresentationFrame {
  return buildPresentationFrame(
    choices.filter((choice) => choice.disclosed).map((choice) => choice.path),
    policy,
  );
}

// ---------------------------------------------------------------------------
// READING REQUIREMENTS OFF THE WIRE
// ---------------------------------------------------------------------------

/**
 * The JSONPath prefix that identifies a Presentation Exchange field as naming a
 * SUBJECT CLAIM rather than credential metadata.
 *
 * `$.type` and `$.issuer` are also legitimate PE fields, but they constrain
 * WHICH credential satisfies the request — they are not claims a holder chooses
 * to disclose. Treating them as disclosure choices would put "type" in the
 * sheet as a toggle the holder can refuse, which is meaningless: it is outside
 * the issuer's disclosure frame and present in every presentation regardless.
 */
const SUBJECT_PATH_PREFIX = '$.credentialSubject.';

/**
 * Extract the per-claim requirements a verifier stated, from one Presentation
 * Exchange input descriptor.
 *
 * ONE WIRE FORMAT, NOT TWO. The obvious alternative — having the verifier send a
 * bespoke `claim_requirements` block alongside the presentation definition — was
 * rejected: two structures saying what the verifier needs is two structures that
 * can disagree, and the one the wallet renders would then differ from the one
 * the verifier enforces. The holder would be shown a requirement list that is
 * not the list they are actually judged against. So the standard PE descriptor
 * is the single source and this is its only reader.
 *
 * A field carrying several paths is treated as requiring ALL of them, which is
 * the conservative reading: PE's semantics are "any of these paths may satisfy
 * the field", so listing every one as required over-states the ask. That errs
 * toward showing the holder MORE of what a verifier might want rather than
 * silently omitting a claim it will reject them for withholding, and the holder
 * can still decline each one individually.
 */
export function claimRequestsFromInputDescriptor(descriptor: unknown): VerifierClaimRequest[] {
  if (!isPlainObject(descriptor)) return [];
  const constraints = descriptor.constraints;
  if (!isPlainObject(constraints) || !Array.isArray(constraints.fields)) return [];

  const requests: VerifierClaimRequest[] = [];
  const seen = new Set<string>();

  for (const field of constraints.fields) {
    if (!isPlainObject(field) || !Array.isArray(field.path)) continue;
    // PE marks a field optional; absent means required. Note the polarity is the
    // opposite of this module's `requirement`, which is why it is converted here
    // once rather than at each consumer.
    const requirement: ClaimRequirement = field.optional === true ? 'optional' : 'required';
    const purpose = typeof field.purpose === 'string' ? field.purpose : undefined;

    for (const jsonPath of field.path) {
      if (typeof jsonPath !== 'string' || !jsonPath.startsWith(SUBJECT_PATH_PREFIX)) continue;
      const path = jsonPath.slice(SUBJECT_PATH_PREFIX.length);
      if (path.length === 0 || seen.has(path)) continue;
      seen.add(path);
      requests.push({ path, requirement, ...(purpose ? { purpose } : {}) });
    }
  }

  return requests;
}

/**
 * The JSONPath a Presentation Exchange field uses to name a subject claim.
 *
 * The inverse of {@link claimRequestsFromInputDescriptor}'s path handling, kept
 * beside it so the two cannot drift into disagreeing about the prefix.
 */
export function subjectClaimJsonPath(path: string): string {
  return `${SUBJECT_PATH_PREFIX}${path}`;
}

/**
 * Extract the claim requirements from a parsed OID4VP authorization request.
 *
 * DEFENSIVE BY NECESSITY. The SDK's `parsePresentationRequestAsync` returns
 * `parsed as PresentationRequest`, and `PresentationRequest` does not declare
 * `presentation_definition` at all — but the object it returns at runtime is the
 * raw authorization request, which does carry one. That is precisely the
 * type-says-one-thing/runtime-says-another shape that has produced silent
 * `undefined` reads in this codebase before, so every level here is checked
 * rather than asserted, and an unrecognised shape yields NO requirements.
 *
 * WHY "NO REQUIREMENTS" IS THE SAFE FAILURE. With no stated requirements,
 * {@link buildDisclosureChoices} pre-selects NOTHING, and the holder must
 * deliberately choose every claim they disclose. A verifier whose request we
 * could not read therefore gets the minimum rather than the maximum. The
 * alternative default — "unreadable request, so disclose everything" — would
 * make a malformed or hostile request the most effective way to extract a full
 * credential, which inverts the entire property this module exists to provide.
 *
 * @param credentialType when given, only descriptors constraining `$.type` to
 *   this type contribute. Credo 0.6 carries exactly ONE credential per v2
 *   presentation, so the sheet describes one credential and must not show
 *   requirements belonging to a different one in the same request.
 */
export function claimRequestsFromPresentationRequest(
  request: unknown,
  credentialType?: string,
): VerifierClaimRequest[] {
  if (!isPlainObject(request)) return [];

  const definition =
    (isPlainObject(request.presentation_definition) && request.presentation_definition) ||
    (isPlainObject(request.definition) && request.definition) ||
    request;

  if (!isPlainObject(definition) || !Array.isArray(definition.input_descriptors)) return [];

  const requests: VerifierClaimRequest[] = [];
  const seen = new Set<string>();

  for (const descriptor of definition.input_descriptors) {
    if (credentialType && !descriptorMatchesType(descriptor, credentialType)) continue;
    for (const request_ of claimRequestsFromInputDescriptor(descriptor)) {
      if (seen.has(request_.path)) continue;
      seen.add(request_.path);
      requests.push(request_);
    }
  }

  return requests;
}

/**
 * Does this descriptor constrain `$.type` to the given credential type?
 *
 * A descriptor with NO type constraint matches anything, which is the correct
 * reading of Presentation Exchange: an unconstrained descriptor is satisfiable
 * by any credential, so its claim requirements apply to the one in hand.
 */
function descriptorMatchesType(descriptor: unknown, credentialType: string): boolean {
  if (!isPlainObject(descriptor)) return false;
  const constraints = descriptor.constraints;
  if (!isPlainObject(constraints) || !Array.isArray(constraints.fields)) return true;

  let sawTypeConstraint = false;
  for (const field of constraints.fields) {
    if (!isPlainObject(field) || !Array.isArray(field.path)) continue;
    if (!field.path.includes('$.type')) continue;
    sawTypeConstraint = true;
    const filter = field.filter;
    if (!isPlainObject(filter)) continue;
    const contains = filter.contains;
    if (!isPlainObject(contains)) continue;

    // `const` names ONE acceptable type; `enum` names several. Both are valid
    // JSON Schema and both appear in real presentation definitions — a verifier
    // that accepts "a health card OR a professional licence" has to write the
    // enum form, because Presentation Exchange treats two input descriptors as
    // BOTH-required unless submission_requirements say otherwise.
    //
    // Only `const` was read. The consequence was silent and pointed the wrong
    // way: an enum descriptor set sawTypeConstraint and then matched nothing,
    // so the descriptor was SKIPPED and its claim requests never reached the
    // disclosure sheet. The holder was shown a request for a credential with no
    // claims attached, disclosed nothing — correctly, since the sheet defaults
    // to the minimum (#224) — and the verifier then refused the login for
    // claims it had, as far as the wallet could tell, never asked for.
    if (contains.const === credentialType) return true;
    if (Array.isArray(contains.enum) && contains.enum.includes(credentialType)) return true;
  }

  return !sawTypeConstraint;
}
