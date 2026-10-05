/**
 * SSI Healthcare Backend - SD-JWT Securing Mechanism (VC 2.0)
 *
 * The selective-disclosure counterpart of `jwtVc.ts`. Same data model
 * (`W3cV2Credential`), same holder binding (`cnf`), same revocation
 * (BitstringStatusList) — a different securing mechanism, per VC 2.0's
 * separation of the credential from the proof that secures it.
 *
 * ===========================================================================
 * THE CENTRAL WARNING: `isValid` FROM CREDO IS NOT AN AUTHORIZATION DECISION
 * ===========================================================================
 * `W3cV2SdJwtCredentialService.verifyPresentation` is a SIGNATURE AND DIGEST
 * CHECK. It is not a complete verification, and two of the things it omits are
 * exploitable. Both were demonstrated against Credo 0.6.3 with real did:cheqd
 * identities on this project's own ledger — measured, not inferred from source:
 *
 *   HOLE 1 — REPLAY. `verifyPresentation` never reads `options.challenge` or
 *     `options.domain`. A presentation signed over nonce A for audience
 *     `hospital-a` returned `isValid: true` when the verifier asked for a
 *     different nonce and audience `pharmacy-b`. Every captured presentation is
 *     therefore replayable, forever, against any verifier.
 *
 *   HOLE 2 — THEFT. Nothing anywhere compares the credential's `cnf` — the
 *     holder binding the issuer signed — to the party that actually signed the
 *     presentation. Credo's nearest check, `credentialSubjectAuthentication`,
 *     compares `credentialSubject.id` to the signer and is SKIPPED ENTIRELY
 *     when no subject id is disclosed. With a disclosable `id` withheld, an
 *     attacker wrapped a captured credential in their own presentation under
 *     their own DID, signed with their own key, and got `isValid: true`.
 *
 *   HOLE 3 — UNMATCHED DISCLOSURES. A disclosure whose digest does not match
 *     anything the issuer signed is silently DROPPED rather than rejected, and
 *     the presentation still reports `isValid: true`. No claim is forged — the
 *     digest is what makes forgery impossible — but an attacker gets to delete
 *     chosen claims from an otherwise genuine credential while it continues to
 *     verify. RFC 9807 §7.3 requires rejection.
 *
 *   HOLE 4 — KEY-BINDING JWTs ARE PARSED AND NEVER VERIFIED. Credo reaches
 *     `@sd-jwt/core`'s `verify(encoded, { skewSeconds })`, and that function
 *     returns BEFORE touching the key binding unless `keyBindingNonce` is
 *     passed — which Credo never passes, in either `verifyCredential` or
 *     `verifyPresentation`. So a compact SD-JWT carrying a KB-JWT with a
 *     garbage signature, a wrong `sd_hash`, a stale `nonce` or someone else's
 *     audience verifies exactly as if the KB-JWT were absent. Credo does build
 *     a `kbVerifier` from the holder binding, which makes the omission look
 *     closed from the outside; the verifier is simply never invoked. This one
 *     is inert TODAY only because Credo's own `vp+sd-jwt` signer never attaches
 *     a KB-JWT, so nothing in this system emits one — but Credo's PARSER
 *     accepts one happily (measured: `fromCompact` round-trips it and exposes
 *     `sdJwt.kbJwt`), which means any non-Credo wallet, and R5 Phase B's
 *     device-side signing, can put one on the wire tomorrow. See
 *     {@link verifyKeyBinding}.
 *
 * Note the asymmetry: the JWT sibling `W3cV2JwtCredentialService` DOES compare
 * nonce against challenge and aud against domain. So this is a gap between two
 * securing mechanisms rather than a deliberate design, and a future Credo
 * version may well close it. The checks below are written to AGREE with that
 * future rather than conflict with it — they assert the same equalities Credo
 * would, so a Credo that starts enforcing them changes nothing here.
 *
 * These checks live in our code, not in a patch to `node_modules`. This project
 * does patch dependencies where there is no alternative (see `patches/`), but a
 * security check we own belongs where it is greppable, reviewable, and cannot
 * be quietly dropped by an upgrade that changes Credo's internals.
 *
 * ===========================================================================
 * CLAIMS COME FROM `prettyClaims`, NEVER FROM THE DISCLOSURE LIST
 * ===========================================================================
 * A tampered disclosure does not forge a claim — its digest stops matching, so
 * `getClaimsSync` drops it — but Credo still returns `isValid: true` for the
 * presentation carrying it. The safe reading is therefore available only from
 * `prettyClaims`, which contains exactly the disclosures whose digests matched.
 *
 * This module is the only place that reads either, and it exposes no accessor
 * for the raw disclosure list at all. Callers receive already-resolved claims
 * from {@link verifySdJwtPresentation} and {@link sdJwtVcToW3cJson}; there is
 * no supported way to reach the unverified list, which is the point.
 */

import {
  W3cV2SdJwtVerifiableCredential,
  W3cV2SdJwtVerifiablePresentation,
  W3cV2SdJwtCredentialService,
  W3cV2EnvelopedVerifiableCredential,
  W3cV2Presentation,
  W3cV2Credential,
  ClaimFormat,
  Hasher,
  TypedArrayEncoder,
  Kms,
  getPublicJwkFromVerificationMethod,
  type Agent,
  type IDisclosureFrame,
} from '@credo-ts/core';
import {
  CREDENTIAL_FORMATS,
  PRESENTATION_FORMATS,
  type CredentialFormat,
  type VerifiableCredential,
  type SdJwtDisclosureFrame,
  type SdJwtPresentationFrame,
} from '@ssi-healthcare/shared';
// `export … from` does not bind locally, so the symbols this module USES are
// imported as well as re-exported below.
import {
  SD_SEPARATOR,
  credentialClaimsOf,
  didOf,
  looksLikeSdJwt,
  splitSdJwtCompact,
} from '@ssi-healthcare/sdk/verify';
import { logger } from '../utils/logger.js';

/**
 * The wire format, read by the SDK.
 *
 * THESE WERE DECLARED HERE UNTIL #341's DRIFT WAS PAID DOWN. `didOf` was
 * byte-identical to the SDK verifier's copy, the fourteen envelope claims were a
 * hand-kept mirror of it (the SDK copy said so in its own comment), and the
 * positional `~` split existed twice in two shapes. None of it is verification
 * logic, so consolidating it flattens nothing — the two verifiers still make
 * different checks and still reach their verdicts independently. What they no
 * longer do is disagree by accident about how to take an artifact apart.
 *
 * Re-exported under exactly the names this module has always published, so no
 * call site or test changed. See `@ssi-healthcare/sdk/verify`'s `sdJwtWire.ts`
 * for what is deliberately NOT shared — the key-binding parser below stays here,
 * because the backend VERIFIES a KB-JWT and the SDK REFUSES one.
 */
export {
  SD_JWT_MEDIA_TYPE,
  VC_SD_JWT_TYP,
  VP_SD_JWT_TYP,
  didOf,
  envelopedCredentialToSdJwt,
  looksLikeSdJwt,
  splitSdJwtCompact,
} from '@ssi-healthcare/sdk/verify';
export type { SdJwtCompactParts } from '@ssi-healthcare/sdk/verify';

/** `typ` header of a key-binding JWT (RFC 9807 §4.3). */
export const KB_JWT_TYP = 'kb+jwt';

/** A key-binding JWT taken apart, with the bytes its signature is over. */
export interface ParsedKeyBindingJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** Base64url signature, as it appears on the wire. */
  signature: string;
  /** `<header>.<payload>` — exactly the bytes that were signed. */
  signingInput: string;
}

/**
 * Read the key-binding slot, or refuse it.
 *
 * STRUCTURE IS THE ONLY THING THAT DISTINGUISHES A KB-JWT FROM AN INJECTED
 * DISCLOSURE, and this is where that distinction is made. The trailing slot is
 * the key-binding position by definition, so an attacker who appends a
 * disclosure without a trailing `~` lands it there — and if the slot were
 * merely "skipped when non-empty", that append would buy them exactly the RFC
 * 9807 §7.3 exemption the disclosure check exists to deny. So a non-empty slot
 * must be a well-formed KB-JWT: three segments, decodable JSON header and
 * payload, `typ: kb+jwt`, and an `alg` that is not `none`. Anything else
 * returns `null` and the caller REJECTS the artifact.
 *
 * This says nothing about whether the KB-JWT is genuine — see
 * {@link verifyKeyBinding}.
 */
export function parseKeyBindingJwt(slot: string): ParsedKeyBindingJwt | null {
  const parts = slot.split('.');
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, signature] = parts as [string, string, string];
  if (signature.length === 0) return null;

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!header || typeof header !== 'object' || Array.isArray(header)) return null;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  if (header.typ !== KB_JWT_TYP) return null;
  if (typeof header.alg !== 'string' || header.alg.length === 0 || header.alg === 'none') {
    return null;
  }

  return { header, payload, signature, signingInput: `${encodedHeader}.${encodedPayload}` };
}

/**
 * Decide the securing mechanism of a stored row.
 *
 * Prefers the recorded format and falls back to structure only when the row
 * predates the column. Returns `null` for a row with no envelope at all, which
 * is a legacy VC 1.1 credential carrying an embedded `JwtProof2020`.
 */
export function credentialEnvelopeFormat(row: {
  credentialJwt?: string | null;
  credentialFormat?: string | null;
}): CredentialFormat | null {
  if (row.credentialFormat) return row.credentialFormat as CredentialFormat;
  if (typeof row.credentialJwt === 'string' && row.credentialJwt.length > 0) {
    return looksLikeSdJwt(row.credentialJwt)
      ? CREDENTIAL_FORMATS.SD_JWT_VC
      : CREDENTIAL_FORMATS.VC_JWT;
  }
  return null;
}

/**
 * Wrap a compact SD-JWT in the Credo class its v2 API insists on.
 *
 * The same runtime-only mismatch documented in `jwtVc.ts` applies: the v2
 * dispatcher branches on `instanceof` and rejects a string that typechecks
 * perfectly against its `unknown`-typed options.
 *
 * Returns `null` rather than throwing so a caller can record a verification
 * failure instead of a 500.
 */
export function toV2SdJwtVerifiableCredential(
  compact: string,
): W3cV2SdJwtVerifiableCredential | null {
  try {
    return W3cV2SdJwtVerifiableCredential.fromCompact(compact);
  } catch (error) {
    logger.warn('Compact string could not be read as a VC 2.0 SD-JWT credential', {
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

/** The presentation counterpart of {@link toV2SdJwtVerifiableCredential}. */
export function toV2SdJwtVerifiablePresentation(
  compact: string,
): W3cV2SdJwtVerifiablePresentation | null {
  try {
    return W3cV2SdJwtVerifiablePresentation.fromCompact(compact);
  } catch (error) {
    logger.warn('Compact string could not be read as a VC 2.0 SD-JWT presentation', {
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

/**
 * Decode a compact SD-JWT into the W3C JSON of the claims IT ACTUALLY
 * DISCLOSES.
 *
 * Reads `prettyClaims` — never the disclosure list — so the result contains
 * exactly those claims whose digests matched the issuer's signed commitments.
 * Withheld claims are absent, not blank: there is no key for them at all.
 *
 * Returns `null` for anything that is not a readable SD-JWT credential, so one
 * bad row cannot fail a whole wallet listing.
 */
export function sdJwtVcToW3cJson(compact: string): VerifiableCredential | null {
  const credential = toV2SdJwtVerifiableCredential(compact);
  if (!credential) return null;

  // `prettyClaims` is Credo's resolution of the disclosures; stripping the
  // envelope's own claims from it is the step the SDK verifier also performs,
  // and it is shared so the two cannot disagree about which claims those are.
  const result = credentialClaimsOf(credential.sdJwt.prettyClaims as Record<string, unknown>);

  // Same fail-loud contract as the JWT decoder: a credential missing either of
  // these is not a credential, and returning a husk is how empty rows got
  // persisted for months before the v2 migration.
  const context = result['@context'];
  if (!Array.isArray(context) || context.length === 0) {
    logger.error('SD-JWT payload has no @context — refusing to decode', {
      prefix: compact.slice(0, 16),
    });
    return null;
  }
  if (!result.credentialSubject || typeof result.credentialSubject !== 'object') {
    logger.error('SD-JWT payload has no credentialSubject — refusing to decode', {
      prefix: compact.slice(0, 16),
    });
    return null;
  }

  // No `proof` member, for the same reason as `vc+jwt`: this is an ENVELOPING
  // proof, and writing it into `proof.jwt` would claim an embedded proof the
  // credential does not have. The envelope travels alongside, in the
  // `credentialJwt` column and `WalletCredential.credentialJwt`.
  return result as unknown as VerifiableCredential;
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/**
 * Options for securing a credential with SD-JWT.
 *
 * `holder` is the SAME binding `resolveHolderBinding` in `jwtVc.ts` produces
 * for the JWT path, deliberately: SD-JWT's `SdJwtVcHolderBinding` and the JWT
 * path's `holder` option are the same `cnf` concept, and having two ways to
 * decide who a credential is bound to is how the two issuance paths drifted
 * apart before. There is one resolver and one fail-closed policy; this is just
 * another consumer of them.
 */
export interface SignSdJwtCredentialOptions {
  credential: W3cV2Credential;
  verificationMethod: string;
  holder: { method: 'did'; didUrl: string };
  disclosureFrame: SdJwtDisclosureFrame | undefined;
}

/**
 * Sign a credential as `vc+sd-jwt`.
 *
 * Thin by design: the interesting decisions (which claims are disclosable, who
 * the credential is bound to) are made by the policy module and the holder
 * binding resolver respectively, and arrive here already settled.
 *
 * THE CAST ON `disclosureFrame` IS LOAD BEARING, NOT COSMETIC. Credo types
 * `IDisclosureFrame._sd` as `string[]`. The runtime underneath it — the
 * `@sd-jwt/core` frame walker — requires NUMBERS for array element indices and
 * silently ignores string ones, emitting the whole array in cleartext. So the
 * declared type and the working values disagree, and obeying the type produces
 * a credential that leaks. Measured: a frame of `{ _sd: ['0','1','2'] }` over a
 * three-element medication list disclosed all three when the holder asked for
 * one; `{ _sd: [0,1,2] }` disclosed exactly one. The policy module emits
 * numbers on purpose and this cast is what lets them through.
 */
export async function signSdJwtCredential(
  agent: Agent,
  options: SignSdJwtCredentialOptions,
): Promise<W3cV2SdJwtVerifiableCredential> {
  return agent.w3cV2Credentials.signCredential<ClaimFormat.SdJwtW3cVc>({
    format: ClaimFormat.SdJwtW3cVc,
    credential: options.credential,
    verificationMethod: options.verificationMethod,
    alg: 'EdDSA',
    holder: options.holder,
    // `undefined` means "nothing is selectively disclosable", which is the
    // correct reading when the policy found no eligible claim. Substituting an
    // empty object would be a different, meaningless instruction.
    ...(options.disclosureFrame
      ? { disclosureFrame: options.disclosureFrame as unknown as IDisclosureFrame }
      : {}),
  });
}

/**
 * The issuer-signed `credentialSubject`, as it appears BEFORE any disclosure is
 * applied.
 *
 * This — not `prettyClaims` — is what the policy self-check must inspect. It is
 * the view a verifier gets when the holder discloses nothing, so it is where a
 * frame that failed to take effect shows up as patient data in cleartext.
 */
export function issuerSignedCredentialSubject(
  credential: W3cV2SdJwtVerifiableCredential,
): unknown {
  return (credential.sdJwt.payload as Record<string, unknown>).credentialSubject;
}

// ---------------------------------------------------------------------------
// Holder side
// ---------------------------------------------------------------------------

/**
 * A holder's choice of what to reveal.
 *
 * Re-exported from the shared policy module rather than declared here, so the
 * two frames a holder deals with have ONE definition each. Build these with
 * `buildPresentationFrame` / `presentationFrameForChoices` — a frame assembled
 * at a call site is a frame nobody reviews, and the measured semantics it has
 * to respect (naming a container alone discloses it EMPTY) are documented
 * there, not here.
 */
export type { SdJwtPresentationFrame } from '@ssi-healthcare/shared';

/**
 * Apply a presentation frame, producing a credential that carries ONLY the
 * chosen disclosures.
 *
 * The withheld claims are not hidden from a display path — they are removed
 * from the artifact. What remains is the issuer's original signature over the
 * `_sd` digests, plus the disclosures the holder chose to keep. Nothing in the
 * result lets a verifier recover the rest, because the preimages are gone.
 *
 * Passing `true` discloses everything, for a verifier that legitimately
 * requires the whole credential.
 *
 * `true` IS TRANSLATED TO `undefined`, NOT PASSED THROUGH. Measured (R4): a
 * literal `true` reaches `@sd-jwt/core` as a frame with no keys and discloses
 * NOTHING — the result carries only the mandatory `credentialSubject.id` and
 * every other claim is dropped. That is the opposite of what this parameter
 * says it does, and it fails silently: the verifier receives a well-formed,
 * correctly-signed credential that simply asserts nothing. `undefined` is the
 * library's actual "disclose everything". No production caller had ever passed
 * `true`, which is why the divergence survived.
 */
export async function presentSdJwtCredential(
  agent: Agent,
  compactOrCredential: string | W3cV2SdJwtVerifiableCredential,
  presentationFrame: SdJwtPresentationFrame | true,
): Promise<W3cV2SdJwtVerifiableCredential> {
  const service = agent.dependencyManager.resolve(W3cV2SdJwtCredentialService);
  return service.present(agent.context, {
    credential: compactOrCredential,
    presentationFrame: (presentationFrame === true ? undefined : presentationFrame) as never,
  });
}

/**
 * Build and sign a `vp+sd-jwt` presentation around one disclosed credential.
 *
 * ONE CREDENTIAL, NOT MANY: Credo 0.6's
 * `extractHolderFromPresentationCredentials` throws on any presentation
 * carrying a number of credentials other than exactly one. That is a hard
 * constraint of the library, not a choice made here, and it applies equally to
 * the JWT path.
 *
 * The signing key is derived from the credential's own `cnf`, so this cannot
 * produce a presentation the holder is not entitled to make — the key has to be
 * in the wallet for signing to succeed at all.
 */
export async function signSdJwtPresentation(
  agent: Agent,
  options: {
    holderDid: string;
    credential: W3cV2SdJwtVerifiableCredential;
    challenge: string;
    domain?: string;
  },
): Promise<W3cV2SdJwtVerifiablePresentation> {
  const presentation = new W3cV2Presentation({
    holder: options.holderDid,
    verifiableCredential: [
      W3cV2EnvelopedVerifiableCredential.fromVerifiableCredential(options.credential),
    ],
  });

  return agent.w3cV2Credentials.signPresentation<ClaimFormat.SdJwtW3cVp>({
    format: ClaimFormat.SdJwtW3cVp,
    presentation,
    challenge: options.challenge,
    ...(options.domain ? { domain: options.domain } : {}),
  });
}

// ---------------------------------------------------------------------------
// Verification — the hardened boundary
// ---------------------------------------------------------------------------

/** One credential pulled out of a verified presentation. */
export interface PresentedSdJwtCredential {
  /**
   * The disclosed claims as W3C JSON, resolved from `prettyClaims`. Withheld
   * claims are absent from this object entirely.
   */
  credential: VerifiableCredential;
  /** The compact SD-JWT that secures it, for downstream revocation checks. */
  envelope: string;
  /** The holder binding the issuer signed into the credential. */
  cnfKeyId: string | null;
}

export interface SdJwtPresentationChecks {
  /** Credo's own verdict: issuer signature, holder signature, digests. */
  signatures: boolean;
  /** Every disclosure carried resolves to a digest the issuer signed. */
  disclosureIntegrity: boolean;
  /** VP `nonce` equals the challenge this verifier issued. Closes HOLE 1. */
  challenge: boolean;
  /** VP `aud` includes the expected domain. Closes HOLE 1. */
  domain: boolean;
  /** Credential `cnf` names the key that signed the VP. Closes HOLE 2. */
  holderBinding: boolean;
  /**
   * Every key-binding JWT carried is genuine. Closes HOLE 4.
   *
   * TRUE WHEN NOTHING CARRIED A KB-JWT, which is every presentation Credo 0.6
   * can produce. That is not a skipped check: `holderBinding` above is the
   * unconditional possession proof, and it does not depend on this one. When a
   * KB-JWT IS present it must verify in full — see {@link verifyKeyBinding}.
   */
  keyBinding: boolean;
}

export interface SdJwtPresentationVerification {
  isValid: boolean;
  errors: string[];
  checks: SdJwtPresentationChecks;
  /** Empty unless every check passed — see {@link verifySdJwtPresentation}. */
  credentials: PresentedSdJwtCredential[];
}

/**
 * Every disclosure attached to an SD-JWT must correspond to a digest the issuer
 * actually signed.
 *
 * WHY THIS IS A SEPARATE CHECK. A tampered disclosure does not forge a claim:
 * its digest stops matching, so `getClaimsSync` drops it and the claim simply
 * disappears. But NOTHING REPORTS THAT. Credo returns `isValid: true` for a
 * presentation carrying a disclosure that resolves to nothing — measured — so a
 * verifier that asked for `hivStatus` receives a "valid" presentation in which
 * `hivStatus` is silently missing, and an attacker gets to choose which claims
 * vanish from an otherwise genuine credential.
 *
 * Dropping a claim is much less bad than forging one, but it is not nothing:
 * "valid presentation, claim absent" and "valid presentation, claim withheld by
 * the holder" become indistinguishable, and any verifier logic that treats an
 * absent claim as a default rather than a refusal is now attacker-controlled.
 *
 * RFC 9807 (SD-JWT) §7.3 requires a verifier to reject a presentation carrying
 * a disclosure it cannot match to a digest, so this is conformance rather than
 * a house rule.
 *
 * The digest of a disclosure is the hash of its base64url ENCODED form, exactly
 * as it appears on the wire — not of the decoded JSON. Legitimate digests live
 * in `_sd` arrays and, for array elements, in `{"...": digest}` entries; both
 * may appear inside a disclosure's own value when containers nest, so the
 * search covers the payload and every disclosure's decoded value.
 *
 * THE KEY-BINDING SLOT IS NOT ONE OF THE DISCLOSURES, and excluding it is not a
 * relaxation. Everything the artifact carries is still accounted for: a
 * disclosure must match a committed digest, and the trailing slot must be
 * either empty or a well-formed KB-JWT. Nothing appended to the wire can end up
 * unexamined, which is the property §7.3 is asking for. Whether a well-formed
 * KB-JWT is GENUINE is a signature question and belongs to
 * {@link verifyKeyBinding}; this function is pure and cannot answer it.
 */
export function assertDisclosuresResolve(compact: string): string[] {
  const errors: string[] = [];
  const { issuerJwt, disclosures: encodedDisclosures, keyBindingJwt } =
    splitSdJwtCompact(compact);

  // The trailing slot is the key-binding position whatever it contains, so a
  // non-KB-JWT sitting there is an injected segment claiming an exemption it is
  // not entitled to. Refuse before anything else — this is what stops KB
  // support from being a way around the digest check below.
  if (keyBindingJwt.length > 0 && !parseKeyBindingJwt(keyBindingJwt)) {
    errors.push(
      'Presentation carries a trailing segment that is neither absent nor a key-binding JWT',
    );
  }

  if (encodedDisclosures.length === 0) return errors;

  // The issuer names the digest algorithm in the payload. Honour it rather than
  // assuming sha-256: a credential using sha-512 would otherwise have every
  // disclosure declared unmatched and be rejected wholesale.
  let payload: Record<string, unknown>;
  try {
    const raw = issuerJwt.split('.')[1]!;
    payload = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    errors.push('SD-JWT payload could not be read to validate disclosures');
    return errors;
  }
  const alg = typeof payload._sd_alg === 'string' ? payload._sd_alg : 'sha-256';

  // Collect every digest the issuer committed to, wherever it appears.
  const committed = new Set<string>();
  const collect = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) collect(item);
      return;
    }
    if (!node || typeof node !== 'object') return;
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (key === '_sd' && Array.isArray(value)) {
        for (const digest of value) if (typeof digest === 'string') committed.add(digest);
        continue;
      }
      // Array element digests use the reserved `...` key.
      if (key === '...' && typeof value === 'string') {
        committed.add(value);
        continue;
      }
      collect(value);
    }
  };
  collect(payload);

  const decoded: unknown[] = [];
  for (const encoded of encodedDisclosures) {
    try {
      decoded.push(JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')));
    } catch {
      errors.push('Presentation carries a disclosure that is not decodable');
    }
  }
  // A container disclosure's value legitimately carries the digests of its own
  // members, which are not reachable from the payload until it is resolved.
  collect(decoded);

  for (const encoded of encodedDisclosures) {
    const digest = TypedArrayEncoder.toBase64URL(Hasher.hash(TypedArrayEncoder.fromString(encoded), alg));
    if (!committed.has(digest)) {
      errors.push(
        'Presentation carries a disclosure the issuer never committed to — it has been tampered with or injected',
      );
    }
  }

  return errors;
}

/**
 * Verify the key-binding JWT an artifact carries — or establish that it carries
 * none.
 *
 * WHY THIS EXISTS RATHER THAN A SKIP. HOLE 4: Credo parses a KB-JWT and never
 * checks it, so "the KB-JWT slot is excused from the disclosure check" on its
 * own would leave a signed-looking possession proof that nothing in the stack
 * ever validates. An unverified KB-JWT that parses is worse than one that fails
 * to parse, because it reads as a second factor and is not one. So the slot is
 * either empty, or it is verified here in full.
 *
 * WHAT IS CHECKED, all of it fail-closed:
 *   - `sd_hash` covers THIS artifact — the issuer JWT, these disclosures, and
 *     the trailing `~`, which is exactly the byte range RFC 9807 §4.3 names and
 *     exactly what `@sd-jwt/core`'s `calculateSDHash` hashes. This is what stops
 *     a KB-JWT being lifted off one presentation and stapled onto another, or
 *     surviving the removal of a disclosure.
 *   - `nonce` equals the challenge THIS verifier issued.
 *   - `aud` equals the domain this verifier stated.
 *   - the signature verifies under the key the ISSUER bound the credential to
 *     (`cnf`), resolved from the ledger — not under any key the presentation
 *     nominates for itself, which would be circular.
 *
 * A KB-JWT WITH NO STATED AUDIENCE TO CHECK IT AGAINST IS REFUSED. `domain` is
 * optional elsewhere in this module because a verifier may legitimately decline
 * to name itself; but a holder that minted a possession proof named an audience
 * on purpose, and accepting it without reading that name re-opens across
 * verifiers the replay the nonce closes within one. If a caller wants key
 * binding, it has to say who it is.
 *
 * Returns an empty array when the artifact carries no key binding. Absence is
 * not an error HERE — the unconditional `cnf`-vs-signer check in
 * {@link verifySdJwtPresentation} is what proves possession today, and demanding
 * a KB-JWT would reject every presentation Credo 0.6 can currently produce.
 * Requiring one is a policy the caller can add on top; forging one is not.
 */
export async function verifyKeyBinding(
  agent: Agent,
  options: {
    /** The compact artifact whose trailing slot is under examination. */
    compact: string;
    /** The DID URL the issuer bound the credential to. */
    boundKeyId: string | null;
    challenge: string;
    domain: string | undefined;
    /** Names the artifact in error messages: `presentation` or `credential`. */
    artifact: string;
  },
): Promise<string[]> {
  const { issuerJwt, disclosures, keyBindingJwt } = splitSdJwtCompact(options.compact);
  if (keyBindingJwt.length === 0) return [];

  const errors: string[] = [];
  const parsed = parseKeyBindingJwt(keyBindingJwt);
  if (!parsed) {
    // `assertDisclosuresResolve` reports this too; both paths must refuse
    // independently, because a later phase re-establishing its own precondition
    // is the only kind of failsafe that composes.
    return [`Presented ${options.artifact} carries a malformed key-binding JWT`];
  }

  // --------------------------------------------------------------- sd_hash
  let alg = 'sha-256';
  try {
    const issuerPayload = JSON.parse(
      Buffer.from(issuerJwt.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    if (typeof issuerPayload._sd_alg === 'string') alg = issuerPayload._sd_alg;
  } catch {
    return [
      `Presented ${options.artifact} payload could not be read to check its key-binding JWT`,
    ];
  }

  // The trailing '' rebuilds the final `~`, which RFC 9807 4.3 includes in the
  // covered range. SD_SEPARATOR comes from the vendored library rather than a
  // local literal, so this hashes the same bytes the encoder wrote.
  const covered = [issuerJwt, ...disclosures, ''].join(SD_SEPARATOR);
  const expectedSdHash = TypedArrayEncoder.toBase64URL(
    Hasher.hash(TypedArrayEncoder.fromString(covered), alg),
  );
  const sdHash = parsed.payload.sd_hash;
  if (typeof sdHash !== 'string' || sdHash !== expectedSdHash) {
    errors.push(
      `Key-binding JWT on the ${options.artifact} does not cover the artifact it arrived on — it has been moved from another presentation or the disclosures were altered after it was signed`,
    );
  }

  // ---------------------------------------------------------------- nonce
  if (parsed.payload.nonce !== options.challenge) {
    errors.push(
      `Key-binding JWT on the ${options.artifact} was minted for a different challenge`,
    );
  }

  // ------------------------------------------------------------------ aud
  if (!options.domain) {
    errors.push(
      `Presented ${options.artifact} carries a key-binding JWT, but this verifier stated no domain to check its audience against`,
    );
  } else {
    const aud = parsed.payload.aud;
    const audiences = Array.isArray(aud) ? aud : aud === undefined ? [] : [aud];
    if (!audiences.includes(options.domain)) {
      errors.push(
        `Key-binding JWT on the ${options.artifact} names a different audience than this verifier ('${options.domain}')`,
      );
    }
  }

  // ------------------------------------------------------------ signature
  if (!options.boundKeyId) {
    errors.push(
      `Presented ${options.artifact} carries a key-binding JWT but names no key it should be signed by`,
    );
    return errors;
  }

  try {
    const verificationMethod = (await agent.dids.resolveDidDocument(options.boundKeyId))
      .dereferenceKey(options.boundKeyId, ['authentication', 'assertionMethod']);
    const publicJwk = getPublicJwkFromVerificationMethod(verificationMethod);
    const kms = agent.dependencyManager.resolve(Kms.KeyManagementApi);
    const { verified } = await kms.verify({
      key: { publicJwk: publicJwk.toJson() },
      data: TypedArrayEncoder.fromString(parsed.signingInput),
      signature: TypedArrayEncoder.fromBase64(parsed.signature),
      algorithm: publicJwk.signatureAlgorithm,
    });
    if (!verified) {
      errors.push(
        `Key-binding JWT on the ${options.artifact} is not signed by the key the credential is bound to ('${options.boundKeyId}')`,
      );
    }
  } catch (error) {
    // Resolution or KMS failure is not evidence of a valid signature.
    errors.push(
      `Key-binding JWT on the ${options.artifact} could not be checked against '${
        options.boundKeyId
      }': ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  return errors;
}

/**
 * Normalise a JOSE `kid` to an absolute DID URL.
 *
 * A `kid` may legitimately be a relative fragment (`#key-1`), in which case the
 * DID it belongs to comes from the presentation's holder. Comparing a relative
 * `kid` against an absolute `cnf.kid` as plain strings would fail every honest
 * presentation that used the relative form, so normalise before comparing
 * rather than after discovering the mismatch.
 */
function absoluteKeyId(kid: string | undefined, subjectDid: string | undefined): string | null {
  if (!kid) return null;
  if (kid.startsWith('#')) return subjectDid ? `${subjectDid}${kid}` : null;
  return kid.startsWith('did:') ? kid : null;
}

/**
 * Verify a `vp+sd-jwt` presentation, and do the two things Credo does not.
 *
 * FAIL CLOSED THROUGHOUT. Every check defaults to `false` and must be actively
 * satisfied; an absent `nonce`, an unreadable credential or a missing `cnf` is
 * a failure, never a skipped check. "There was nothing to check" is the shape
 * every fail-open bug in this codebase has taken, so it is not available here.
 *
 * `credentials` is populated only on full success. A caller that reads claims
 * out of a failed verification is a caller acting on unauthenticated data, and
 * the easiest way to make that impossible is to not hand the claims over.
 *
 * @param challenge the nonce THIS verifier generated for THIS exchange. It must
 *   come from verifier-side state (the `Presentation` row), never from the
 *   submission — comparing a presentation against a nonce it supplied itself is
 *   not a replay check.
 */
export async function verifySdJwtPresentation(
  agent: Agent,
  options: {
    presentation: string | W3cV2SdJwtVerifiablePresentation;
    challenge: string;
    domain?: string;
  },
): Promise<SdJwtPresentationVerification> {
  const errors: string[] = [];
  const checks: SdJwtPresentationChecks = {
    signatures: false,
    disclosureIntegrity: false,
    challenge: false,
    domain: false,
    holderBinding: false,
    keyBinding: false,
  };

  const presentation =
    typeof options.presentation === 'string'
      ? toV2SdJwtVerifiablePresentation(options.presentation)
      : options.presentation;

  if (!presentation) {
    errors.push('Presentation is not a readable vp+sd-jwt');
    return { isValid: false, errors, checks, credentials: [] };
  }

  // -------------------------------------------------------------- signatures
  // Credo's contribution: issuer signature on each credential, holder signature
  // on the presentation, and the digest match that ties disclosures to the
  // issuer's commitments. Necessary, and on its own not sufficient.
  try {
    const credoResult = await agent.w3cV2Credentials.verifyPresentation({
      presentation,
      challenge: options.challenge,
      ...(options.domain ? { domain: options.domain } : {}),
    });
    checks.signatures = credoResult.isValid;
    if (!credoResult.isValid) {
      errors.push('Presentation signature verification failed');
      const detail = collectCredoErrors(credoResult);
      if (detail.length > 0) errors.push(...detail);
    }
  } catch (error) {
    // An agent or resolver failure is not evidence of validity. Report it as a
    // verification failure rather than letting it fall through as a pass.
    errors.push(
      `Presentation signature verification unavailable: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return { isValid: false, errors, checks, credentials: [] };
  }

  const payload = presentation.sdJwt.payload as Record<string, unknown>;

  // ----------------------------------------------------- disclosure integrity
  // Applies to the presentation envelope AND to every credential inside it.
  // Credo checks neither: it drops unmatched disclosures and reports success.
  const disclosureErrors = assertDisclosuresResolve(presentation.encoded);
  for (const entry of asArray(presentation.resolvedPresentation.verifiableCredential)) {
    const enveloped = entry.envelopedCredential;
    if (enveloped instanceof W3cV2SdJwtVerifiableCredential) {
      disclosureErrors.push(...assertDisclosuresResolve(enveloped.encoded));
    }
  }
  if (disclosureErrors.length === 0) {
    checks.disclosureIntegrity = true;
  } else {
    errors.push(...new Set(disclosureErrors));
  }

  // --------------------------------------------------------------- challenge
  // HOLE 1. Credo's SD-JWT verifier accepts `challenge` and never reads it; the
  // JWT sibling compares it. We compare, which agrees with the JWT path today
  // and with any future Credo that closes the gap.
  const nonce = payload.nonce;
  if (typeof nonce !== 'string' || nonce.length === 0) {
    errors.push(
      'Presentation carries no nonce, so it cannot be bound to this verification request',
    );
  } else if (nonce !== options.challenge) {
    errors.push('Presentation nonce does not match the challenge issued for this request');
  } else {
    checks.challenge = true;
  }

  // ------------------------------------------------------------------ domain
  // Only meaningful when the verifier stated an audience. When it did, an
  // absent `aud` fails: a presentation that names no audience is one the holder
  // did not intend for us specifically, and accepting it re-opens the replay
  // path across verifiers that the nonce closes within one verifier.
  if (!options.domain) {
    checks.domain = true;
  } else {
    const aud = payload.aud;
    const audiences = Array.isArray(aud) ? aud : aud === undefined ? [] : [aud];
    if (audiences.includes(options.domain)) {
      checks.domain = true;
    } else {
      errors.push(
        `Presentation audience does not include this verifier ('${options.domain}')`,
      );
    }
  }

  // ----------------------------------------------------------- holder binding
  // HOLE 2. This is the check Credo does not perform anywhere, and the one that
  // stops a captured credential being re-presented by whoever captured it.
  //
  // UNCONDITIONAL, deliberately. Credo's `credentialSubjectAuthentication` does
  // something adjacent but skips itself when no `credentialSubject.id` is
  // disclosed, and the disclosure policy's decision to keep `id` mandatory is
  // what stops that skip from being reachable. Making this check depend on the
  // same condition would collapse two independent defences into one, so it does
  // not: the credential's `cnf` is compared to the presentation signer whether
  // or not any subject id is present.
  const proverKeyId = absoluteKeyId(
    presentation.sdJwt.header.kid as string | undefined,
    presentation.resolvedPresentation.holderId,
  );

  const presented: PresentedSdJwtCredential[] = [];
  const bindingErrors: string[] = [];

  const entries = asArray(presentation.resolvedPresentation.verifiableCredential);
  if (entries.length === 0) {
    bindingErrors.push('Presentation contains no credentials');
  }
  if (!proverKeyId) {
    bindingErrors.push(
      'Presentation does not name the key that signed it, so it cannot be bound to a holder',
    );
  }

  for (const entry of entries) {
    const enveloped = entry.envelopedCredential;
    if (!(enveloped instanceof W3cV2SdJwtVerifiableCredential)) {
      bindingErrors.push('Presentation carries a credential that is not vc+sd-jwt');
      continue;
    }

    const cnfKeyId = cnfKeyIdOf(enveloped);

    if (!cnfKeyId) {
      // An unbound credential is a bearer token. Issuance refuses to mint one
      // (see `assertHolderBound`), so this means the credential came from
      // elsewhere — and accepting it would mean accepting a credential anyone
      // in possession of can present.
      bindingErrors.push(
        'Credential carries no cnf holder binding, so possession of it proves nothing',
      );
      continue;
    }

    if (proverKeyId && cnfKeyId !== proverKeyId) {
      // Report the DID mismatch specifically when the DIDs differ at all: that
      // is theft, whereas a same-DID different-key mismatch is a holder using a
      // key the issuer did not commit to. Both are refused; the operator should
      // be able to tell them apart in the log.
      bindingErrors.push(
        didOf(cnfKeyId) === didOf(proverKeyId)
          ? `Presentation was signed with '${proverKeyId}', but the credential is bound to a different key of the same holder ('${cnfKeyId}')`
          : `Presentation was signed by '${didOf(proverKeyId)}', but the credential is bound to '${didOf(cnfKeyId)}'`,
      );
      continue;
    }

    const credential = sdJwtVcToW3cJson(enveloped.encoded);
    if (!credential) {
      bindingErrors.push('Presented credential could not be decoded');
      continue;
    }

    presented.push({ credential, envelope: enveloped.encoded, cnfKeyId });
  }

  if (bindingErrors.length === 0 && presented.length === entries.length && entries.length > 0) {
    checks.holderBinding = true;
  } else {
    errors.push(...bindingErrors);
  }

  // -------------------------------------------------------------- key binding
  // HOLE 4. Runs over the envelope AND every credential inside it, because
  // either level can carry a KB-JWT and Credo verifies neither. The key each
  // one must be signed by is the key the ISSUER named: the presentation's
  // signer for the envelope, the credential's own `cnf` for each credential.
  // `holderBinding` above has already required those to be the same key, so
  // this cannot be satisfied by a binding the presentation nominates for itself.
  const keyBindingErrors = await verifyKeyBinding(agent, {
    compact: presentation.encoded,
    boundKeyId: proverKeyId,
    challenge: options.challenge,
    domain: options.domain,
    artifact: 'presentation',
  });
  for (const entry of entries) {
    const enveloped = entry.envelopedCredential;
    if (!(enveloped instanceof W3cV2SdJwtVerifiableCredential)) continue;
    keyBindingErrors.push(
      ...(await verifyKeyBinding(agent, {
        compact: enveloped.encoded,
        boundKeyId: cnfKeyIdOf(enveloped),
        challenge: options.challenge,
        domain: options.domain,
        artifact: 'credential',
      })),
    );
  }
  if (keyBindingErrors.length === 0) {
    checks.keyBinding = true;
  } else {
    errors.push(...new Set(keyBindingErrors));
  }

  const isValid =
    checks.signatures &&
    checks.disclosureIntegrity &&
    checks.challenge &&
    checks.domain &&
    checks.holderBinding &&
    checks.keyBinding;

  if (!isValid) {
    logger.warn('SD-JWT presentation REJECTED', {
      checks,
      errors,
      proverKeyId,
    });
  } else {
    logger.info('SD-JWT presentation verified', {
      proverKeyId,
      credentialCount: presented.length,
      disclosedClaimCount: presented.map((p) =>
        Object.keys((p.credential.credentialSubject ?? {}) as Record<string, unknown>).length,
      ),
    });
  }

  // Claims are withheld from a caller unless everything passed. See the
  // docstring: handing back claims from a failed verification invites acting on
  // them.
  return { isValid, errors, checks, credentials: isValid ? presented : [] };
}

/** The holder binding the ISSUER signed into a credential, if it named one. */
function cnfKeyIdOf(credential: W3cV2SdJwtVerifiableCredential): string | null {
  const claims = credential.sdJwt.prettyClaims as Record<string, unknown>;
  const cnf = claims.cnf as { kid?: unknown } | undefined;
  return typeof cnf?.kid === 'string' ? cnf.kid : null;
}

function asArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

/** Flatten Credo's nested validation result into readable messages. */
function collectCredoErrors(result: unknown): string[] {
  const messages: string[] = [];

  const walk = (node: unknown): void => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    const record = node as Record<string, unknown>;
    if (record.error instanceof Error) messages.push(record.error.message);
    if (record.validations) walk(record.validations);
    for (const value of Object.values(record)) {
      if (value && typeof value === 'object' && 'isValid' in (value as object)) walk(value);
    }
  };

  walk(result);
  return [...new Set(messages)];
}

/** Media type of the presentation this module produces, for wire contracts. */
export const SD_JWT_PRESENTATION_FORMAT = PRESENTATION_FORMATS.VP_SD_JWT;
