/**
 * Professional accreditation — role is a credential, not a column.
 *
 * A self-declared group at onboarding is a UI routing hint. Professional
 * authority is asserted by a credential from an accrediting authority and
 * decided at presentation time, which is why nothing in this module reads a
 * database and nothing in it is mutable at runtime.
 *
 * ---------------------------------------------------------------------------
 * WHY THE TRUST ROOTS ARE A FROZEN LITERAL AND NOT A TABLE
 * ---------------------------------------------------------------------------
 * A trust root an attacker can INSERT into is not a trust root. The same
 * argument rules out discovering roots from the chain: the chain is the thing
 * whose contents we are trying to evaluate, so deriving the evaluation criteria
 * from it is circular. This is a CA root store and is defensible as one —
 * changing it is a code change, a review and a release, and that cost is the
 * feature (#214).
 *
 * ---------------------------------------------------------------------------
 * TWO TEMPORAL QUESTIONS, NEVER ONE BOOLEAN
 * ---------------------------------------------------------------------------
 *   1. Was the issuer authorised to accredit AT THE CREDENTIAL'S ISSUANCE TIME?
 *   2. Has the credential been revoked BY NOW?
 *
 * These come apart in exactly the case that matters. An authority that retires
 * keeps every licence it lawfully issued while it held the mandate; an
 * authority found to have been issuing fraudulently has its records revoked
 * retroactively. Collapsing them into one "is this issuer trusted" flag answers
 * the second question for both cases and gets the first one wrong. Question 1
 * lives here ({@link wasAuthorisedToAccredit}); question 2 is a status-list
 * lookup and lives at the verification boundary.
 */

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/** Regulated professions this system recognises. One accrediting body each. */
export const PROFESSIONS = ['doctor', 'nurse', 'pharmacist'] as const;

export type Profession = (typeof PROFESSIONS)[number];

/**
 * What a licence authorises its holder to do.
 *
 * Atoms, not levels. Delegation narrows scope by subset (#214), and a subset
 * check is only meaningful over a flat set — an ordered "seniority" would make
 * narrowing a comparison, which cannot express "may dispense but not prescribe".
 */
export const PRACTICE_SCOPES = [
  'view-patient-record',
  'write-patient-record',
  'prescribe',
  'dispense',
  'administer-medication',
  'order-diagnostic',
] as const;

export type PracticeScope = (typeof PRACTICE_SCOPES)[number];

export function isProfession(value: unknown): value is Profession {
  return typeof value === 'string' && (PROFESSIONS as readonly string[]).includes(value);
}

export function isPracticeScope(value: unknown): value is PracticeScope {
  return typeof value === 'string' && (PRACTICE_SCOPES as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// The credential
// ---------------------------------------------------------------------------

/** VC `type` member that marks a professional licence. */
export const PROFESSIONAL_LICENCE_CREDENTIAL_TYPE = 'ProfessionalLicenceCredential';

/**
 * The VC `type` of an EBSI-style accreditation — the credential by which one
 * authority delegates to another (#214).
 *
 * `...ToAccredit` rather than EBSI's `...ToAttest`, because the delegation this
 * system needs is "you may accredit others of this profession", which is the
 * accredit variant. A `...ToAttest` (a hospital may issue certificates, but may
 * not create further issuers) is a real second shape and is NOT this one; do not
 * widen this constant to cover both, or a verifier can no longer tell which
 * authority it is granting.
 */
export const VERIFIABLE_ACCREDITATION_TYPE = 'VerifiableAccreditationToAccredit';

/**
 * The `credentialSubject` of a professional licence credential.
 *
 * `licenceValidFrom` / `licenceValidUntil` are the window of THE LICENCE and are
 * deliberately not the same as the credential's own `validFrom` / `validUntil`,
 * which are the window of THE ATTESTATION. A council re-issuing an attestation
 * mid-licence must not silently extend the licence, and a licence that outlives
 * its attestation must not be presentable. Both windows are checked, separately.
 *
 * Every member is required. Under selective disclosure a holder can withhold any
 * of them, and a withheld claim must read as "not proven", never as "not
 * applicable" — so authorization refuses on absence rather than defaulting.
 */
export interface ProfessionalLicenceSubject {
  /** DID of the professional. Must equal the presentation's holder. */
  id: string;
  profession: Profession;
  /** Registration number as printed on the register, e.g. `BMDC-A-45123`. */
  licenceNumber: string;
  /** The register the number belongs to, for human-readable audit. */
  register: string;
  /** What the licence authorises. Checked as a superset of what a route needs. */
  practiceScope: PracticeScope[];
  /** ISO 8601. Start of the licence's own validity window. */
  licenceValidFrom: string;
  /** ISO 8601. End of it. Required — an open-ended licence is not a thing. */
  licenceValidUntil: string;
}

/**
 * The `credentialSubject` of an EBSI-style Verifiable Accreditation — the
 * credential by which one authority delegates to another.
 *
 * DESIGN-LEVEL, NOT YET ISSUED. The shape and the pure validation of a chain
 * ({@link validateAccreditationChain}) exist because the scope-subset and
 * temporal predicates are needed for the root case anyway. No issuance path
 * mints one and no verifier accepts a chain longer than zero yet.
 */
export interface AccreditationSubject {
  /** DID of the body being accredited. */
  id: string;
  /** Which professions it may in turn accredit. Never widens (#214). */
  professions: Profession[];
  /** Ceiling on the scope of licences it may issue. Never widens. */
  scope: PracticeScope[];
  /** ISO 8601 window during which this delegation is effective. */
  validFrom: string;
  validUntil?: string;
}

/** One hop of a delegation chain, already signature-verified by the caller. */
export interface AccreditationLink extends AccreditationSubject {
  /** DID that signed this accreditation. Must be the previous hop's subject. */
  issuerDid: string;
}

/**
 * Hops of delegation a verifier will follow.
 *
 * 2 by decision, 3 as the absolute ceiling (#214): an unbounded chain is
 * unbounded to verify and unauditable by a human, and neither cost is worth
 * paying for a hierarchy that in practice is council → hospital → clinician.
 */
export const MAX_DELEGATION_DEPTH = 2;
export const ABSOLUTE_DELEGATION_DEPTH_CEILING = 3;

// ---------------------------------------------------------------------------
// Trust roots
// ---------------------------------------------------------------------------

/** An accrediting authority pinned out of band. */
export interface AccreditationAuthority {
  did: string;
  name: string;
  shortName: string;
  /** Professions this authority may accredit. Nothing else. */
  professions: readonly Profession[];
  /** Ceiling on the scope of any licence it issues, and on any delegation. */
  maxScope: readonly PracticeScope[];
  /** ISO 8601. When this authority's mandate began. */
  authorisedFrom: string;
  /** ISO 8601. When it ended. Absent means the mandate still stands. */
  authorisedUntil?: string;
  /** True while the DID is a stand-in rather than the council's real DID. */
  placeholder: boolean;
  /**
   * base64url raw X25519 public key. Round 5's target for
   * `crypto/contentKeyWrap.ts`'s ECIES wrap — carried here, not resolved from
   * the DID document, because no DID this codebase mints carries a
   * `keyAgreement` verification method (see that module's docblock for why).
   * Only the ministry's matching private seed is actually configured
   * anywhere (`packages/issuer-console/.env.local`); the three councils'
   * are pinned so `documentTypes.ts` has a real key to wrap licence
   * submissions to, exercised structurally even though no council console
   * seed exists to unwrap them yet.
   */
  contentKeyPublicKey: string;
}

/** Exported so other pinned-literal stores (e.g. `identity/documentTypes.ts`) can freeze the same way. */
export function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

/**
 * THE ROOT STORE.
 *
 * The three DIDs are MINTED ON OUR TESTNET (9 Sep 2026) and resolve to real
 * institution-shaped documents with three officer keys each, read back from the
 * chain at provisioning time. They were placeholders — `…:11111111-…` and
 * friends, resolving to nothing — which blocked everything downstream:
 * `authoriseProfessional` reduced to "the issuer must be a pinned root",
 * professional licences could not be issued at all, and the HMS refused every
 * clinical login because the accreditation it checks could never verify.
 *
 * `placeholder` remains the flag a deployment check asserts on, rather than
 * pattern-matching the DID string. It now reads `false` because these resolve.
 *
 * WHAT IS STILL NOT REAL, and must not be read as if it were: these are OUR
 * testnet DIDs, not identifiers any council has enrolled or acknowledged. A
 * production deployment replaces them, and the flag exists so that replacement
 * is a data change rather than a code change.
 *
 * `authorisedFrom` is likewise NOT the statutory commencement date of each
 * council. Inventing a legal date we have not verified would make a temporal
 * refusal look authoritative when it is arbitrary; when real council DIDs are
 * enrolled, the real dates arrive with them.
 */
export const PROFESSIONAL_TRUST_ROOTS: readonly AccreditationAuthority[] = deepFreeze([
  {
    did: 'did:cheqd:bdhealthtestnet:cb977556-ce6e-413b-b8c6-1ba6e53eeb0f',
    name: 'Bangladesh Medical and Dental Council',
    shortName: 'BMDC',
    professions: ['doctor'],
    maxScope: [
      'view-patient-record',
      'write-patient-record',
      'prescribe',
      'administer-medication',
      'order-diagnostic',
    ],
    authorisedFrom: '2026-01-01T00:00:00.000Z',
    placeholder: false,
    contentKeyPublicKey: 'PEkQHFGyHWEAUwUKwy-0nE5kl8E6R_0oIG6cn6ZTRhc',
  },
  {
    did: 'did:cheqd:bdhealthtestnet:2b86a5df-1a16-4609-abf3-b37bd82c16cd',
    name: 'Bangladesh Nursing and Midwifery Council',
    shortName: 'BNMC',
    professions: ['nurse'],
    maxScope: ['view-patient-record', 'write-patient-record', 'administer-medication'],
    authorisedFrom: '2026-01-01T00:00:00.000Z',
    placeholder: false,
    contentKeyPublicKey: 'nBCo5DfW4lOfEomdMrG7Y7nbtExpiXx44ig9k6mpQSs',
  },
  {
    did: 'did:cheqd:bdhealthtestnet:5ec73178-7e8c-4f60-ad4b-9573a0362a39',
    name: 'Pharmacy Council of Bangladesh',
    shortName: 'PCB',
    professions: ['pharmacist'],
    maxScope: ['view-patient-record', 'dispense'],
    authorisedFrom: '2026-01-01T00:00:00.000Z',
    placeholder: false,
    contentKeyPublicKey: 'm8WsOPaBK-RtPByA9nQEmgdujW7jRJkPpmSbMfC3AX0',
  },
] as const satisfies readonly AccreditationAuthority[]);

/** True while any pinned root is still a stand-in. Log it; do not ship on it. */
export const TRUST_ROOTS_ARE_PLACEHOLDERS: boolean =
  PROFESSIONAL_TRUST_ROOTS.some((authority) => authority.placeholder);

/**
 * WHY EVERY PREDICATE BELOW TAKES AN OPTIONAL ROOT STORE.
 *
 * The default is the pinned set, so omitting the argument is the safe choice
 * and forgetting it cannot weaken anything. The seam exists so the live test
 * tier can pin an authority it actually controls on our testnet, instead of the
 * alternative — shipping a dev DID inside the production root store, where a
 * deployment that forgot to swap it would trust a key sitting in someone's
 * wallet. A caller that can pass a different store is server code that could
 * already do anything; a REQUEST can never reach this parameter, and the guard
 * never passes it.
 */
export type TrustRootStore = readonly AccreditationAuthority[];

/** The pinned authority for a DID, or `undefined` — never a partial match. */
export function trustRootForDid(
  did: string,
  roots: TrustRootStore = PROFESSIONAL_TRUST_ROOTS,
): AccreditationAuthority | undefined {
  return roots.find((authority) => authority.did === did);
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/** Parse an ISO 8601 instant, or `null`. Fail-closed callers treat null as a refusal. */
function instant(iso: string | undefined): number | null {
  if (typeof iso !== 'string' || iso.length === 0) return null;
  const parsed = Date.parse(iso);
  return Number.isNaN(parsed) ? null : parsed;
}

/** Does `child` stay within `parent`? Equal sets narrow trivially; supersets do not. */
export function narrowsScope(
  parent: readonly PracticeScope[],
  child: readonly PracticeScope[],
): boolean {
  return child.every((scope) => parent.includes(scope));
}

/** Which of `required` is missing from `held`. Empty means the scope is covered. */
export function uncoveredScope(
  held: readonly PracticeScope[],
  required: readonly PracticeScope[],
): PracticeScope[] {
  return required.filter((scope) => !held.includes(scope));
}

export interface AuthorityDecision {
  authorised: boolean;
  /** Empty when authorised. One entry per independent reason to refuse. */
  reasons: string[];
  authority?: AccreditationAuthority;
}

/**
 * TEMPORAL ASSERTION 1: was this authority entitled to accredit this profession
 * at this instant?
 *
 * `at` is the credential's issuance time, not now. Asking about now would refuse
 * every licence issued by a council that has since been restructured, which is
 * the retirement case that must NOT invalidate past records.
 */
export function wasAuthorisedToAccredit(params: {
  authorityDid: string;
  profession: Profession;
  at: string;
  roots?: TrustRootStore;
}): AuthorityDecision {
  const reasons: string[] = [];
  const authority = trustRootForDid(params.authorityDid, params.roots);

  if (!authority) {
    return {
      authorised: false,
      reasons: [`'${params.authorityDid}' is not a pinned accrediting authority`],
    };
  }

  if (!authority.professions.includes(params.profession)) {
    reasons.push(
      `${authority.shortName} does not accredit '${params.profession}' (it accredits ${authority.professions.join(', ')})`,
    );
  }

  const issuedAt = instant(params.at);
  const from = instant(authority.authorisedFrom);
  const until = instant(authority.authorisedUntil);

  if (issuedAt === null) {
    reasons.push('Credential carries no readable issuance time, so its issuer cannot be dated');
  } else if (from === null) {
    reasons.push(`${authority.shortName} has no readable mandate start in the root store`);
  } else if (issuedAt < from) {
    reasons.push(
      `${authority.shortName} held no mandate at the credential's issuance time (${params.at}); its mandate began ${authority.authorisedFrom}`,
    );
  } else if (until !== null && issuedAt > until) {
    reasons.push(
      `${authority.shortName}'s mandate ended ${authority.authorisedUntil}, before the credential's issuance time (${params.at})`,
    );
  }

  return { authorised: reasons.length === 0, reasons, authority };
}

/** Is an ISO 8601 window open at `at`? Unreadable bounds are a refusal, not a pass. */
export function windowCovers(
  window: { from: string | undefined; until: string | undefined },
  at: string,
): { covers: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const now = instant(at);
  const from = instant(window.from);
  const until = instant(window.until);

  if (now === null) return { covers: false, reasons: ['Evaluation instant is unreadable'] };
  if (from === null) reasons.push('Validity window has no readable start');
  else if (now < from) reasons.push(`Not yet in force (starts ${window.from})`);
  if (until === null) reasons.push('Validity window has no readable end');
  else if (now > until) reasons.push(`Expired (ended ${window.until})`);

  return { covers: reasons.length === 0, reasons };
}

// ---------------------------------------------------------------------------
// Delegation chains
// ---------------------------------------------------------------------------

export interface ChainDecision {
  valid: boolean;
  reasons: string[];
  /** DID entitled to issue licences, once the chain is walked. */
  accreditedIssuerDid?: string;
  /** What survives the narrowing at every hop. */
  effectiveProfessions: Profession[];
  effectiveScope: PracticeScope[];
}

/**
 * Walk a delegation chain from a pinned root, narrowing at every hop.
 *
 * `chain` is ROOT-FIRST and every link must ALREADY have had its signature and
 * revocation verified by the caller — this function decides entitlement, not
 * authenticity, and an unverified link fed in here is an unverified link
 * trusted. An empty chain is valid and means "the root issues directly", which
 * is the only case any request path currently accepts.
 */
export function validateAccreditationChain(params: {
  rootDid: string;
  chain: readonly AccreditationLink[];
  at: string;
  roots?: TrustRootStore;
}): ChainDecision {
  const reasons: string[] = [];
  const root = trustRootForDid(params.rootDid, params.roots);

  if (!root) {
    return {
      valid: false,
      reasons: [`'${params.rootDid}' is not a pinned accrediting authority`],
      effectiveProfessions: [],
      effectiveScope: [],
    };
  }

  if (params.chain.length > MAX_DELEGATION_DEPTH) {
    reasons.push(
      `Delegation chain is ${params.chain.length} hops, over the cap of ${MAX_DELEGATION_DEPTH}`,
    );
  }

  let issuerDid = root.did;
  let professions: Profession[] = [...root.professions];
  let scope: PracticeScope[] = [...root.maxScope];

  for (const [index, link] of params.chain.entries()) {
    const hop = index + 1;

    if (link.issuerDid !== issuerDid) {
      reasons.push(
        `Hop ${hop} is issued by '${link.issuerDid}' but the previous hop delegated to '${issuerDid}'`,
      );
    }

    const window = windowCovers({ from: link.validFrom, until: link.validUntil }, params.at);
    if (!window.covers) {
      reasons.push(...window.reasons.map((reason) => `Hop ${hop}: ${reason}`));
    }

    const widened = link.professions.filter((profession) => !professions.includes(profession));
    if (widened.length > 0) {
      reasons.push(`Hop ${hop} widens professions to include ${widened.join(', ')}`);
    }

    if (!narrowsScope(scope, link.scope)) {
      reasons.push(
        `Hop ${hop} widens scope to include ${uncoveredScope(scope, link.scope).join(', ')}`,
      );
    }

    issuerDid = link.id;
    professions = link.professions.filter((profession) => professions.includes(profession));
    scope = link.scope.filter((entry) => scope.includes(entry));
  }

  return {
    valid: reasons.length === 0,
    reasons,
    accreditedIssuerDid: reasons.length === 0 ? issuerDid : undefined,
    effectiveProfessions: professions,
    effectiveScope: scope,
  };
}

// ---------------------------------------------------------------------------
// WHAT THE WALLET HOLDS — A UI ROUTING HINT, NEVER AN AUTHORIZATION DECISION
// ---------------------------------------------------------------------------

/**
 * =========================================================================
 * READ THIS BEFORE USING ANYTHING BELOW.
 * =========================================================================
 * Everything in this section answers ONE question: *does this wallet appear to
 * hold a professional licence, so should the app offer verifier mode?* It is a
 * question about which SCREENS to show. It is NOT, and must never become, the
 * basis of an authorization decision.
 *
 * The reason is the whole claim of R4. A wallet deciding it holds a valid
 * licence is a client asserting its own authority — the same shape as the
 * self-declared group chosen at onboarding, and the same shape as a `role`
 * column on a session. It is trivially defeated by a modified client, and even
 * an honest one is working from a cached copy: it cannot see a revocation
 * published thirty seconds ago, and it has no way to know whether the issuer
 * held a mandate at issuance time. Only `authoriseProfessional`, deciding on a
 * presentation verified during the request against the deployment's pinned
 * roots, answers "may they".
 *
 * So the contract is asymmetric on purpose, and the asymmetry is the safety
 * property:
 *
 *   - A wallet that shows verifier mode may still be refused. Expected.
 *   - A wallet that hides it has lost nothing but a menu item.
 *
 * What it buys is real, though, and it is a usability property rather than a
 * security one: an entry point that appears for everyone and fails on tap is
 * worse than no entry point, because the user cannot tell "not for me" from
 * "broken", and in a low-technical-literacy population the second reading is
 * the one that sticks.
 */

/** The minimum of a credential this module needs in order to recognise it. */
export interface HeldCredential {
  /** Stable identifier, so a caller can find the credential again. */
  id: string;
  /** The VC `type` array, including the generic marker. */
  type: readonly string[];
  credentialSubject: unknown;
  /** DID of the issuer, as the wallet recorded it. */
  issuerDid?: string;
  /**
   * The wallet's LOCAL view of the credential's lifecycle.
   *
   * Deliberately a wallet-side status and not a ledger read: this module is
   * pure and a network call here would make a screen-routing decision depend on
   * connectivity. A stale `active` is exactly why this cannot authorise
   * anything.
   */
  locallyRevoked?: boolean;
}

/** A licence this wallet appears to hold, as far as the wallet can tell. */
export interface HeldProfessionalLicence {
  credentialId: string;
  profession: Profession;
  licenceNumber: string;
  register: string;
  practiceScope: PracticeScope[];
  licenceValidFrom: string;
  licenceValidUntil: string;
  issuerDid?: string;
  /**
   * Short name of the pinned authority that issued it, when the issuer is one.
   *
   * `undefined` means "this wallet does not recognise the issuer as a pinned
   * authority", which is worth SHOWING the holder — but it is not a refusal,
   * because the wallet's root store may legitimately differ from the
   * verifier's, and the verifier's is the one that decides.
   */
  accreditedByName?: string;
  /** Whether the licence's own window is open at the evaluation instant. */
  inForce: boolean;
  /** Why not, when `inForce` is false. Shown to the holder, never enforced. */
  notInForceReasons: string[];
}

function readLicenceSubject(
  subject: unknown,
): Omit<HeldProfessionalLicence, 'credentialId' | 'issuerDid' | 'accreditedByName' | 'inForce' | 'notInForceReasons'> | null {
  if (typeof subject !== 'object' || subject === null || Array.isArray(subject)) return null;
  const claims = subject as Record<string, unknown>;

  // Structural rather than zod, so this module keeps its zero-dependency
  // footprint and stays importable by the wallet — `ProfessionalLicenceSubjectSchema`
  // lives in `validation`, which imports FROM here, and reaching back for it
  // would close a cycle.
  const { profession, licenceNumber, register, practiceScope, licenceValidFrom, licenceValidUntil } =
    claims;

  if (!isProfession(profession)) return null;
  if (typeof licenceNumber !== 'string' || licenceNumber.length === 0) return null;
  if (typeof register !== 'string' || register.length === 0) return null;
  if (!Array.isArray(practiceScope) || practiceScope.length === 0) return null;
  if (!practiceScope.every(isPracticeScope)) return null;
  if (typeof licenceValidFrom !== 'string' || typeof licenceValidUntil !== 'string') return null;

  return {
    profession,
    licenceNumber,
    register,
    practiceScope: [...practiceScope],
    licenceValidFrom,
    licenceValidUntil,
  };
}

/**
 * The professional licences a wallet appears to hold.
 *
 * A credential qualifies only if it carries the licence type AND every licence
 * claim is present and well formed. A licence presented under selective
 * disclosure could be missing claims — but this reads the credential as the
 * HOLDER stores it, which is fully disclosed, so a missing claim here means the
 * credential is not a licence rather than that something was withheld.
 *
 * Locally-revoked credentials are excluded: the wallet already knows that one
 * will be refused, and offering it is the "fails on tap" case.
 */
export function professionalLicencesHeld(
  credentials: readonly HeldCredential[],
  options: { at?: string; roots?: TrustRootStore } = {},
): HeldProfessionalLicence[] {
  const at = options.at ?? new Date().toISOString();
  const held: HeldProfessionalLicence[] = [];

  for (const credential of credentials) {
    if (credential.locallyRevoked === true) continue;
    if (!credential.type.includes(PROFESSIONAL_LICENCE_CREDENTIAL_TYPE)) continue;

    const licence = readLicenceSubject(credential.credentialSubject);
    if (!licence) continue;

    const window = windowCovers(
      { from: licence.licenceValidFrom, until: licence.licenceValidUntil },
      at,
    );
    const authority = credential.issuerDid
      ? trustRootForDid(credential.issuerDid, options.roots)
      : undefined;

    held.push({
      credentialId: credential.id,
      ...licence,
      ...(credential.issuerDid ? { issuerDid: credential.issuerDid } : {}),
      ...(authority ? { accreditedByName: authority.shortName } : {}),
      inForce: window.covers,
      notInForceReasons: window.reasons,
    });
  }

  return held;
}

/**
 * Whether the app should offer verifier mode.
 *
 * True when the wallet holds at least one licence that is IN FORCE. An expired
 * licence is excluded because presenting it is a guaranteed refusal, and the
 * point of gating the entry point at all is that tapping it should be able to
 * work.
 *
 * Never call this to decide whether an action is permitted. See the section
 * header — the verifier decides, on a presentation, during the request.
 */
export function walletOffersVerifierMode(
  credentials: readonly HeldCredential[],
  options: { at?: string; roots?: TrustRootStore } = {},
): boolean {
  return professionalLicencesHeld(credentials, options).some((licence) => licence.inForce);
}
