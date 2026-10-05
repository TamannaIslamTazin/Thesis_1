/**
 * Professional authority from an already-verified presentation.
 *
 * `import { authoriseProfessional } from '@ssi-healthcare/sdk/verify'`
 *
 * The decision procedure behind the backend's `requireProfessional`, and the
 * same one a hospital or a wallet runs for itself. It answers exactly one
 * question: does this ALREADY-VERIFIED presentation prove that its holder is a
 * licensed professional of the required kind, with the required scope, right
 * now?
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS MODULE DELIBERATELY DOES NOT DO
 * ---------------------------------------------------------------------------
 * It does not verify signatures, nonces, audiences, disclosure integrity or
 * holder binding. All five belong to the presentation verifier — the backend's
 * `verifySdJwtPresentation`, or {@link ./presentation} here — and a second
 * verification path in this file would be a weaker one, which is the specific
 * mistake this project has already made. The input type is a credential such a
 * verifier only ever emits on FULL success, so a caller cannot reach this
 * function with unverified claims.
 *
 * ---------------------------------------------------------------------------
 * FAIL CLOSED, AND EVERY CHECK IS ITS OWN FIELD
 * ---------------------------------------------------------------------------
 * Every member of `checks` starts `false` and must be actively satisfied.
 * "There was nothing to check" — a withheld claim, an unresolvable status list,
 * an unreadable date — is a refusal, never a skip.
 *
 * The two temporal questions are two fields (#214), not one:
 *
 *   issuerAccreditedAtIssuance   was the council entitled to accredit this
 *                                profession WHEN THE CREDENTIAL WAS ISSUED
 *   notRevoked                   has the credential been revoked BY NOW
 *
 * A retired council keeps every licence it lawfully issued; a fraudulent one
 * has its records revoked retroactively. One boolean cannot express both.
 *
 * ---------------------------------------------------------------------------
 * WHY THE I/O IS INJECTED
 * ---------------------------------------------------------------------------
 * This logic was the backend's until the #334 consolidation. It reached the
 * ledger through a Credo agent and logged through winston, both of which are
 * node-only and neither of which belongs in a library a hospital server, a
 * browser verifier and a React Native wallet all import. They are ports now,
 * and the composition root supplies them. See {@link RevocationPort} for why
 * exactly one of the two is mandatory.
 */

import {
  ProfessionalLicenceSubjectSchema,
  PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  credentialValidFrom,
  credentialValidUntil,
  narrowsScope,
  silentLogger,
  trustRootForDid,
  uncoveredScope,
  validateAccreditationChain,
  wasAuthorisedToAccredit,
  windowCovers,
  type AccreditationLink,
  type CredentialStatus,
  type LoggerPort,
  type PracticeScope,
  type Profession,
  type ProfessionalLicenceSubject,
  type TrustRootStore,
  type VerifiableCredential,
} from '@ssi-healthcare/shared';
import { didOf } from './presentation';

// ---------------------------------------------------------------------------
// Ports — the I/O this decision cannot do for itself
// ---------------------------------------------------------------------------

/**
 * What a revocation lookup has to tell us. A narrowing of the backend's
 * `StatusCheckResult`, not a copy of it: a richer result satisfies this
 * structurally, and declaring only the three fields the decision reads keeps
 * the rest of that type free to change without a second declaration to keep
 * in step.
 */
export interface RevocationStatus {
  /** `true` when the list says this credential is revoked. */
  revoked: boolean;
  /** `false` when the list could not be dereferenced or parsed. */
  checked: boolean;
  /** Why it could not be established. Quoted verbatim in the refusal reason. */
  error?: string;
}

/**
 * Where revocation is read from.
 *
 * THIS PORT IS MANDATORY, and that is the single most important line in this
 * file. Made optional, an integrator who omitted it would get a decision that
 * reported `notRevoked: true` for a list nobody ever read — a professional
 * authority service failing OPEN on revocation, which is the worst default
 * available. Wrong states are made unconstructable here rather than merely
 * discouraged: there is no default, so the type system refuses the omission
 * before it can become a runtime one.
 *
 * An implementation that cannot reach its list must return
 * `{ checked: false }` rather than throw or guess; this decision then refuses.
 * Deciding what an unreadable list means is the caller's business only in the
 * sense that it may choose HOW to read it, never WHETHER a silent read counts.
 */
export interface RevocationPort {
  check(status: CredentialStatus | undefined): Promise<RevocationStatus>;
}

export interface ProfessionalAuthorityPorts {
  /** @see RevocationPort — required, deliberately and permanently. */
  revocation: RevocationPort;
  /**
   * Optional, unlike `revocation`, and the asymmetry is the point: a logger
   * asserts nothing, so its absence costs observability, while a missing
   * revocation check would assert a security property nobody established.
   * Defaults to {@link silentLogger}.
   */
  log?: LoggerPort;
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/**
 * The part of a verified presentation this decision reads.
 *
 * Narrower than the backend's `PresentedSdJwtCredential` — the envelope is not
 * read here, so it is not asked for — and satisfied by it structurally, which
 * is why the adapter needs no conversion and no cast.
 */
export interface PresentedLicence {
  /**
   * The disclosed claims as W3C JSON. Withheld claims are absent from this
   * object entirely, and are refused below rather than defaulted.
   */
  credential: VerifiableCredential;
  /** The holder binding the issuer signed into the credential. */
  cnfKeyId: string | null;
}

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

export interface ProfessionalAuthorityChecks {
  /** The credential claims to be a professional licence at all. */
  credentialType: boolean;
  /** Every licence claim survived disclosure and parsed. */
  claimsDisclosed: boolean;
  /** The licence names the holder who presented it. */
  subjectBinding: boolean;
  /** TEMPORAL 1 — the issuer held the mandate at issuance time. */
  issuerAccreditedAtIssuance: boolean;
  /** The issuer did not grant more scope than its own mandate permits. */
  issuerWithinMandate: boolean;
  /** TEMPORAL 2 — the status list says this credential is live, now. */
  notRevoked: boolean;
  /** The attestation's own validity window is open. */
  credentialInForce: boolean;
  /** The licence's validity window is open. Not the same window. */
  licenceInForce: boolean;
  professionMatches: boolean;
  scopeCovered: boolean;
}

/** Who the caller turned out to be. Populated only on a full pass. */
export interface ProfessionalIdentity {
  did: string;
  profession: Profession;
  licenceNumber: string;
  register: string;
  practiceScope: PracticeScope[];
  /** DID of the accrediting authority that issued the licence. */
  accreditedBy: string;
  /** Its short name, for logs and for showing a patient who vouched for them. */
  accreditedByName: string;
  /** The credential id, so an access record can name the evidence it acted on. */
  licenceCredentialId: string;
}

export interface ProfessionalAuthorisation {
  authorised: boolean;
  /** Empty on success. One entry per independent reason to refuse. */
  reasons: string[];
  checks: ProfessionalAuthorityChecks;
  professional?: ProfessionalIdentity;
}

export interface ProfessionalRequirement {
  /** The profession the route requires. Omit to accept any licensed professional. */
  profession?: Profession;
  /** Every scope the route needs. The licence must cover all of them. */
  scope: readonly PracticeScope[];
}

/**
 * The decision's inputs, excluding the ports.
 *
 * Kept separate from {@link ProfessionalAuthorityPorts} so an adapter that
 * binds the ports can re-export exactly this as the signature its own callers
 * see, without them ever naming a port they do not supply.
 */
export interface AuthoriseProfessionalOptions {
  /** A credential a presentation verifier has already fully verified. */
  presented: PresentedLicence;
  requirement: ProfessionalRequirement;
  /**
   * Verified delegation hops from a pinned root to the credential's issuer.
   *
   * Empty means "the issuer must itself be a pinned root", which is the only
   * case any request path currently produces. Links passed here must ALREADY
   * have had their signatures and revocation checked — see #214.
   */
  accreditationChain?: readonly AccreditationLink[];
  /** Evaluation instant. Injectable so a test can pin it. */
  now?: Date;
  /**
   * Root store to decide against. Defaults to the pinned set.
   *
   * The backend's `requireProfessional` never passes this from a request — no
   * request can reach it. It exists so a deployment can pin an authority it
   * controls on its own testnet rather than putting a dev DID in the shipped
   * root store.
   */
  trustRoots?: TrustRootStore;
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

export async function authoriseProfessional(
  options: AuthoriseProfessionalOptions & ProfessionalAuthorityPorts,
): Promise<ProfessionalAuthorisation> {
  const { presented, requirement, revocation } = options;
  const log = options.log ?? silentLogger;
  const now = options.now ?? new Date();
  const nowIso = now.toISOString();

  const reasons: string[] = [];
  const checks: ProfessionalAuthorityChecks = {
    credentialType: false,
    claimsDisclosed: false,
    subjectBinding: false,
    issuerAccreditedAtIssuance: false,
    issuerWithinMandate: false,
    notRevoked: false,
    credentialInForce: false,
    licenceInForce: false,
    professionMatches: false,
    scopeCovered: false,
  };

  // Deduped: an unpinned issuer legitimately fails both the chain walk and the
  // issuance-time check, and reporting it twice reads as two defects.
  const refuse = (): ProfessionalAuthorisation => ({
    authorised: false,
    reasons: [...new Set(reasons)],
    checks,
  });

  const { credential } = presented;

  // ------------------------------------------------------------------- type
  if (Array.isArray(credential.type) && credential.type.includes(PROFESSIONAL_LICENCE_CREDENTIAL_TYPE)) {
    checks.credentialType = true;
  } else {
    reasons.push(
      `Presented credential is not a ${PROFESSIONAL_LICENCE_CREDENTIAL_TYPE} (it is ${
        Array.isArray(credential.type) ? credential.type.join(', ') : 'untyped'
      })`,
    );
    // Nothing below is meaningful for a credential of another type, and reading
    // licence claims off one would be reading claims that were never asserted.
    return refuse();
  }

  // ------------------------------------------------------------------ claims
  // A withheld claim reads as "not proven". Parsing is strict, so a licence
  // presented with `practiceScope` held back is refused rather than treated as
  // scopeless-but-otherwise-fine.
  const parsed = ProfessionalLicenceSubjectSchema.safeParse(credential.credentialSubject);
  if (!parsed.success) {
    reasons.push(
      `Licence claims are missing or malformed: ${parsed.error.issues
        .map((issue) => `${issue.path.join('.') || '(root)'} ${issue.message}`)
        .join('; ')}`,
    );
    return refuse();
  }
  checks.claimsDisclosed = true;
  const licence: ProfessionalLicenceSubject = parsed.data;

  // --------------------------------------------------------- subject binding
  // The verifier proved the presentation was signed by the key the credential
  // is bound to. It did NOT prove that key belongs to the DID the licence names
  // as its subject — a credential bound to one holder's key while naming
  // another DID as the professional would pass there and must not pass here.
  // A conformant verifier refuses an unbound credential, so this is unreachable
  // via one. Typed as nullable all the same, and a null read as "no binding to
  // compare" would silently pass the comparison below.
  if (!presented.cnfKeyId) {
    reasons.push('Presented licence carries no holder binding');
    return refuse();
  }
  const holderDid = didOf(presented.cnfKeyId);
  if (holderDid === licence.id) {
    checks.subjectBinding = true;
  } else {
    reasons.push(
      `Licence names '${licence.id}' as the professional but was presented by '${holderDid}'`,
    );
  }

  // ----------------------------------------------------------------- issuer
  const issuerDid =
    typeof credential.issuer === 'string' ? credential.issuer : credential.issuer?.id;
  const issuedAt = credentialValidFrom(credential);

  if (!issuerDid) {
    reasons.push('Credential names no issuer');
    return refuse();
  }

  // Walk delegation first, so the DID we then date is the one actually entitled
  // to issue. With an empty chain this reduces to "the issuer is a pinned root",
  // which is the only shape a request path produces today.
  const chain = options.accreditationChain ?? [];
  const roots = options.trustRoots;
  const rootDid = chain.length === 0 ? issuerDid : chain[0]!.issuerDid;
  const delegation = validateAccreditationChain({ rootDid, chain, at: nowIso, roots });

  if (!delegation.valid) {
    reasons.push(...delegation.reasons);
  } else if (delegation.accreditedIssuerDid !== issuerDid) {
    reasons.push(
      `Licence was issued by '${issuerDid}', which the accreditation chain does not entitle to issue`,
    );
  }

  // ------------------------------------------ TEMPORAL 1: authority at issuance
  const authority = wasAuthorisedToAccredit({
    authorityDid: rootDid,
    profession: licence.profession,
    at: issuedAt ?? '',
    roots,
  });
  if (authority.authorised) {
    checks.issuerAccreditedAtIssuance = true;
  } else {
    reasons.push(...authority.reasons);
  }

  // ------------------------------------------------------- mandate ceiling
  // An authority cannot grant scope it does not itself hold. Without this a
  // pinned nursing council could mint a licence carrying `prescribe`, and every
  // later check would happily agree the licence says so.
  const ceiling = delegation.valid
    ? delegation.effectiveScope
    : (trustRootForDid(rootDid, roots)?.maxScope ?? []);
  if (narrowsScope(ceiling, licence.practiceScope)) {
    checks.issuerWithinMandate = true;
  } else {
    reasons.push(
      `Licence grants ${uncoveredScope(ceiling, licence.practiceScope).join(', ')}, beyond the issuing authority's mandate`,
    );
  }

  // ------------------------------------------------ TEMPORAL 2: revoked now?
  // Read through the injected port, which the backend binds to the LEDGER
  // rather than to its own database, so a third-party verifier gets the same
  // answer we do. An unresolvable list is a refusal: reporting "not revoked"
  // for a list nobody read is the fail-open shape this codebase keeps finding
  // in itself, and is why the port has no default.
  const status = await revocation.check(credential.credentialStatus);
  if (!status.checked) {
    reasons.push(
      `Revocation status could not be established (${status.error ?? 'no reason given'}), so authority is refused`,
    );
  } else if (status.revoked) {
    reasons.push('Licence has been revoked by its issuing authority');
  } else {
    checks.notRevoked = true;
  }

  // ------------------------------------------------------------- two windows
  const attestation = windowCovers(
    { from: credentialValidFrom(credential), until: credentialValidUntil(credential) },
    nowIso,
  );
  if (attestation.covers) checks.credentialInForce = true;
  else reasons.push(...attestation.reasons.map((reason) => `Licence attestation: ${reason}`));

  const inForce = windowCovers(
    { from: licence.licenceValidFrom, until: licence.licenceValidUntil },
    nowIso,
  );
  if (inForce.covers) checks.licenceInForce = true;
  else reasons.push(...inForce.reasons.map((reason) => `Licence: ${reason}`));

  // ------------------------------------------------------ profession & scope
  if (!requirement.profession || requirement.profession === licence.profession) {
    checks.professionMatches = true;
  } else {
    reasons.push(
      `This action requires a ${requirement.profession}; the presented licence is for a ${licence.profession}`,
    );
  }

  const missingScope = uncoveredScope(licence.practiceScope, requirement.scope);
  if (missingScope.length === 0) {
    checks.scopeCovered = true;
  } else {
    reasons.push(`Licence does not cover ${missingScope.join(', ')}`);
  }

  const authorised = Object.values(checks).every(Boolean);

  if (!authorised) {
    const refusal = refuse();
    // Log the DEDUPED reasons the caller gets, not the raw accumulator — an
    // operator comparing a log line to a 403 body should see the same list.
    log.warn('Professional authority REFUSED', {
      holderDid,
      issuerDid,
      required: requirement,
      checks,
      reasons: refusal.reasons,
    });
    return refusal;
  }

  const root = trustRootForDid(rootDid, roots);
  log.info('Professional authority established', {
    holderDid,
    profession: licence.profession,
    accreditedBy: root?.shortName,
    // What the route was allowed to do, not the whole licence — the log should
    // not become a second copy of the credential.
    grantedFor: requirement.scope,
  });

  return {
    authorised: true,
    reasons: [],
    checks,
    professional: {
      did: holderDid,
      profession: licence.profession,
      licenceNumber: licence.licenceNumber,
      register: licence.register,
      practiceScope: licence.practiceScope,
      accreditedBy: rootDid,
      accreditedByName: root?.shortName ?? rootDid,
      licenceCredentialId: credential.id,
    },
  };
}
