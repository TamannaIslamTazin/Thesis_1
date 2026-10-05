/**
 * Local, offline verification of BDHealthTrust presentations.
 *
 * `import { verifySdJwtPresentation } from '@ssi-healthcare/sdk/verify'`
 *
 * This is the entry point a relying party should use. It verifies in YOUR
 * process, against key material YOU chose to trust. Contrast
 * `SSIClient.verifyPresentation`, which asks our backend and returns its
 * opinion — useful for a first-party integration, useless as a trust anchor for
 * anyone who is not us.
 *
 * The full argument for the shape of this API, including why it does not stop
 * at the disclosure layer, is at the top of ./presentation.ts. Read it before
 * adding anything here.
 */
export {
  verifySdJwtPresentation,
  didOf,
  DEFAULT_ALLOWED_ALGORITHMS,
  NOT_CHECKED,
} from './presentation';
export type {
  VerifySdJwtPresentationOptions,
  SdJwtPresentationVerification,
  SdJwtPresentationChecks,
  VerifiedSdJwtCredential,
  ResolveVerificationKey,
  VerificationJwk,
} from './presentation';

// Exported so a caller building or inspecting SD-JWTs with the vendored library
// does not have to write its own platform-correct hasher. Verification does not
// need these — `verifySdJwtPresentation` wires them up itself.
export { webCryptoHasher, webCryptoSaltGenerator } from './crypto';

/**
 * How an SD-JWT artifact is taken apart — the plumbing under BOTH verifiers.
 *
 * Published because the backend's Credo-side verifier consumes exactly these,
 * rather than keeping the second copy it used to have (#341). They are also
 * genuinely useful to an integrator inspecting an artifact: the positional
 * key-binding split in particular is the one every hand-rolled reader gets
 * wrong (#290).
 *
 * This is plumbing, not verification. Nothing here checks a signature, a digest
 * or a nonce, and none of it should be mistaken for having done so — use
 * `verifySdJwtPresentation` for that.
 */
export {
  SD_JWT_ENVELOPE_CLAIMS,
  SD_SEPARATOR,
  SD_JWT_MEDIA_TYPE,
  VC_SD_JWT_TYP,
  VP_SD_JWT_TYP,
  credentialClaimsOf,
  envelopedCredentialToSdJwt,
  issuerSignedJws,
  keyBindingSlot,
  looksLikeSdJwt,
  splitSdJwtCompact,
} from './sdJwtWire';
export type { SdJwtCompactParts } from './sdJwtWire';

/**
 * The AUTHORISATION half, which runs after verification and answers a
 * different question: not "is this presentation genuine" but "does what it
 * proves entitle its holder to act".
 *
 * Two steps rather than one because they fail differently and are trusted
 * differently — a genuine presentation of an expired licence is a valid
 * artifact and an unauthorised caller, and collapsing the two would lose that
 * distinction in a single boolean.
 */
export { authoriseProfessional } from './professionalAuthority';
export type {
  AuthoriseProfessionalOptions,
  PresentedLicence,
  ProfessionalAuthorisation,
  ProfessionalAuthorityChecks,
  ProfessionalAuthorityPorts,
  ProfessionalIdentity,
  ProfessionalRequirement,
  RevocationPort,
  RevocationStatus,
} from './professionalAuthority';

/**
 * ONE hop of a delegation chain, verified. This is what makes
 * `accreditationChain` usable: it decides authenticity (signature, claims,
 * revocation) so the chain walk can decide entitlement on links it may trust.
 */
export { verifyAccreditationLink } from './accreditation';
export type {
  AccreditationKeyResolver,
  AccreditationLinkResult,
  AccreditationRevocationPort,
} from './accreditation';
