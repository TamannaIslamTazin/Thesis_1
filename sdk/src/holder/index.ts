/**
 * `@ssi-healthcare/sdk/holder` — the wallet's half.
 *
 * Selective-disclosure selection and presentation building: deciding WHICH
 * claims to reveal and assembling the artifact that reveals them. This is the
 * code that must run on the handset, so the dependency-direction guard holds it
 * to the strict standard.
 *
 * WHAT IS HERE, AND WHY IT ARRIVED FIRST. The professional-authority exchange —
 * request a challenge, decide what to reveal, sign a `vp+sd-jwt` over the
 * verifier's nonce, retry the real call carrying it. It moved out of the backend
 * whole, because `agent: Agent` was only ever used to reach two key-holding
 * operations and everything else was arithmetic over a presentation definition.
 * Those two are now {@link ProfessionalLicenceHolder}, which the backend
 * satisfies with Credo and a device satisfies with its own key.
 *
 * STILL DELIBERATELY ABSENT: the credential STORE port — implemented with
 * SQLite/secure-store on device and Prisma in the backend. It is not designed
 * yet, the DB-coupled services it would serve are deferred, and building a port
 * before there is a second implementation to satisfy it is guessing at an
 * interface. A wrong abstraction is more expensive to remove than a missing one.
 */
export {
  PRESENTATION_REQUEST_HEADER,
  PRESENTATION_HEADER,
  ProfessionalPresentationError,
  requestProfessionalChallenge,
  claimsRequestedBy,
  signProfessionalPresentation,
  professionalPresentationHeaders,
  callWithProfessionalAuthority,
  presentProfessionalAuthority,
} from './professionalPresentation';
export type {
  ProfessionalLicenceHolder,
  HeldLicence,
  ProfessionalChallengeResponse,
  ProfessionalRequirementRequest,
  GuardedCallResult,
} from './professionalPresentation';
