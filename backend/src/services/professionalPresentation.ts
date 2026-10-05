/**
 * The Credo-backed adapter for `@ssi-healthcare/sdk/holder`.
 *
 * The holder's half of the professional-authority exchange MOVED to the SDK,
 * where the handset can reach it. What is left here is the part that could not
 * travel: the two operations that need the key the credential's `cnf` names,
 * which in this process lives in the Credo agent's Askar wallet.
 *
 * THE FILE IT REPLACES PREDICTED THIS. Its header said the boundary it
 * presented — "give me the licence and the holder's DID, get back a compact VP"
 * — was "deliberately the shape a device-side signer would also satisfy, so
 * moving it is a change of implementation and not of protocol". It was. Nothing
 * about the exchange changed; `agent: Agent` became a two-method port.
 *
 * EVERY EXPORT OF THE OLD MODULE IS STILL EXPORTED FROM HERE, with the same
 * names and the same signatures, so no call site changed. `signProfessionalPresentation`
 * and `presentProfessionalAuthority` still take an `Agent` first — this file
 * wraps it into the port rather than making thirty call sites learn about the
 * port. There is ONE implementation of each; these are not second copies.
 *
 * WHAT MUST NOT HAPPEN, restated because moving the code does not retire the
 * rule: the backend must never sign on a holder's behalf inside a request it is
 * also authorising. Nothing here is reachable from a route, and the guard
 * imports none of it.
 */

import type { Agent } from '@credo-ts/core';
import type { SdJwtPresentationFrame } from '@ssi-healthcare/shared';
import {
  signProfessionalPresentation as signWithHolder,
  presentProfessionalAuthority as presentWithHolder,
  type ProfessionalLicenceHolder,
  type HeldLicence,
  type ProfessionalChallengeResponse,
  type GuardedCallResult,
  type ProfessionalRequirementRequest,
} from '@ssi-healthcare/sdk/holder';

import { presentSdJwtCredential, sdJwtVcToW3cJson, signSdJwtPresentation } from './sdJwtVc.js';

// The pure half, re-exported unchanged. One definition, in the SDK.
export {
  PRESENTATION_REQUEST_HEADER,
  PRESENTATION_HEADER,
  ProfessionalPresentationError,
  requestProfessionalChallenge,
  claimsRequestedBy,
  professionalPresentationHeaders,
  callWithProfessionalAuthority,
} from '@ssi-healthcare/sdk/holder';
export type {
  ProfessionalLicenceHolder,
  HeldLicence,
  ProfessionalChallengeResponse,
  ProfessionalRequirementRequest,
  GuardedCallResult,
} from '@ssi-healthcare/sdk/holder';

/**
 * A {@link ProfessionalLicenceHolder} backed by this process's Credo agent.
 *
 * `presentLicence` is one call rather than two because the value passed between
 * `presentSdJwtCredential` and `signSdJwtPresentation` is a
 * `W3cV2SdJwtVerifiableCredential` — a Credo type. Keeping the pair on this side
 * of the port is what keeps that type out of the SDK, and therefore out of the
 * typecheck of anyone who links the SDK without Credo.
 */
export function credoLicenceHolder(agent: Agent): ProfessionalLicenceHolder {
  return {
    readLicence(compactLicence: string): HeldLicence | null {
      return sdJwtVcToW3cJson(compactLicence);
    },

    async presentLicence(input: {
      readonly compactLicence: string;
      readonly frame: SdJwtPresentationFrame;
      readonly holderDid: string;
      readonly challenge: string;
      readonly domain: string;
    }): Promise<string> {
      const disclosed = await presentSdJwtCredential(agent, input.compactLicence, input.frame);
      const presentation = await signSdJwtPresentation(agent, {
        holderDid: input.holderDid,
        credential: disclosed,
        challenge: input.challenge,
        domain: input.domain,
      });
      return presentation.encoded;
    },
  };
}

/** @see signProfessionalPresentation in `@ssi-healthcare/sdk/holder`. */
export async function signProfessionalPresentation(
  agent: Agent,
  options: {
    holderDid: string;
    licence: string;
    challenge: ProfessionalChallengeResponse;
    volunteeredClaims?: readonly string[];
  },
): Promise<string> {
  return signWithHolder(credoLicenceHolder(agent), options);
}

/** @see presentProfessionalAuthority in `@ssi-healthcare/sdk/holder`. */
export async function presentProfessionalAuthority<T = unknown>(
  agent: Agent,
  options: {
    baseUrl: string;
    accessToken: string;
    holderDid: string;
    licence: string;
    requirement: ProfessionalRequirementRequest;
    path: string;
    body?: unknown;
    method?: string;
    volunteeredClaims?: readonly string[];
    fetchImpl?: typeof fetch;
  },
): Promise<GuardedCallResult<T>> {
  return presentWithHolder<T>(credoLicenceHolder(agent), options);
}
