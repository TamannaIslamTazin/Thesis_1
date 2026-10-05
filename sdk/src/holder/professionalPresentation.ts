/**
 * SSI Healthcare — the HOLDER's half of the professional-authority exchange.
 *
 * `professionalChallenge.ts` is the verifier's half (mint a nonce, spend it
 * once). `professionalAuthority.ts` is the decision. This is the third party in
 * that exchange: the professional's wallet, which requests a challenge, decides
 * what to reveal, signs a `vp+sd-jwt` over the verifier's nonce, and retries
 * the real request carrying it.
 *
 * ---------------------------------------------------------------------------
 * IT USED TO LIVE IN THE BACKEND. THE PREDICTION IN THAT HEADER HELD.
 * ---------------------------------------------------------------------------
 * The version of this file in `packages/backend/src/services` said the boundary
 * it presents — "give me the licence and the holder's DID, get back a compact
 * VP" — was "deliberately the shape a device-side signer would also satisfy, so
 * moving it is a change of implementation and not of protocol". That is exactly
 * what this move turned out to be. Not one line of the exchange changed: the
 * challenge request, the leaf-path expansion, the frame, the headers and the
 * retry semantics are the same, because `agent: Agent` was only ever used to
 * reach two operations, and those two are now {@link ProfessionalLicenceHolder}.
 *
 * WHY ONE PORT METHOD AND NOT TWO. The backend built the presentation with
 * `presentSdJwtCredential` and then signed it with `signSdJwtPresentation`,
 * passing a `W3cV2SdJwtVerifiableCredential` — a CREDO TYPE — between them.
 * Splitting the port along that seam would have put that type in the port's
 * signature and forced every implementer, including the React Native wallet, to
 * depend on Credo to name it. Collapsing the pair into one call keeps the Credo
 * type entirely inside the backend's adapter, where it belongs, and leaves a
 * port an integrator can satisfy without installing anything.
 *
 * WHAT MUST NOT HAPPEN, restated because moving the file does not retire the
 * rule: the backend must never sign on a holder's behalf inside a request it is
 * also authorising. Nothing here is reachable from a route, and the guard
 * imports none of it.
 *
 * ---------------------------------------------------------------------------
 * MINIMAL DISCLOSURE IS THE DEFAULT AND IS NOT A PREFERENCE
 * ---------------------------------------------------------------------------
 * The frame is derived from the verifier's own presentation definition, read
 * with the SAME reader the disclosure sheet uses
 * (`claimRequestsFromInputDescriptor`), so what the wallet reveals and what the
 * holder was shown cannot drift apart. Only claims the verifier marked required
 * are disclosed unless a caller explicitly volunteers more.
 *
 * Note this is NOT `presentSdJwtCredential(agent, x, true)`. Whole-credential
 * disclosure would hand a pharmacy every claim a licence happens to carry when
 * it asked for six, and `true` additionally has a history here: until #259 it
 * disclosed NOTHING while claiming the opposite, silently.
 */

import {
  buildPresentationFrame,
  claimRequestsFromInputDescriptor,
  enumerateDisclosableClaims,
  type PracticeScope,
  type PresentationDefinition,
  type Profession,
  type SdJwtPresentationFrame,
  type VerifierClaimRequest,
} from '@ssi-healthcare/shared';

/**
 * The two operations that need the holder's KEY, and therefore cannot be
 * portable code — only a portable INTERFACE.
 *
 * Narrow on purpose. Everything else in this module is arithmetic over a
 * presentation definition and can run anywhere; these two are the whole of what
 * differs between a backend holding a Credo/Askar wallet and a handset holding a
 * device key. An integrator implements two methods, not a credential stack.
 */
export interface ProfessionalLicenceHolder {
  /**
   * Decode a compact `vc+sd-jwt` to the holder's OWN fully-disclosed view of it.
   *
   * Local only — the result is read to decide what to reveal and never leaves
   * the device. Returns null when the credential is not a readable
   * `vc+sd-jwt`; that is a refusal, not an error to swallow.
   */
  readLicence(compactLicence: string): Promise<HeldLicence | null> | HeldLicence | null;

  /**
   * Disclose `compactLicence` under `frame` and sign the result as a
   * `vp+sd-jwt` bound to `challenge` and `domain`. Returns the compact
   * presentation.
   *
   * One method rather than two: the intermediate disclosed credential is a Credo
   * type in our backend implementation, and naming it here would export Credo
   * into every implementer's typecheck.
   */
  presentLicence(input: {
    readonly compactLicence: string;
    readonly frame: SdJwtPresentationFrame;
    readonly holderDid: string;
    /** The verifier's nonce. Never chosen here. */
    readonly challenge: string;
    /** The audience the VERIFIER named. Never our own idea of who we are. */
    readonly domain: string;
  }): Promise<string>;
}

/** As much of a decoded licence as the disclosure decision actually reads. */
export interface HeldLicence {
  readonly credentialSubject: unknown;
}

/** Header carrying the challenge a presentation answers. Mirrors the guard's. */
export const PRESENTATION_REQUEST_HEADER = 'X-Presentation-Request-Id';
/** Header carrying the compact `vp+sd-jwt`. Mirrors the guard's. */
export const PRESENTATION_HEADER = 'X-Professional-Presentation';

/** The challenge as `POST /api/professional/challenge` returns it. */
export interface ProfessionalChallengeResponse {
  requestId: string;
  nonce: string;
  /** The DID the presentation must name as `aud`. The verifier's, never ours. */
  audience: string;
  expiresAt: string;
  definition: PresentationDefinition;
}

export interface ProfessionalRequirementRequest {
  profession?: Profession;
  scope: readonly PracticeScope[];
}

/**
 * A refusal from the verifier, with the distinction the wallet has to act on.
 *
 * 401 means the presentation was absent, malformed or answered a spent
 * challenge — get a new challenge and try again. 403 means a presentation was
 * verified and found insufficient — retrying with the same licence cannot help,
 * and a wallet that retries anyway burns a challenge per attempt for nothing.
 */
export class ProfessionalPresentationError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string | undefined,
    /** Per-check reasons the verifier returned, when it returned any. */
    readonly reasons: string[] = [],
  ) {
    super(message);
    this.name = 'ProfessionalPresentationError';
  }

  /** Whether a fresh challenge could plausibly change the outcome. */
  get isRetryable(): boolean {
    return this.status === 401;
  }
}

interface ApiEnvelope<T> {
  success?: boolean;
  data?: T;
  error?: { code?: string; message?: string; details?: { checks?: unknown } };
}

async function readEnvelope<T>(response: Response): Promise<ApiEnvelope<T>> {
  try {
    return (await response.json()) as ApiEnvelope<T>;
  } catch {
    return {};
  }
}

/**
 * Ask the verifier for a nonce.
 *
 * The nonce, the audience and the definition all come from the verifier and
 * none of them is chosen here — a presenter that picks its own audience has
 * bound the presentation to nothing.
 */
export async function requestProfessionalChallenge(options: {
  baseUrl: string;
  accessToken: string;
  requirement: ProfessionalRequirementRequest;
  fetchImpl?: typeof fetch;
}): Promise<ProfessionalChallengeResponse> {
  const doFetch = options.fetchImpl ?? fetch;
  const response = await doFetch(`${options.baseUrl}/api/professional/challenge`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${options.accessToken}`,
    },
    body: JSON.stringify({
      ...(options.requirement.profession ? { profession: options.requirement.profession } : {}),
      scope: options.requirement.scope,
    }),
  });

  const body = await readEnvelope<ProfessionalChallengeResponse>(response);

  if (!response.ok || !body.data) {
    throw new ProfessionalPresentationError(
      body.error?.message ?? `Could not obtain a professional challenge (HTTP ${response.status})`,
      response.status,
      body.error?.code,
    );
  }

  return body.data;
}

/**
 * The claims this challenge asks the licence to reveal.
 *
 * Exposed rather than kept private because a wallet must be able to SHOW the
 * holder what is about to leave the device before it leaves. A client that only
 * offered "present" would make that impossible without re-deriving the list,
 * and a second derivation is a second thing to disagree with the first.
 */
export function claimsRequestedBy(
  definition: PresentationDefinition,
): VerifierClaimRequest[] {
  const requests: VerifierClaimRequest[] = [];
  const seen = new Set<string>();

  for (const descriptor of definition.inputDescriptors ?? []) {
    for (const request of claimRequestsFromInputDescriptor(descriptor)) {
      if (seen.has(request.path)) continue;
      seen.add(request.path);
      requests.push(request);
    }
  }

  return requests;
}

/**
 * Expand the paths a verifier asked for into the LEAF paths a presentation
 * frame can be built from, against the credential this holder actually holds.
 *
 * ===========================================================================
 * MEASURED (R4 Phase B): NAMING A CONTAINER DISCLOSES IT **EMPTY**.
 * ===========================================================================
 * A presentation definition names claims as JSONPath — Phase A's asks for
 * `$.credentialSubject.practiceScope`. Mapped straight into a frame that is
 * `{ practiceScope: true }`, and `@sd-jwt/core` reads that as "disclose the
 * container, not its members": the verifier receives `practiceScope: []`. A
 * pharmacist with two practice scopes presents a licence asserting none, and
 * `ProfessionalLicenceSubjectSchema`'s `.min(1)` refuses it. The exchange was
 * unsatisfiable by any wallet that took the definition literally, and nothing
 * about it was visible before a request ran end to end.
 *
 * It fails CLOSED, which is why it survived Phase A: the artifact is
 * well-formed and correctly signed, it simply asserts less than it should.
 *
 * The fix is the rule `buildPresentationFrame` already documents — a container
 * is disclosed by disclosing its LEAVES — applied where the leaves are known.
 * Only the holder knows them, because only the holder has the credential; the
 * verifier cannot name `practiceScope[1]` without already knowing how many
 * scopes the licence carries. So the expansion belongs here, on the wallet
 * side, and not in the definition.
 */
function leafPathsFor(
  requested: readonly string[],
  credentialSubject: unknown,
): string[] {
  const disclosable = enumerateDisclosableClaims(credentialSubject);
  const selected = new Set<string>();

  for (const path of requested) {
    for (const claim of disclosable) {
      const isDescendant =
        claim.path === path ||
        claim.path.startsWith(`${path}.`) ||
        claim.path.startsWith(`${path}[`);
      if (isDescendant) selected.add(claim.path);
    }
  }

  return [...selected];
}

/**
 * Build and sign the presentation this challenge asks for.
 *
 * `volunteeredClaims` are paths beyond the verifier's ask. They exist because a
 * holder may have a reason to over-disclose and refusing that outright would be
 * paternalistic — but they are a separate, explicit argument, so over-disclosure
 * is never what happens when a caller passes nothing.
 */
export async function signProfessionalPresentation(
  holder: ProfessionalLicenceHolder,
  options: {
    holderDid: string;
    /** The licence as the wallet holds it: a compact `vc+sd-jwt`. */
    licence: string;
    challenge: ProfessionalChallengeResponse;
    volunteeredClaims?: readonly string[];
  },
): Promise<string> {
  const asked = claimsRequestedBy(options.challenge.definition)
    .filter((request) => request.requirement === 'required')
    .map((request) => request.path);

  // The wallet's own view of the credential, fully disclosed. Local only — it
  // is read to decide what to reveal and never leaves this function.
  const held = await holder.readLicence(options.licence);
  if (!held) {
    throw new ProfessionalPresentationError(
      'The licence in this wallet is not a readable vc+sd-jwt and cannot be presented',
      0,
      'LICENCE_UNREADABLE',
    );
  }

  const frame = buildPresentationFrame(
    leafPathsFor([...asked, ...(options.volunteeredClaims ?? [])], held.credentialSubject),
  );

  return holder.presentLicence({
    compactLicence: options.licence,
    frame,
    holderDid: options.holderDid,
    challenge: options.challenge.nonce,
    // The audience the VERIFIER named. Binding to anything else — including our
    // own idea of who we are talking to — produces a presentation this verifier
    // will correctly refuse.
    domain: options.challenge.audience,
  });
}

/** The two headers the guard reads. One spelling, used by client and test alike. */
export function professionalPresentationHeaders(
  requestId: string,
  vpToken: string,
): Record<string, string> {
  return {
    [PRESENTATION_REQUEST_HEADER]: requestId,
    [PRESENTATION_HEADER]: vpToken,
  };
}

export interface GuardedCallResult<T> {
  status: number;
  data?: T;
  error?: { code?: string; message?: string };
}

/**
 * Call a route guarded by `requireProfessional`, carrying a presentation.
 *
 * Returns the response rather than throwing on a refusal: a 403 here is an
 * ANSWER — "this licence does not authorise this action" — and a caller
 * frequently wants to show it rather than handle an exception.
 */
export async function callWithProfessionalAuthority<T = unknown>(options: {
  baseUrl: string;
  path: string;
  accessToken: string;
  requestId: string;
  presentation: string;
  body?: unknown;
  method?: string;
  fetchImpl?: typeof fetch;
}): Promise<GuardedCallResult<T>> {
  const doFetch = options.fetchImpl ?? fetch;
  const response = await doFetch(`${options.baseUrl}${options.path}`, {
    method: options.method ?? 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${options.accessToken}`,
      ...professionalPresentationHeaders(options.requestId, options.presentation),
    },
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  });

  const envelope = await readEnvelope<T>(response);

  return {
    status: response.status,
    ...(envelope.data === undefined ? {} : { data: envelope.data }),
    ...(envelope.error === undefined ? {} : { error: envelope.error }),
  };
}

/**
 * The whole exchange, for a caller that has no reason to hold the pieces:
 * challenge, present, call.
 *
 * TWO ROUND TRIPS, ALWAYS. There is deliberately no cached-challenge fast path.
 * A challenge that survives one use is a window in which a captured
 * presentation replays, and the single-use property is the only thing that
 * makes the guard's replay claim true.
 */
export async function presentProfessionalAuthority<T = unknown>(
  holder: ProfessionalLicenceHolder,
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
  const challenge = await requestProfessionalChallenge({
    baseUrl: options.baseUrl,
    accessToken: options.accessToken,
    requirement: options.requirement,
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
  });

  const presentation = await signProfessionalPresentation(holder, {
    holderDid: options.holderDid,
    licence: options.licence,
    challenge,
    ...(options.volunteeredClaims ? { volunteeredClaims: options.volunteeredClaims } : {}),
  });

  return callWithProfessionalAuthority<T>({
    baseUrl: options.baseUrl,
    path: options.path,
    accessToken: options.accessToken,
    requestId: challenge.requestId,
    presentation,
    ...(options.body === undefined ? {} : { body: options.body }),
    ...(options.method ? { method: options.method } : {}),
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
  });
}
