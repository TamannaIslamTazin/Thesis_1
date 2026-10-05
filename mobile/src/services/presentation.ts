/**
 * Present a credential over OID4VP, signed ON THIS DEVICE.
 *
 * WHAT THIS REPLACES, AND WHY IT HAD TO GO.
 * `SSIClient.presentCredentials` posted `{ requestId, credentials: [{ id,
 * disclosedAttributes }] }` to `POST /api/verification/submit`. Two things were
 * wrong with that, and the second is the serious one:
 *
 *   1. THE ROUTE DOES NOT EXIST. `verification.ts` was retired; nothing mounts
 *      it. Measured 8 Sep 2026 — the wallet's share landed on a 404 and the
 *      holder was told "The requested endpoint does not exist." This is the
 *      dead-client-route class recorded in steno #336/#338, reaching the wallet.
 *
 *   2. IT SENT ATTRIBUTE NAMES AND LET THE SERVER BUILD AND SIGN THE
 *      PRESENTATION. That is a custodian holding the holder's key and asserting
 *      on their behalf — the shape the on-device holder ruling (#331) exists to
 *      remove. A presentation the holder did not sign proves nothing about the
 *      holder.
 *
 * So the wallet builds the VP itself and posts it to `POST /oid4vp/response`,
 * which is unauthenticated by design: the signature IS the authentication, and
 * requiring a session on top would say the server's opinion of who you are
 * matters more than your key.
 *
 * THE SIGNATURE IS THE POSSESSION PROOF. `nonce` and `aud` come from the
 * verifier's own request and are signed over, so the verifier can bind this
 * presentation to the exchange it started. That is the same property a KB-JWT
 * would give and it is why the backend boundary checks both (steno #196/#200).
 */
import {
  bytesToBase64Url,
  base64UrlToBytes,
  buildConsentReceiptPayload,
  signConsentReceipt,
} from '@ssi-healthcare/shared';

import { prepareDeviceSigner } from './deviceSigner';
import { narrowToSelection, claimsRevealedBy, isSdJwtCredential } from './selectiveDisclosure';

/** The fields of a parsed OID4VP authorization request that presenting needs. */
export interface Oid4vpRequest {
  client_id?: string;
  /**
   * What the verifier says it can read. See `preferredVpFormat`.
   */
  client_metadata?: {
    client_name?: string;
    vp_formats?: Record<string, unknown>;
  };
  redirect_uri?: string;
  response_uri?: string;
  nonce?: string;
  state?: string;
  presentation_definition?: {
    id?: string;
    input_descriptors?: Array<{ id?: string }>;
  };
}

export class PresentationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PresentationError';
  }
}

const b64uJson = (value: unknown): string =>
  bytesToBase64Url(new TextEncoder().encode(JSON.stringify(value)));

/** A v4 UUID from the same CSPRNG the seeds use. */
function uuid(): string {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Every claim path readable in the credential ACTUALLY BEING SENT.
 *
 * Derived by decoding the compact JWT itself rather than from the wallet's
 * in-memory model of it, because the receipt attests to what the verifier can
 * read and the only unfalsifiable source for that is the bytes on the wire.
 *
 * This is what makes the over-disclosure countable. A `vc+jwt` credential has
 * no SD-JWT disclosures, so the whole `credentialSubject` travels no matter
 * which switches the holder left off; the receipt records that plainly instead
 * of restating the holder's selection as though it had been enforced (#360).
 */
export function transmittedClaimPaths(credentialJwt: string): string[] {
  try {
    const payloadB64 = credentialJwt.split('.')[1];
    if (!payloadB64) return [];
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64)));
    const subject = payload?.credentialSubject ?? {};
    const paths: string[] = [];
    const walk = (value: unknown, prefix: string) => {
      if (Array.isArray(value)) {
        value.forEach((entry, i) => walk(entry, `${prefix}[${i}]`));
      } else if (value !== null && typeof value === 'object') {
        for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
          walk(child, prefix ? `${prefix}.${key}` : key);
        }
      } else if (prefix) {
        // `_sd` holds DIGESTS of claims that are not present. Listing them would
        // report withheld claims as disclosed — the precise inversion this whole
        // module exists to prevent.
        if (!prefix.startsWith('_sd') && !prefix.includes('._sd')) paths.push(prefix);
      }
    };
    walk(subject, '');
    return paths;
  } catch {
    // An unreadable credential means we cannot honestly state what was sent.
    // Empty is the safe answer: it never CLAIMS minimisation that did not happen.
    return [];
  }
}

/**
 * Which presentation envelope this verifier can actually read.
 *
 * TWO VERIFIERS, TWO ENVELOPES, AND NEITHER IS A SUPERSET (steno #341). The
 * BDHealthTrust backend reads a W3C `vp+jwt`; the SDK verifier — which the HMS
 * and any third-party relying party use — reads a `vp+sd-jwt` and refuses
 * anything else, because a `vp+jwt` carries no SD-JWT structure for it to check.
 * Sending one shape to both means one of them refuses every presentation, which
 * is what happened: the HMS answered "Presentation is not a well-formed SD-JWT
 * artifact" for a login the wallet considered successful.
 *
 * So the VERIFIER declares what it reads and the wallet complies, rather than
 * the wallet guessing. Absent a declaration the default stays `vp+jwt`, because
 * that is what the deployed backend speaks and silently changing it would break
 * the path that works.
 *
 * The two envelopes are otherwise the SAME payload — same holder, same nonce,
 * same aud, same enveloped `vc+sd-jwt` credential. Only the header `typ` and the
 * trailing separator differ.
 */
function preferredVpFormat(request: Oid4vpRequest): 'vp+jwt' | 'vp+sd-jwt' {
  const formats = request.client_metadata?.vp_formats;
  if (formats && Object.keys(formats).some((f) => f.toLowerCase().includes('sd-jwt'))) {
    return 'vp+sd-jwt';
  }
  return 'vp+jwt';
}

/**
 * Read the fields presenting depends on, refusing rather than defaulting.
 *
 * A missing `nonce` or `client_id` would produce a presentation bound to
 * nothing — it would still verify as a signature and mean nothing as an
 * authorisation, which is precisely the failure the verifier boundary was built
 * to catch. Better to refuse here, where the cause is legible.
 */
function requireRequestFields(request: Oid4vpRequest) {
  const audience = request.client_id;
  const nonce = request.nonce;
  const responseUri = request.response_uri ?? request.redirect_uri;
  const state = request.state;

  const missing = [
    !audience && 'client_id',
    !nonce && 'nonce',
    !responseUri && 'redirect_uri',
    !state && 'state',
  ].filter(Boolean);

  if (missing.length > 0) {
    throw new PresentationError(
      `This verification request is incomplete — it is missing ${missing.join(', ')}. ` +
        'Ask the verifier for a new code.',
    );
  }
  return { audience: audience!, nonce: nonce!, responseUri: responseUri!, state: state! };
}

/**
 * Build and submit the presentation.
 *
 * `credentialJwt` is the SIGNED artifact, not the rendered JSON. A VC 2.0
 * credential carries its signature only in the envelope, so presenting the
 * data-model object would present something with no proof attached at all
 * (steno #185 is why the wallet holds this at all).
 */
/** The values a verifier's request normally supplies to bind a presentation. */
export interface BuildPresentationArgs {
  holderDid: string;
  credentialJwt: string;
  /** The party that will verify. MUST be the value the verifier expects. */
  audience: string;
  /** The verifier's single-use value. This is what stops replay. */
  nonce: string;
  /** Which envelope the verifier can read; defaults to `vp+jwt`. */
  vpFormat?: 'vp+jwt' | 'vp+sd-jwt';
  /** Everything the consent receipt needs to describe this disclosure. */
  consent: {
    verifierName: string;
    /** The verifier's own words, or the holder's description of a self-started share. */
    purpose: string;
    purposeCategory: string;
    credentialTypes: string[];
    /** What the holder chose in the disclosure sheet. THIS IS ENFORCED, not recorded. */
    holderSelectedClaims: string[];
    /** What the verifier stated it needed. */
    requestedClaims: string[];
    /** The exchange this belongs to, for the receipt. */
    requestId: string;
  };
}

export interface BuiltPresentation {
  vpToken: string;
  consentReceipt: string;
  receiptId: string;
  /** What the verifier can actually read, derived from the narrowed bytes. */
  disclosedClaims: string[];
  minimisationEnforced: boolean;
}

/**
 * Build and sign the presentation. THIS IS THE HOLDER'S ACT OF CONSENT.
 *
 * Split out of `presentOverOid4vp` for the holder-initiated exchange, which
 * has no OID4VP request to read `nonce`/`aud` from: it receives them from the
 * verifier's challenge instead. Everything here — narrow-first, holder binding,
 * the receipt signed inside the same unlocked session — is shared with the
 * verifier-initiated path so the two cannot drift.
 */
export async function buildPresentation(args: BuildPresentationArgs): Promise<BuiltPresentation> {
  const { audience, nonce } = args;

  if (!args.credentialJwt) {
    throw new PresentationError(
      'This credential has no signed envelope on this device, so it cannot be presented.',
    );
  }

  // NARROW FIRST, SIGN SECOND.
  //
  // The holder's selection is applied to the credential BEFORE it is placed
  // inside the presentation, so what the holder's signature commits to is the
  // narrowed artifact. Doing it the other way round would sign the whole
  // credential and then hope the verifier ignored part of it, which is not
  // disclosure control — it is a request for discretion.
  const narrowed = narrowToSelection(args.credentialJwt, args.consent.holderSelectedClaims);
  const mediaType = isSdJwtCredential(narrowed.compact)
    ? 'application/vc+sd-jwt'
    : 'application/vc+jwt';

  // ONE biometric prompt, taken before any of the signing work — see
  // `prepareDeviceSigner` for why the prompt must not sit inside signing.
  const signer = await prepareDeviceSigner();
  let vpToken: string;
  let consentReceipt: string;
  let receiptId: string;
  let transmitted: string[];
  try {
    const now = Math.floor(Date.now() / 1000);
    const vpFormat = args.vpFormat ?? 'vp+jwt';
    const header = { alg: 'EdDSA', typ: vpFormat, kid: `${args.holderDid}#key-1` };
    // THE PAYLOAD IS THE PRESENTATION, FLATTENED. VC 2.0 dropped the `vp`
    // wrapper that VC 1.1 nested everything under; Credo's `W3cV2Presentation`
    // validates the TOP LEVEL, so a `vp`-wrapped payload is rejected with
    // "context must be an array of strings or objects" — an error that points
    // at the context and is really about the shape one level up.
    //
    // And `verifiableCredential` entries are ENVELOPED CREDENTIAL OBJECTS, not
    // bare compact strings: Credo requires `W3cV2EnvelopedVerifiableCredential`,
    // whose `id` is a `data:` URI carrying the whole compact JWT. That is also
    // what binds the disclosure set to the holder's signature — the credential
    // is inside the signed payload rather than referenced beside it (#344).
    const payload = {
      iss: args.holderDid,
      aud: audience,
      nonce,
      iat: now,
      // Deliberately short. A presentation is for one exchange; a long-lived
      // one is a bearer token for anyone who captures it.
      exp: now + 300,
      jti: `urn:uuid:${uuid()}`,
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: args.holderDid,
      verifiableCredential: [
        {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          // THE NARROWED artifact, under the media type it actually is. Sending
          // `args.credentialJwt` here is what shipped every claim regardless of
          // the disclosure sheet, and mislabelling an SD-JWT as `vc+jwt` makes
          // the verifier read it with a decoder that succeeds on a husk.
          id: `data:${mediaType},${narrowed.compact}`,
          type: 'EnvelopedVerifiableCredential',
        },
      ],
    };

    const signingInput = `${b64uJson(header)}.${b64uJson(payload)}`;
    const signature = await signer.sign(new TextEncoder().encode(signingInput));
    // The trailing `~` is what makes this an SD-JWT artifact rather than a bare
    // JWS: the SD-JWT reader splits on it, and a verifier that gates on
    // "contains a separator" rejects the signature without it. Zero disclosures
    // at the PRESENTATION layer is correct — the credential inside carries them.
    vpToken =
      vpFormat === 'vp+sd-jwt'
        ? `${signingInput}.${signature}~`
        : `${signingInput}.${signature}`;

    // THE CONSENT RECEIPT, SIGNED HERE — inside the same unlocked signer
    // session, so consenting costs the holder no second biometric prompt and,
    // more importantly, cannot silently be skipped: the receipt is produced by
    // the same act that produces the presentation.
    //
    // It is signed AFTER the vp_token exists because it commits to that exact
    // token's hash. A receipt built before would have to describe a disclosure
    // that had not been constructed yet, and could then be paired with a
    // different one (steno #279).
    receiptId = `urn:uuid:${uuid()}`;
    // What the verifier can read, from the NARROWED bytes: the claims still
    // present in the signed payload, plus the disclosures that survived.
    transmitted = Array.from(
      new Set([...transmittedClaimPaths(narrowed.compact), ...claimsRevealedBy(narrowed.compact)]),
    );
    consentReceipt = await signConsentReceipt(
      buildConsentReceiptPayload({
        holderDid: args.holderDid,
        verifierDid: audience,
        verifierName: args.consent.verifierName,
        purpose: args.consent.purpose,
        purposeCategory: args.consent.purposeCategory,
        credentialTypes: args.consent.credentialTypes,
        disclosedClaims: transmitted,
        holderSelectedClaims: args.consent.holderSelectedClaims,
        requestedClaims: args.consent.requestedClaims,
        // Reported by the narrowing itself, from what it could actually do to
        // this artifact — never asserted by this call site. A `vc+jwt` still
        // cannot be narrowed, and saying otherwise in a SIGNED receipt would be
        // the worst kind of over-claim.
        minimisationEnforced: narrowed.minimisationEnforced,
        requestId: args.consent.requestId,
        nonce,
        vpToken,
        receiptId,
      }),
      `${args.holderDid}#key-1`,
      (input) => signer.sign(input),
    );
  } finally {
    signer.dispose();
  }

  return {
    vpToken,
    consentReceipt,
    receiptId,
    disclosedClaims: transmitted,
    minimisationEnforced: narrowed.minimisationEnforced,
  };
}

/** Submit a built presentation to the verifier's OID4VP endpoint. */
export async function deliverPresentation(args: {
  responseUri: string;
  vpToken: string;
  consentReceipt: string;
  state: string;
  presentationDefinitionId?: string;
  descriptorId?: string;
}): Promise<void> {
  const submission = {
    id: uuid(),
    definition_id: args.presentationDefinitionId ?? args.state,
    descriptor_map: [
      {
        id: args.descriptorId ?? 'descriptor_0',
        format: 'jwt_vp',
        path: '$',
        path_nested: { format: 'jwt_vc', path: '$.verifiableCredential[0]' },
      },
    ],
  };

  const res = await fetch(args.responseUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      vp_token: args.vpToken,
      presentation_submission: submission,
      state: args.state,
      // A SEPARATE PARAMETER beside the presentation, never a second credential
      // inside it — that is the whole point of the receipt being a JWS.
      consent_receipt: args.consentReceipt,
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new PresentationError(
      `The verifier refused the presentation (status ${res.status}): ${body.slice(0, 300)}`,
    );
  }
}

/**
 * Build and submit the presentation for a verifier's OID4VP request.
 *
 * `credentialJwt` is the SIGNED artifact, not the rendered JSON. A VC 2.0
 * credential carries its signature only in the envelope, so presenting the
 * data-model object would present something with no proof attached at all
 * (steno #185 is why the wallet holds this at all).
 */
export async function presentOverOid4vp(args: {
  request: Oid4vpRequest;
  holderDid: string;
  credentialJwt: string;
  /** Everything the consent receipt needs to describe this disclosure. */
  consent: {
    verifierName: string;
    /** The verifier's own words. */
    purpose: string;
    /** Our lossy five-value enum, for querying. */
    purposeCategory: string;
    credentialTypes: string[];
    /** What the holder chose in the disclosure sheet. THIS IS ENFORCED, not recorded. */
    holderSelectedClaims: string[];
    /** What the verifier stated it needed. */
    requestedClaims: string[];
  };
}): Promise<{ receiptId: string }> {
  const { audience, nonce, responseUri, state } = requireRequestFields(args.request);

  const built = await buildPresentation({
    holderDid: args.holderDid,
    credentialJwt: args.credentialJwt,
    audience,
    nonce,
    vpFormat: preferredVpFormat(args.request),
    consent: { ...args.consent, requestId: state },
  });

  await deliverPresentation({
    responseUri,
    vpToken: built.vpToken,
    consentReceipt: built.consentReceipt,
    state,
    presentationDefinitionId: args.request.presentation_definition?.id,
    descriptorId: args.request.presentation_definition?.input_descriptors?.[0]?.id,
  });

  return { receiptId: built.receiptId };
}