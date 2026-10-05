/**
 * Holder-initiated sharing: OFFER -> CHALLENGE -> PRESENTATION.
 *
 * ===========================================================================
 * WHY THERE ARE TWO ROUNDS AND NOT ONE QR OF THE CREDENTIAL
 * ===========================================================================
 * A presentation that is signed before anyone asks for it is a bearer token: a
 * screenshot of the QR can be replayed to any verifier until the clock runs
 * out. This system's whole verification boundary exists to stop exactly that —
 * the nonce and audience are signed over so a presentation is bound to ONE
 * exchange (steno #196, #200), and the SDK verifier fails closed when either is
 * missing.
 *
 * So the holder does not present first. The holder OFFERS:
 *
 *   1. OFFER (this screen's QR) — "here is what I am willing to show; talk to
 *      me". Carries claim PATHS only, no values, plus the holder's DID. It
 *      confers nothing and needs no signature: the values have not moved yet.
 *   2. CHALLENGE (the verifier's QR or deep link) — the verifier answers with
 *      `nonce` (single use) and `audience` (its identifier), and optionally a
 *      `responseUri` to receive the result.
 *   3. PRESENTATION — built by `buildPresentation` on this device, narrowed to
 *      the offered claims, signed by the holder's key, bound to the challenge's
 *      nonce and audience. It is worthless for any other exchange.
 *
 * The presentation is large (the credential alone is ~2 KB), so it is DELIVERED
 * where the challenge said to deliver it; only the small offer/challenge ever
 * travel in a QR. When a challenge names no `responseUri`, the holder sends the
 * presentation through the OS share sheet instead, and the UI says so.
 *
 * WHAT A CHALLENGE DOES NOT PROVE. It is not signed, so a party who intercepts
 * the offer could answer first with their own nonce and audience. The holder
 * sees BOTH the audience and the destination on the confirm screen before
 * anything is signed, which is the check that stops a mis-delivery; proving the
 * verifier's identity needs a signed challenge and DID resolution, and is a
 * deliberate follow-up (the exchange is versioned for it).
 */
import { bytesToBase64Url, base64UrlToBytes } from '@ssi-healthcare/shared';

import {
  buildPresentation,
  deliverPresentation,
  type BuiltPresentation,
} from './presentation';

export const PRESENTATION_OFFER_TYPE = 'ssi-presentation-offer';
export const PRESENTATION_CHALLENGE_TYPE = 'ssi-presentation-challenge';

/** Offers live long enough to walk to the verifier's desk, and no longer. */
const OFFER_TTL_SECONDS = 5 * 60;
/** A challenge is answered in-session; a stale one is a replayed one. */
const CHALLENGE_TTL_SECONDS = 2 * 60;

export class PresentationOfferError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PresentationOfferError';
  }
}

export interface PresentationOffer {
  v: 1;
  type: typeof PRESENTATION_OFFER_TYPE;
  offerId: string;
  holderDid: string;
  credentialId: string;
  credentialType: string;
  /** Claim paths only. NO VALUES — an offer may travel over any channel. */
  claims: string[];
  exp: number;
}

export interface PresentationChallenge {
  v: 1;
  type: typeof PRESENTATION_CHALLENGE_TYPE;
  offerId: string;
  /** Single-use value the presentation is signed over. */
  nonce: string;
  /** The verifier's identifier; becomes the presentation's `aud`. */
  audience: string;
  /** Optional label for the confirm screen (a name the verifier states). */
  audienceName?: string;
  /** Where to POST the finished presentation. Absent = holder sends it manually. */
  responseUri?: string;
  exp: number;
}

function uuid(): string {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const encode = (value: unknown): string =>
  bytesToBase64Url(new TextEncoder().encode(JSON.stringify(value)));

/** Read the one query parameter a deep link carries, without a URL polyfill. */
function queryParam(url: string, name: string): string | null {
  const start = url.indexOf('?');
  if (start < 0) return null;
  for (const pair of url.slice(start + 1).split('&')) {
    const [key, rawValue] = pair.split('=');
    if (key === name && rawValue) {
      try {
        return decodeURIComponent(rawValue);
      } catch {
        return rawValue;
      }
    }
  }
  return null;
}

function decodePayload(url: string, param: string): unknown {
  const encoded = queryParam(url, param);
  const payload = encoded ?? url;
  try {
    const bytes = base64UrlToBytes(payload);
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    // Not base64url — try it as JSON directly. Some scanners hand back the raw
    // object when the QR carries JSON rather than a link.
    try {
      return JSON.parse(payload);
    } catch {
      return null;
    }
  }
}

/**
 * The wrapper the INSTALLED app can actually receive.
 *
 * `exp+ssi-healthcare-wallet://` is read off the device with `dumpsys`, not
 * chosen (steno #421): there is no Android manifest to add an intent filter to
 * on this machine. The parsers below read the payload out of ANY wrapper, so a
 * production scheme needs no change here when a native build can register one.
 */
const WALLET_LINK_SCHEME = 'exp+ssi-healthcare-wallet://';

export function createPresentationOffer(args: {
  holderDid: string;
  credentialId: string;
  credentialType: string;
  claims: readonly string[];
}): { offer: PresentationOffer; url: string } {
  const offer: PresentationOffer = {
    v: 1,
    type: PRESENTATION_OFFER_TYPE,
    offerId: `urn:uuid:${uuid()}`,
    holderDid: args.holderDid,
    credentialId: args.credentialId,
    credentialType: args.credentialType,
    claims: [...args.claims],
    exp: Math.floor(Date.now() / 1000) + OFFER_TTL_SECONDS,
  };
  return { offer, url: `${WALLET_LINK_SCHEME}presentation-offer?o=${encode(offer)}` };
}

export function parseChallenge(urlOrPayload: string): PresentationChallenge | null {
  const value = decodePayload(urlOrPayload, 'c');
  if (!value || typeof value !== 'object') return null;
  const candidate = value as Partial<PresentationChallenge>;
  if (candidate.v !== 1 || candidate.type !== PRESENTATION_CHALLENGE_TYPE) return null;
  if (typeof candidate.offerId !== 'string' || candidate.offerId.length === 0) return null;
  if (typeof candidate.nonce !== 'string' || candidate.nonce.length < 16) return null;
  if (typeof candidate.audience !== 'string' || candidate.audience.length === 0) return null;
  if (typeof candidate.exp !== 'number' || candidate.exp * 1000 < Date.now()) return null;
  if (candidate.responseUri !== undefined && typeof candidate.responseUri !== 'string') return null;
  return candidate as PresentationChallenge;
}

export function parseOffer(urlOrPayload: string): PresentationOffer | null {
  const value = decodePayload(urlOrPayload, 'o');
  if (!value || typeof value !== 'object') return null;
  const candidate = value as Partial<PresentationOffer>;
  if (candidate.v !== 1 || candidate.type !== PRESENTATION_OFFER_TYPE) return null;
  if (typeof candidate.holderDid !== 'string' || typeof candidate.credentialId !== 'string') return null;
  if (!Array.isArray(candidate.claims)) return null;
  return candidate as PresentationOffer;
}

export interface PresentationDelivery extends BuiltPresentation {
  /** True when the challenge named a responseUri and the POST succeeded. */
  delivered: boolean;
  responseUri?: string;
}

/**
 * Answer a challenge: narrow to the OFFERED claims, sign, and deliver.
 *
 * The selection comes from the offer the verifier answered, not from whatever
 * happens to be toggled on screen now — an offer is a promise about what will
 * be shown, and a verifier that answered it is entitled to that exact set.
 */
export async function presentForChallenge(args: {
  offer: PresentationOffer;
  challenge: PresentationChallenge;
  credentialJwt: string;
}): Promise<PresentationDelivery> {
  if (args.challenge.offerId !== args.offer.offerId) {
    throw new PresentationOfferError(
      'That response is for a different share. Start again and scan the verifier’s response to THIS code.',
    );
  }

  const built = await buildPresentation({
    holderDid: args.offer.holderDid,
    credentialJwt: args.credentialJwt,
    audience: args.challenge.audience,
    nonce: args.challenge.nonce,
    // The holder-initiated exchange targets the SDK verifier's envelope
    // (`vp+sd-jwt`), which is what the wallet, the HMS and any adopting
    // relying party in this system can read. The verifier-initiated path keeps
    // complying with whatever the request declared.
    vpFormat: 'vp+sd-jwt',
    consent: {
      verifierName: args.challenge.audienceName ?? args.challenge.audience,
      purpose: 'You chose to share these claims with this verifier.',
      purposeCategory: 'holder-initiated',
      credentialTypes: [args.offer.credentialType],
      holderSelectedClaims: args.offer.claims,
      // The verifier requested NOTHING: it answered an offer. Recording the
      // offer here would report the holder's own selection back as if the
      // verifier had asked for it, which is the kind of over-claim a signed
      // receipt must never make.
      requestedClaims: [],
      requestId: args.offer.offerId,
    },
  });

  if (!args.challenge.responseUri) {
    return { ...built, delivered: false };
  }

  await deliverPresentation({
    responseUri: args.challenge.responseUri,
    vpToken: built.vpToken,
    consentReceipt: built.consentReceipt,
    state: args.offer.offerId,
  });

  return { ...built, delivered: true, responseUri: args.challenge.responseUri };
}
