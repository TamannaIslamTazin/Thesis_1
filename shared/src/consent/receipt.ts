/**
 * The holder-signed consent receipt (steno #279).
 *
 * WHY A JWS AND NOT A VERIFIABLE CREDENTIAL.
 * Consent was specified as a receipt the HOLDER signs, deliberately not as a
 * W3C credential. Three reasons, and the first is structural:
 *
 *   1. A receipt rides beside the presentation as its own parameter, so Credo's
 *      one-credential-per-VC-2.0-presentation limit never applies and the
 *      sequential-presentation mix-and-match surface never opens.
 *   2. Issuing a credential would make every patient an issuer, which the DID
 *      shapes forbid: a patient DID is 2-of-2 controlled, and `x/resource`
 *      applies the SUBJECT's controller set, so it cannot publish a status list
 *      and therefore cannot issue (#313).
 *   3. It avoids a status-list chain write per consent — consent is high
 *      frequency and block latency already dominates issuance (#318).
 *
 * WHY THIS CAN EXIST NOW AND COULD NOT BEFORE.
 * The sequencing in #279 was deliberate: a consent "signed by the holder" with
 * a key the BACKEND holds proves nothing at all — it is the operator asserting
 * that the patient agreed. It became meaningful only when signing moved onto
 * the handset. The same device key that signs the presentation signs this.
 *
 * WHAT THE RECEIPT IS BOUND TO, AND WHY EACH BINDING IS LOAD-BEARING.
 * A receipt that says only "I consented" is a generic grant: it can be replayed
 * to justify a disclosure the holder never made. So it carries
 *
 *   - `nonce` and `requestId`  — the exchange it belongs to,
 *   - `vpTokenHash`            — the EXACT bytes that were presented,
 *   - `disclosedClaims`        — what actually left the device.
 *
 * With `vpTokenHash` the receipt cannot be moved to a different disclosure even
 * between the same two parties, because the hash would not recompute.
 *
 * THE VERIFIER'S OWN WORDS ARE CARRIED VERBATIM. `purposeCategory` is our
 * five-value enum and is lossy by construction — a pharmacy asking to "confirm
 * this is your health identity before dispensing" is not "TREATMENT", it is
 * merely nearest to it. `purpose` holds what the verifier actually said. The
 * enum is for querying; the text is the record.
 *
 * Field names follow Kantara Consent Receipt v1.1 (ISO/IEC 29184) where one
 * exists, so this is legible to a reviewer who knows that specification.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';

import { bytesToBase64Url, base64UrlToBytes } from '../recovery/base64Url.js';

/** JOSE `typ`. Distinct from `vp+jwt` so a receipt can never be read as a presentation. */
export const CONSENT_RECEIPT_TYP = 'consent-receipt+jwt';

/** Kantara Consent Receipt specification version this payload models. */
export const CONSENT_RECEIPT_SPEC_VERSION = 'KI-CR-v1.1.0';

/** How stale a receipt may be when it reaches the verifier. */
export const CONSENT_RECEIPT_MAX_AGE_SECONDS = 600;

/** Clock skew allowed for a receipt dated in the future. */
export const CONSENT_RECEIPT_MAX_SKEW_SECONDS = 60;

export interface ConsentReceiptPurpose {
  /** The verifier's own words, verbatim. */
  purpose: string;
  /** Our enum. Lossy — see the header. */
  purposeCategory: string;
  /** Kantara: consent was explicit, not inferred from use. */
  consentType: 'EXPLICIT';
  /**
   * WHAT THE VERIFIER CAN ACTUALLY READ — not what the holder selected.
   *
   * These must be the claims genuinely present in the transmitted credential.
   * Recording the holder's SELECTION here would make the receipt a signed
   * assertion of a minimisation that may not have happened: a `vc+jwt`
   * credential carries no disclosures to withhold, so the whole subject travels
   * regardless of which switches the holder left off. A receipt that overstates
   * privacy is worse than none, because it is cryptographically attested.
   */
  piiCategory: string[];
  primaryPurpose: boolean;
  /**
   * ISO timestamp after which this consent no longer stands.
   *
   * For a one-time disclosure this EQUALS the consent timestamp, and that is
   * the honest statement rather than a degenerate one: the consent covered a
   * single act which is complete by the time the receipt is written. Claiming a
   * 24-hour term would describe a standing permission that does not exist and
   * cannot be exercised — nothing re-fetches anything.
   */
  termination: string;
  /**
   * Whether anything continues after this receipt.
   *
   * `one-time-disclosure` means the verifier already holds the claims and no
   * further access flows from this consent. It is the honest description of a
   * presentation, and it is what tells a wallet not to offer a "revoke" that
   * cannot un-send what was sent.
   */
  consentKind: 'one-time-disclosure' | 'standing-access';
  thirdPartyDisclosure: boolean;
}

export interface ConsentReceiptPayload {
  /** The holder signs their own consent, so they are both issuer and subject. */
  iss: string;
  sub: string;
  /** The verifier this consent is addressed to. */
  aud: string;
  iat: number;
  exp: number;
  /** Kantara `consentReceiptID`. */
  jti: string;

  version: typeof CONSENT_RECEIPT_SPEC_VERSION;
  jurisdiction: string;
  collectionMethod: string;
  language: string;

  piiControllers: Array<{ piiController: string; did: string }>;
  services: Array<{ service: string; purposes: ConsentReceiptPurpose[] }>;

  /** Health data is special category under GDPR Art. 9 and ISO/IEC 29184. */
  sensitive: boolean;
  spiCat: string[];

  /** What this receipt is evidence ABOUT. See the header. */
  presentation: {
    requestId: string;
    nonce: string;
    /** `sha-256:<base64url>` over the exact vp_token bytes. */
    vpTokenHash: string;
    credentialTypes: string[];
    /** Truth: every claim readable by the verifier in what was sent. */
    disclosedClaims: string[];
    /** Intent: the claims the holder chose in the disclosure sheet. */
    holderSelectedClaims: string[];
    /** The ask: the claims the verifier stated it needed. */
    requestedClaims: string[];
    /**
     * Whether the holder's selection was CRYPTOGRAPHICALLY enforced.
     *
     * False means the wallet's disclosure sheet expressed a preference the
     * securing mechanism could not carry — currently the case for `vc+jwt`
     * credentials, which have no SD-JWT disclosures (steno #360). When this is
     * false and `disclosedClaims` exceeds `holderSelectedClaims`, the gap IS the
     * over-disclosure, and it is recorded here precisely so it stays countable
     * instead of silently contradicting what the holder was shown.
     */
    minimisationEnforced: boolean;
  };
}

/** `sha-256:<base64url>` over the exact bytes of a compact token. */
export function hashVpToken(vpToken: string): string {
  return `sha-256:${bytesToBase64Url(sha256(new TextEncoder().encode(vpToken)))}`;
}

const b64uJson = (value: unknown): string =>
  bytesToBase64Url(new TextEncoder().encode(JSON.stringify(value)));

export function buildConsentReceiptPayload(args: {
  holderDid: string;
  verifierDid: string;
  verifierName: string;
  purpose: string;
  purposeCategory: string;
  credentialTypes: string[];
  /** Every claim readable in the credential actually transmitted. */
  disclosedClaims: string[];
  holderSelectedClaims: string[];
  requestedClaims: string[];
  minimisationEnforced: boolean;
  requestId: string;
  nonce: string;
  vpToken: string;
  receiptId: string;
  /**
   * How long the consent stands, in seconds. DEFAULTS TO ZERO — a disclosure is
   * over when it happens. Pass a duration only where access genuinely continues.
   */
  durationSeconds?: number;
  jurisdiction?: string;
  now?: number;
}): ConsentReceiptPayload {
  const iat = args.now ?? Math.floor(Date.now() / 1000);
  const durationSeconds = args.durationSeconds ?? 0;
  const consentKind = durationSeconds > 0 ? 'standing-access' : 'one-time-disclosure';

  return {
    iss: args.holderDid,
    sub: args.holderDid,
    aud: args.verifierDid,
    iat,
    // The RECEIPT is short-lived as a transport artifact; the CONSENT it
    // records stands until `termination`. Conflating the two would either make
    // the receipt replayable for a day or expire the consent in five minutes.
    exp: iat + 300,
    jti: args.receiptId,

    version: CONSENT_RECEIPT_SPEC_VERSION,
    jurisdiction: args.jurisdiction ?? 'BD',
    collectionMethod: 'oid4vp-presentation',
    language: 'en',

    piiControllers: [{ piiController: args.verifierName, did: args.verifierDid }],
    services: [
      {
        service: args.credentialTypes.join(', ') || 'Credential verification',
        purposes: [
          {
            purpose: args.purpose,
            purposeCategory: args.purposeCategory,
            consentType: 'EXPLICIT',
            piiCategory: args.disclosedClaims,
            primaryPurpose: true,
            termination: new Date((iat + durationSeconds) * 1000).toISOString(),
            consentKind,
            thirdPartyDisclosure: false,
          },
        ],
      },
    ],

    sensitive: true,
    spiCat: ['health'],

    presentation: {
      requestId: args.requestId,
      nonce: args.nonce,
      vpTokenHash: hashVpToken(args.vpToken),
      credentialTypes: args.credentialTypes,
      disclosedClaims: args.disclosedClaims,
      holderSelectedClaims: args.holderSelectedClaims,
      requestedClaims: args.requestedClaims,
      minimisationEnforced: args.minimisationEnforced,
    },
  };
}

/**
 * Sign a receipt with an INJECTED signer.
 *
 * The signing function is passed in rather than a key: on the handset the seed
 * lives behind `requireAuthentication` in the keystore and is never handed to a
 * caller, so a signature is the only thing that can cross this boundary.
 */
export async function signConsentReceipt(
  payload: ConsentReceiptPayload,
  verificationMethodId: string,
  sign: (signingInput: Uint8Array) => Promise<string>,
): Promise<string> {
  const header = { alg: 'EdDSA', typ: CONSENT_RECEIPT_TYP, kid: verificationMethodId };
  const signingInput = `${b64uJson(header)}.${b64uJson(payload)}`;
  const signature = await sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${signature}`;
}

export interface ConsentReceiptChecks {
  /** `alg` is EdDSA, `typ` is a consent receipt, `kid` is present. */
  header: boolean;
  /** The DID part of `kid` is the holder. Attribution is by VM ID PREFIX (#281). */
  holderAttribution: boolean;
  signature: boolean;
  /** `iss` and `sub` are the holder. */
  holderBinding: boolean;
  /** `aud` is the verifier that asked. */
  verifierBinding: boolean;
  /** `nonce` and `requestId` match the exchange. */
  exchangeBinding: boolean;
  /** `vpTokenHash` recomputes over the presented bytes. */
  presentationBinding: boolean;
  freshness: boolean;
}

export interface ConsentReceiptVerification {
  verified: boolean;
  checks: ConsentReceiptChecks;
  errors: string[];
  payload?: ConsentReceiptPayload;
}

/**
 * Verify a receipt, FAILING CLOSED on every check.
 *
 * Absence is failure, never a skip. That is the whole lesson of the Credo
 * boundary (#196): `challenge` and `domain` were "not read" rather than
 * "rejected when missing", and the result was a replayable presentation that
 * reported itself valid. Every field below is compared unconditionally, and a
 * receipt missing one fails on that check rather than bypassing it.
 *
 * The public key is supplied by the caller, which resolves the holder's DID
 * document and confirms the verification method is in `authentication`. Keeping
 * resolution out of here is what lets the same module run on the handset.
 */
export function verifyConsentReceipt(
  jws: string,
  holderPublicKey: Uint8Array,
  expected: {
    holderDid: string;
    verifierDid: string;
    requestId: string;
    nonce: string;
    vpToken: string;
    now?: number;
  },
): ConsentReceiptVerification {
  const checks: ConsentReceiptChecks = {
    header: false,
    holderAttribution: false,
    signature: false,
    holderBinding: false,
    verifierBinding: false,
    exchangeBinding: false,
    presentationBinding: false,
    freshness: false,
  };
  const errors: string[] = [];

  const parts = jws.split('.');
  if (parts.length !== 3) {
    errors.push('Consent receipt is not a compact JWS with three segments');
    return { verified: false, checks, errors };
  }
  const [headerB64, payloadB64, signatureB64] = parts;

  let header: { alg?: string; typ?: string; kid?: string };
  let payload: ConsentReceiptPayload;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(headerB64!)));
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64!)));
  } catch {
    errors.push('Consent receipt header or payload is not readable JSON');
    return { verified: false, checks, errors };
  }

  if (header.alg !== 'EdDSA') errors.push(`Consent receipt alg must be EdDSA, got ${header.alg}`);
  else if (header.typ !== CONSENT_RECEIPT_TYP)
    errors.push(`Consent receipt typ must be ${CONSENT_RECEIPT_TYP}, got ${header.typ}`);
  else if (!header.kid) errors.push('Consent receipt carries no kid, so it attributes to nobody');
  else checks.header = true;

  // ATTRIBUTION BY VM ID PREFIX, never by a controller field. This is the same
  // rule the chain applies and the same one Credo gets wrong: a patient DID's
  // verification method is controlled by the RECOVERY CONTROLLER, so comparing
  // controllers would reject every legitimate patient receipt (#281, #313).
  const kidDid = header.kid?.split('#')[0];
  if (kidDid && kidDid === expected.holderDid) checks.holderAttribution = true;
  else errors.push(`Consent receipt signed by ${kidDid ?? 'nobody'}, expected ${expected.holderDid}`);

  try {
    checks.signature = ed25519.verify(
      base64UrlToBytes(signatureB64!),
      new TextEncoder().encode(`${headerB64}.${payloadB64}`),
      holderPublicKey,
    );
  } catch {
    checks.signature = false;
  }
  if (!checks.signature) errors.push('Consent receipt signature does not verify');

  if (payload.iss === expected.holderDid && payload.sub === expected.holderDid)
    checks.holderBinding = true;
  else errors.push('Consent receipt iss/sub is not the holder that presented');

  if (payload.aud === expected.verifierDid) checks.verifierBinding = true;
  else errors.push(`Consent receipt aud is ${payload.aud}, expected ${expected.verifierDid}`);

  if (
    payload.presentation?.requestId === expected.requestId &&
    payload.presentation?.nonce === expected.nonce
  )
    checks.exchangeBinding = true;
  else errors.push('Consent receipt is not bound to this request and nonce');

  if (payload.presentation?.vpTokenHash === hashVpToken(expected.vpToken))
    checks.presentationBinding = true;
  else
    errors.push(
      'Consent receipt vpTokenHash does not match the presented token — ' +
        'this receipt was written for a different disclosure',
    );

  const now = expected.now ?? Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== 'number') errors.push('Consent receipt has no iat');
  else if (payload.iat > now + CONSENT_RECEIPT_MAX_SKEW_SECONDS)
    errors.push('Consent receipt is dated in the future');
  else if (now - payload.iat > CONSENT_RECEIPT_MAX_AGE_SECONDS)
    errors.push('Consent receipt is too old to belong to this exchange');
  else checks.freshness = true;

  const verified = Object.values(checks).every(Boolean);
  return { verified, checks, errors, payload: verified ? payload : undefined };
}
