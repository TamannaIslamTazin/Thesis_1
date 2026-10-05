/**
 * OID4VCI Holder Client
 *
 * Implements the OID4VCI Pre-Authorized Code Flow from the holder (wallet) side.
 *
 *   - Internal offers: created by the SSI backend (looked up via
 *     /api/credentials/resolve-offer). SUPPORTED.
 *   - External offers: created by a 3rd-party issuer (hospital, clinic, etc.).
 *     DISABLED — planned, not abandoned. The backend has no
 *     /api/credentials/store-external route, so this flow dead-ended on a 404
 *     after already burning the single-use pre-authorized code. See the block
 *     comment above `EXTERNAL_ISSUER_UNSUPPORTED_MESSAGE` for the full note and
 *     the revival checklist. OpenDiscussion §P4, steno #193.
 */

const SSI_BACKEND_URL =
  typeof window !== 'undefined'
    ? window.location.origin
    : process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3000';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ParsedCredentialOffer {
  credentialIssuer: string;
  credentials: string[];
  preAuthorizedCode: string;
  pinRequired: boolean;
  /** True when the issuer is the SSI backend itself */
  isInternal: boolean;
}

export interface IssuerMetadata {
  credential_issuer: string;
  credential_endpoint: string;
  token_endpoint?: string;
  credentials_supported?: Record<string, unknown>[];
  display?: { name?: string; locale?: string }[];
}

export interface OID4VCITokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  c_nonce?: string;
}

export interface ReceivedCredential {
  id: string;
  type: string[];
  issuerDid: string;
  issuerName: string;
  issuedAt: string;
  expiresAt: string | null;
  credentialData: Record<string, unknown>;
  rawJwt?: string;
}

// ---------------------------------------------------------------------------
// Parse openid-credential-offer:// URI
// ---------------------------------------------------------------------------

export function parseCredentialOfferUri(raw: string): ParsedCredentialOffer | null {
  try {
    const normalized = raw.startsWith('openid-credential-offer://')
      ? raw.replace('openid-credential-offer://', 'https://placeholder/')
      : raw;

    const url = new URL(normalized);

    // The offer may be inline (credential_offer param) or by reference (credential_offer_uri)
    const offerParam = url.searchParams.get('credential_offer');
    if (!offerParam) return null;

    const offer = JSON.parse(offerParam) as {
      credential_issuer?: string;
      credentials?: string[];
      grants?: Record<string, { 'pre-authorized_code'?: string; user_pin_required?: boolean }>;
    };

    const credentialIssuer = offer.credential_issuer ?? '';
    const credentials = offer.credentials ?? [];
    const grantKey = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
    const grant = offer.grants?.[grantKey];
    const preAuthorizedCode = grant?.['pre-authorized_code'] ?? '';
    const pinRequired = grant?.user_pin_required ?? false;

    if (!preAuthorizedCode) return null;

    // Determine if this is an internal SSI-backend offer
    const isInternal =
      !credentialIssuer ||
      credentialIssuer.startsWith(SSI_BACKEND_URL) ||
      credentialIssuer === 'self' ||
      // For dev: accept backend port 3001
      credentialIssuer.includes('localhost:3001') ||
      credentialIssuer.includes('localhost:3000');

    return { credentialIssuer, credentials, preAuthorizedCode, pinRequired, isInternal };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Internal SSI backend flow helpers (thin wrappers, real work in api/index.ts)
// ---------------------------------------------------------------------------

export interface InternalResolvedOffer {
  offerId: string;
  credentialType: string;
  issuerDid: string;
  issuerName: string;
  previewData: Record<string, unknown>;
  pinRequired: boolean;
  expiresAt: string;
}

// THIRD-PARTY CREDENTIAL IMPORT IS DISABLED — PLANNED, NOT ABANDONED.
// Owner's ruling: OpenDiscussion §P4, steno #193.
//
// The backend has no `POST /api/credentials/store-external` route, so this flow
// dead-ended on a 404 at the LAST step — after the wallet had discovered the
// issuer, redeemed the pre-authorized code and pulled the credential down. A
// pre-authorized code is single-use, so the user lost the offer AND got an
// error. Hence the two functions below refuse BEFORE any network call, and
// `scan/page.tsx` refuses earlier still, at scan time.
//
// The implementation and the ordered revival checklist are real code at
// Backup/SSI_healthcare/packages/web/src/lib/api/oid4vciClient.external-flow.ts.bak

/**
 * Why third-party import is refused. Surfaced verbatim to the user, so it says
 * "not yet" rather than implying the issuer or the QR code is at fault.
 */
export const EXTERNAL_ISSUER_UNSUPPORTED_MESSAGE =
  'Importing credentials from an outside issuer is not available yet. ' +
  'This wallet can currently receive credentials issued through BD Health Trust. ' +
  'Support for third-party issuers is planned.';

/**
 * Full OID4VCI Pre-Authorized Code Flow for an **external** issuer.
 *
 * DISABLED. Fails closed, and fails FIRST: it throws before contacting the
 * issuer, so a single-use pre-authorized code is not burned on a flow that
 * cannot complete. Kept as a function rather than deleted so every existing
 * call site keeps compiling and keeps failing loudly — silently removing it
 * would let a caller fall through to a success path.
 */
export async function receiveExternalCredential(
  _offer: ParsedCredentialOffer,
  _authToken: string,
  _userPin?: string,
): Promise<ReceivedCredential> {
  throw new Error(EXTERNAL_ISSUER_UNSUPPORTED_MESSAGE);
}

/**
 * Resolve an external offer for preview before the user accepts it.
 *
 * DISABLED for the same reason. A preview is an invitation to accept, and
 * accepting cannot work — showing the review screen would be showing a door
 * with nothing behind it.
 */
export async function resolveExternalOffer(_offer: ParsedCredentialOffer): Promise<{
  credentialType: string;
  issuerDid: string;
  issuerName: string;
  pinRequired: boolean;
}> {
  throw new Error(EXTERNAL_ISSUER_UNSUPPORTED_MESSAGE);
}
