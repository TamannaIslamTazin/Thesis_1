/**
 * Turn an incoming deep link into the same request the camera would have read.
 *
 * ===========================================================================
 * WHY THE SCHEME LOOKS LIKE THAT
 * ===========================================================================
 * `exp+ssi-healthcare-wallet://` is not a stylistic choice. It is the scheme the
 * INSTALLED dev client actually declares — confirmed from the device with
 * `dumpsys package`, which lists exactly two browsable schemes. Registering
 * `openid4vp://` would need an intent filter in the Android manifest, and that
 * needs a native rebuild: there is no `android/` directory and no Android SDK on
 * this machine, so the APK cannot be regenerated here.
 *
 * So this reads the SSI payload out of whatever wrapper carried it, rather than
 * insisting on a canonical scheme it cannot register. When a native build is
 * possible, add `openid4vp` and `openid-credential-offer` intent filters and
 * this function keeps working unchanged — the branch below already accepts them.
 *
 * ===========================================================================
 * A LINK IS NOT MORE TRUSTED THAN A QR CODE
 * ===========================================================================
 * Both arrive from outside and both end up at the SAME authorization sheet, with
 * the same disclosure choices and the same fingerprint. That is deliberate: a
 * deep link is if anything easier for an attacker to deliver than a printed QR
 * code — it can be a link in a message — so giving it a shorter path to the
 * holder's key would be exactly backwards.
 */
import { qrScannerService, QRCodeType, type ParsedQRCode } from './qrScanner';

/** Schemes that carry an SSI payload directly rather than wrapping one. */
const NATIVE_SSI_SCHEMES = ['openid4vp:', 'openid-credential-offer:', 'openid-vc:'];

/**
 * Extract the SSI payload from an incoming URL, or null if there is none.
 *
 * Returns null — not a guess — for links this wallet has no business acting on.
 * A deep link that cannot be read must do NOTHING rather than open a sheet
 * describing a request nobody made.
 */
export function ssiPayloadFromUrl(url: string): string | null {
  if (!url) return null;

  // Already an SSI URI: the browser or another app handed it over intact.
  if (NATIVE_SSI_SCHEMES.some((s) => url.toLowerCase().startsWith(s))) return url;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  // Wrapped form: exp+ssi-healthcare-wallet://<anything>?request_uri=… or ?uri=…
  //
  // `request_uri` is read as a WHOLE URI and handed on untouched. Reconstructing
  // an OID4VP URI from parts here would be a second place that decides what a
  // request looks like, and the two would drift.
  const requestUri = parsed.searchParams.get('request_uri');
  if (requestUri) return `openid4vp://?request_uri=${encodeURIComponent(requestUri)}`;

  const offer = parsed.searchParams.get('credential_offer_uri');
  if (offer) return `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offer)}`;

  const inlineOffer = parsed.searchParams.get('credential_offer');
  if (inlineOffer) return `openid-credential-offer://?credential_offer=${encodeURIComponent(inlineOffer)}`;

  // A payload passed whole, percent-encoded, under `uri` or `payload`.
  const whole = parsed.searchParams.get('uri') ?? parsed.searchParams.get('payload');
  if (whole && NATIVE_SSI_SCHEMES.some((s) => whole.toLowerCase().startsWith(s))) return whole;

  return null;
}

/**
 * Parse an incoming deep link into the same shape the scanner produces.
 *
 * Anything unrecognised returns null, so an unknown link is silently ignored
 * rather than surfaced as an "Unknown QR Code" sheet the holder did not ask for.
 */
export function parseDeepLink(url: string): ParsedQRCode | null {
  const payload = ssiPayloadFromUrl(url);
  if (!payload) return null;

  const parsed = qrScannerService.parseQRCode(payload);
  return parsed.type === QRCodeType.UNKNOWN ? null : parsed;
}
