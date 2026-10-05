/**
 * The pairing-code payload format, and nothing else.
 *
 * WHY THIS IS ITS OWN MODULE. It is imported by BOTH a server module
 * (`identity.ts`, which touches `node:crypto` and `node:sqlite`) and a CLIENT
 * component (`QrScanner.tsx`). When the scanner imported the constant from
 * `identity.ts`, Next pulled server-only built-ins into the browser bundle, React
 * resolved to null, and every hook call in the admin page died with
 * "Cannot read properties of null (reading 'useInsertionEffect')".
 *
 * So the shared string lives here, with NO imports at all. A module a client
 * component can safely import must not reach the server — that is the rule this
 * file exists to make easy to follow.
 */

/** What the issuer console puts in the QR. Recognised so anything else is refused. */
export const ENROLMENT_URI_PREFIX = 'bdht-enrol:v1:';

/**
 * Parse a scanned pairing payload.
 *
 * ACCEPTS THE PREFIX AND NOTHING ELSE. A camera sees the whole room — price
 * labels, stock stickers, another screen — and a mis-scan must not become a
 * network call against the issuer. Returning null for anything unrecognised is
 * what makes an unrelated barcode a quiet non-event.
 */
export function parseEnrolmentUri(scanned: string): string | null {
  const text = scanned.trim();
  if (!text.startsWith(ENROLMENT_URI_PREFIX)) return null;
  const token = text.slice(ENROLMENT_URI_PREFIX.length).trim();
  return token.length > 0 ? token : null;
}
