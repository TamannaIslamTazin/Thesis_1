/**
 * `did:cheqd:bdhealthtestnet:5d3c6ffe-…-c86d24594753` -> `did:cheqd:bdhealt…94753`.
 *
 * Short enough for a badge, still recognisable — and, unlike the phrase it
 * replaced, it does not claim to know LESS than it does. "Unknown Issuer" over
 * an identifier the screen is holding is a false statement about our own data;
 * a truncated DID is honest and lets the holder check it against the authority's
 * published identifier.
 */
export function truncateDid(did: string, head = 16, tail = 6): string {
  if (did.length <= head + tail + 1) return did;
  return `${did.slice(0, head)}…${did.slice(-tail)}`;
}

/**
 * A coarse "how long ago", e.g. "just now", "12 min ago", "3 h ago", "2 d ago".
 *
 * COARSE ON PURPOSE: it answers "is this stale?" for a holder glancing at the
 * screen, not "exactly when". Coarse buckets also stop the string from changing
 * every second and re-rendering for no reason.
 */
export function relativeTime(timestampMs: number, now: number = Date.now()): string {
  const seconds = Math.max(0, Math.round((now - timestampMs) / 1000));
  if (seconds < 45) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
}
