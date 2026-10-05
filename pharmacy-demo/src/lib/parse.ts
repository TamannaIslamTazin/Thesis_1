/**
 * Small, explicit readers for request bodies.
 *
 * WHY NOT `as`. A cast tells the compiler what it wants to hear and checks
 * nothing at runtime, so `body.unitPrice` typed as `number` can still be the
 * string "abc" from a hand-made POST. These return a real value or null, and
 * every caller has to handle the null — which is the point.
 */

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

export function asTrimmed(value: unknown): string | null {
  const text = asString(value);
  return text === null ? null : text.trim();
}

export function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

export function asInteger(value: unknown): number | null {
  const num = asNumber(value);
  return num !== null && Number.isInteger(num) ? num : null;
}

/** Parse a JSON request body, or null if it is not a JSON object. */
export async function readJsonObject(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const parsed: unknown = await req.json();
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
