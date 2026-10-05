/**
 * The browser-side half of the capability-gated document read
 * (OFFICER-DOCUMENT-ACCESS.md §3). The DID authentication and the capability
 * header both happen server-side, in src/app/console/locker/object/route.ts
 * — see that file for why. This module only ever handles ciphertext.
 */
import type { LockerCapabilityToken } from '@ssi-healthcare/shared';

export type { LockerCapabilityToken };

export class LockerClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LockerClientError';
  }
}

export async function fetchLockerObject(objectId: string, capability: LockerCapabilityToken): Promise<Uint8Array> {
  const res = await fetch('/console/locker/object', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ objectId, capability }),
  });
  const body = (await res.json().catch(() => null)) as { objectBase64?: string; error?: string; code?: string } | null;
  if (!res.ok || !body?.objectBase64) {
    throw new LockerClientError(body?.error ?? `Locker object fetch failed with status ${res.status}.`);
  }
  const binary = atob(body.objectBase64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
