/**
 * Constant-time bearer check. A plain `===` on a secret leaks its length and
 * a per-character early-exit timing signal; hashing both sides to a fixed
 * length before comparing removes both, and `timingSafeEqual` removes the
 * comparison-time signal on top of that.
 */

import { createHash, timingSafeEqual } from 'node:crypto';

export function isAuthorised(providedHeader: string | undefined, expectedSecret: string): boolean {
  if (!providedHeader?.startsWith('Bearer ')) return false;
  const provided = providedHeader.slice('Bearer '.length);

  const providedDigest = createHash('sha256').update(provided, 'utf8').digest();
  const expectedDigest = createHash('sha256').update(expectedSecret, 'utf8').digest();

  return timingSafeEqual(providedDigest, expectedDigest);
}
