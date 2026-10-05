import { NextResponse } from 'next/server';
import { readSession } from '@/lib/accounts';
import { listDispenses } from '@/lib/db';
import { isTokenExpired, tokenExpiresAt } from '@/lib/tokenExpiry';

/**
 * The seller dashboard's feed. Signed-in staff only — it carries prices.
 *
 * Each row also carries the READ-TIME expiry, computed HERE on the counter's
 * server and never in the browser: a token raised more than 24 hours ago and
 * still open is expired, and the desk must see that before it takes money
 * (A1 stage 4b). The rule is the backend's; the backend remains the enforcer,
 * and this is the counter's read of it. See lib/tokenExpiry.ts.
 */
export async function GET(req: Request) {
  if (!readSession(req.headers.get('cookie'))) {
    return NextResponse.json({ error: 'Sign in to view the counter' }, { status: 401 });
  }

  const now = Date.now();
  const dispenses = listDispenses().map((dispense) => {
    const expiresAt = tokenExpiresAt(dispense.createdAt);
    return {
      ...dispense,
      expiresAt: expiresAt === null ? null : new Date(expiresAt).toISOString(),
      // Expiry applies only to an OPEN token: a settled or abandoned one is
      // already terminal, and the 24-hour rule does not re-open it.
      expired:
        !dispense.paid && dispense.abandonedAt === null && isTokenExpired(dispense.createdAt, now),
    };
  });

  return NextResponse.json({ dispenses });
}
