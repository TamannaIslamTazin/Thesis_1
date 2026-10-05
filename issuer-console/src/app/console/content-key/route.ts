import { NextResponse } from 'next/server';
import { unwrapContentKey, bytesToBase64Url, base64UrlToBytes, ContentKeyWrapError } from '@ssi-healthcare/shared';

/**
 * Server-side unwrap of a released `wrappedContentKey` (round 5's ECIES
 * scheme, `@ssi-healthcare/shared` `crypto/contentKeyWrap.ts`). Runs on the
 * console's own Next.js server, never in the browser — same reasoning as
 * `console/locker/object/route.ts` for `ISSUER_LOCKER_SIGNING_SEED`: the
 * X25519 private key that opens this envelope must never reach a browser
 * tab. The browser gets the plaintext CONTENT KEY back (not the private key),
 * which it already legitimately holds once the officer clicked "Reveal
 * decryption key" — this route only moves WHERE the unwrap arithmetic runs,
 * not what the officer's session is trusted to see.
 *
 * This is a stand-in for real institution key custody, same status as the
 * Ed25519 signing seed — see CONTENT-KEY-ENVELOPE-GAP.md.
 */
export async function POST(request: Request): Promise<NextResponse> {
  const body = (await request.json().catch(() => null)) as
    | { wrappedContentKey?: unknown; issuanceRequestId?: unknown }
    | null;
  if (!body || !body.wrappedContentKey || typeof body.issuanceRequestId !== 'string') {
    return NextResponse.json({ error: 'wrappedContentKey and issuanceRequestId are required' }, { status: 400 });
  }

  // EVERY AUTHORITY KEY THIS INSTANCE HOLDS, TRIED IN TURN.
  //
  // The wallet seals a submission to the PUBLIC key of the authority its
  // document type names, so exactly one key can open it and the AES-GCM tag is
  // what decides. Trying them in order therefore reveals nothing and grants
  // nothing: a key that was not the recipient fails to authenticate, which is
  // the same answer as not trying it.
  //
  // WHY NOT TAKE THE AUTHORITY FROM THE CLIENT: this route has no session, and
  // a body-supplied authority would let an officer name someone else's key.
  // Deriving it from the artifact instead removes that choice entirely.
  //
  // WHAT A REAL DEPLOYMENT DOES INSTEAD, and why this is not it: each authority
  // runs its OWN console holding ONLY its own seed, so the loop below has one
  // entry and cross-authority decryption is impossible rather than merely
  // unreachable. This single instance hosts all four because one machine is
  // running the whole country's stack; that is a deployment property, not a
  // security one, and it is the reason this comment exists.
  const seeds = Object.entries(process.env)
    .filter(([name, value]) =>
      Boolean(value) &&
      (name === 'ISSUER_CONTENT_KEY_X25519_SEED' || name.startsWith('ISSUER_CONTENT_KEY_X25519_SEED__')))
    .map(([name, value]) => ({ name, seed: value as string }));

  if (seeds.length === 0) {
    return NextResponse.json(
      { error: 'No ISSUER_CONTENT_KEY_X25519_SEED is configured on this console instance.' },
      { status: 500 },
    );
  }

  const failures: string[] = [];
  for (const { name, seed } of seeds) {
    try {
      const contentKey = unwrapContentKey({
        recipientPrivateKey: base64UrlToBytes(seed),
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        wrapped: body.wrappedContentKey as any,
        issuanceRequestId: body.issuanceRequestId,
      });
      return NextResponse.json({ contentKeyBase64Url: bytesToBase64Url(contentKey) });
    } catch (error) {
      failures.push(`${name}: ${error instanceof ContentKeyWrapError ? error.message : String(error)}`);
    }
  }

  // NAME WHICH KEYS WERE TRIED. "Did not authenticate" on its own sent the last
  // review round chasing a decryption bug when the real answer was that the
  // document had been sealed to an authority whose private half was never
  // configured anywhere.
  return NextResponse.json(
    {
      error:
        'No configured authority key could open this envelope. It was sealed to an authority ' +
        'this console does not hold a key for — check the document type\'s ' +
        '`contentKeyPublicKey` against the seeds configured here.',
      tried: seeds.map((s) => s.name),
      failures,
    },
    { status: 400 },
  );
}
