import { NextResponse } from 'next/server';
import { ed25519 } from '@noble/curves/ed25519';

/**
 * Server-side proxy for the officer's read of a holder's locker object
 * (OFFICER-DOCUMENT-ACCESS.md §3). Runs on the console's own Next.js server,
 * never in the browser, for one reason: `ISSUER_LOCKER_SIGNING_SEED` signs as
 * the L1 authority's DID, and a key that can do that must never reach a
 * browser tab. The browser gets ciphertext bytes back; it already holds the
 * content key (from the single-use release in the queue screen) and decrypts
 * client-side with `decryptLockerObject` — the plaintext content key is
 * never sent to this route or to the locker.
 *
 * This is a stand-in for real institution key custody, which does not exist
 * anywhere in this codebase yet (Institution carries a `did` column and
 * nothing else — see __docs__/backend/CONTENT-KEY-ENVELOPE-GAP.md). A real
 * deployment needs this signing operation behind an authenticated,
 * audited endpoint of its own (an HSM or KMS), not a seed in an env var.
 */

const LOCKER_URL = process.env.ISSUER_LOCKER_URL ?? 'http://localhost:4540';
const AUTH_PAYLOAD_DOMAIN = 'bdhealthtrust/locker-auth/v1';

function authPayload(args: { audience: string; did: string; nonce: string; issuedAtSeconds: number }): Uint8Array {
  const canonical =
    `${AUTH_PAYLOAD_DOMAIN}\n` +
    `aud:${args.audience}\n` +
    `did:${args.did}\n` +
    `nonce:${args.nonce}\n` +
    `iat:${args.issuedAtSeconds}\n`;
  return new TextEncoder().encode(canonical);
}

/**
 * The locker identity to act as, chosen from the CAPABILITY the holder signed.
 *
 * A capability names its audience: the authority the holder granted access to.
 * Authenticating as anyone else is not merely wrong, it is refused by the locker
 * — so reading the identity from `aud` makes the console act as exactly the
 * authority the holder chose, and makes acting as another impossible rather than
 * merely discouraged.
 *
 * NOT taken from the request body or a session: the body is client-controlled,
 * and this route has no session. The capability is signed by the holder, so it
 * is the one input here that cannot be forged.
 *
 * Env is read as `NAME__SHORT`, falling back to the unsuffixed name, which is
 * how the ministry was already configured.
 */
function lockerIdentityFor(audienceDid: string | undefined): {
  did: string;
  verificationMethodId: string;
  seedB64: string;
} {
  const suffixes = ['BMDC', 'BNMC', 'PCB', 'MOHFW'];
  const match = suffixes.find(
    (short) => process.env[`ISSUER_LOCKER_DID__${short}`] === audienceDid,
  );

  const did = match ? process.env[`ISSUER_LOCKER_DID__${match}`] : process.env.ISSUER_LOCKER_DID;
  const verificationMethodId = match
    ? process.env[`ISSUER_LOCKER_VERIFICATION_METHOD_ID__${match}`]
    : process.env.ISSUER_LOCKER_VERIFICATION_METHOD_ID;
  const seedB64 = match
    ? process.env[`ISSUER_LOCKER_SIGNING_SEED__${match}`]
    : process.env.ISSUER_LOCKER_SIGNING_SEED;

  if (!did || !verificationMethodId || !seedB64) {
    throw new Error(
      `No locker identity is configured for '${audienceDid ?? 'the default authority'}'. ` +
        'The holder granted this capability to that DID, so no other identity can spend it.',
    );
  }
  return { did, verificationMethodId, seedB64 };
}

async function mintLockerSession(audienceDid?: string): Promise<string> {
  const { did, verificationMethodId, seedB64 } = lockerIdentityFor(audienceDid);
  const privateKey = Buffer.from(seedB64, 'base64url');

  const challengeRes = await fetch(`${LOCKER_URL}/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did }),
  });
  if (!challengeRes.ok) {
    throw new Error(`locker challenge failed with status ${challengeRes.status}`);
  }
  const challenge = (await challengeRes.json()) as { nonce: string; audience: string };

  const iat = Math.floor(Date.now() / 1000);
  const payload = authPayload({ audience: challenge.audience, did, nonce: challenge.nonce, issuedAtSeconds: iat });
  const signature = ed25519.sign(payload, privateKey);

  const tokenRes = await fetch(`${LOCKER_URL}/v1/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      nonce: challenge.nonce,
      signature: Buffer.from(signature).toString('base64url'),
      verificationMethodId,
      iat,
    }),
  });
  if (!tokenRes.ok) {
    const body = await tokenRes.json().catch(() => ({}));
    throw new Error(`locker auth failed with status ${tokenRes.status}: ${JSON.stringify(body)}`);
  }
  const token = (await tokenRes.json()) as { token: string };
  return token.token;
}

export async function POST(request: Request): Promise<NextResponse> {
  const body = (await request.json().catch(() => null)) as { objectId?: unknown; capability?: unknown } | null;
  if (!body || typeof body.objectId !== 'string' || body.objectId.length === 0 || !body.capability) {
    return NextResponse.json({ error: 'objectId and capability are required' }, { status: 400 });
  }

  // The authority the HOLDER granted access to. Read from the signed capability
  // rather than from anywhere the caller controls — see lockerIdentityFor.
  const audienceDid = (body.capability as { claims?: { aud?: string } } | undefined)?.claims?.aud;

  let sessionToken: string;
  try {
    sessionToken = await mintLockerSession(audienceDid);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 502 },
    );
  }

  const capabilityHeader = Buffer.from(JSON.stringify(body.capability), 'utf8').toString('base64url');
  const objectRes = await fetch(
    `${LOCKER_URL}/v1/objects/${encodeURIComponent(body.objectId)}/capability`,
    { headers: { Authorization: `Bearer ${sessionToken}`, 'X-Locker-Capability': capabilityHeader } },
  );

  if (!objectRes.ok) {
    const errBody = await objectRes.json().catch(() => ({}));
    return NextResponse.json(errBody, { status: objectRes.status });
  }

  const bytes = Buffer.from(await objectRes.arrayBuffer());
  return NextResponse.json({ objectBase64: bytes.toString('base64') });
}
