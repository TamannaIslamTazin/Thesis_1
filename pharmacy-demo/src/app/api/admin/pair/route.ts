/**
 * POST /api/admin/pair — scan the officer's pairing code and become an institution.
 *
 * ADMIN ONLY. Staff derive authority from the admin; the pharmacy's identity IS
 * the admin's act, and a counter user must not be able to re-key the premises.
 *
 * The passphrase is used and discarded — it seals the private key at rest and is
 * never stored, never logged, and never returned.
 */
import { NextResponse } from 'next/server';

import { requireRole } from '@/lib/accounts';
import { createIdentity, getIdentity, isUnlocked, parseEnrolmentUri, recordDid, unlockForSigning } from '@/lib/identity';
import { claimEnrolment, fetchMyDid } from '@/lib/pairing';
import { BackendError } from '@/lib/backend';

export async function POST(request: Request) {
  if (!requireRole(request.headers.get('cookie'), 'admin')) {
    return NextResponse.json({ error: 'Owner access required' }, { status: 401 });
  }

  let body: { scanned?: unknown; passphrase?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: 'Expected a JSON body.' }, { status: 400 });
  }

  const scanned = typeof body.scanned === 'string' ? body.scanned : '';
  const passphrase = typeof body.passphrase === 'string' ? body.passphrase : '';

  // Recognise the payload BEFORE anything else. A counter scanner types whatever
  // barcode is in front of it, so a stock label must be refused here rather than
  // turned into a doomed request against the issuer.
  const token = parseEnrolmentUri(scanned);
  if (!token) {
    return NextResponse.json(
      {
        error:
          'That does not look like a pairing code. Scan the code shown on the officer’s screen — ' +
          'it starts with bdht-enrol:v1:.',
      },
      { status: 400 },
    );
  }

  try {
    // The key is generated BEFORE the claim, because the claim must carry its
    // public half. Refusals on the passphrase happen here, before anything is
    // sent to the issuer.
    const identity = createIdentity(passphrase);

    // Unlock NOW, while the passphrase is in hand. The counter signs unattended,
    // so the key is held in memory for this process — see identity.ts. Pairing is
    // the one moment the admin is certainly present to supply it.
    unlockForSigning(passphrase);

    const claimed = await claimEnrolment(token, identity.publicKeyMultibase);

    return NextResponse.json({
      ok: true,
      enrolmentId: claimed.enrolmentId,
      authorityId: claimed.authorityId,
      publicKeyMultibase: identity.publicKeyMultibase,
      // Said plainly, because this is the step people assume is the end.
      note:
        'Paired. The officer must now confirm what they verified on site — the institution ' +
        'does not exist until they do.',
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Pairing failed.' },
      { status: error instanceof BackendError ? error.status : 400 },
    );
  }
}

/**
 * GET /api/admin/pair — what this pharmacy currently holds, if anything.
 *
 * ALSO DISCOVERS THE DID. At pairing the pharmacy cannot know its DID — the
 * officer has not confirmed yet, and the DID does not exist until they do. So
 * each read asks the backend whether this public key has an institution behind
 * it, and records the answer the first time it does. That is what turns "paired,
 * waiting" into "onboarded" without the officer having to type a DID anywhere.
 */
export async function GET(request: Request) {
  if (!requireRole(request.headers.get('cookie'), 'admin')) {
    return NextResponse.json({ error: 'Owner access required' }, { status: 401 });
  }

  const identity = getIdentity();
  if (identity && !identity.did) {
    try {
      const did = await fetchMyDid(identity.publicKeyMultibase);
      if (did) {
        recordDid(did);
        // The public key and DID only. The sealed private key is never returned,
        // not even to the admin: no screen needs it, so no route sends it.
        return NextResponse.json({ identity: { ...identity, did }, unlocked: isUnlocked() });
      }
    } catch {
      // Unreachable backend is not "no institution" — leave the DID unset and
      // let the next poll ask again.
    }
  }

  return NextResponse.json({ identity, unlocked: isUnlocked() });
}

/**
 * PUT /api/admin/pair — unlock the signing key.
 *
 * SEPARATE FROM PAIRING, and needed after every restart: the counter signs
 * unattended, so the key lives in memory for the process (see identity.ts), and a
 * restart locks it again. Requiring the passphrase once per server start is the
 * deliberate cost of not writing the key to disk in the clear.
 *
 * OWNER ONLY. Staff derive authority from the owner; a counter user must not be
 * able to unlock the key that signs the pharmacy's records.
 */
export async function PUT(request: Request) {
  if (!requireRole(request.headers.get('cookie'), 'admin')) {
    return NextResponse.json({ error: 'Owner access required' }, { status: 401 });
  }
  let body: { passphrase?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: 'Expected a JSON body.' }, { status: 400 });
  }
  const passphrase = typeof body.passphrase === 'string' ? body.passphrase : '';
  if (!passphrase) {
    return NextResponse.json({ error: 'A passphrase is required.' }, { status: 400 });
  }
  try {
    unlockForSigning(passphrase);
    return NextResponse.json({ unlocked: true });
  } catch (error) {
    // The message from identity.ts is deliberately the same for a wrong
    // passphrase and a corrupt blob — the two are indistinguishable to an
    // attacker and the operator's next step is identical either way.
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Could not unlock.' },
      { status: 401 },
    );
  }
}
