import { NextResponse } from 'next/server';
import { readSession } from '@/lib/accounts';
import { backend, BackendError } from '@/lib/backend';
import { dispense, readPrescription } from '@/lib/dispense';
import { voidDispense } from '@/lib/db';
import { getIdentity, isUnlocked, signAppend } from '@/lib/identity';
import { reportAppend } from '@/lib/pairing';
import { randomUUID } from 'node:crypto';
import { asTrimmed, readJsonObject } from '@/lib/parse';

interface SessionResult {
  requestId: string;
  status: string;
  /** The citizen the presentation belongs to. The wallet reads its tokens by this. */
  holderDid?: string;
  credentials?: Array<{ type?: string[]; claims?: Record<string, unknown> }>;
}

/**
 * Turn a VERIFIED presentation into a token and a pack list.
 *
 * TWO INDEPENDENT CHECKS, and both matter. (1) A signed-in counter user must be
 * asking — otherwise anyone who reaches the port can mint tokens. (2) The
 * verdict is re-read from the BACKEND, never taken from the client, so a caller
 * cannot POST "trust me, it verified". The counter's page only ever holds a
 * request id, which is what makes the rest of the flow safe to assume.
 */
export async function POST(req: Request) {
  if (!readSession(req.headers.get('cookie'))) {
    return NextResponse.json({ error: 'Sign in to dispense' }, { status: 401 });
  }

  const body = await readJsonObject(req);
  const requestId = body ? asTrimmed(body.requestId) : null;
  if (!requestId) {
    return NextResponse.json({ error: 'requestId is required' }, { status: 400 });
  }

  try {
    const session = await backend<SessionResult>(`/oid4vp/sessions/${encodeURIComponent(requestId)}`);
    if (session.status !== 'VERIFIED') {
      return NextResponse.json(
        { error: `This presentation is not verified (status ${session.status})` },
        { status: 409 },
      );
    }

    const claims = session.credentials?.[0]?.claims ?? {};
    const prescription = readPrescription(claims);
    if (!prescription) {
      return NextResponse.json(
        { error: 'The verified presentation carried no prescription to dispense' },
        { status: 422 },
      );
    }

    // THE LEDGER MUST LEARN ABOUT THIS BEFORE THE TOKEN IS MINTED.
    //
    // If this pharmacy cannot sign, it cannot be held to what it dispensed — and
    // an unreported dispense is exactly the hole that let the same prescription
    // be filled at two counters. Refusing is the fail-closed answer: a counter
    // that cannot report is not permitted to dispense, which is the owner's
    // decision that a dispense requires connectivity.
    const identity = getIdentity();
    if (!identity?.did) {
      return NextResponse.json(
        {
          error:
            'This pharmacy is not onboarded yet, so a dispense cannot be recorded. An officer ' +
            'must pair and confirm the institution before it can dispense.',
        },
        { status: 409 },
      );
    }
    if (!isUnlocked()) {
      return NextResponse.json(
        { error: 'This pharmacy’s signing key is locked. Unlock it with the owner passphrase.' },
        { status: 409 },
      );
    }

    // MINT FIRST, THEN REPORT — and undo the mint if the report fails.
    //
    // The order is the reverse of what it was, and the reason is A1: the append
    // must carry the queue number so the wallet can show it, and the number does
    // not exist until the counter mints it. The ORIGINAL intent still holds — a
    // counter that cannot report must not dispense — and it is enforced by the
    // rollback below rather than by the ordering: a failed report undoes the mint
    // and returns an error, so no token survives for a dispense the ledger never
    // recorded.
    // Generated BEFORE the mint, because the local row stores it: the counter
    // later settles or abandons the dispense BY this id, and a token minted
    // without it could never be settled.
    const dispenseId = randomUUID();

    const outcome = dispense(prescription, dispenseId);
    if (!outcome.ok) {
      return NextResponse.json({ error: outcome.reason }, { status: 409 });
    }

    const holderDid = session.holderDid;
    if (!holderDid) {
      voidDispense(outcome.token);
      return NextResponse.json(
        { error: 'The verified presentation did not name the holder, so the dispense cannot be recorded.' },
        { status: 422 },
      );
    }

    const appendPayload = {
      prescriptionId: prescription.id,
      quantity: prescription.items.reduce((sum, item) => sum + item.quantity, 0),
      dispenseId,
      dispensedAt: new Date().toISOString(),
      pharmacyDid: identity.did,
      holderDid,
    };

    let ledger: { recorded: boolean; dispensedTotal: number };
    try {
      ledger = await reportAppend({
        ...appendPayload,
        queueToken: outcome.token,
        signature: signAppend(appendPayload),
      });
    } catch (error) {
      // Undo the mint. Without this the patient would hold a token for a
      // dispense the ledger refused, which is the divergence this whole path
      // exists to prevent.
      voidDispense(outcome.token);
      return NextResponse.json(
        {
          error:
            'The dispense was refused because it could not be recorded: ' +
            (error instanceof Error ? error.message : String(error)),
        },
        { status: 502 },
      );
    }

    return NextResponse.json({
      token: outcome.token,
      lines: outcome.lines,
      total: outcome.total,
      prescriptionId: prescription.id,
      ledger,
    });
  } catch (error) {
    const status = error instanceof BackendError ? error.status : 500;
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status },
    );
  }
}
