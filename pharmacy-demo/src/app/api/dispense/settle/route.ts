import { NextResponse } from 'next/server';
import { readSession } from '@/lib/accounts';
import { dispenseState, markAbandoned, markPaid } from '@/lib/db';
import { isTokenExpired } from '@/lib/tokenExpiry';
import { getIdentity, isUnlocked, signSettle } from '@/lib/identity';
import { backend, BackendError } from '@/lib/backend';
import { asInteger, asTrimmed, readJsonObject } from '@/lib/parse';

/**
 * Settle or close a token, LOCALLY AND AT THE BACKEND.
 *
 * ===========================================================================
 * WHY BOTH, AND WHY THE ORDER MATTERS
 * ===========================================================================
 * The counter's own record is what the desk shows; the backend's record is what
 * the PATIENT'S WALLET reads. Writing only locally was the state before A1, and it
 * left the wallet showing a token for ever — the holder had no way to learn that
 * the counter had settled it.
 *
 * The local write happens FIRST and the backend call second. If the backend call
 * fails, the response is an error and the desk shows it, so the operator knows the
 * wallet has not been told. Doing it the other way round would tell the wallet
 * about a settlement the counter had not recorded, which is the worse divergence:
 * the patient would lose the token while the desk still expected payment.
 *
 * ===========================================================================
 * IDEMPOTENT BY THE STORE, NOT BY THIS ROUTE
 * ===========================================================================
 * Both local writes carry their once-only condition in the WHERE clause, so a
 * double tap cannot double-count. `alreadyPaid` / `alreadyClosed` are reported so
 * the desk can say so rather than pretending it did something.
 */
export async function POST(req: Request) {
  if (!readSession(req.headers.get('cookie'))) {
    return NextResponse.json({ error: 'Sign in to settle a token' }, { status: 401 });
  }

  const body = await readJsonObject(req);
  const token = body ? asInteger(body.token) : null;
  const outcome = body ? asTrimmed(body.outcome) : null;

  if (token === null || token <= 0) {
    return NextResponse.json({ error: 'A positive token is required' }, { status: 400 });
  }
  if (outcome !== 'paid' && outcome !== 'not-paid') {
    // No default. Guessing here would settle a payment the operator never
    // confirmed, and this is a one-time process.
    return NextResponse.json({ error: 'An outcome of paid or not-paid is required' }, { status: 400 });
  }

  const state = dispenseState(token);
  if (!state) {
    return NextResponse.json({ error: 'No token with that number.' }, { status: 404 });
  }

  // PRE-EMPTIVE EXPIRY GUARD (A1 stage 4b). The dashboard should already have
  // withdrawn the actions, but a tab can be stale and the boundary can fall
  // between render and tap. Refusing HERE keeps the counter from recording a
  // payment the backend will not accept — the "patient pays at hour 25" money
  // case from __docs__/design/TOKEN-EXPIRY-CLOCK-OWNERSHIP.md. The backend
  // refuses independently; this is the counter's own fail-closed step, and it
  // writes nothing.
  if (!state.paid && state.abandonedAt === null && isTokenExpired(state.createdAt)) {
    return NextResponse.json(
      {
        error:
          'This token expired, so it cannot be settled. ' +
          'The patient’s wallet already shows it as not collected.',
        expired: true,
      },
      { status: 409 },
    );
  }

  const dispenseId = state.dispenseId;
  if (!dispenseId) {
    return NextResponse.json(
      {
        error:
          'This token was minted before the dispense ledger recorded an id, so it cannot be ' +
          'settled at the backend. Ask the patient to present again.',
      },
      { status: 409 },
    );
  }

  // Local first.
  let changed: boolean;
  if (outcome === 'paid') {
    changed = markPaid(token);
  } else {
    changed = markAbandoned(token, 'declined');
  }

  // Then the backend, which is what the wallet reads. SIGNED, not sessioned:
  // the pharmacy has no wallet, and an institution is authenticated by its
  // signature against a chain-resolved DID.
  const identity = getIdentity();
  if (!identity?.did) {
    return NextResponse.json(
      { error: 'This pharmacy is not onboarded, so the settlement cannot be signed.', walletNotified: false },
      { status: 409 },
    );
  }
  if (!isUnlocked()) {
    return NextResponse.json(
      { error: 'The signing key is locked, so the settlement cannot be signed. Unlock it in the back office.', walletNotified: false },
      { status: 409 },
    );
  }

  const settledAt = new Date().toISOString();
  const outcomeCode = outcome === 'paid' ? 'paid' : 'not-paid';
  const signable = { dispenseId, outcome: outcomeCode as 'paid' | 'not-paid', settledAt, pharmacyDid: identity.did };

  try {
    await backend(`/api/pharmacy/${outcome === 'paid' ? 'settle' : 'abandon'}`, {
      method: 'POST',
      // An OBJECT, not a string: `backend()` stringifies the body itself, and
      // passing a pre-stringified one would send a quoted JSON string.
      body: {
        dispenseId,
        settledAt,
        pharmacyDid: identity.did,
        signature: signSettle(signable),
        ...(outcome === 'not-paid' ? { reason: 'declined' } : {}),
      },
    });
  } catch (error) {
    const status = error instanceof BackendError ? error.status : 502;
    // The backend's own words, because it distinguishes a token that was already
    // terminal from one that could not be found, and the operator needs to know
    // which — one is harmless, the other means the desk and the ledger disagree.
    return NextResponse.json(
      {
        error:
          'Recorded at the counter, but the wallet could not be told: ' +
          (error instanceof Error ? error.message : String(error)),
        recordedLocally: true,
        walletNotified: false,
      },
      { status },
    );
  }

  return NextResponse.json({
    token,
    outcome,
    alreadyRecorded: !changed,
    walletNotified: true,
  });
}
