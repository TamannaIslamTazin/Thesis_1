import { NextResponse } from 'next/server';
import { readSession } from '@/lib/accounts';
import { updateLineQuantity } from '@/lib/db';
import { asInteger, readJsonObject } from '@/lib/parse';

/** Edit one line's quantity. Staff only; stock and the total move together. */
export async function POST(req: Request) {
  if (!readSession(req.headers.get('cookie'))) {
    return NextResponse.json({ error: 'Sign in to edit a token' }, { status: 401 });
  }
  const body = await readJsonObject(req);
  const token = body ? asInteger(body.token) : null;
  const medicineId = body ? asInteger(body.medicineId) : null;
  const quantity = body ? asInteger(body.quantity) : null;
  if (token === null || medicineId === null || quantity === null) {
    return NextResponse.json({ error: 'token, medicineId and quantity are required' }, { status: 400 });
  }
  const outcome = updateLineQuantity({ token, medicineId, quantity });
  if (!outcome.ok) {
    return NextResponse.json({ error: outcome.reason }, { status: 409 });
  }
  return NextResponse.json({ ok: true });
}
