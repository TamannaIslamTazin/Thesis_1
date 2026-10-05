import { NextResponse } from 'next/server';
import { requireRole } from '@/lib/accounts';
import { addMedicine, listMedicines } from '@/lib/db';
import { asInteger, asNumber, asTrimmed, readJsonObject } from '@/lib/parse';

/**
 * Stock is OWNER-ONLY. A counter user must not be able to change what the shop
 * sells or what it charges, so the check is here on the server - hiding the
 * button in the UI is a convenience, never the control.
 */
export async function GET(req: Request) {
  if (!requireRole(req.headers.get('cookie'), 'admin')) {
    return NextResponse.json({ error: 'Owner access required' }, { status: 401 });
  }
  return NextResponse.json({ medicines: listMedicines() });
}

export async function POST(req: Request) {
  if (!requireRole(req.headers.get('cookie'), 'admin')) {
    return NextResponse.json({ error: 'Owner access required' }, { status: 401 });
  }

  const body = await readJsonObject(req);
  if (!body) {
    return NextResponse.json({ error: 'Malformed request body' }, { status: 400 });
  }

  const name = asTrimmed(body.name) ?? '';
  const strength = asTrimmed(body.strength) ?? '';
  const form = asTrimmed(body.form) ?? '';
  const unitPrice = asNumber(body.unitPrice);
  const stock = asInteger(body.stock);
  const storeArea = asTrimmed(body.storeArea) ?? '';

  if (name.length === 0) {
    return NextResponse.json({ error: 'A name is required' }, { status: 400 });
  }
  if (unitPrice === null || unitPrice < 0) {
    return NextResponse.json({ error: 'Unit price must be zero or more' }, { status: 400 });
  }
  if (stock === null || stock < 0) {
    return NextResponse.json({ error: 'Stock must be a whole number of zero or more' }, { status: 400 });
  }

  return NextResponse.json({ medicine: addMedicine({ name, strength, form, unitPrice, stock, storeArea }) });
}
