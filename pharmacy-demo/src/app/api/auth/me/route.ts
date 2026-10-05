import { NextResponse } from 'next/server';
import { readSession } from '@/lib/accounts';

/** Who is signed in, and with which role. 401 when nobody is. */
export async function GET(req: Request) {
  const session = readSession(req.headers.get('cookie'));
  if (!session) {
    return NextResponse.json({ error: 'Not signed in' }, { status: 401 });
  }
  return NextResponse.json(session);
}
