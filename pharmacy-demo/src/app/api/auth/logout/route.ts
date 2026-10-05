import { NextResponse } from 'next/server';
import { clearSessionCookie } from '@/lib/accounts';

export async function POST() {
  const res = NextResponse.json({ ok: true });
  res.headers.set('Set-Cookie', clearSessionCookie());
  return res;
}
