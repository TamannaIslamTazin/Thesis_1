import { NextResponse } from 'next/server';
import { requireRole } from '@/lib/accounts';
import { adminStats } from '@/lib/db';

/** Total sales, total revenue, and what is running out. Owner only. */
export async function GET(req: Request) {
  if (!requireRole(req.headers.get('cookie'), 'admin')) {
    return NextResponse.json({ error: 'Owner access required' }, { status: 401 });
  }
  return NextResponse.json(adminStats());
}
