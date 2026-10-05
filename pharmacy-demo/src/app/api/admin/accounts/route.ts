import { NextResponse } from 'next/server';
import { ROLES, accountExists, createAccount, listAccounts, requireRole, type Role } from '@/lib/accounts';
import { asTrimmed, readJsonObject } from '@/lib/parse';

/** The owner sees who works here. */
export async function GET(req: Request) {
  if (!requireRole(req.headers.get('cookie'), 'admin')) {
    return NextResponse.json({ error: 'Owner access required' }, { status: 401 });
  }
  return NextResponse.json({ accounts: listAccounts() });
}

function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

/**
 * The owner creates staff accounts — self-registration is not a thing here,
 * because a pharmacy's software has no public sign-up: you work there or you do
 * not. Usernames may not contain ':' because the session cookie is a
 * colon-separated payload and a colon would let one field forge another.
 */
export async function POST(req: Request) {
  if (!requireRole(req.headers.get('cookie'), 'admin')) {
    return NextResponse.json({ error: 'Owner access required' }, { status: 401 });
  }

  const body = await readJsonObject(req);
  if (!body) {
    return NextResponse.json({ error: 'Malformed request body' }, { status: 400 });
  }

  const username = asTrimmed(body.username) ?? '';
  const password = asTrimmed(body.password) ?? '';
  const displayName = asTrimmed(body.displayName) ?? '';
  const role = asTrimmed(body.role) ?? 'user';

  if (username.length < 3) {
    return NextResponse.json({ error: 'Username must be at least 3 characters' }, { status: 400 });
  }
  if (username.includes(':')) {
    return NextResponse.json({ error: "Username may not contain ':'" }, { status: 400 });
  }
  if (password.length < 8) {
    return NextResponse.json({ error: 'Password must be at least 8 characters' }, { status: 400 });
  }
  if (!isRole(role)) {
    return NextResponse.json({ error: 'Role must be user or admin' }, { status: 400 });
  }
  if (accountExists(username)) {
    return NextResponse.json({ error: 'That username is taken' }, { status: 409 });
  }

  return NextResponse.json({ account: createAccount({ username, password, displayName, role }) });
}
