import { NextResponse } from 'next/server';
import { ensureOwnerSeeded, issueSessionCookie, signIn } from '@/lib/accounts';
import { asTrimmed, readJsonObject } from '@/lib/parse';

/**
 * Sign in — one door for both roles; the role comes from the account, not the
 * request. A caller cannot ask to be an admin.
 *
 * One message for a wrong username and a wrong password on purpose: telling them
 * apart tells an attacker which half they already have.
 */
export async function POST(req: Request) {
  ensureOwnerSeeded();

  const body = await readJsonObject(req);
  const username = body ? asTrimmed(body.username) : null;
  const password = body ? asTrimmed(body.password) : null;
  if (!username || !password) {
    return NextResponse.json({ error: 'Username and password are required' }, { status: 400 });
  }

  const account = signIn(username, password);
  if (!account) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
  }

  const res = NextResponse.json({
    username: account.username,
    displayName: account.displayName,
    role: account.role,
  });
  res.headers.set('Set-Cookie', issueSessionCookie(account));
  return res;
}
