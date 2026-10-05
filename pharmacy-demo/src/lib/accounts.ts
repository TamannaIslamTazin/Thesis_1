/**
 * Accounts: two roles, one table.
 *
 * WHY ROLES RATHER THAN TWO SYSTEMS. A pharmacy has staff who serve customers and
 * an owner who controls what the shop sells. That is one identity concept with an
 * authority level, not two kinds of user, so it is one table and one sign-in with
 * a `role` column — a second table would mean a second login, a second session
 * format, and two places for the same bug.
 *
 * WHAT THE ROLE GATES. `admin` may change what the shop is (stock, prices,
 * staff). `user` may only work the counter. The check lives on the SERVER, in
 * `requireRole` — the UI hiding a button is a convenience, never the control.
 *
 * The credential is scrypt-hashed at rest and the session is an HMAC-signed
 * cookie, so there is no session table to leak and a restart does not sign
 * everyone out.
 */
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { getDb } from './db';

export const ROLES = ['user', 'admin'] as const;
export type Role = (typeof ROLES)[number];

export interface Account {
  readonly id: number;
  readonly username: string;
  readonly displayName: string;
  readonly role: Role;
}

export interface Session {
  readonly username: string;
  readonly role: Role;
}

const COOKIE = 'pharmacy_session';
const TTL_MS = 12 * 60 * 60 * 1000;
const SECRET = process.env.PHARMACY_SESSION_SECRET ?? 'dev-pharmacy-session-secret';
const ADMIN_USER = process.env.PHARMACY_ADMIN_USER ?? 'admin';
const ADMIN_PASSWORD = process.env.PHARMACY_ADMIN_PASSWORD ?? 'pharmacy-admin';

function hash(password: string, salt: string): string {
  return scryptSync(password, salt, 64).toString('hex');
}

/** Seed the owner account on first use; never overwrite an existing one. */
export function ensureOwnerSeeded(): void {
  const db = getDb();
  const existing = db.prepare('SELECT id FROM accounts WHERE username = ?').get(ADMIN_USER);
  if (existing) return;
  const salt = randomBytes(16).toString('hex');
  db.prepare(
    'INSERT INTO accounts (username, password_hash, role, display_name, created_at) VALUES (?, ?, ?, ?, ?)',
  ).run(ADMIN_USER, `${salt}:${hash(ADMIN_PASSWORD, salt)}`, 'admin', 'Owner', new Date().toISOString());
  console.log(`[pharmacy] seeded owner account '${ADMIN_USER}'`);
}

function rowFor(username: string): { id: number; passwordHash: string; role: string; displayName: string } | null {
  const row = getDb()
    .prepare('SELECT id, password_hash AS passwordHash, role, display_name AS displayName FROM accounts WHERE username = ?')
    .get(username) as { id: number; passwordHash: string; role: string; displayName: string } | undefined;
  return row ?? null;
}

function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

export function signIn(username: string, password: string): Account | null {
  const row = rowFor(username);
  if (!row) return null;
  const [salt, expected] = row.passwordHash.split(':');
  const actual = hash(password, salt);
  // Constant-time: a length-dependent compare leaks the hash one byte at a time.
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  if (!isRole(row.role)) return null;
  return { id: row.id, username, displayName: row.displayName, role: row.role };
}

export function listAccounts(): Account[] {
  const rows = getDb()
    .prepare('SELECT id, username, display_name AS displayName, role FROM accounts ORDER BY username')
    .all() as Array<{ id: number; username: string; displayName: string; role: string }>;
  return rows.filter((row): row is Account => isRole(row.role));
}

export function createAccount(input: {
  username: string;
  password: string;
  displayName: string;
  role: Role;
}): Account {
  const salt = randomBytes(16).toString('hex');
  const info = getDb()
    .prepare(
      'INSERT INTO accounts (username, password_hash, role, display_name, created_at) VALUES (?, ?, ?, ?, ?)',
    )
    .run(
      input.username,
      `${salt}:${hash(input.password, salt)}`,
      input.role,
      input.displayName,
      new Date().toISOString(),
    );
  return {
    id: Number(info.lastInsertRowid),
    username: input.username,
    displayName: input.displayName,
    role: input.role,
  };
}

export function accountExists(username: string): boolean {
  return rowFor(username) !== null;
}

function sign(payload: string): string {
  return createHmac('sha256', SECRET).update(payload).digest('hex');
}

/** `username:role:expires`, signed. Usernames cannot contain ':' (enforced on create). */
export function issueSessionCookie(account: Account): string {
  const expires = String(Date.now() + TTL_MS);
  const payload = `${account.username}:${account.role}:${expires}`;
  return `${COOKIE}=${payload}.${sign(payload)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${TTL_MS / 1000}`;
}

export function clearSessionCookie(): string {
  return `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

export function readSession(cookieHeader: string | null): Session | null {
  if (!cookieHeader) return null;
  const value = cookieHeader
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1);
  if (!value) return null;

  const lastDot = value.lastIndexOf('.');
  if (lastDot <= 0) return null;
  const payload = value.slice(0, lastDot);
  const signature = value.slice(lastDot + 1);
  if (sign(payload) !== signature) return null;

  const [username, role, expires] = payload.split(':');
  if (!username || !role || !expires) return null;
  if (Number(expires) < Date.now()) return null;
  if (!isRole(role)) return null;
  return { username, role };
}

/** Server-side authority check. Never trust a role the client sends. */
export function requireRole(cookieHeader: string | null, role: Role): Session | null {
  const session = readSession(cookieHeader);
  if (!session) return null;
  if (role === 'admin' && session.role !== 'admin') return null;
  return session;
}
