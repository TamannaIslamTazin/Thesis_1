/**
 * SSI Healthcare - User Repository
 * 
 * Database operations for user management
 */

import { createHash } from 'crypto';
import { db } from './index.js';
import type { Prisma } from '../../prisma/generated/client/index.js';

/**
 * Hash a session token with SHA-256 before storage/lookup.
 * Plaintext tokens are never persisted — only the hash is stored.
 * If the database is compromised, active sessions cannot be hijacked.
 */
function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export type UserCreateInput = Prisma.UserCreateInput;
export type UserUpdateInput = Prisma.UserUpdateInput;
export type UserWhereInput = Prisma.UserWhereInput;

/**
 * Create a new user
 */
export async function createUser(data: UserCreateInput) {
  return db.user.create({
    data,
    include: {
      accounts: true,
      passkeys: true,
      notificationPrefs: true,
    },
  });
}

/**
 * Find user by ID
 */
export async function findUserById(id: string) {
  return db.user.findUnique({
    where: { id },
    include: {
      accounts: true,
      passkeys: true,
      notificationPrefs: true,
    },
  });
}

/**
 * Find user by email
 */
export async function findUserByEmail(email: string) {
  return db.user.findUnique({
    where: { email },
    include: {
      accounts: true,
      passkeys: true,
      notificationPrefs: true,
    },
  });
}

/**
 * Find user by DID
 */
export async function findUserByDid(did: string) {
  return db.user.findUnique({
    where: { did },
    include: {
      credentials: {
        where: { status: 'ACTIVE' },
        orderBy: { issuedAt: 'desc' },
      },
    },
  });
}

/**
 * Update user
 */
export async function updateUser(id: string, data: UserUpdateInput) {
  return db.user.update({
    where: { id },
    data,
    include: {
      accounts: true,
      notificationPrefs: true,
    },
  });
}

/**
 * Update user's last login
 */
export async function updateUserLogin(id: string) {
  return db.user.update({
    where: { id },
    data: {
      lastLoginAt: new Date(),
    },
  });
}

/**
 * Set user wallet as setup
 */
export async function setWalletSetup(
  userId: string, 
  did: string, 
  walletType: 'CLOUD' | 'DEVICE' | 'HARDWARE' | 'HYBRID'
) {
  return db.user.update({
    where: { id: userId },
    data: {
      did,
      walletSetup: true,
      walletType,
    },
  });
}

/**
 * Delete user (soft delete by deactivating)
 */
export async function deleteUser(id: string) {
  return db.user.delete({
    where: { id },
  });
}

/**
 * Count users
 */
export async function countUsers(where?: UserWhereInput) {
  return db.user.count({ where });
}

/**
 * List users with pagination
 */
export async function listUsers(options: {
  skip?: number;
  take?: number;
  where?: UserWhereInput;
  orderBy?: Prisma.UserOrderByWithRelationInput;
}) {
  const { skip = 0, take = 20, where, orderBy = { createdAt: 'desc' } } = options;
  
  return db.user.findMany({
    skip,
    take,
    where,
    orderBy,
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      displayName: true,
      did: true,
      walletSetup: true,
      createdAt: true,
      lastLoginAt: true,
    },
  });
}

// Session operations

/**
 * Create a new session
 */
export async function createSession(data: Prisma.SessionCreateInput) {
  return db.session.create({
    data: {
      ...data,
      token: hashToken(data.token),
      refreshToken: data.refreshToken ? hashToken(data.refreshToken) : data.refreshToken,
    },
  });
}

/**
 * Find an ACTIVE session by token.
 *
 * SECURITY: the status predicate is applied here, not at the call sites, so a
 * caller cannot forget it. POST /api/auth/login persists a session row to carry
 * the OTP challenge and hands its token to a caller who has not yet proved they
 * control the mailbox; without this filter that token is accepted by
 * requireAuth as a fully valid bearer token.
 *
 * `findFirst` rather than `findUnique` because `status` is not part of a unique
 * constraint. `token` is still `@unique`, so this remains a single index hit.
 *
 * The OTP verification path deliberately does NOT use this function — it looks
 * the pending row up directly and flips it to ACTIVE on success.
 */
export async function findSessionByToken(token: string) {
  return db.session.findFirst({
    where: { token: hashToken(token), status: 'ACTIVE' },
    include: { user: true },
  });
}

/**
 * Update session activity
 */
export async function updateSessionActivity(token: string) {
  return db.session.update({
    where: { token: hashToken(token) },
    data: { lastActiveAt: new Date() },
  });
}

/**
 * Delete session
 */
export async function deleteSession(token: string) {
  return db.session.delete({ where: { token: hashToken(token) } });
}

/**
 * Delete session by ID
 */
export async function deleteSessionById(id: string) {
  return db.session.delete({ where: { id } });
}

/**
 * Find session by refresh token
 */
export async function findSessionByRefreshToken(refreshToken: string) {
  // Same status predicate as findSessionByToken: a session still awaiting OTP
  // verification must not be refreshable into an active one.
  return db.session.findFirst({
    where: { refreshToken: hashToken(refreshToken), status: 'ACTIVE' },
    include: { user: true },
  });
}

/**
 * Update session tokens (for refresh)
 */
export async function updateSessionTokens(
  id: string,
  tokens: {
    token: string;
    refreshToken: string;
    expiresAt: Date;
    refreshExpiresAt: Date;
  }
) {
  return db.session.update({
    where: { id },
    data: {
      token: hashToken(tokens.token),
      refreshToken: hashToken(tokens.refreshToken),
      expiresAt: tokens.expiresAt,
      refreshExpiresAt: tokens.refreshExpiresAt,
      lastActiveAt: new Date(),
    },
  });
}

/**
 * Delete all sessions for a user
 */
export async function deleteUserSessions(userId: string) {
  return db.session.deleteMany({ where: { userId } });
}

/**
 * Clean up expired sessions
 */
export async function cleanupExpiredSessions() {
  return db.session.deleteMany({
    where: {
      expiresAt: { lt: new Date() },
    },
  });
}

// OAuth Account operations

/**
 * Link OAuth account to user
 */
export async function linkOAuthAccount(data: Prisma.AccountCreateInput) {
  return db.account.create({ data });
}

/**
 * Find OAuth account
 */
export async function findOAuthAccount(provider: string, providerAccountId: string) {
  return db.account.findUnique({
    where: {
      provider_providerAccountId: { provider, providerAccountId },
    },
    include: { user: true },
  });
}

/**
 * Update OAuth tokens
 */
export async function updateOAuthTokens(
  id: string,
  tokens: {
    accessToken?: string;
    refreshToken?: string;
    expiresAt?: number;
  }
) {
  return db.account.update({
    where: { id },
    data: tokens,
  });
}

// Passkey operations

/**
 * Register a passkey
 */
export async function registerPasskey(data: Prisma.PasskeyCreateInput) {
  return db.passkey.create({ data });
}

/**
 * Find passkey by credential ID
 */
export async function findPasskeyByCredentialId(credentialId: string) {
  return db.passkey.findUnique({
    where: { credentialId },
    include: { user: true },
  });
}

/**
 * Update passkey counter (for replay attack prevention)
 */
export async function updatePasskeyCounter(credentialId: string, counter: bigint) {
  return db.passkey.update({
    where: { credentialId },
    data: {
      counter,
      lastUsedAt: new Date(),
    },
  });
}

/**
 * List user's passkeys
 */
export async function listUserPasskeys(userId: string) {
  return db.passkey.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
  });
}

/**
 * Delete passkey
 */
export async function deletePasskey(credentialId: string) {
  return db.passkey.delete({ where: { credentialId } });
}
