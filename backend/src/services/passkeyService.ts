/**
 * SSI Healthcare Backend - Passkey / WebAuthn Service
 *
 * Bridge between SSI DIDs and FIDO2/WebAuthn Passkey authentication.
 * Uses @simplewebauthn/server for cryptographic verification and
 * Prisma via userRepository for persistence.
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
} from '@simplewebauthn/server';

import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';
import { db } from '../db/index.js';
import {
  registerPasskey,
  findPasskeyByCredentialId,
  updatePasskeyCounter,
  listUserPasskeys,
  deletePasskey,
} from '../db/userRepository.js';

// ---------------------------------------------------------------------------
// Challenge store (durable DB-backed storage with expiry — H-14)
// Challenges expire in 5 minutes and are consumed (deleted) on use.
// ---------------------------------------------------------------------------

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

async function storeChallenge(
  challenge: string,
  userId: string,
  type: 'registration' | 'authentication',
  did?: string,
): Promise<void> {
  await db.passkeyChallenge.create({
    data: {
      challenge,
      userId,
      did,
      type,
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
    },
  });
  await db.passkeyChallenge.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
}

/**
 * Atomically consume a one-time WebAuthn challenge.
 *
 * `challenge` is `@unique`, so this is a single `DELETE ... RETURNING`: exactly
 * one concurrent caller can win and every other caller sees "record not found".
 *
 * The previous implementation was a find, then a separate delete. Two requests
 * carrying the same challenge could both complete the find before either
 * delete landed, so both proceeded — a WebAuthn challenge is single-use by
 * definition and that made it replayable.
 *
 * The record is consumed even when the type or expiry check then fails, which
 * is intended: a challenge that has been presented is spent either way.
 */
async function consumeChallenge(
  challenge: string,
  expectedType: 'registration' | 'authentication',
): Promise<{ userId: string; did?: string | null }> {
  let record: { userId: string; did: string | null; type: string; expiresAt: Date };

  try {
    record = await db.passkeyChallenge.delete({ where: { challenge } });
  } catch {
    // P2025 (or any failure to claim the row) means someone else consumed it,
    // or it never existed.
    throw new Error(`Invalid or expired ${expectedType} challenge`);
  }

  if (record.type !== expectedType) {
    throw new Error(`Invalid or expired ${expectedType} challenge`);
  }

  if (record.expiresAt < new Date()) {
    throw new Error(`${expectedType} challenge has expired`);
  }

  return { userId: record.userId, did: record.did };
}

// ---------------------------------------------------------------------------
// Registration Flow
// ---------------------------------------------------------------------------

/**
 * Generate WebAuthn registration options for a user.
 * The client passes these to `navigator.credentials.create()`.
 */
export async function generatePasskeyRegistrationOptions(
  userId: string,
  did?: string,
) {
  const existingPasskeys = await listUserPasskeys(userId);

  const excludeCredentials = existingPasskeys.map((pk) => ({
    id: pk.credentialId,
    transports: (pk.transports ?? []) as AuthenticatorTransportFuture[],
  }));

  const options = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpId,
    userName: did ?? userId,
    userDisplayName: did ? `SSI User (${did.substring(0, 20)}…)` : 'SSI Healthcare User',
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
    attestationType: 'none',
    timeout: 120_000,
  });

  await storeChallenge(options.challenge, userId, 'registration', did);

  logger.info('Passkey registration options generated', { userId, did });

  return options;
}

/**
 * Verify the registration response from the client and persist the new passkey.
 */
export async function verifyPasskeyRegistration(
  response: RegistrationResponseJSON,
  expectedChallenge: string,
  /**
   * The authenticated session user. The new passkey is bound to the challenge's
   * owner, so this MUST be supplied and MUST match, otherwise the caller
   * chooses whose account the credential lands on.
   */
  authenticatedUserId: string,
) {
  const pending = await consumeChallenge(expectedChallenge, 'registration');

  // SECURITY: `expectedChallenge` arrives in the request body, and the passkey
  // below is attached to `pending.userId` — the user the challenge was minted
  // for, not the caller. Without this comparison any authenticated user who
  // obtained another user's registration challenge could enrol their own
  // authenticator on that user's account and log in as them thereafter.
  if (pending.userId !== authenticatedUserId) {
    logger.warn('Passkey registration challenge does not belong to the caller', {
      challengeUserId: pending.userId,
      authenticatedUserId,
    });
    throw new Error('Registration challenge does not belong to the current user');
  }

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: config.rpOrigin,
    expectedRPID: config.rpId,
    requireUserVerification: true,
  });

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('Registration verification failed');
  }

  const { credential } = verification.registrationInfo;

  const passkey = await registerPasskey({
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey),
    counter: BigInt(credential.counter),
    transports: (credential.transports ?? []) as string[],
    user: { connect: { id: pending.userId } },
  });

  logger.info('Passkey registered', {
    userId: pending.userId,
    credentialId: credential.id,
    did: pending.did,
  });

  return {
    id: passkey.id,
    credentialId: passkey.credentialId,
    userId: passkey.userId,
    createdAt: passkey.createdAt,
  };
}

// ---------------------------------------------------------------------------
// Authentication Flow
// ---------------------------------------------------------------------------

/**
 * Generate WebAuthn authentication options.
 * If a userId is provided, only their registered credentials are allowed.
 */
export async function generatePasskeyAuthOptions(userId?: string) {
  let allowCredentials:
    | { id: string; transports?: AuthenticatorTransportFuture[] }[]
    | undefined;

  if (userId) {
    const passkeys = await listUserPasskeys(userId);
    allowCredentials = passkeys.map((pk) => ({
      id: pk.credentialId,
      transports: (pk.transports ?? []) as AuthenticatorTransportFuture[],
    }));
  }

  const options = await generateAuthenticationOptions({
    rpID: config.rpId,
    allowCredentials,
    userVerification: 'required',
    timeout: 120_000,
  });

  await storeChallenge(options.challenge, userId ?? '', 'authentication');

  logger.info('Passkey auth options generated', { userId });

  return options;
}

/**
 * Verify the authentication response and update counter.
 * Returns the authenticated user's info on success.
 */
export async function verifyPasskeyAuthentication(
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
) {
  await consumeChallenge(expectedChallenge, 'authentication');

  const storedPasskey = await findPasskeyByCredentialId(response.id);
  if (!storedPasskey) {
    throw new Error('Credential not found');
  }

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: config.rpOrigin,
    expectedRPID: config.rpId,
    credential: {
      id: storedPasskey.credentialId,
      publicKey: new Uint8Array(storedPasskey.publicKey),
      counter: Number(storedPasskey.counter),
      transports: (storedPasskey.transports ?? []) as AuthenticatorTransportFuture[],
    },
    requireUserVerification: true,
  });

  if (!verification.verified) {
    throw new Error('Authentication verification failed');
  }

  await updatePasskeyCounter(
    storedPasskey.credentialId,
    BigInt(verification.authenticationInfo.newCounter),
  );

  logger.info('Passkey authentication successful', {
    userId: storedPasskey.userId,
    credentialId: storedPasskey.credentialId,
  });

  return {
    authenticated: true,
    userId: storedPasskey.userId,
    did: storedPasskey.user?.did ?? null,
    credentialId: storedPasskey.credentialId,
  };
}

// ---------------------------------------------------------------------------
// Management
// ---------------------------------------------------------------------------

/**
 * List all passkeys for a user.
 */
export async function listPasskeys(userId: string) {
  const passkeys = await listUserPasskeys(userId);
  return passkeys.map((pk) => ({
    id: pk.id,
    credentialId: pk.credentialId,
    deviceName: pk.deviceName,
    transports: pk.transports,
    lastUsedAt: pk.lastUsedAt,
    createdAt: pk.createdAt,
  }));
}

/**
 * Remove a passkey by credential ID.
 */
export async function removePasskey(credentialId: string, userId: string) {
  const passkey = await findPasskeyByCredentialId(credentialId);
  if (!passkey || passkey.userId !== userId) {
    throw new Error('Passkey not found or not owned by user');
  }
  await deletePasskey(credentialId);
  logger.info('Passkey removed', { credentialId, userId });
}

/**
 * Update device name for a passkey.
 */
export async function renamePasskey(
  credentialId: string,
  userId: string,
  deviceName: string,
) {
  const passkey = await findPasskeyByCredentialId(credentialId);
  if (!passkey || passkey.userId !== userId) {
    throw new Error('Passkey not found or not owned by user');
  }
  return db.passkey.update({
    where: { credentialId },
    data: { deviceName },
  });
}
