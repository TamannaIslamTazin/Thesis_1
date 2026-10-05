/**
 * SSI Healthcare Backend - Authentication Routes
 * 
 * Handles user registration, login, and session management
 */

import { Router, Request, Response, NextFunction } from 'express';
import { randomBytes, createHash, randomInt } from 'crypto';
import { z } from 'zod';
// `createDID` is deliberately NOT imported. A patient DID is minted ONLY by
// `enrolPatient`, which is the sole path that can express the S-1 §8.1 shape
// and the only one that is atomic. A generic factory sitting in scope here is
// an invitation to "just call it" and reintroduce the unrecoverable shape.
import { getAgent } from '../agent/index.js';
import {
  enrolPatient,
  selectRecoveryControllerProvider,
} from '../services/patientEnrolment.js';
import { db } from '../db/index.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import * as userRepo from '../db/userRepository.js';
import * as consentRepo from '../db/consentRepository.js';
import { AuditEventType, SessionStatus, type WalletType } from '../../prisma/generated/client/index.js';
import { sendLoginCode, sendWelcomeEmail } from '../services/emailService.js';
import { requireAuth, type AuthenticatedRequest } from '../middleware/auth.js';
import {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  generatePasskeyAuthOptions,
  verifyPasskeyAuthentication,
} from '../services/passkeyService.js';
import { generateTotpSetup, verifyTotpCode } from '../services/totpService.js';
import { config } from '../config/index.js';
import {
  issueChallenge,
  consumeChallenge,
  verifySignedDidLogin,
} from '../services/didLoginAuth.js';

const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

interface OAuthProviderConfig {
  jwksUri: string;
  /** Expected `iss` claim. An array permits the provider's known aliases. */
  issuer: string | string[];
  /** Expected `aud` claim: this server's OAuth client ID for the provider. */
  audience: string;
}

/**
 * OAuth providers this server will accept ID tokens from.
 *
 * A provider appears here only when its client ID is configured, because an ID
 * token can only be trusted if it was issued *for this application*. Signature
 * and issuer checks alone do not establish that — every relying party on
 * Google, Apple or Microsoft receives tokens signed by the same keys with the
 * same issuer, distinguished only by `aud`.
 *
 * Built once at module load; it depends solely on static configuration.
 */
const OAUTH_PROVIDERS: Record<string, OAuthProviderConfig> = (() => {
  const providers: Record<string, OAuthProviderConfig> = {};

  if (config.googleClientId) {
    providers.google = {
      jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
      issuer: ['https://accounts.google.com', 'accounts.google.com'],
      audience: config.googleClientId,
    };
  }

  if (config.appleClientId) {
    providers.apple = {
      jwksUri: 'https://appleid.apple.com/auth/keys',
      issuer: 'https://appleid.apple.com',
      audience: config.appleClientId,
    };
  }

  // Microsoft issuers are tenant-scoped: the issuer contains the concrete
  // tenant GUID. The previous literal 'https://login.microsoftonline.com/
  // {tenantid}/v2.0' was the un-substituted documentation template and could
  // never match a real token, so Microsoft sign-in was permanently broken.
  // A concrete tenant is required to build both the issuer and its JWKS URI.
  if (config.microsoftClientId && config.microsoftTenantId) {
    providers.microsoft = {
      jwksUri: `https://login.microsoftonline.com/${config.microsoftTenantId}/discovery/v2.0/keys`,
      issuer: `https://login.microsoftonline.com/${config.microsoftTenantId}/v2.0`,
      audience: config.microsoftClientId,
    };
  }

  return providers;
})();

const router = Router();

/**
 * Generate a cryptographically secure session token
 * Uses 32 bytes (256 bits) of entropy, encoded as hex (64 characters)
 */
function generateSecureToken(): string {
  return randomBytes(32).toString('hex');
}

// Validation schemas
const registerSchema = z.object({
  /**
   * OPTIONAL, and omitted by the wallet.
   *
   * Identity here is the patient DID, minted at enrolment with a key the
   * handset holds. An email address is a third-party IAM dependency that binds
   * a name-bearing identifier to that DID, and it put this operator in the loop
   * for something the design says the operator must not see. It remains
   * accepted only so the issuer console and existing accounts keep working.
   * See __docs__/REMOVING-EMAIL-FROM-AUTH.md.
   */
  email: z.string().email().optional(),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  provider: z.enum(['email', 'google', 'apple', 'microsoft']).optional(),
  providerAccountId: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  // For now, we use magic link / OAuth, no password
});

const walletSetupSchema = z.object({
  walletType: z.enum(['CLOUD', 'DEVICE', 'HARDWARE', 'HYBRID']),
  /**
   * The patient's own Ed25519 public key, generated on their device, as an
   * `z`-prefixed multibase string.
   *
   * When present the minted DID's `#key-1` is this key and the private half
   * never reaches this process, which is what lets the wallet authenticate by
   * signing a challenge instead of receiving a code by email. When absent the
   * agent generates the key, and the resulting account can only sign in through
   * the legacy email path — see __docs__/REMOVING-EMAIL-FROM-AUTH.md.
   */
  devicePublicKeyMultibase: z.string().min(40).optional(),
});

/**
 * POST /api/auth/register
 * Register a new user
 */
router.post('/register', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = registerSchema.parse(req.body);
    
    // Only meaningful when an address was supplied; DID-only accounts are
    // distinguished by their identifier, which does not exist yet at this point.
    const existingUser = data.email ? await userRepo.findUserByEmail(data.email) : null;
    if (existingUser) {
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        'User with this email already exists',
        409
      );
    }
    
    // Create user
    const user = await userRepo.createUser({
      email: data.email,
      firstName: data.firstName,
      lastName: data.lastName,
      displayName: data.firstName ? `${data.firstName} ${data.lastName || ''}`.trim() : undefined,
    });
    
    // If OAuth provider, link account
    if (data.provider && data.providerAccountId) {
      await userRepo.linkOAuthAccount({
        type: 'oauth',
        provider: data.provider,
        providerAccountId: data.providerAccountId,
        user: { connect: { id: user.id } },
      });
    }
    
    // Create audit log
    await consentRepo.createAuditLog({
      eventType: AuditEventType.USER_REGISTERED,
      action: 'User registered',
      actorUserId: user.id,
      details: { provider: data.provider || 'email' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });
    
    // Create session with access and refresh tokens
    const token = generateSecureToken();
    const refreshToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    const refreshExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
    
    await userRepo.createSession({
      token,
      refreshToken,
      expiresAt,
      refreshExpiresAt,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      user: { connect: { id: user.id } },
    });
    
    logger.info('User registered', { userId: user.id, email: user.email });
    
    // Send welcome email (non-blocking — don't delay registration response).
    // `data.email`, not `user.email`: this route only ever creates a user FROM
    // a validated email, so `data.email` is a known non-null string, while
    // `User.email` is `string | null` at the type level since it became
    // optional for the DID-only signup path this round adds.
    if (data.email) sendWelcomeEmail(data.email, user.firstName ?? undefined).catch((err) => {
      logger.error('Failed to send welcome email', {
        email: user.email,
        error: err instanceof Error ? err.message : String(err),
      });
    });
    
    res.status(201).json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          walletSetup: user.walletSetup,
        },
        token,
        refreshToken,
        expiresIn: 900, // 15 minutes in seconds
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/login
 * Unified magic link auth — works for both new and existing users.
 * Creates the account if it doesn't exist, then sends a 6-digit OTP via email.
 *
 * Always sends the code via email — SMTP must be configured.
 */
/**
 * EMAIL LOGIN — THE ISSUER CONSOLE ONLY. The wallet no longer has this path.
 *
 * A citizen's identity is their DID, and they sign in by proving control of its
 * key (`/auth/challenge` + `/auth/did-login`). Email was removed from the wallet
 * because it makes a third-party IAM provider part of a citizen's identity,
 * binds a name-bearing address to their DID, and puts this operator in the loop
 * for something the design says the operator must not see.
 *
 * None of that reasoning applies to `packages/issuer-console`, whose users are
 * institutional staff, selected for the role and already known to the authority
 * employing them. These two routes exist for them. DO NOT reintroduce them into
 * the wallet. See __docs__/REMOVING-EMAIL-FROM-AUTH.md.
 */
router.post('/login', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = loginSchema.parse(req.body);

    // Find or create user — new users are created inline (email verified on OTP success)
    let user = await userRepo.findUserByEmail(data.email);
    let isNewUser = false;

    if (!user) {
      user = await userRepo.createUser({ email: data.email });
      if (!user) throw new Error('Failed to create user account');
      isNewUser = true;
      await consentRepo.createAuditLog({
        eventType: AuditEventType.USER_REGISTERED,
        action: 'User account created via magic link',
        actorUserId: user.id,
        details: { provider: 'email' },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      logger.info('New user created via magic link', { userId: user.id, email: user.email });
    }

    // Generate a uniform 6-digit one-time login code using crypto.randomInt
    const loginCode = randomInt(0, 1_000_000).toString().padStart(6, '0');
    const codeExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Store the login code hash in the pending session (deviceName used as metadata slot)
    // SECURITY: pendingToken is NEVER stored in the audit log — only the code hash is stored
    // and it is stored server-side in the session record, not in any log.
    const pendingToken = generateSecureToken();
    const codeHash = createHash('sha256').update(loginCode).digest('hex');
    // Use a unique placeholder for refreshToken (unique constraint requires distinct values)
    const pendingRefreshToken = `pending_${generateSecureToken()}`;
    await userRepo.createSession({
      token: pendingToken,
      refreshToken: pendingRefreshToken,
      expiresAt: codeExpiresAt,
      refreshExpiresAt: codeExpiresAt,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      // Store codeHash in deviceName slot — consumed and cleared after verification
      deviceName: `pending_code:${codeHash}`,
      // SECURITY: this row exists only to carry the OTP challenge. The caller
      // has not yet proved control of the mailbox, and `pendingToken` is
      // returned to them below. PENDING_VERIFICATION keeps it out of
      // findSessionByToken, so requireAuth rejects it with 401 until
      // /verify-code promotes it to ACTIVE.
      status: SessionStatus.PENDING_VERIFICATION,
      user: { connect: { id: user.id } },
    });

    // Audit: record that a login code was sent — NO security tokens in audit log
    await consentRepo.createAuditLog({
      eventType: AuditEventType.USER_LOGIN,
      action: 'Login code generated (pending verification)',
      actorUserId: user.id,
      details: { expiresAt: codeExpiresAt.toISOString() },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    logger.info('Login code generated', { userId: user.id, email: user.email, isNewUser });

    // DEV-ONLY, DOUBLE-GUARDED. Institutional staff sign in with an emailed
    // code (the #398 exception), and on a test deployment those addresses are
    // fictitious — `officer@bmdc.bdhealthtrust.test` has no inbox, so the code
    // is unrecoverable and the console cannot be signed into at all.
    //
    // TWO conditions, not one, and both must be deliberate: `NODE_ENV` must not
    // be production AND the flag must be explicitly set. A single check is one
    // typo away from printing login codes in production logs, and the failure
    // would be silent — nothing breaks, the codes are just there for anyone
    // with log access. There is deliberately no default-on path.
    if (process.env.NODE_ENV !== 'production' && process.env.SSI_DEV_LOG_LOGIN_CODES === 'true') {
      logger.warn('DEV ONLY — login code, because this deployment cannot deliver email', {
        email: user.email,
        loginCode,
        warning: 'Never enable SSI_DEV_LOG_LOGIN_CODES outside a test deployment.',
      });
    }

    // Send code via email — throws if SMTP fails. `data.email`, not
    // `user.email`: this endpoint only reaches here for a validated email
    // (see the `sendWelcomeEmail` comment above for why `User.email` alone is
    // no longer known non-null at the type level).
    await sendLoginCode(data.email, loginCode);

    res.json({
      success: true,
      data: {
        pendingToken,
        expiresIn: 600, // 10 minutes
        isNewUser,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/verify-code
 * Verify login code and issue session tokens
 */
const verifyCodeSchema = z.object({
  pendingToken: z.string().min(1),
  code: z.string().length(6),
});

router.post('/verify-code', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = verifyCodeSchema.parse(req.body);
    
    // Compute hash of submitted code for comparison
    const codeHash = createHash('sha256').update(data.code).digest('hex');
    const expectedDeviceName = `pending_code:${codeHash}`;
    
    // ATOMIC: find-and-consume the pending session in a single transaction.
    // If two requests arrive simultaneously with the same pendingToken, only one
    // will see deviceName still set to the expected value — the second will fail.
    const consumed = await db.$transaction(async (tx) => {
      // Look up pending session — must have the code hash stored and not expired
      const session = await tx.session.findUnique({
        where: { token: createHash('sha256').update(data.pendingToken).digest('hex') },
        include: { user: true },
      });

      if (!session || session.expiresAt < new Date()) {
        return null; // expired or not found
      }

      // Only a session still awaiting verification may be consumed here. This
      // stops an already-active session token from being replayed against this
      // endpoint to mint a fresh token pair.
      if (session.status !== SessionStatus.PENDING_VERIFICATION) {
        return null;
      }

      if (session.deviceName !== expectedDeviceName) {
        return null; // wrong code or already consumed
      }

      // Clear deviceName to mark code as consumed before issuing new tokens
      const token = generateSecureToken();
      const refreshToken = generateSecureToken();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      const refreshExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

      await tx.session.update({
        where: { id: session.id },
        data: {
          token: createHash('sha256').update(token).digest('hex'),
          refreshToken: createHash('sha256').update(refreshToken).digest('hex'),
          expiresAt,
          refreshExpiresAt,
          lastActiveAt: new Date(),
          deviceName: null, // consumed — code hash cleared
          // Identity is now proven; promote the row so requireAuth accepts it.
          status: SessionStatus.ACTIVE,
        },
      });

      return { session, token, refreshToken, expiresAt };
    });

    if (!consumed) {
      throw new AppError(ERROR_CODES.AUTH_FAILED, 'Invalid or expired login code', 401);
    }
    
    await userRepo.updateUserLogin(consumed.session.userId);
    
    await consentRepo.createAuditLog({
      eventType: AuditEventType.USER_LOGIN,
      action: 'User logged in (code verified)',
      actorUserId: consumed.session.userId,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });
    
    const user = consumed.session.user;
    
    logger.info('User logged in via verified code', { userId: user.id, email: user.email });
    
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          did: user.did,
          walletSetup: user.walletSetup,
        },
        token: consumed.token,
        refreshToken: consumed.refreshToken,
        expiresIn: 15 * 60,
        needsWalletSetup: !user.walletSetup,
      },
    });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// DID challenge-response login (AUTH-AND-KEYSTORE-API.md §1)
//
// An ADDITIONAL path for a device that already completed wallet setup and
// already holds a device key bound to `User.did` — not a replacement for the
// email/OTP endpoints above, which the wallet still needs until its own
// screens are rebuilt in a later round.
// ---------------------------------------------------------------------------

const didChallengeSchema = z.object({
  did: z.string().startsWith('did:'),
});

/**
 * POST /api/auth/challenge
 * Issue a single-use, short-lived login nonce for a DID the caller claims to
 * control. Possession is NOT checked here — that is what /did-login proves.
 */
router.post('/challenge', async (req: Request, res: Response, next: NextFunction) => {
  try {
    // The audience is ours and must be configured — same guard
    // `requireProfessional` already applies to `config.verifierDid`, reused
    // here rather than inventing a second "who are we" value. Unset means no
    // signature can be safely bound to this deployment, so refuse rather than
    // issue an audience-less challenge.
    if (!config.verifierDid) {
      throw new AppError(
        ERROR_CODES.INTERNAL_ERROR,
        'This deployment has no VERIFIER_DID configured, so a DID-login challenge cannot be ' +
          'bound to an audience.',
        503,
      );
    }

    const { did } = didChallengeSchema.parse(req.body);
    const challenge = await issueChallenge(did, config.verifierDid);

    res.status(201).json({
      success: true,
      data: {
        nonce: challenge.nonce,
        expiresAt: challenge.expiresAt,
        // Additive beyond the documented { nonce, expiresAt }: the exact
        // audience and payload template a wallet needs to build the
        // signature, so it does not have to know this value out of band.
        audience: challenge.audience,
        payloadTemplate: challenge.payloadTemplate,
      },
    });
  } catch (error) {
    next(error);
  }
});

const didLoginSchema = z.object({
  did: z.string().startsWith('did:'),
  nonce: z.string().min(1),
  signature: z.string().min(1),
});

/**
 * POST /api/auth/did-login
 * Verify a signed challenge and issue session tokens, identically to
 * POST /api/auth/verify-code, for whichever User row already carries this DID.
 */
router.post('/did-login', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = didLoginSchema.parse(req.body);

    // SPEND FIRST. The nonce is consumed before the slower, chain-bound
    // verification runs, so a flood of replays cannot each buy a free chain
    // query and two concurrent replays of the same captured signature cannot
    // both proceed — same discipline as /verify-code's atomic consume above
    // and locker's /v1/auth/token.
    const consumption = await consumeChallenge(data.nonce);
    if (!consumption.ok) {
      throw new AppError(ERROR_CODES.AUTH_FAILED, 'Invalid or expired login challenge', 401);
    }

    // The challenge is already spent by this point regardless of what follows
    // — a mismatched `did` does not get a second attempt against this nonce.
    if (consumption.did !== data.did) {
      throw new AppError(
        ERROR_CODES.AUTH_FAILED,
        "did does not match the DID this challenge was issued for",
        401,
      );
    }

    const agent = getAgent();
    const outcome = await verifySignedDidLogin({
      agent,
      did: consumption.did,
      audience: consumption.audience,
      nonce: data.nonce,
      signatureBase64Url: data.signature,
    });

    if (!outcome.ok) {
      throw new AppError(outcome.code, outcome.reason, outcome.httpStatus);
    }

    const user = await userRepo.findUserByDid(outcome.did);
    if (!user) {
      throw new AppError(
        ERROR_CODES.NOT_FOUND,
        `No account on this deployment is linked to '${outcome.did}'.`,
        404,
      );
    }

    // Session tokens issued exactly as /verify-code issues them, so every
    // downstream consumer (requireAuth, /refresh, /logout) keeps working
    // unchanged.
    const token = generateSecureToken();
    const refreshToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    const refreshExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

    await userRepo.createSession({
      token,
      refreshToken,
      expiresAt,
      refreshExpiresAt,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      user: { connect: { id: user.id } },
    });

    await userRepo.updateUserLogin(user.id);

    await consentRepo.createAuditLog({
      eventType: AuditEventType.USER_LOGIN,
      action: 'User logged in via DID challenge-response',
      actorUserId: user.id,
      actorDid: user.did ?? undefined,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    logger.info('User logged in via DID challenge-response', { userId: user.id, did: user.did });

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          did: user.did,
          walletSetup: user.walletSetup,
        },
        token,
        refreshToken,
        expiresIn: 15 * 60,
        needsWalletSetup: !user.walletSetup,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/oauth
 * OAuth login/register flow
 * 
 * SECURITY: Requires an OAuth ID token (not just an access token). The server
 * verifies the token's signature and claims server-side. Client-provided
 * email/providerAccountId are NOT trusted — they must match the verified token.
 */
router.post('/oauth', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const schema = z.object({
      provider: z.enum(['google', 'apple', 'microsoft']),
      idToken: z.string().min(1, 'ID token is required for server-side verification'),
    });
    
    const data = schema.parse(req.body);
    
    // Server-side ID token verification using provider JWKS endpoints
    let tokenPayload: { sub: string; email: string; email_verified?: boolean; name?: string; given_name?: string; family_name?: string };
    
    try {
      const { createRemoteJWKSet, jwtVerify } = await import('jose');
      
      const providerCfg = OAUTH_PROVIDERS[data.provider];

      // Fail closed. A provider is only usable when its expected audience (this
      // server's OAuth client ID) is configured. Verifying signature and issuer
      // alone is NOT sufficient: Google signs ID tokens for every application
      // on the platform with the same keys, so without an `aud` check an
      // attacker can present a token minted for their own unrelated app and
      // take over the account matching its email claim.
      if (!providerCfg) {
        throw new Error(
          `OAuth provider ${data.provider} is not configured on this server`
        );
      }

      const jwks = createRemoteJWKSet(new URL(providerCfg.jwksUri));
      const { payload } = await jwtVerify(data.idToken, jwks, {
        issuer: providerCfg.issuer,
        audience: providerCfg.audience,
      });

      // Validate required claims
      if (!payload.sub || !payload.email) {
        throw new Error('Missing required claims (sub, email)');
      }
      
      // Verify email is confirmed by the provider
      if (payload.email_verified === false) {
        throw new Error('Email not verified by OAuth provider');
      }
      
      tokenPayload = payload as typeof tokenPayload;
    } catch (err) {
      throw new AppError(
        ERROR_CODES.AUTH_FAILED,
        `Invalid OAuth ID token: ${err instanceof Error ? err.message : 'verification failed'}`,
        401,
      );
    }
    
    const { sub: providerAccountId, email, given_name: firstName, family_name: lastName } = tokenPayload;
    
    // Check if OAuth account already exists
    const existingAccount = await userRepo.findOAuthAccount(data.provider, providerAccountId);
    
    let user;
    
    if (existingAccount) {
      user = existingAccount.user;
    } else {
      // Check if email already exists (link accounts)
      const existingUser = await userRepo.findUserByEmail(email);
      
      if (existingUser) {
        await userRepo.linkOAuthAccount({
          type: 'oauth',
          provider: data.provider,
          providerAccountId,
          user: { connect: { id: existingUser.id } },
        });
        user = existingUser;
      } else {
        // Create new user with OAuth
        user = await userRepo.createUser({
          email,
          firstName,
          lastName,
          displayName: firstName ? `${firstName} ${lastName || ''}`.trim() : undefined,
          accounts: {
            create: {
              type: 'oauth',
              provider: data.provider,
              providerAccountId,
            },
          },
        });
        
        await consentRepo.createAuditLog({
          eventType: AuditEventType.USER_REGISTERED,
          action: `User registered via ${data.provider}`,
          actorUserId: user.id,
          details: { provider: data.provider },
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
        });
      }
    }
    
    // Create session with access and refresh tokens
    const token = generateSecureToken();
    const refreshToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    const refreshExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
    
    await userRepo.createSession({
      token,
      refreshToken,
      expiresAt,
      refreshExpiresAt,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      user: { connect: { id: user.id } },
    });
    
    await userRepo.updateUserLogin(user.id);
    
    await consentRepo.createAuditLog({
      eventType: AuditEventType.USER_LOGIN,
      action: `User logged in via ${data.provider}`,
      actorUserId: user.id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });
    
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          did: user.did,
          walletSetup: user.walletSetup,
        },
        token,
        refreshToken,
        expiresIn: 900, // 15 minutes in seconds
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/logout
 * Logout and invalidate session
 */
router.post('/logout', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      res.json({ success: true });
      return;
    }
    
    const token = authHeader.slice(7);
    const session = await userRepo.findSessionByToken(token);
    
    if (session) {
      await userRepo.deleteSession(token);
      
      await consentRepo.createAuditLog({
        eventType: AuditEventType.USER_LOGOUT,
        action: 'User logged out',
        actorUserId: session.userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
    }
    
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/refresh
 * Refresh access token using refresh token
 */
const refreshSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

router.post('/refresh', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = refreshSchema.parse(req.body);
    
    // Find the session by refresh token
    const session = await userRepo.findSessionByRefreshToken(data.refreshToken);
    
    if (!session) {
      throw new AppError(
        ERROR_CODES.AUTH_TOKEN_EXPIRED,
        'Invalid refresh token',
        401
      );
    }
    
    // Check if refresh token is expired
    if (session.refreshExpiresAt && session.refreshExpiresAt < new Date()) {
      // Delete the expired session
      await userRepo.deleteSessionById(session.id);
      throw new AppError(
        ERROR_CODES.AUTH_TOKEN_EXPIRED,
        'Refresh token expired. Please login again.',
        401
      );
    }
    
    // Generate new tokens
    const newToken = generateSecureToken();
    const newRefreshToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    const refreshExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
    
    // Update session with new tokens
    await userRepo.updateSessionTokens(session.id, {
      token: newToken,
      refreshToken: newRefreshToken,
      expiresAt,
      refreshExpiresAt,
    });
    
    logger.info('Token refreshed', { userId: session.userId });
    
    res.json({
      success: true,
      data: {
        token: newToken,
        refreshToken: newRefreshToken,
        expiresIn: 900, // 15 minutes in seconds
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/auth/me
 * Get current user info
 */
router.get('/me', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      throw new AppError(ERROR_CODES.AUTH_TOKEN_EXPIRED, 'No token provided', 401);
    }
    
    const token = authHeader.slice(7);
    const session = await userRepo.findSessionByToken(token);
    
    if (!session || session.expiresAt < new Date()) {
      throw new AppError(ERROR_CODES.AUTH_TOKEN_EXPIRED, 'Session expired', 401);
    }
    
    // Update session activity
    await userRepo.updateSessionActivity(token);
    
    const user = session.user;
    
    res.json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        displayName: user.displayName,
        did: user.did,
        walletSetup: user.walletSetup,
        walletType: user.walletType,
        totpEnabled: user.totpEnabled,
        biometricEnabled: user.biometricEnabled,
        autoLockMinutes: user.autoLockMinutes,
        createdAt: user.createdAt.toISOString(),
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Mint the patient's durable identifier on our sovereign ledger.
 *
 * WHY did:cheqd AND NOT did:key. did:key cannot rotate: the public key IS the
 * identifier, so any recovery that mints a new key mints a new identity and
 * orphans every credential previously issued to the holder. For a health record
 * that is a data-loss bug wearing an identifier's clothes. did:cheqd separates
 * the identifier from the key material, which is the precondition for recovery.
 * did:key remains correct for ephemeral and pairwise use; it is not correct for
 * the identity a patient keeps.
 *
 * NEW USERS ONLY — THERE IS DELIBERATELY NO MIGRATION. Credentials are stored
 * against `holderDid`, so re-keying an existing user silently orphans
 * everything they hold. The existing did:key accounts are dummy test data and
 * are being left exactly as they are. Do not "helpfully" backfill them; that is
 * the same hazard the idempotence guard in the handler exists to prevent, just
 * applied to more rows at once.
 *
 * =========================================================================
 * THE 503 IS LIFTED — R5 PHASE A (#242). WHAT REPLACED IT, AND WHAT DID NOT
 * =========================================================================
 * This used to be a single `createDID('cheqd')`, which took the @cheqd/sdk
 * default and emitted `verificationMethod[0].controller = <the patient's own
 * DID>`. Spike S-1 established BY EXECUTION that that shape is PERMANENTLY
 * UNRECOVERABLE (R0, `1101` at height 46229), so the call was replaced by a
 * hard 503 rather than by a plausible guess.
 *
 * Both values it was waiting for now exist:
 *
 *   1. THE CONTROLLER SET — `[recovery controller, institutional DID]`, 2-of-2
 *      AND. The institutional DID is `config.institutionalDid`, provisioned in
 *      the 1-of-N self-controlled shape #292 requires.
 *   2. THE VERIFICATION-METHOD CONTROLLER — the recovery controller from (1),
 *      never the patient. `enrolPatient` is the only path that can express it
 *      and `assertPatientRecoverableShape` re-checks the assembled document
 *      before broadcast AND the resolved document after it.
 *
 * THE 503 STILL EXISTS, and deliberately: it now means "this deployment has not
 * been told which institution controls its patients, or who holds their
 * recovery keys" rather than "nobody has decided yet". Absent configuration
 * must not become a default, because a controller set can never be repaired
 * (S-1 §5.4) — a DID anchored to a guessed institution is unrepairable from the
 * moment it is written.
 *
 * CUSTODY IS NO LONGER A SINGLE-CALL DECISION — R5 PHASE B.
 * `backend-held-phase-a` put the recovery key in this backend's own store, so
 * both halves of the 2-of-2 sat in one building. Phase B moves it to the device
 * and splits it with SLIP-39 guardians, WITHOUT changing the document — so
 * nothing minted under Phase A needs re-issuing.
 *
 * The consequence for THIS route is structural: a device-held RCK cannot be
 * provisioned inside one request. Guardian shares must be delivered to, and
 * read back by, several humans before the identity is anchored to that key, and
 * shares cannot be retrofitted (S-2 §8). So the device-held path is driven by
 * the guardian ceremony rather than by `/wallet/setup`, and this route REFUSES
 * rather than quietly falling back to the custodial provider — a silent
 * fallback is exactly how a cohort of custodial identities gets minted without
 * anyone noticing.
 */
async function mintPatientDid(
  userId: string,
  walletType: string,
  devicePublicKeyMultibase?: string,
): Promise<string> {
  const institutionalDid = config.institutionalDid;

  if (!institutionalDid) {
    logger.error('wallet_setup_blocked_on_did_controller_policy', {
      userId,
      walletType,
      institutionalDidConfigured: false,
      recoveryCustodyConfigured: Boolean(config.patientRecoveryCustody),
      reference: 'S1-DID-CONTROLLER-SEMANTICS.md §8.1, ROADMAP R5',
    });

    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      'Wallet provisioning is disabled: INSTITUTIONAL_DID is not set. A patient DID needs a ' +
        'controller set of [recovery controller, institution] and a verification method ' +
        'controlled by the recovery controller. The controller set can never be repaired ' +
        'afterwards, so an unconfigured deployment refuses rather than guesses. See ' +
        'S1-DID-CONTROLLER-SEMANTICS.md §8.1.',
      503,
    );
  }

  // Re-derived from this process's own configuration at the point of use —
  // see `selectRecoveryControllerProvider`'s docblock for why that call is
  // shared with `scripts/reissue-identity.ts` rather than each re-implementing
  // the refusal.
  const recoveryControllerProvider = selectRecoveryControllerProvider(
    config.patientRecoveryCustody,
  );

  const agent = getAgent();

  // `persist` runs INSIDE the enrolment, after the shape has been re-read from
  // the chain. Passing it in rather than writing the row here is what makes the
  // whole thing all-or-nothing: if it throws, `enrolPatient` abandons the
  // on-chain artifacts and nothing is recorded (the `assertHolderBound`
  // property, applied to enrolment).
  let mintedDid: string | undefined;
  await enrolPatient(agent, {
    userId,
    institutionalDid,
    recoveryControllerProvider,
    devicePublicKeyMultibase,
    persist: async (result) => {
      await userRepo.setWalletSetup(userId, result.patientDid, walletType as WalletType);
      mintedDid = result.patientDid;
    },
  });

  if (!mintedDid) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      'Enrolment reported success without persisting a DID.',
      500,
    );
  }

  return mintedDid;
}

/**
 * POST /api/auth/wallet/setup
 * Complete wallet setup and generate DID
 */
router.post('/wallet/setup', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      throw new AppError(ERROR_CODES.AUTH_TOKEN_EXPIRED, 'No token provided', 401);
    }
    
    const token = authHeader.slice(7);
    const session = await userRepo.findSessionByToken(token);
    
    if (!session || session.expiresAt < new Date()) {
      throw new AppError(ERROR_CODES.AUTH_TOKEN_EXPIRED, 'Session expired', 401);
    }
    
    const data = walletSetupSchema.parse(req.body);

    // IDEMPOTENCE IS A SAFETY REQUIREMENT, NOT A CONVENIENCE.
    //
    // Credentials are stored against `holderDid`, not against the user id.
    // Minting a second DID for a user who already has one therefore does not
    // "reset" their wallet — it orphans every credential ever issued to them,
    // silently and irreversibly, because the list query filters on the new DID.
    // Any client that retries this call (a dropped response, a double tap, a
    // re-run of an onboarding step) would destroy the user's records.
    //
    // Returning the existing identifier is also the correct semantic: a wallet
    // is provisioned once.
    if (session.user.did && session.user.walletSetup) {
      logger.info('Wallet setup requested for an already-provisioned user — returning existing DID', {
        userId: session.userId,
      });

      res.json({
        success: true,
        data: {
          did: session.user.did,
          walletType: session.user.walletType ?? data.walletType,
        },
      });
      return;
    }

    // The row is written INSIDE this call, by the `persist` callback, once the
    // shape has been verified on chain. Writing it again here would be a second
    // source of truth for the same fact.
    const did = await mintPatientDid(
      session.userId,
      data.walletType,
      data.devicePublicKeyMultibase,
    );

    await consentRepo.createAuditLog({
      eventType: AuditEventType.WALLET_CREATED,
      action: 'Wallet created',
      actorUserId: session.userId,
      actorDid: did,
      details: { walletType: data.walletType },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });
    
    logger.info('Wallet setup complete', { userId: session.userId, did });
    
    res.json({
      success: true,
      data: {
        did,
        walletType: data.walletType,
      },
    });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// TOTP 2FA Routes
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/totp/setup
 * Generate a TOTP secret + QR code. Does NOT enable 2FA until /verify is called.
 */
router.post('/totp/setup', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const user = await userRepo.findUserById(authReq.user.id);
    if (!user) throw new AppError(ERROR_CODES.NOT_FOUND, 'User not found');
    // TOTP embeds the account label in the otpauth:// URI an authenticator app
    // displays; an account enrolled through the DID-only signup path (spec
    // §4) may genuinely carry no email since this round's migration. Refusing
    // here is the fail-closed choice — there is no other stable label to
    // offer instead, and guessing one (the DID, the userId) would put an
    // identifier the user did not choose into their authenticator app.
    if (!user.email) {
      throw new AppError(
        ERROR_CODES.VALIDATION_FAILED,
        'TOTP setup requires an email on the account. This account has none.',
        400,
      );
    }
    if (user.totpEnabled) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'TOTP is already enabled. Disable it first.');
    }

    const { secret, otpauthUrl, qrCodeDataUrl } = await generateTotpSetup(user.email);

    // Store the pending secret temporarily (cleared on verify or next setup call)
    await userRepo.updateUser(user.id, { totpSecret: secret, totpEnabled: false });

    logger.info('TOTP setup initiated', { userId: user.id });

    res.json({
      success: true,
      data: {
        otpauthUrl,
        qrCodeDataUrl,
        // Only expose this in dev — in production omit and require QR scan
        ...(process.env.NODE_ENV === 'development' ? { secret } : {}),
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/totp/verify
 * Verify the TOTP code from the authenticator app, then enable 2FA.
 */
router.post('/totp/verify', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { code } = z.object({ code: z.string().length(6) }).parse(req.body);

    const user = await userRepo.findUserById(authReq.user.id);
    if (!user || !user.totpSecret) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'TOTP setup not initiated. Call /totp/setup first.');
    }

    const valid = await verifyTotpCode(code, user.totpSecret);
    if (!valid) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Invalid TOTP code');
    }

    await userRepo.updateUser(user.id, { totpEnabled: true });

    await consentRepo.createAuditLog({
      eventType: AuditEventType.USER_2FA_ENABLED,
      action: 'TOTP 2FA enabled',
      actorUserId: user.id,
      actorDid: user.did ?? undefined,
      details: {},
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    logger.info('TOTP enabled', { userId: user.id });

    res.json({ success: true, data: { totpEnabled: true } });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/auth/totp
 * Disable TOTP 2FA. Requires valid TOTP code to confirm.
 */
router.delete('/totp', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { code } = z.object({ code: z.string().length(6) }).parse(req.body);

    const user = await userRepo.findUserById(authReq.user.id);
    if (!user || !user.totpEnabled || !user.totpSecret) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'TOTP is not enabled');
    }

    const valid = await verifyTotpCode(code, user.totpSecret);
    if (!valid) {
      throw new AppError(ERROR_CODES.VALIDATION_FAILED, 'Invalid TOTP code');
    }

    await userRepo.updateUser(user.id, { totpEnabled: false, totpSecret: null });

    await consentRepo.createAuditLog({
      eventType: AuditEventType.USER_2FA_DISABLED,
      action: 'TOTP 2FA disabled',
      actorUserId: user.id,
      actorDid: user.did ?? undefined,
      details: {},
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    logger.info('TOTP disabled', { userId: user.id });

    res.json({ success: true, data: { totpEnabled: false } });
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// Passkey (WebAuthn) Routes
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/passkey/register/options
 * Generate WebAuthn registration options for the authenticated user.
 */
router.post('/passkey/register/options', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const options = await generatePasskeyRegistrationOptions(
      authReq.user.id,
      authReq.user.did ?? undefined,
    );
    res.json({ success: true, data: options });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/passkey/register/verify
 * Verify the registration response and persist the new passkey.
 */
router.post('/passkey/register/verify', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { response, challenge } = z.object({
      response: z.any(),
      challenge: z.string(),
    }).parse(req.body);

    const passkey = await verifyPasskeyRegistration(response, challenge, authReq.user.id);

    await consentRepo.createAuditLog({
      eventType: AuditEventType.PASSKEY_REGISTERED,
      action: 'Passkey registered',
      actorUserId: authReq.user.id,
      actorDid: authReq.user.did ?? undefined,
      details: { credentialId: passkey.credentialId },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    logger.info('Passkey registered via route', { userId: authReq.user.id });

    res.json({ success: true, data: { verified: true, passkeyId: passkey.id } });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/passkey/authenticate/options
 * Generate WebAuthn authentication options. Optional userId for user-specific flow.
 */
router.post('/passkey/authenticate/options', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId } = z.object({ userId: z.string().optional() }).parse(req.body);
    const options = await generatePasskeyAuthOptions(userId);
    res.json({ success: true, data: options });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/passkey/authenticate/verify
 * Verify authentication response and issue a session token.
 */
router.post('/passkey/authenticate/verify', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { response, challenge } = z.object({
      response: z.any(),
      challenge: z.string(),
    }).parse(req.body);

    const { userId } = await verifyPasskeyAuthentication(response, challenge);
    const user = await userRepo.findUserById(userId);
    if (!user) throw new AppError(ERROR_CODES.NOT_FOUND, 'User not found');

    const token = generateSecureToken();
    const refreshToken = generateSecureToken();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 15 * 60 * 1000);
    const refreshExpiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

    await userRepo.createSession({
      user: { connect: { id: user.id } },
      token,
      refreshToken,
      expiresAt,
      refreshExpiresAt,
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip,
    });

    await consentRepo.createAuditLog({
      eventType: AuditEventType.USER_LOGIN,
      action: 'Passkey login',
      actorUserId: user.id,
      actorDid: user.did ?? undefined,
      details: {},
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });

    logger.info('Passkey authentication successful', { userId: user.id });

    res.json({
      success: true,
      data: {
        token,
        refreshToken,
        expiresIn: 900,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          did: user.did,
          walletSetup: user.walletSetup,
          biometricEnabled: user.biometricEnabled,
          autoLockMinutes: user.autoLockMinutes,
        },
        needsWalletSetup: !user.walletSetup,
      },
    });
  } catch (error) {
    next(error);
  }
});

export { router as authRouter };
