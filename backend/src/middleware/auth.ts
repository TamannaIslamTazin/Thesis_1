/**
 * SSI Healthcare Backend - Authentication Middleware
 * 
 * Reusable middleware for protecting routes that require authentication.
 * Supports session token validation and optional DID-based authorization.
 */

import { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import * as userRepo from '../db/userRepository.js';
import { logger } from '../utils/logger.js';
import { attachActorUserId } from '../utils/actorContext.js';

// Extend Request type to include authenticated user
export interface AuthenticatedRequest extends Request {
  user: {
    id: string;
    /** Optional since the auth/keystore round: the DID-only signup path (spec §4) creates no mailbox. */
    email: string | null;
    did: string | null;
    firstName: string | null;
    lastName: string | null;
    walletSetup: boolean;
    walletType: string | null;
  };
}

/**
 * Middleware that requires a valid session token.
 * Attaches the user object to the request.
 * 
 * Usage:
 *   router.get('/protected', requireAuth, (req, res) => { ... })
 */
export async function requireAuth(
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader?.startsWith('Bearer ')) {
      throw new AppError(
        ERROR_CODES.AUTH_REQUIRED,
        'Authorization header with Bearer token required',
        401
      );
    }
    
    const token = authHeader.slice(7);
    
    if (!token || token.length < 32) {
      throw new AppError(
        ERROR_CODES.AUTH_REQUIRED,
        'Invalid token format',
        401
      );
    }
    
    const session = await userRepo.findSessionByToken(token);
    
    if (!session) {
      throw new AppError(
        ERROR_CODES.AUTH_TOKEN_EXPIRED,
        'Invalid or expired session',
        401
      );
    }
    
    if (session.expiresAt < new Date()) {
      // ONE ROW HOLDS BOTH TOKENS. Deleting it here destroyed the refresh token
      // along with the expired access token, so `POST /auth/refresh` could never
      // find the session and answered "Invalid refresh token" — the 401 below
      // instructed the client to do the very thing this line had just made
      // impossible. Every session therefore became unrecoverable 15 minutes
      // after it was issued, and the wallet showed "Failed to load" on every
      // screen with no way back short of signing in again.
      //
      // The row is dropped only once the refresh token is spent too. Until then
      // it is the client's remaining means of recovery, and it is not ours to
      // discard. `/auth/refresh` already deletes the row when refresh itself has
      // expired, so nothing accumulates.
      const now = new Date();
      const refreshUnusable =
        !session.refreshToken ||
        (session.refreshExpiresAt !== null && session.refreshExpiresAt < now);

      if (refreshUnusable) {
        await userRepo.deleteSession(token);
      }

      throw new AppError(
        ERROR_CODES.AUTH_TOKEN_EXPIRED,
        'Session expired. Please refresh your token.',
        401
      );
    }
    
    // Update session activity timestamp
    await userRepo.updateSessionActivity(token);
    
    // Attach user to request
    (req as AuthenticatedRequest).user = {
      id: session.user.id,
      email: session.user.email,
      did: session.user.did,
      firstName: session.user.firstName,
      lastName: session.user.lastName,
      walletSetup: session.user.walletSetup,
      walletType: session.user.walletType,
    };

    // So the R5 signing audit log can attribute a signature to a person, not
    // only to an IP. The context itself was established at the boundary.
    attachActorUserId(session.user.id);

    logger.debug('Request authenticated', {
      userId: session.user.id,
      path: req.path,
    });
    
    next();
  } catch (error) {
    next(error);
  }
}

/**
 * Middleware that requires a valid session AND a configured wallet/DID.
 * Use this for routes that require the user to have completed wallet setup.
 * 
 * Usage:
 *   router.post('/credentials', requireWallet, (req, res) => { ... })
 */
export async function requireWallet(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  // First, require authentication
  await requireAuth(req, res, (error) => {
    if (error) {
      next(error);
      return;
    }
    
    const user = (req as AuthenticatedRequest).user;
    
    if (!user.walletSetup || !user.did) {
      next(new AppError(
        ERROR_CODES.WALLET_REQUIRED,
        'Wallet setup required. Please complete wallet setup first.',
        403
      ));
      return;
    }
    
    next();
  });
}

/**
 * Middleware that optionally authenticates (doesn't fail if no token).
 * Use for routes that work for both authenticated and anonymous users.
 * 
 * Usage:
 *   router.get('/public', optionalAuth, (req, res) => { ... })
 */
export async function optionalAuth(
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader?.startsWith('Bearer ')) {
      // No token, continue as anonymous
      next();
      return;
    }
    
    const token = authHeader.slice(7);
    
    if (!token || token.length < 32) {
      // Invalid token format, continue as anonymous
      next();
      return;
    }
    
    const session = await userRepo.findSessionByToken(token);
    
    if (session && session.expiresAt >= new Date()) {
      // Valid session, attach user
      (req as AuthenticatedRequest).user = {
        id: session.user.id,
        email: session.user.email,
        did: session.user.did,
        firstName: session.user.firstName,
        lastName: session.user.lastName,
        walletSetup: session.user.walletSetup,
        walletType: session.user.walletType,
      };
      
      await userRepo.updateSessionActivity(token);
    }
    
    next();
  } catch (error) {
    // On any error, continue as anonymous (don't block the request)
    logger.warn('Optional auth failed, continuing as anonymous', { error });
    next();
  }
}

/**
 * Middleware that requires the user's DID to match a parameter.
 * Use for routes where users should only access their own resources.
 * 
 * Usage:
 *   router.get('/consent/:holderDid', requireAuth, requireOwnership('holderDid'), ...)
 */
export function requireOwnership(paramName: string) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const user = (req as AuthenticatedRequest).user;
    const paramValue = req.params[paramName] || '';
    // Handle both string and string[] cases (Express 5 typing)
    const paramDid = decodeURIComponent(Array.isArray(paramValue) ? paramValue[0] : paramValue);
    
    if (!user) {
      next(new AppError(
        ERROR_CODES.AUTH_REQUIRED,
        'Authentication required',
        401
      ));
      return;
    }
    
    if (!user.did) {
      next(new AppError(
        ERROR_CODES.WALLET_REQUIRED,
        'Wallet setup required',
        403
      ));
      return;
    }
    
    if (user.did !== paramDid) {
      next(new AppError(
        ERROR_CODES.AUTH_FORBIDDEN,
        'You do not have permission to access this resource',
        403
      ));
      return;
    }
    
    next();
  };
}

/**
 * Type guard to check if request has authenticated user
 */
export function isAuthenticated(req: Request): req is AuthenticatedRequest {
  return 'user' in req && req.user !== undefined;
}
