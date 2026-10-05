/**
 * SSI Healthcare Backend - Security Middleware
 *
 * Configures Helmet (HTTP headers), CORS, rate limiting, and request logging.
 * Also includes a security interceptor that checks for common injection patterns.
 * 
 * P1: Security Audit - Enhanced security configuration
 */

import { type Express, type Request, type Response, type NextFunction } from 'express';
import { randomBytes } from 'crypto';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit, { type Options as RateLimitOptions } from 'express-rate-limit';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';
import { SYSTEM_DEFAULTS } from '@ssi-healthcare/shared';

// Rate limiting configurations for different endpoint types
//
// EVERY PHONE SHARES ONE BUDGET. The handsets reach the host through
// `adb reverse`, so they all arrive from 127.0.0.1 — the limiter counts two
// devices as one client, and a few "Try Again" taps on one phone exhaust the
// window for both. Measured 23 Sep 2026: a demo stalled because the emergency
// check on one device 429'd the credential fetch on the other.
//
// The numbers below are therefore DEFAULTS FOR DEMO use and are overridable
// per deployment. Raising them is a deliberate trade: the limiter exists to
// blunt credential stuffing and enumeration, and it is still doing that at a
// higher ceiling — it is not being disabled. Production values belong in env,
// where the deployment's real traffic shape is known.
const envInt = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

/*
 * RESOLVED PER REQUEST, NOT AT MODULE LOAD.
 *
 * `config/index.ts` calls `dotenv.config()` in its module body, and ES imports
 * are evaluated in DEPENDENCY order rather than the order they are written. So
 * whether `process.env` is populated by the time a limiter's module body runs
 * depends on which file the bundler happens to reach first — and when it is
 * not, the limiter silently keeps its hardcoded production default.
 *
 * Measured 23 Sep 2026: `RATE_LIMIT_RPM=6000` was set in .env and the backend
 * still answered `RateLimit-Limit: 60`, exhausting the budget on one handset.
 * A function default is evaluated when the limiter FIRST SEES A REQUEST, which
 * is necessarily after every module has loaded, so the ordering stops
 * mattering.
 */
const envIntLazy =
  (name: string, fallback: number) =>
  (): number =>
    envInt(name, fallback);

const rateLimitConfigs = {
  default: {
    windowMs: 60 * 1000,
    max: envIntLazy('RATE_LIMIT_RPM', SYSTEM_DEFAULTS.RATE_LIMIT_RPM),
    message: {
      success: false,
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please try again later.',
      },
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: envIntLazy('RATE_LIMIT_AUTH_MAX', 1000),
    message: {
      success: false,
      error: {
        code: 'TOO_MANY_AUTH_ATTEMPTS',
        message: 'Too many authentication attempts. Please try again in 15 minutes.',
      },
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
  api: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: envIntLazy('RATE_LIMIT_API_MAX', 10000),
    message: {
      success: false,
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please try again later.',
      },
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
  credentials: {
    windowMs: 60 * 1000,
    max: envIntLazy('RATE_LIMIT_CREDENTIALS_MAX', 600),
    message: {
      success: false,
      error: {
        code: 'TOO_MANY_CREDENTIAL_OPERATIONS',
        message: 'Too many credential operations. Please try again later.',
      },
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
  emergency: {
    windowMs: 60 * 1000,
    max: envIntLazy('RATE_LIMIT_EMERGENCY_MAX', 300),
    message: {
      success: false,
      error: {
        code: 'TOO_MANY_EMERGENCY_REQUESTS',
        message: 'Too many emergency access requests.',
      },
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
};

// Create rate limiters
export const defaultLimiter = rateLimit(rateLimitConfigs.default as Partial<RateLimitOptions>);
export const authLimiter = rateLimit(rateLimitConfigs.auth as Partial<RateLimitOptions>);
export const apiLimiter = rateLimit(rateLimitConfigs.api as Partial<RateLimitOptions>);
export const credentialsLimiter = rateLimit(rateLimitConfigs.credentials as Partial<RateLimitOptions>);
export const emergencyLimiter = rateLimit(rateLimitConfigs.emergency as Partial<RateLimitOptions>);

/**
 * Apply all security middleware to the Express application.
 */
export function applySecurityMiddleware(app: Express): void {
  // HTTP security headers with comprehensive configuration
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          connectSrc: ["'self'", 'https://api.web3auth.io'],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
        },
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      crossOriginEmbedderPolicy: false, // May need to be false for some integrations
    })
  );

  // CORS configuration
  app.use(
    cors({
      origin: config.corsOrigin.split(',').map(o => o.trim()),
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Correlation-ID', 'x-client-id'],
      exposedHeaders: ['X-Request-ID', 'X-Correlation-ID'],
      credentials: true,
      maxAge: 86400, // 24 hours
    }),
  );

  // Default rate limiting (can be overridden per-route)
  app.use(defaultLimiter);

  // Request ID middleware for tracing
  app.use((req: Request, res: Response, next: NextFunction) => {
    const requestId = req.get('X-Request-ID') || `req_${randomBytes(16).toString('hex')}`;
    res.setHeader('X-Request-ID', requestId);
    (req as any).requestId = requestId;
    next();
  });

  // Request logging — log metadata only, no request body (PII exposure risk)
  app.use((req: Request, _res: Response, next: NextFunction) => {
    logger.info('Incoming request', {
      requestId: (req as any).requestId,
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    });
    next();
  });

  // Security interceptor: check for injection patterns
  app.use(securityInterceptor);
}

// Sensitive fields to redact in logs
/**
 * Middleware that inspects request bodies for common injection patterns.
 * Rejects requests containing SQL injection, XSS, or NoSQL injection payloads.
 */
function securityInterceptor(req: Request, res: Response, next: NextFunction): void {
  const suspiciousPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|TABLE|WHERE)\b)/gi,
    /\$(?:gt|gte|lt|lte|ne|in|nin|regex|exists|type|where)\b/gi,
    /javascript:/gi,
    /on(?:error|load|click|mouse|focus|blur)\s*=/gi,
  ];

  const bodyStr = JSON.stringify(req.body || {});
  const queryStr = JSON.stringify(req.query || {});
  const combined = bodyStr + queryStr;

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(combined)) {
      logger.warn('Security interceptor: suspicious pattern detected', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        pattern: pattern.source,
      });

      res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request contains invalid characters or patterns.',
        },
        timestamp: new Date().toISOString(),
      });
      return;
    }
  }

  next();
}
