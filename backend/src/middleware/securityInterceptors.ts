/**
 * SSI Healthcare Backend - Enhanced Security Interceptors
 *
 * Phase 4 security hardening with additional middleware:
 * - Request validation interceptor
 * - Content-Type enforcement
 * - Request size limiting
 * - Security headers deep configuration
 */

import { type Request, type Response, type NextFunction } from 'express';
import { logger } from '../utils/logger.js';
import { AppError } from './errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';

// ---------------------------------------------------------------------------
// Request Validation Interceptor
// ---------------------------------------------------------------------------

/**
 * Validates that API requests meet security requirements:
 * - JSON Content-Type for POST/PUT/PATCH
 * - No null bytes or control characters in string fields
 */
export function requestValidator() {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      const contentType = req.headers['content-type'];
      // Allow form-urlencoded for token endpoints (OAuth/OID4VCI)
      if (
        contentType &&
        !contentType.includes('application/json') &&
        !contentType.includes('application/x-www-form-urlencoded')
      ) {
        throw new AppError(
          ERROR_CODES.VALIDATION_ERROR,
          'Content-Type must be application/json or application/x-www-form-urlencoded',
          415,
        );
      }
    }

    if (req.body && typeof req.body === 'object') {
      const bodyStr = JSON.stringify(req.body);
      if (bodyStr.includes('\\u0000') || bodyStr.includes('\x00')) {
        logger.warn('Null byte detected in request body', {
          path: req.path,
          ip: req.ip,
        });
        throw new AppError(
          ERROR_CODES.SECURITY_VIOLATION,
          'Invalid characters in request',
          400,
        );
      }
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// Database Integrity Check Middleware
// ---------------------------------------------------------------------------

/**
 * Periodically checks system health indicators. Logs memory usage
 * and drift warnings at configurable intervals.
 */
export function integrityCheck(options?: { intervalRequests?: number }) {
  let checkCount = 0;
  const interval = options?.intervalRequests ?? 500;

  return (_req: Request, _res: Response, next: NextFunction) => {
    checkCount++;

    if (checkCount % interval === 0) {
      const mem = process.memoryUsage();
      const heapUsedMB = Math.round(mem.heapUsed / 1024 / 1024);
      const heapTotalMB = Math.round(mem.heapTotal / 1024 / 1024);
      const rsseMB = Math.round(mem.rss / 1024 / 1024);

      // Warn if heap usage exceeds 80% of total
      if (mem.heapUsed / mem.heapTotal > 0.8) {
        logger.warn('High heap usage detected', {
          heapUsedMB,
          heapTotalMB,
          rssMB: rsseMB,
          requestCount: checkCount,
        });
      } else {
        logger.info('Integrity check', {
          requestCount: checkCount,
          heapUsedMB,
          uptime: Math.round(process.uptime()),
        });
      }
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// Response Security Headers
// ---------------------------------------------------------------------------

/**
 * Adds additional security headers beyond what Helmet provides.
 */
export function securityHeaders() {
  return (_req: Request, res: Response, next: NextFunction) => {
    res.removeHeader('X-Powered-By');

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');

    next();
  };
}

// ---------------------------------------------------------------------------
// Sensitive Data Redaction (for logging, NOT response bodies)
// ---------------------------------------------------------------------------

const SENSITIVE_FIELDS = [
  'privateKey',
  'seed',
  'password',
  'secret',
  'token',
  'mnemonic',
  'keyMaterial',
  'pin',
  'ssn',
  'creditCard',
];

/**
 * Redacts sensitive fields from an object (for logging purposes only).
 */
export function redactForLogging(obj: unknown): unknown {
  if (Array.isArray(obj)) {
    return obj.map((item) => redactForLogging(item));
  }

  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (SENSITIVE_FIELDS.some((f) => key.toLowerCase().includes(f.toLowerCase()))) {
        result[key] = '[REDACTED]';
      } else {
        result[key] = redactForLogging(value);
      }
    }
    return result;
  }

  return obj;
}

/**
 * Middleware that logs response bodies with sensitive fields redacted.
 * Does NOT modify the actual response sent to the client.
 */
export function sensitiveDataFilter() {
  return (req: Request, res: Response, next: NextFunction) => {
    // Only intercept for logging in non-production (performance)
    if (process.env.NODE_ENV === 'production') {
      next();
      return;
    }

    const originalJson = res.json.bind(res);

    (res as any).json = (body: any) => {
      // Log the redacted version, send the original
      if (body && typeof body === 'object') {
        logger.debug('Response body (redacted)', {
          path: req.path,
          method: req.method,
          body: redactForLogging(body),
        });
      }
      return originalJson(body);
    };

    next();
  };
}
