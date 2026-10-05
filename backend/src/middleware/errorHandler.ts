/**
 * SSI Healthcare Backend - Error Handling Middleware
 *
 * Centralised error handler that catches unhandled errors, logs them,
 * and returns a consistent ApiResponse envelope.
 */

import { type Request, type Response, type NextFunction } from 'express';
import { ZodError } from 'zod';
import { logger } from '../utils/logger.js';
import type { ApiResponse } from '@ssi-healthcare/shared';
import { SsiError, isSsiError } from '@ssi-healthcare/shared';

/**
 * Application-level error with an error code for structured responses.
 *
 * NOW A SUBCLASS OF `SsiError` RATHER THAN OF `Error`. Protocol logic that has
 * moved into `@ssi-healthcare/sdk` cannot import this file — it reaches Express
 * and winston — so it refuses with `SsiError`, which carries the same four
 * fields under the same names. Making `AppError` extend it means the backend has
 * ONE error hierarchy instead of two, and this handler's envelope is produced by
 * one branch for both.
 *
 * This class is kept, rather than every call site rewritten to `SsiError`,
 * because `AppError` is what 35 backend files already name and because "an error
 * raised by the server" stays a useful thing to be able to say. It adds no
 * fields; it is a name.
 */
export class AppError extends SsiError {}

/**
 * Express error-handling middleware.
 * Must be registered AFTER all routes.
 */
export function errorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void {
  // Zod validation errors
  if (err instanceof ZodError) {
    const response: ApiResponse = {
      success: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed.',
        details: { issues: err.issues },
      },
      timestamp: new Date().toISOString(),
    };
    res.status(400).json(response);
    return;
  }

  // Known application errors, whether raised here or by the SDK.
  // `isSsiError` rather than `instanceof`: an SDK entry point is bundled without
  // code splitting, so a class identity can be duplicated per entry point while
  // the `Symbol.for` brand cannot. See @ssi-healthcare/shared's errors module.
  if (isSsiError(err)) {
    logger.warn('Application error', {
      code: err.code,
      message: err.message,
      statusCode: err.statusCode,
    });

    const response: ApiResponse = {
      success: false,
      error: {
        code: err.code,
        message: err.message,
        details: err.details,
      },
      timestamp: new Date().toISOString(),
    };
    res.status(err.statusCode).json(response);
    return;
  }

  // Unknown/unhandled errors
  logger.error('Unhandled error', {
    name: err.name,
    message: err.message,
    stack: err.stack,
  });

  const response: ApiResponse = {
    success: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred.',
    },
    timestamp: new Date().toISOString(),
  };
  res.status(500).json(response);
}
