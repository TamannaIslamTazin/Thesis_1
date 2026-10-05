/**
 * SSI Healthcare Backend - Structured Logger
 *
 * Winston-based logger with JSON output for structured logging.
 * All SSI operations, consent events, and security incidents are logged
 * to maintain an immutable audit trail.
 */

import winston from 'winston';
import type { LoggerPort } from '@ssi-healthcare/shared';

const { combine, timestamp, json, errors, colorize, simple } = winston.format;

const isProduction = process.env.NODE_ENV === 'production';

/**
 * Application logger configured for structured JSON output in production
 * and human-readable colored output in development.
 */
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  defaultMeta: { service: 'ssi-healthcare-backend' },
  format: combine(
    errors({ stack: true }),
    timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
    json(),
  ),
  transports: [
    new winston.transports.Console({
      format: isProduction ? combine(timestamp(), json()) : combine(colorize(), simple()),
    }),
  ],
});

/**
 * Compile-time proof that winston satisfies the port protocol logic depends on.
 *
 * Services moving into the SDK take a `LoggerPort`; the adapter left behind
 * passes THIS instance. If a winston upgrade ever changed those four
 * signatures, the failure would otherwise surface as a moved service quietly
 * logging nothing. Fail at build instead, next to the cause.
 *
 * Nothing wraps `logger` — the assignment is structural, so level, message,
 * context, `defaultMeta` and transport are unchanged by the indirection.
 */
const _winstonSatisfiesLoggerPort: LoggerPort = logger;
void _winstonSatisfiesLoggerPort;

/**
 * Create a child logger with additional context metadata.
 * Use this for request-scoped or module-scoped logging.
 */
export function createChildLogger(meta: Record<string, unknown>): winston.Logger {
  return logger.child(meta);
}
