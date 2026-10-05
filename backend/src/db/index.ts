/**
 * SSI Healthcare - Database Client
 * 
 * Exports a singleton PrismaClient instance for database operations.
 * In production, this ensures connection pooling is properly managed.
 * 
 * Updated for Prisma 7.x - requires driver adapter
 */

import { PrismaClient } from '../../prisma/generated/client/index.js';
import { PrismaPg } from '@prisma/adapter-pg';
import { logger } from '../utils/logger.js';

// Prevent multiple instances during hot reloading in development
declare global {
  // eslint-disable-next-line no-var
  var __prisma: PrismaClient | undefined;
}

/**
 * Create PrismaClient with Prisma 7.x driver adapter
 */
function createPrismaClient(): PrismaClient {
  const connectionString = process.env.DATABASE_URL;
  
  if (!connectionString) {
    throw new Error('DATABASE_URL environment variable is required');
  }
  
  const adapter = new PrismaPg({ connectionString });
  
  return new PrismaClient({
    adapter,
    log: [
      { level: 'query', emit: 'event' },
      { level: 'error', emit: 'event' },
      { level: 'warn', emit: 'event' },
    ],
  });
}

/**
 * Get or create the singleton PrismaClient instance.
 * Uses a module-level variable for production and globalThis for dev hot-reload.
 */
let _client: PrismaClient | undefined;

function getPrismaClient(): PrismaClient {
  // Module-level singleton — works in both production and development
  if (_client) return _client;

  // In development, also check globalThis to survive hot reloads
  if (process.env.NODE_ENV !== 'production' && globalThis.__prisma) {
    _client = globalThis.__prisma;
    return _client;
  }

  _client = createPrismaClient();

  // Set up logging in non-production
  if (process.env.NODE_ENV !== 'production') {
    globalThis.__prisma = _client;

    _client.$on('query' as never, (e: { query: string; duration: number }) => {
      logger.debug('Prisma Query', { query: e.query, duration: `${e.duration}ms` });
    });

    _client.$on('error' as never, (e: { message: string }) => {
      logger.error('Prisma Error', { message: e.message });
    });
  }

  return _client;
}

export const db = getPrismaClient();

/**
 * Connect to database
 */
export async function connectDatabase(): Promise<void> {
  try {
    await db.$connect();
    logger.info('Database connected successfully');
  } catch (error) {
    logger.error('Failed to connect to database', { error });
    throw error;
  }
}

/**
 * Disconnect from database
 */
export async function disconnectDatabase(): Promise<void> {
  await db.$disconnect();
  logger.info('Database disconnected');
}

/**
 * Health check for database connection
 */
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    await db.$queryRaw`SELECT 1`;
    return true;
  } catch {
    return false;
  }
}

export default db;
