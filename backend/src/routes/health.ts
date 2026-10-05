/**
 * SSI Healthcare Backend - Health Check Routes
 *
 * GET /api/health           - Overall health (liveness)
 * GET /api/health/readiness - Readiness probe (checks DB + agent)
 */

import { Router, type Request, type Response } from 'express';
import type { ApiResponse } from '@ssi-healthcare/shared';
import { checkDatabaseHealth } from '../db/index.js';
import { getAgent } from '../agent/index.js';
import { createRequire } from 'module';

export const healthRouter = Router();

const require = createRequire(import.meta.url);
let packageVersion = '0.0.0';
try {
  const pkg = require('../../../package.json');
  packageVersion = pkg.version || '0.0.0';
} catch {
  // package.json not found — use fallback
}

interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  uptime: number;
  timestamp: string;
  checks: {
    agent: boolean;
    database: boolean;
  };
}

/**
 * GET /api/health
 * Liveness probe — returns 200 if process is alive.
 */
healthRouter.get('/', (_req: Request, res: Response) => {
  const response: ApiResponse<{ status: string; uptime: number; version: string }> = {
    success: true,
    data: {
      status: 'alive',
      uptime: process.uptime(),
      version: packageVersion,
    },
    timestamp: new Date().toISOString(),
  };
  res.json(response);
});

/**
 * GET /api/health/readiness
 * Readiness probe — checks database and agent connectivity.
 */
healthRouter.get('/readiness', async (_req: Request, res: Response) => {
  const checks = {
    database: false,
    agent: false,
  };

  // Check database
  try {
    checks.database = await checkDatabaseHealth();
  } catch {
    checks.database = false;
  }

  // Check Credo-TS agent
  try {
    const agent = getAgent();
    checks.agent = agent.isInitialized;
  } catch {
    checks.agent = false;
  }

  const allHealthy = checks.database && checks.agent;
  const someHealthy = checks.database || checks.agent;
  const status = allHealthy ? 'healthy' : someHealthy ? 'degraded' : 'unhealthy';

  const health: HealthStatus = {
    status,
    version: packageVersion,
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    checks,
  };

  const response: ApiResponse<HealthStatus> = {
    success: allHealthy,
    data: health,
    timestamp: new Date().toISOString(),
  };

  res.status(allHealthy ? 200 : 503).json(response);
});
