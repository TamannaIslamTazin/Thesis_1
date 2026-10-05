/**
 * Hospital Coupler Routes
 *
 * Bidirectional bridge between the SSI wallet and external hospital systems.
 *
 * Flow A – Import (Hospital → SSI):
 *   1. User connects their hospital patient ID to their SSI DID
 *   2. Backend fetches patient data from hospital API (vitals, medications, etc.)
 *   3. Each record is wrapped as an immutable Verifiable Credential
 *   4. Credentials stored in the SSI wallet DB
 *
 * Flow B – Share (SSI → Hospital):
 *   1. Hospital generates a presentation request (OID4VP QR code)
 *   2. Patient scans & selects credentials to share
 *   3. SSI wallet creates a VP and posts it to the hospital's SSI callback
 *
 * Routes:
 *   POST   /api/hospital/connect          - Link hospital patient ID
 *   GET    /api/hospital/connections      - List all connections
 *   DELETE /api/hospital/connections/:id  - Remove a connection
 *   GET    /api/hospital/records          - List imported hospital VCs
 */

import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import dns from 'dns';
import { db } from '../db/index.js';
import { requireAuth, requireWallet, type AuthenticatedRequest } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';
import type { ApiResponse } from '@ssi-healthcare/shared';

export const hospitalRouter: Router = Router();

hospitalRouter.use(requireAuth);

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const connectSchema = z.object({
  hospitalId: z.string().min(1),
  hospitalName: z.string().min(1),
  hospitalUrl: z.string().url(),
  patientId: z.string().min(1),
  apiKey: z.string().optional(),
});

const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PRIVATE_IP_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/,
];

async function validateExternalUrl(urlStr: string): Promise<void> {
  const url = new URL(urlStr);
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only http/https URLs allowed');
  }
  const { address } = await dns.promises.lookup(url.hostname);
  if (PRIVATE_IP_RANGES.some((r) => r.test(address))) {
    throw new Error('Access to private/internal addresses is not allowed');
  }
}

function makeTimestamp(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// POST /api/hospital/connect
// ---------------------------------------------------------------------------

hospitalRouter.post('/connect', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const { hospitalId, hospitalName, hospitalUrl, patientId, apiKey } = connectSchema.parse(req.body);

    const existing = await db.hospitalConnection.findUnique({
      where: { userId_hospitalId: { userId: user.id, hospitalId } },
    });

    if (existing) {
      const updated = await db.hospitalConnection.update({
        where: { id: existing.id },
        data: { isActive: true, hospitalName, hospitalUrl, patientId },
      });
      const response: ApiResponse<typeof updated> = { success: true, data: updated, timestamp: makeTimestamp() };
      res.json(response);
      return;
    }

    // Optionally verify patient exists at hospital
    let patientName: string | undefined;
    try {
      await validateExternalUrl(hospitalUrl);
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (apiKey) headers['X-SSI-API-Key'] = apiKey;
      const ping = await fetch(`${hospitalUrl.replace(/\/$/, '')}/api/ssi/patient/${patientId}/profile`, {
        headers,
        signal: AbortSignal.timeout(5000),
      });
      if (ping.ok) {
        const data = (await ping.json()) as Record<string, unknown>;
        const dataObj = (data?.data ?? data) as Record<string, unknown>;
        patientName = (dataObj?.name ?? dataObj?.patientName) as string | undefined;
      }
    } catch (err) {
      logger.warn('Hospital patient verification skipped — hospital may be offline', {
        hospitalUrl,
        patientId,
        error: err instanceof Error ? err.message : String(err),
      });
    }

    const connection = await db.hospitalConnection.create({
      data: { userId: user.id, hospitalId, hospitalName, hospitalUrl, patientId, patientName },
    });

    logger.info('Hospital connection created', { userId: user.id, hospitalId, patientId });

    const response: ApiResponse<typeof connection> = { success: true, data: connection, timestamp: makeTimestamp() };
    res.status(201).json(response);
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// GET /api/hospital/connections
// ---------------------------------------------------------------------------

hospitalRouter.get('/connections', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const { page, limit } = paginationSchema.parse(req.query);
    const skip = (page - 1) * limit;

    const [connections, total] = await Promise.all([
      db.hospitalConnection.findMany({
        where: { userId: user.id, isActive: true },
        orderBy: { linkedAt: 'desc' },
        skip,
        take: limit,
      }),
      db.hospitalConnection.count({ where: { userId: user.id, isActive: true } }),
    ]);

    const response: ApiResponse<{ items: typeof connections; total: number; page: number; limit: number }> = {
      success: true,
      data: { items: connections, total, page, limit },
      timestamp: makeTimestamp(),
    };
    res.json(response);
  } catch (error) {
    next(error);
  }
});

// ---------------------------------------------------------------------------
// DELETE /api/hospital/connections/:id
// ---------------------------------------------------------------------------

hospitalRouter.delete('/connections/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;
    const { id } = req.params as { id: string };

    const connection = await db.hospitalConnection.findFirst({
      where: { id, userId: user.id },
    });

    if (!connection) {
      res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Connection not found' }, timestamp: makeTimestamp() });
      return;
    }

    await db.hospitalConnection.update({ where: { id }, data: { isActive: false } });

    const response: ApiResponse<{ deleted: true }> = { success: true, data: { deleted: true }, timestamp: makeTimestamp() };
    res.json(response);
  } catch (error) {
    next(error);
  }
});

// POST /api/hospital/sync/:id was removed. It minted Verifiable Credentials
// locally from hospital API data with no `proof`, status ACTIVE, and `issuer`
// defaulting to the patient's own DID when ISSUER_DID was unset — self-issued,
// unsigned objects presented as hospital-attested records (BE-ARCH-010, SSI-008,
// INTEG-012). Issuance belongs to the OID4VCI flow in routes/oid4vci.ts, which
// signs the credential and binds it to a real issuer.

// ---------------------------------------------------------------------------
// GET /api/hospital/records
// ---------------------------------------------------------------------------

hospitalRouter.get('/records', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as AuthenticatedRequest).user;

    if (!user.did) {
      res.status(400).json({ success: false, error: { code: 'NO_DID', message: 'Wallet not set up' }, timestamp: makeTimestamp() });
      return;
    }

    const { page, limit } = paginationSchema.parse(req.query);
    const skip = (page - 1) * limit;

    const hospitalTypes = [
      'HospitalPatientRecord',
      'VitalSignsRecord',
      'MedicationRecord',
      'AppointmentRecord',
      'HospitalConnectionRecord',
    ];

    const [credentials, total] = await Promise.all([
      db.credential.findMany({
        where: {
          holderDid: user.did,
          status: 'ACTIVE',
          type: { hasSome: hospitalTypes },
        },
        orderBy: { issuedAt: 'desc' },
        skip,
        take: limit,
      }),
      db.credential.count({
        where: {
          holderDid: user.did,
          status: 'ACTIVE',
          type: { hasSome: hospitalTypes },
        },
      }),
    ]);

    const response: ApiResponse<{ items: typeof credentials; total: number; page: number; limit: number }> = {
      success: true,
      data: { items: credentials, total, page, limit },
      timestamp: makeTimestamp(),
    };
    res.json(response);
  } catch (error) {
    next(error);
  }
});

export default hospitalRouter;
