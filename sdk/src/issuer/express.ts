/**
 * OID4VCI Express Middleware Factory
 *
 * Provides plug-and-play Express routers for any organization acting as a
 * Verifiable Credential issuer via the OID4VCI pre-authorized code flow.
 *
 * Usage:
 *   import express from 'express';
 *   import { IssuerAgent, createIssuerRouter, createIssuerWellKnown } from '@ssi-healthcare/sdk/issuer';
 *
 *   const issuer = await IssuerAgent.create({ issuerName: 'City Hospital', issuerUrl: '...' });
 *   app.use('/.well-known', createIssuerWellKnown(express, issuer));
 *   app.use('/api/oid4vci', createIssuerRouter(express, issuer));
 */

import type { Router, Request, Response, NextFunction } from 'express';
import type { IssuerAgent } from './IssuerAgent';
import type { HealthcareCredentialType } from './types';

// ---------------------------------------------------------------------------
// Express-like interface — avoids hard dependency on express at compile time
// ---------------------------------------------------------------------------

interface ExpressLike {
  Router: () => Router;
  urlencoded: (opts: { extended: boolean }) => (req: Request, res: Response, next: NextFunction) => void;
}

// ---------------------------------------------------------------------------
// Error helper — translates IssuerAgent errors into OID4VCI error responses
// ---------------------------------------------------------------------------

interface IssuerHttpError extends Error {
  statusCode?: number;
}

function handleIssuerError(res: Response, err: unknown): void {
  if (err instanceof Error) {
    const httpErr = err as IssuerHttpError;
    const status = httpErr.statusCode ?? 500;
    const code = status >= 500 ? 'server_error' : err.message.split(':')[0].trim();
    res.status(status).json({
      error: code,
      error_description: err.message,
    });
    return;
  }
  res.status(500).json({ error: 'server_error', error_description: 'Internal server error' });
}

// ---------------------------------------------------------------------------
// Public interface: options accepted by the router factories
// ---------------------------------------------------------------------------

/**
 * Options for the OID4VCI credential issuance router.
 *
 * @param buildSubject - Application-specific callback that assembles the
 *   credentialSubject payload from your domain data. Receives the Express
 *   request so you can read body, params, DB, etc.
 *
 * @param authMiddleware - Optional Express middleware to protect the /offer
 *   endpoint (e.g. JWT verification for doctors). Token and credential
 *   endpoints are unauthenticated per OID4VCI spec (protected by pre-auth codes).
 */
export interface IssuerRouterOptions {
  buildSubject?: (
    credentialType: HealthcareCredentialType,
    req: Request,
  ) => Promise<Record<string, unknown>>;

  authMiddleware?: (req: Request, res: Response, next: NextFunction) => void;
}

// ---------------------------------------------------------------------------
// Well-known discovery router
// ---------------------------------------------------------------------------

/**
 * Creates an Express router that serves OID4VCI discovery endpoints:
 *   GET /.well-known/openid-credential-issuer
 *
 * Mount at `/.well-known`:
 *   app.use('/.well-known', createIssuerWellKnown(express, issuer));
 *
 * @param express - The express module (pass `import express from 'express'`)
 * @param agent - The initialized IssuerAgent instance
 */
export function createIssuerWellKnown(express: ExpressLike, agent: IssuerAgent): Router {
  const router = express.Router();

  router.get('/openid-credential-issuer', (_req: Request, res: Response) => {
    res.json(agent.getIssuerMetadata());
  });

  return router;
}

// ---------------------------------------------------------------------------
// OID4VCI API router
// ---------------------------------------------------------------------------

/**
 * Creates an Express router implementing the OID4VCI endpoints:
 *   POST /offer       — Create a credential offer (protected by authMiddleware)
 *   POST /token       — Exchange pre-auth code for access token
 *   POST /credential  — Issue signed JWT-VC
 *
 * Mount at `/api/oid4vci`:
 *   app.use('/api/oid4vci', createIssuerRouter(express, issuer, { authMiddleware, buildSubject }));
 *
 * @param express - The express module (pass `import express from 'express'`)
 * @param agent - The initialized IssuerAgent instance
 * @param options - Optional auth middleware and subject builder
 */
export function createIssuerRouter(
  express: ExpressLike,
  agent: IssuerAgent,
  options: IssuerRouterOptions = {},
): Router {
  const router = express.Router();

  // ── POST /offer — Create credential offer ────────────────────────────────

  const offerMiddleware: Array<(req: Request, res: Response, next: NextFunction) => void> = [];
  if (options.authMiddleware) {
    offerMiddleware.push(options.authMiddleware);
  }

  router.post('/offer', ...offerMiddleware, async (req: Request, res: Response) => {
    try {
      const { credentialType, patientId, subjectDid } = req.body as {
        credentialType: string;
        patientId?: string;
        subjectDid?: string;
      };

      if (!credentialType) {
        res.status(400).json({
          success: false,
          error: 'credentialType is required',
        });
        return;
      }

      // Normalize: accept bare names (e.g. "Prescription") or full names ("PrescriptionCredential")
      const normalizedType = credentialType.endsWith('Credential')
        ? credentialType as HealthcareCredentialType
        : `${credentialType}Credential` as HealthcareCredentialType;

      // Build credential subject via application callback or from request body
      let credentialSubject: Record<string, unknown>;
      if (options.buildSubject) {
        credentialSubject = await options.buildSubject(normalizedType, req);
      } else {
        // Fallback: use claims from request body directly
        const { claims, credentialSubject: bodySubject } = req.body as {
          claims?: Record<string, unknown>;
          credentialSubject?: Record<string, unknown>;
        };
        credentialSubject = bodySubject ?? claims ?? {};
        if (patientId) {
          credentialSubject.patientId = patientId;
        }
      }

      const { offer: _offer, offerId, uri } = await agent.createOffer(
        normalizedType,
        credentialSubject,
        { subjectDid },
      );

      res.json({
        success: true,
        data: {
          offerUri: uri,
          offerId,
          credentialType: normalizedType,
          expiresIn: 300,
        },
      });
    } catch (err) {
      handleIssuerError(res, err);
    }
  });

  // ── POST /token — Exchange pre-auth code for access token ─────────────────

  router.post('/token', express.urlencoded({ extended: false }), async (req: Request, res: Response) => {
    try {
      const tokenResponse = await agent.handleTokenRequest(req.body);
      res.json(tokenResponse);
    } catch (err) {
      handleIssuerError(res, err);
    }
  });

  // ── POST /credential — Issue signed JWT-VC ───────────────────────────────

  router.post('/credential', async (req: Request, res: Response) => {
    try {
      const credentialResponse = await agent.handleCredentialRequest(
        req.body,
        req.headers.authorization,
      );
      res.json(credentialResponse);
    } catch (err) {
      handleIssuerError(res, err);
    }
  });

  return router;
}
