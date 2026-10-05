/**
 * SSI Healthcare Backend - Server Entry Point
 *
 * Bootstraps the Express server with:
 * 1. Security middleware (Helmet, CORS, rate limiting, injection detection)
 * 2. API routes (DID, Credential, Health, Auth, Users, Webhooks, Analytics)
 * 3. Error handling middleware
 * 4. Credo TS agent initialization
 * 5. Database connection
 * 6. Graceful shutdown handling
 */

import express from 'express';
import { config } from './config/index.js';
import { logger } from './utils/logger.js';
import { applySecurityMiddleware, authLimiter, emergencyLimiter, credentialsLimiter, apiLimiter } from './middleware/security.js';
import {
  requestValidator,
  securityHeaders,
  sensitiveDataFilter,
  integrityCheck,
} from './middleware/securityInterceptors.js';
import { errorHandler } from './middleware/errorHandler.js';
import { createAgent, shutdownAgent } from './agent/index.js';
import { connectDatabase, disconnectDatabase, checkDatabaseHealth } from './db/index.js';
import { testSmtpConnection } from './services/emailService.js';
import { didRouter } from './routes/did.js';
import { credentialRouter } from './routes/credential.js';
import { healthRouter } from './routes/health.js';
import { consentRouter } from './routes/consent.js';
import { emergencyRouter } from './routes/emergency.js';
import { authRouter } from './routes/auth.js';
import { keystoreRouter } from './routes/keystore.js';
import { usersRouter } from './routes/users.js';
import { webhooksRouter } from './routes/webhooks.js';
import { analyticsRouter } from './routes/analytics.js';
import { oid4vciRouter, getIssuerMetadata } from './routes/oid4vci.js';
import { oid4vpRouter, getVerifierMetadata } from './routes/oid4vp.js';
import { auditRouter } from './routes/audit.js';
import { pharmacyRouter } from './routes/pharmacy.js';
import { claimsRouter } from './routes/claims.js';
import { hospitalRouter } from './routes/hospital.js';
import { professionalRouter } from './routes/professional.js';
import { custodyRouter } from './routes/custody.js';
import { issuanceRouter } from './routes/issuance.js';
import { authorityRouter } from './routes/authority.js';
import { authorityMembersRouter } from './routes/authorityMembers.js';
import { institutionOnboardingRouter } from './routes/institutionOnboarding.js';
import { walletCustodyRouter } from './routes/walletCustody.js';
import { requireAuth } from './middleware/auth.js';
import { actorContext } from './middleware/actorContext.js';
import { startChainWatch, stopChainWatch } from './services/custody/chainWatch.js';

const app = express();

// -- Body parsing (limit configurable via BODY_LIMIT env var) --
app.use(express.json({ limit: config.bodyLimit }));
app.use(express.urlencoded({ extended: true, limit: config.bodyLimit }));

// -- Security middleware --
applySecurityMiddleware(app);
app.use(requestValidator());
app.use(securityHeaders());
app.use(sensitiveDataFilter());
app.use(integrityCheck());
// Establishes source IP, device and request id for the whole request, so the R5
// signing audit log can attribute a signature without any service taking a
// `Request`. Must be before the routers, and is (#293).
app.use(actorContext());

// -- API Routes --
app.use('/api/health', healthRouter);
app.use('/api/auth', authLimiter, authRouter);
// No shared limiter here on purpose: keystore.ts applies its own per-IP AND
// per-handle limiters, tighter than the generic ones, because the handle
// fetch endpoint is unauthenticated by design (spec §6) and is the one an
// attacker will hammer (AUTH-AND-KEYSTORE-API.md §4).
app.use('/api/keystore', keystoreRouter);
app.use('/api/users', apiLimiter, usersRouter);
app.use('/api/dids', apiLimiter, didRouter);
app.use('/api/credentials', credentialsLimiter, credentialRouter);
app.use('/api/consent', apiLimiter, consentRouter);
app.use('/api/emergency', emergencyLimiter, emergencyRouter);
app.use('/api/webhooks', apiLimiter, webhooksRouter);
app.use('/api/analytics', apiLimiter, analyticsRouter);
app.use('/api/audit', apiLimiter, auditRouter);
app.use('/api/pharmacy', apiLimiter, pharmacyRouter);
app.use('/api/claims', apiLimiter, claimsRouter);
app.use('/api/hospital', apiLimiter, hospitalRouter);
app.use('/api/professional', apiLimiter, professionalRouter);
app.use('/api/custody', apiLimiter, custodyRouter);
app.use('/api/issuance', apiLimiter, issuanceRouter);
app.use('/api/authority', apiLimiter, authorityRouter);
app.use('/api/authority', apiLimiter, authorityMembersRouter);
// L2 institution onboarding. Its claim route is intentionally unauthenticated —
// the institution's software has no session, and the token IS its credential.
app.use('/api/authority', apiLimiter, institutionOnboardingRouter);
app.use('/api/wallet', apiLimiter, walletCustodyRouter);

// -- OID4VC Routes (OpenID for Verifiable Credentials) --
app.use('/oid4vci', oid4vciRouter);
app.use('/oid4vp', oid4vpRouter);

// OID4VCI/OID4VP require their discovery documents at the domain root. Only those
// two metadata handlers are exposed there — previously the entire oid4vci and
// oid4vp routers were mounted at '/', which duplicated every protocol endpoint
// (/token, /credential, /response, /sessions/:id, ...) at an unprefixed path.
app.get('/.well-known/openid-credential-issuer', getIssuerMetadata);
app.get('/.well-known/openid-verifier', getVerifierMetadata);

// -- Database health endpoint (requires authentication) --
app.get('/api/health/db', requireAuth, async (_req, res) => {
  const healthy = await checkDatabaseHealth();
  res.status(healthy ? 200 : 503).json({
    success: healthy,
    database: healthy ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString(),
  });
});

// -- Agent health endpoint (requires authentication) --
app.get('/api/health/agent', requireAuth, async (_req, res) => {
  try {
    const agent = await import('./agent/index.js').then(m => {
      try {
        return m.getAgent();
      } catch {
        return null;
      }
    });
    const healthy = agent !== null && agent.isInitialized;
    res.status(healthy ? 200 : 503).json({
      success: healthy,
      agent: healthy ? 'initialized' : 'not_initialized',
      timestamp: new Date().toISOString(),
    });
  } catch {
    res.status(503).json({
      success: false,
      agent: 'error',
      timestamp: new Date().toISOString(),
    });
  }
});

// -- 404 handler --
app.use((_req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: 'The requested endpoint does not exist.',
    },
    timestamp: new Date().toISOString(),
  });
});

// -- Error handler (must be last) --
app.use(errorHandler);

// -- Bootstrap --
async function bootstrap(): Promise<void> {
  try {
    logger.info('Starting SSI Healthcare Backend...');
    const isProduction = config.nodeEnv === 'production';
    
    // Initialize the database
    // In production: FATAL if database fails (healthcare data MUST persist)
    // In development: warn and continue for local testing
    try {
      await connectDatabase();
      logger.info('Database connected');
    } catch (dbError) {
      if (isProduction) {
        logger.error('FATAL: Database connection failed in production', { error: dbError });
        logger.error('Healthcare identity system cannot operate without persistence.');
        process.exit(1);
      }
      logger.warn('Database connection failed - running without persistence (dev only)', { error: dbError });
    }
    
    // Initialize the Credo TS SSI agent
    // In production: FATAL if agent fails (no SSI = no identity operations)
    // In development: warn and continue for UI development
    try {
      await createAgent();
      logger.info('Credo TS agent ready');
    } catch (agentError) {
      if (isProduction) {
        logger.error('FATAL: Credo agent initialization failed in production', { error: agentError });
        logger.error('SSI operations (DID, credentials, presentations) will not work.');
        process.exit(1);
      }
      logger.warn('Credo agent initialization failed - SSI features unavailable (dev only)', { error: agentError });
    }

    // The R5 silent alarm. Detection latency is a load-bearing security control
    // under 1-of-N custody (#291), so a failure to arm it is logged as an ERROR
    // naming the consequence rather than as a start-up nicety. It is not fatal:
    // refusing to serve because the watch is down would take the whole system
    // offline to protect against an event the watch cannot prevent anyway.
    try {
      await startChainWatch();
    } catch (watchError) {
      logger.error('FAILED TO ARM THE INSTITUTIONAL CHAIN WATCH', {
        error: watchError instanceof Error ? watchError.message : String(watchError),
        consequence:
          'MsgUpdateDidDoc and MsgDeactivateDidDoc against institutional DIDs will raise NO ' +
          'alarm. An eviction (S-4 H1) or deactivation (code 1207) would go unnoticed. Check ' +
          'GET /api/custody/status before trusting a quiet alarm list.',
      });
    }

    // Test SMTP connection on startup — logs result, never fatal
    await testSmtpConnection();

    // Start HTTP server
    const server = app.listen(config.port, () => {
      logger.info(`Server running on http://localhost:${config.port}`, {
        env: config.nodeEnv,
        port: config.port,
      });
      
      // Only log endpoint details in development (avoid info leak in production)
      if (!isProduction) {
        logger.debug('Available endpoints:', {
          health: `GET  /api/health`,
          healthDb: `GET  /api/health/db`,
          // Auth
          register: `POST /api/auth/register`,
          login: `POST /api/auth/login`,
          oauth: `POST /api/auth/oauth`,
          logout: `POST /api/auth/logout`,
          me: `GET  /api/auth/me`,
          walletSetup: `POST /api/auth/wallet/setup`,
          didChallenge: `POST /api/auth/challenge`,
          didLogin: `POST /api/auth/did-login`,
          // Keystore vault
          keystorePut: `PUT  /api/keystore/envelope`,
          keystoreFetch: `POST /api/keystore/envelope/fetch`,
          // Users
          userCredentials: `GET  /api/users/me/credentials`,
          userConsents: `GET  /api/users/me/consents`,
          userActivity: `GET  /api/users/me/activity`,
          // DIDs
          createDid: `POST /api/dids`,
          resolveDid: `GET  /api/dids/:did`,
          // OID4VCI (Credential Issuance)
          oid4vciMetadata: `GET  /.well-known/openid-credential-issuer`,
          oid4vciOffers: `POST /oid4vci/offers`,
          oid4vciToken: `POST /oid4vci/token`,
          oid4vciCredential: `POST /oid4vci/credential`,
          // OID4VP (Presentation)
          oid4vpMetadata: `GET  /.well-known/openid-verifier`,
          oid4vpRequest: `POST /oid4vp/authorization-request`,
          oid4vpResponse: `POST /oid4vp/response`,
          oid4vpSession: `GET  /oid4vp/sessions/:id`,
          // Consent
          consentGrant: `POST /api/consent/grant`,
          consentRevoke: `POST /api/consent/revoke`,
          consentQuery: `GET  /api/consent/:holderDid`,
          consentVerify: `POST /api/consent/verify`,
          // Emergency
          emergencyRequest: `POST /api/emergency/request`,
          emergencyRevoke: `POST /api/emergency/revoke`,
          // Webhooks
          webhooks: `GET  /api/webhooks`,
          createWebhook: `POST /api/webhooks`,
          // Analytics
          analyticsEvents: `POST /api/analytics/events`,
          analyticsDashboard: `GET  /api/analytics/dashboard`,
        });
      }
    });

    // Graceful shutdown
    const shutdown = async (signal: string) => {
      logger.info(`Received ${signal}. Shutting down gracefully...`);
      server.close(async () => {
        // Before the database closes: the cursor persists, so the next start
        // re-scans the gap rather than resuming at "now".
        stopChainWatch();
        await shutdownAgent();
        await disconnectDatabase();
        logger.info('Server shut down successfully');
        process.exit(0);
      });

      // Force exit after 10s
      setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
      }, 10_000);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
  } catch (error) {
    logger.error('Failed to start server', { error });
    process.exit(1);
  }
}

bootstrap();

export { app };
