/**
 * SSI Healthcare Backend - Analytics Routes
 * 
 * UX analytics for research and A/B testing
 */

import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import * as analyticsRepo from '../db/uxAnalyticsRepository.js';
import { requireAuth, optionalAuth, type AuthenticatedRequest } from '../middleware/auth.js';

const router = Router();

/** Coerce + validate date query params */
const dateStringSchema = z.string().refine(
  (s) => !isNaN(new Date(s).getTime()),
  { message: 'Invalid date format' },
).transform(s => new Date(s));

/**
 * POST /api/analytics/events
 * Record UX event(s)
 */
router.post('/events', optionalAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const eventSchema = z.object({
      userId: z.string().optional(),
      sessionId: z.string(),
      eventName: z.string(),
      eventCategory: z.string(),
      pagePath: z.string(),
      componentId: z.string().optional(),
      properties: z.record(z.unknown()).optional(),
      durationMs: z.number().optional(),
      deviceType: z.string().optional(),
      browser: z.string().optional(),
      os: z.string().optional(),
      experimentId: z.string().optional(),
      variant: z.string().optional(),
    });
    
    const schema = z.union([
      eventSchema,
      z.array(eventSchema).max(100), // Max 100 events per batch
    ]);
    
    const data = schema.parse(req.body);

    // Override client-submitted userId with authenticated identity when available
    // For unauthenticated requests, strip userId entirely to prevent spoofing
    const authUser = (req as AuthenticatedRequest).user;
    const trustedUserId = authUser?.did || authUser?.id;
    const stamp = (event: Record<string, unknown>) => {
      if (trustedUserId) {
        event.userId = trustedUserId;
      } else {
        delete event.userId; // Don't trust client-submitted userId for anonymous events
      }
      return event;
    };
    
    if (Array.isArray(data)) {
      await analyticsRepo.recordUXEventsBatch(data.map(e => stamp(e) as typeof e));
    } else {
      await analyticsRepo.recordUXEvent(stamp(data) as typeof data);
    }
    
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/analytics/events/counts
 * Get event counts
 */
router.get('/events/counts', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const querySchema = z.object({
      startDate: dateStringSchema.optional(),
      endDate: dateStringSchema.optional(),
      category: z.string().optional(),
      experimentId: z.string().optional(),
    });
    const { startDate, endDate, category, experimentId } = querySchema.parse(req.query);
    
    const counts = await analyticsRepo.getEventCounts({
      startDate,
      endDate,
      eventCategory: category,
      experimentId,
    });
    
    res.json({
      success: true,
      data: counts.map(c => ({ eventName: c.eventName, count: c._count })),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/analytics/funnel
 * Get funnel analysis
 */
router.post('/funnel', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const schema = z.object({
      events: z.array(z.string()).min(2),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
      experimentId: z.string().optional(),
      variant: z.string().optional(),
    });
    
    const data = schema.parse(req.body);
    
    const funnel = await analyticsRepo.getFunnelAnalysis(data.events, {
      startDate: data.startDate ? new Date(data.startDate) : undefined,
      endDate: data.endDate ? new Date(data.endDate) : undefined,
      experimentId: data.experimentId,
      variant: data.variant,
    });
    
    res.json({
      success: true,
      data: funnel,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/analytics/experiments/:id
 * Get A/B test results
 */
router.get('/experiments/:id', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const experimentId = req.params.id as string;
    const conversionEvent = req.query.conversionEvent as string | undefined;
    
    if (!conversionEvent) {
      res.status(400).json({
        success: false,
        error: 'conversionEvent query parameter required',
      });
      return;
    }
    
    const results = await analyticsRepo.getExperimentResults(experimentId, conversionEvent);
    
    res.json({
      success: true,
      data: {
        experimentId,
        conversionEvent,
        results,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/analytics/events/:eventName/duration
 * Get average event duration
 */
router.get('/events/:eventName/duration', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const eventName = req.params.eventName as string;
    const querySchema = z.object({
      startDate: dateStringSchema.optional(),
      endDate: dateStringSchema.optional(),
      experimentId: z.string().optional(),
    });
    const { startDate, endDate, experimentId } = querySchema.parse(req.query);
    
    const duration = await analyticsRepo.getAverageEventDuration(eventName, {
      startDate,
      endDate,
      experimentId,
    });
    
    res.json({
      success: true,
      data: duration,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/analytics/devices
 * Get device breakdown
 */
router.get('/devices', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const querySchema = z.object({
      startDate: dateStringSchema.optional(),
      endDate: dateStringSchema.optional(),
      experimentId: z.string().optional(),
    });
    const { startDate, endDate, experimentId } = querySchema.parse(req.query);
    
    const devices = await analyticsRepo.getDeviceBreakdown({
      startDate,
      endDate,
      experimentId: experimentId,
    });
    
    res.json({
      success: true,
      data: devices.map(d => ({ deviceType: d.deviceType, count: d._count })),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/analytics/pages
 * Get page view counts
 */
router.get('/pages', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const querySchema = z.object({
      startDate: dateStringSchema.optional(),
      endDate: dateStringSchema.optional(),
      limit: z.coerce.number().int().min(1).max(200).optional(),
    });
    const { startDate, endDate, limit } = querySchema.parse(req.query);
    
    const pages = await analyticsRepo.getPageViewCounts({
      startDate,
      endDate,
      limit,
    });
    
    res.json({
      success: true,
      data: pages.map(p => ({ pagePath: p.pagePath, count: p._count })),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/analytics/sessions/:sessionId/journey
 * Get user journey for a session
 * Requires: session must belong to the authenticated user (ownership check)
 */
router.get('/sessions/:sessionId/journey', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const sessionId = req.params.sessionId as string;
    const authUser = (req as AuthenticatedRequest).user;
    const trustedUserId = authUser.did || authUser.id;

    const ownerCheck = await analyticsRepo.getSessionOwner(sessionId);
    if (!ownerCheck || ownerCheck.userId !== trustedUserId) {
      res.status(403).json({
        success: false,
        error: { code: 'FORBIDDEN', message: 'Access denied to this session' },
      });
      return;
    }

    const journey = await analyticsRepo.getUserJourney(sessionId);

    res.json({
      success: true,
      data: journey,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/analytics/dropoffs
 * Get drop-off points
 */
router.get('/dropoffs', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const querySchema = z.object({
      startDate: dateStringSchema.optional(),
      endDate: dateStringSchema.optional(),
    });
    const { startDate, endDate } = querySchema.parse(req.query);
    
    const dropoffs = await analyticsRepo.getDropOffPoints({
      startDate,
      endDate,
    });
    
    res.json({
      success: true,
      data: dropoffs.slice(0, 20), // Top 20
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/analytics/dashboard
 * Get UX dashboard summary
 */
router.get('/dashboard', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const querySchema = z.object({
      startDate: dateStringSchema.optional(),
      endDate: dateStringSchema.optional(),
    });
    const { startDate, endDate } = querySchema.parse(req.query);
    
    const stats = await analyticsRepo.getUXDashboardStats({
      startDate,
      endDate,
    });
    
    res.json({
      success: true,
      data: stats,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Common UX funnels for SSI healthcare
 */
router.get('/funnels/predefined', async (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      funnels: [
        {
          name: 'User Onboarding',
          description: 'From landing to wallet setup completion',
          events: [
            'page_view_landing',
            'auth_started',
            'auth_completed',
            'wallet_setup_started',
            'wallet_setup_completed',
          ],
        },
        {
          name: 'Credential Receive Flow',
          description: 'From QR scan to credential accepted',
          events: [
            'qr_scanner_opened',
            'qr_code_scanned',
            'credential_offer_viewed',
            'credential_accepted',
          ],
        },
        {
          name: 'Selective Disclosure',
          description: 'From presentation request to completion',
          events: [
            'presentation_request_received',
            'attribute_selection_started',
            'attributes_selected',
            'biometric_verification_started',
            'presentation_submitted',
          ],
        },
        {
          name: 'Consent Management',
          description: 'Consent review and revocation',
          events: [
            'page_view_consents',
            'consent_details_viewed',
            'consent_revoke_clicked',
            'consent_revoked',
          ],
        },
      ],
    },
  });
});

export { router as analyticsRouter };
