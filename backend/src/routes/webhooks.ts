/**
 * SSI Healthcare Backend - Webhook Routes
 * 
 * Manage webhook subscriptions and delivery
 */

import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import { requireAuth } from '../middleware/auth.js';
import * as webhookRepo from '../db/webhookRepository.js';
import { logger } from '../utils/logger.js';

const router = Router();

// Available webhook events
const WEBHOOK_EVENTS = [
  'credential.received',
  'credential.revoked',
  'credential.expired',
  'presentation.requested',
  'presentation.verified',
  'consent.granted',
  'consent.revoked',
  'consent.expired',
  'emergency.activated',
  'emergency.deactivated',
] as const;

/**
 * GET /api/webhooks
 * List user's webhooks
 */
router.get('/', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { id: string } }).user;
    
    const webhooks = await webhookRepo.listUserWebhooks(user.id);
    
    res.json({
      success: true,
      data: webhooks,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/webhooks
 * Create a webhook subscription
 */
router.post('/', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { id: string } }).user;
    
    const schema = z.object({
      url: z.string().url(),
      events: z.array(z.enum(WEBHOOK_EVENTS)).min(1),
    });
    
    const data = schema.parse(req.body);
    
    const webhook = await webhookRepo.createWebhook(user.id, data.url, data.events);
    
    res.status(201).json({
      success: true,
      data: {
        id: webhook.id,
        url: webhook.url,
        events: webhook.events,
        secret: webhook.secret, // Only returned on creation
        isActive: webhook.isActive,
        createdAt: webhook.createdAt.toISOString(),
      },
      message: 'Webhook created. Save the secret - it will not be shown again.',
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/webhooks/:id
 * Get webhook details
 */
router.get('/:id', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { id: string } }).user;
    const id = req.params.id as string;
    
    const webhook = await webhookRepo.findWebhookById(id);
    
    if (!webhook) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Webhook not found', 404);
    }
    
    if (webhook.userId !== user.id) {
      throw new AppError(ERROR_CODES.AUTH_INSUFFICIENT_PERMISSIONS, 'Not authorized', 403);
    }
    
    res.json({
      success: true,
      data: {
        id: webhook.id,
        url: webhook.url,
        events: webhook.events,
        isActive: webhook.isActive,
        consecutiveFailures: webhook.consecutiveFailures,
        lastTriggeredAt: webhook.lastTriggeredAt?.toISOString(),
        lastSuccessAt: webhook.lastSuccessAt?.toISOString(),
        lastError: webhook.lastError,
        createdAt: webhook.createdAt.toISOString(),
        recentDeliveries: webhook.deliveries.map(d => ({
          id: d.id,
          eventType: d.eventType,
          status: d.status,
          attempts: d.attempts,
          lastAttemptAt: d.lastAttemptAt?.toISOString(),
          responseStatus: d.responseStatus,
          createdAt: d.createdAt.toISOString(),
        })),
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PATCH /api/webhooks/:id
 * Update webhook settings
 */
router.patch('/:id', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { id: string } }).user;
    const id = req.params.id as string;
    
    const webhook = await webhookRepo.findWebhookById(id);
    
    if (!webhook || webhook.userId !== user.id) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Webhook not found', 404);
    }
    
    const schema = z.object({
      url: z.string().url().optional(),
      events: z.array(z.enum(WEBHOOK_EVENTS)).min(1).optional(),
      isActive: z.boolean().optional(),
    });
    
    const data = schema.parse(req.body);
    
    await webhookRepo.updateWebhook(id, data);
    
    res.json({
      success: true,
      message: 'Webhook updated',
    });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/webhooks/:id
 * Delete a webhook
 */
router.delete('/:id', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { id: string } }).user;
    const id = req.params.id as string;
    
    const webhook = await webhookRepo.findWebhookById(id);
    
    if (!webhook || webhook.userId !== user.id) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Webhook not found', 404);
    }
    
    await webhookRepo.deleteWebhook(id);
    
    res.json({
      success: true,
      message: 'Webhook deleted',
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/webhooks/:id/test
 * Send a test webhook
 */
router.post('/:id/test', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as Request & { user: { id: string } }).user;
    const id = req.params.id as string;
    
    const webhook = await webhookRepo.findWebhookById(id);
    
    if (!webhook || webhook.userId !== user.id) {
      throw new AppError(ERROR_CODES.NOT_FOUND, 'Webhook not found', 404);
    }
    
    const testPayload = {
      event: 'test',
      timestamp: new Date().toISOString(),
      data: {
        message: 'This is a test webhook delivery',
        webhookId: webhook.id,
      },
    };
    
    const delivery = await webhookRepo.recordDeliveryAttempt(webhook.id, 'test', testPayload);
    const payloadStr = JSON.stringify(testPayload);
    const signature = webhookRepo.generateWebhookSignature(webhook.secret, payloadStr);
    
    // Actually send the webhook
    let responseStatus = 0;
    let responseBody = '';
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10_000);

      const response = await fetch(webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Webhook-Signature': signature,
          'X-Webhook-Id': webhook.id,
          'X-Webhook-Event': 'test',
        },
        body: payloadStr,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      responseStatus = response.status;
      responseBody = await response.text().catch(() => '');

      if (response.ok) {
        await webhookRepo.recordDeliverySuccess(webhook.id, delivery.id, responseStatus, responseBody.slice(0, 500));
      } else {
        await webhookRepo.recordDeliveryFailure(webhook.id, delivery.id, `HTTP ${responseStatus}: ${responseBody.slice(0, 500)}`);
      }
    } catch (fetchError) {
      const errMsg = fetchError instanceof Error ? fetchError.message : 'Network error';
      await webhookRepo.recordDeliveryFailure(webhook.id, delivery.id, errMsg);
      logger.warn('Test webhook delivery failed', { webhookId: webhook.id, error: errMsg });
    }
    
    res.json({
      success: true,
      data: {
        deliveryId: delivery.id,
        signature,
        payload: testPayload,
        responseStatus,
        message: responseStatus >= 200 && responseStatus < 300
          ? 'Test webhook delivered successfully'
          : `Test webhook delivery returned status ${responseStatus}`,
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/webhooks/events
 * List available webhook events
 */
router.get('/events/list', async (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      events: WEBHOOK_EVENTS,
      descriptions: {
        'credential.received': 'When a new credential is received',
        'credential.revoked': 'When a credential is revoked by the issuer',
        'credential.expired': 'When a credential expires',
        'presentation.requested': 'When a verifier requests a presentation',
        'presentation.verified': 'When a presentation is successfully verified',
        'consent.granted': 'When consent is granted to a verifier',
        'consent.revoked': 'When consent is revoked',
        'consent.expired': 'When consent expires',
        'emergency.activated': 'When emergency access is activated',
        'emergency.deactivated': 'When emergency access is deactivated',
      },
    },
  });
});

export { router as webhooksRouter };
