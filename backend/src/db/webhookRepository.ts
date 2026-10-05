/**
 * SSI Healthcare - Webhook Repository
 * 
 * Database operations for webhook management and delivery tracking
 */

import { db } from './index.js';
import type { Prisma, DeliveryStatus } from '../../prisma/generated/client/index.js';
import { randomBytes, createHmac } from 'crypto';

export type WebhookCreateInput = Prisma.WebhookCreateInput;

/**
 * Create a new webhook subscription
 */
export async function createWebhook(userId: string, url: string, events: string[]) {
  // Generate a secret for HMAC signing
  const secret = randomBytes(32).toString('base64url');
  
  return db.webhook.create({
    data: {
      userId,
      url,
      secret,
      events,
    },
  });
}

/**
 * Find webhook by ID
 */
export async function findWebhookById(id: string) {
  return db.webhook.findUnique({
    where: { id },
    include: {
      deliveries: {
        orderBy: { createdAt: 'desc' },
        take: 10,
      },
    },
  });
}

/**
 * List webhooks for a user
 */
export async function listUserWebhooks(userId: string) {
  return db.webhook.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      url: true,
      events: true,
      isActive: true,
      consecutiveFailures: true,
      lastTriggeredAt: true,
      lastSuccessAt: true,
      lastError: true,
      createdAt: true,
    },
  });
}

/**
 * Find webhooks subscribed to an event
 */
export async function findWebhooksForEvent(eventType: string) {
  return db.webhook.findMany({
    where: {
      isActive: true,
      events: { has: eventType },
      consecutiveFailures: { lt: 10 }, // Disable after 10 consecutive failures
    },
  });
}

/**
 * Update webhook
 */
export async function updateWebhook(
  id: string,
  data: {
    url?: string;
    events?: string[];
    isActive?: boolean;
  }
) {
  return db.webhook.update({
    where: { id },
    data,
  });
}

/**
 * Delete webhook
 */
export async function deleteWebhook(id: string) {
  return db.webhook.delete({ where: { id } });
}

/**
 * Record webhook delivery attempt
 */
export async function recordDeliveryAttempt(
  webhookId: string,
  eventType: string,
  payload: object
) {
  return db.webhookDelivery.create({
    data: {
      webhookId,
      eventType,
      payload: payload as Prisma.InputJsonValue,
      status: 'PENDING',
    },
  });
}

/**
 * Update delivery status
 */
export async function updateDeliveryStatus(
  deliveryId: string,
  status: DeliveryStatus,
  response?: {
    responseStatus?: number;
    responseBody?: string;
  }
) {
  return db.webhookDelivery.update({
    where: { id: deliveryId },
    data: {
      status,
      attempts: { increment: 1 },
      lastAttemptAt: new Date(),
      ...response,
    },
  });
}

/**
 * Record successful delivery
 */
export async function recordDeliverySuccess(
  webhookId: string,
  deliveryId: string,
  responseStatus: number,
  responseBody?: string
) {
  return db.$transaction([
    db.webhookDelivery.update({
      where: { id: deliveryId },
      data: {
        status: 'DELIVERED',
        attempts: { increment: 1 },
        lastAttemptAt: new Date(),
        responseStatus,
        responseBody,
      },
    }),
    db.webhook.update({
      where: { id: webhookId },
      data: {
        consecutiveFailures: 0,
        lastTriggeredAt: new Date(),
        lastSuccessAt: new Date(),
        lastError: null,
      },
    }),
  ]);
}

/**
 * Record delivery failure
 */
export async function recordDeliveryFailure(
  webhookId: string,
  deliveryId: string,
  error: string,
  responseStatus?: number
) {
  const [delivery, webhook] = await db.$transaction([
    db.webhookDelivery.update({
      where: { id: deliveryId },
      data: {
        status: 'FAILED',
        attempts: { increment: 1 },
        lastAttemptAt: new Date(),
        responseStatus,
        responseBody: error,
      },
    }),
    db.webhook.update({
      where: { id: webhookId },
      data: {
        consecutiveFailures: { increment: 1 },
        lastTriggeredAt: new Date(),
        lastFailureAt: new Date(),
        lastError: error,
      },
    }),
  ]);
  
  // Auto-disable webhook after too many failures
  if (webhook.consecutiveFailures >= 10) {
    await db.webhook.update({
      where: { id: webhookId },
      data: { isActive: false },
    });
  }
  
  return { delivery, webhook };
}

/**
 * Get pending deliveries for retry
 */
export async function getPendingDeliveries(limit = 100) {
  return db.webhookDelivery.findMany({
    where: {
      status: { in: ['PENDING', 'RETRY'] },
      attempts: { lt: 5 }, // Max 5 attempts
    },
    include: {
      webhook: true,
    },
    orderBy: { createdAt: 'asc' },
    take: limit,
  });
}

/**
 * Mark delivery for retry
 */
export async function markForRetry(deliveryId: string) {
  return db.webhookDelivery.update({
    where: { id: deliveryId },
    data: { status: 'RETRY' },
  });
}

/**
 * Generate HMAC signature for webhook payload
 */
export function generateWebhookSignature(secret: string, payload: string): string {
  return createHmac('sha256', secret).update(payload).digest('hex');
}

/**
 * Clean up old deliveries
 */
export async function cleanupOldDeliveries(retentionDays: number) {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
  
  return db.webhookDelivery.deleteMany({
    where: {
      createdAt: { lt: cutoffDate },
      status: { in: ['DELIVERED', 'FAILED'] },
    },
  });
}

/**
 * Get webhook statistics
 */
export async function getWebhookStats(userId: string) {
  const webhooks = await db.webhook.findMany({
    where: { userId },
    include: {
      _count: {
        select: { deliveries: true },
      },
    },
  });
  
  return {
    totalWebhooks: webhooks.length,
    activeWebhooks: webhooks.filter(w => w.isActive).length,
    totalDeliveries: webhooks.reduce((sum, w) => sum + w._count.deliveries, 0),
  };
}
