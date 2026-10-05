/**
 * SSI Healthcare - UX Analytics Repository
 * 
 * Database operations for tracking UI interactions for UX research
 */

import { db } from './index.js';
import type { Prisma } from '../../prisma/generated/client/index.js';

interface UXEventInput {
  userId?: string;
  sessionId: string;
  eventName: string;
  eventCategory: string;
  pagePath: string;
  componentId?: string;
  properties?: object;
  durationMs?: number;
  deviceType?: string;
  browser?: string;
  os?: string;
  experimentId?: string;
  variant?: string;
}

/**
 * Record a UX event
 */
export async function recordUXEvent(data: UXEventInput) {
  return db.uXEvent.create({ 
    data: {
      ...data,
      properties: data.properties as Prisma.InputJsonValue,
    } 
  });
}

/**
 * Record multiple UX events in batch
 */
export async function recordUXEventsBatch(events: UXEventInput[]) {
  return db.uXEvent.createMany({ 
    data: events.map(event => ({
      ...event,
      properties: event.properties as Prisma.InputJsonValue,
    }))
  });
}

/**
 * Get event counts by name
 */
export async function getEventCounts(options: {
  startDate?: Date;
  endDate?: Date;
  eventCategory?: string;
  experimentId?: string;
}) {
  const { startDate, endDate, eventCategory, experimentId } = options;
  
  return db.uXEvent.groupBy({
    by: ['eventName'],
    where: {
      ...(startDate && { timestamp: { gte: startDate } }),
      ...(endDate && { timestamp: { lte: endDate } }),
      ...(eventCategory && { eventCategory }),
      ...(experimentId && { experimentId }),
    },
    _count: true,
    orderBy: { _count: { eventName: 'desc' } },
  });
}

/**
 * Get funnel analysis for a sequence of events
 */
export async function getFunnelAnalysis(
  eventSequence: string[],
  options: {
    startDate?: Date;
    endDate?: Date;
    experimentId?: string;
    variant?: string;
  } = {}
) {
  const { startDate, endDate, experimentId, variant } = options;
  
  const results = await Promise.all(
    eventSequence.map(async (eventName, index) => {
      const count = await db.uXEvent.count({
        where: {
          eventName,
          ...(startDate && { timestamp: { gte: startDate } }),
          ...(endDate && { timestamp: { lte: endDate } }),
          ...(experimentId && { experimentId }),
          ...(variant && { variant }),
        },
      });
      
      return {
        step: index + 1,
        eventName,
        count,
      };
    })
  );
  
  // Calculate conversion rates
  return results.map((step, index) => ({
    ...step,
    conversionRate: index === 0 
      ? 100 
      : results[index - 1].count > 0 
        ? (step.count / results[index - 1].count) * 100 
        : 0,
    overallConversionRate: results[0].count > 0 
      ? (step.count / results[0].count) * 100 
      : 0,
  }));
}

/**
 * Get A/B test results
 */
export async function getExperimentResults(
  experimentId: string,
  conversionEvent: string
) {
  // Get all variants
  const variants = await db.uXEvent.groupBy({
    by: ['variant'],
    where: { experimentId },
    _count: true,
  });
  
  // Get conversion counts per variant
  const conversions = await db.uXEvent.groupBy({
    by: ['variant'],
    where: {
      experimentId,
      eventName: conversionEvent,
    },
    _count: true,
  });
  
  // Map conversions by variant
  const conversionMap = new Map(conversions.map(c => [c.variant, c._count]));
  
  return variants.map(v => ({
    variant: v.variant,
    totalUsers: v._count,
    conversions: conversionMap.get(v.variant) || 0,
    conversionRate: v._count > 0 
      ? ((conversionMap.get(v.variant) || 0) / v._count) * 100 
      : 0,
  }));
}

/**
 * Get average duration for an event
 */
export async function getAverageEventDuration(
  eventName: string,
  options: {
    startDate?: Date;
    endDate?: Date;
    experimentId?: string;
  } = {}
) {
  const { startDate, endDate, experimentId } = options;
  
  const result = await db.uXEvent.aggregate({
    where: {
      eventName,
      durationMs: { not: null },
      ...(startDate && { timestamp: { gte: startDate } }),
      ...(endDate && { timestamp: { lte: endDate } }),
      ...(experimentId && { experimentId }),
    },
    _avg: { durationMs: true },
    _min: { durationMs: true },
    _max: { durationMs: true },
    _count: true,
  });
  
  return {
    eventName,
    averageDurationMs: result._avg.durationMs || 0,
    minDurationMs: result._min.durationMs || 0,
    maxDurationMs: result._max.durationMs || 0,
    sampleSize: result._count,
  };
}

/**
 * Get device breakdown
 */
export async function getDeviceBreakdown(options: {
  startDate?: Date;
  endDate?: Date;
  experimentId?: string;
} = {}) {
  const { startDate, endDate, experimentId } = options;
  
  return db.uXEvent.groupBy({
    by: ['deviceType'],
    where: {
      deviceType: { not: null },
      ...(startDate && { timestamp: { gte: startDate } }),
      ...(endDate && { timestamp: { lte: endDate } }),
      ...(experimentId && { experimentId }),
    },
    _count: true,
  });
}

/**
 * Get page view counts
 */
export async function getPageViewCounts(options: {
  startDate?: Date;
  endDate?: Date;
  limit?: number;
} = {}) {
  const { startDate, endDate, limit = 20 } = options;
  
  return db.uXEvent.groupBy({
    by: ['pagePath'],
    where: {
      eventCategory: 'navigation',
      ...(startDate && { timestamp: { gte: startDate } }),
      ...(endDate && { timestamp: { lte: endDate } }),
    },
    _count: true,
    orderBy: { _count: { pagePath: 'desc' } },
    take: limit,
  });
}

/**
 * Get user journey (events for a specific session)
 */
export async function getUserJourney(sessionId: string) {
  return db.uXEvent.findMany({
    where: { sessionId },
    orderBy: { timestamp: 'asc' },
    select: {
      eventName: true,
      eventCategory: true,
      pagePath: true,
      componentId: true,
      properties: true,
      durationMs: true,
      timestamp: true,
    },
  });
}

export async function getSessionOwner(sessionId: string): Promise<{ userId: string | null } | null> {
  const event = await db.uXEvent.findFirst({
    where: { sessionId },
    select: { userId: true },
  });
  return event ?? null;
}


export async function getDropOffPoints(options: {
  startDate?: Date;
  endDate?: Date;
} = {}) {
  const { startDate, endDate } = options;
  
  // Get last event per session
  const sessions = await db.uXEvent.groupBy({
    by: ['sessionId'],
    where: {
      ...(startDate && { timestamp: { gte: startDate } }),
      ...(endDate && { timestamp: { lte: endDate } }),
    },
    _max: { timestamp: true },
  });
  
  // Get the event details for each session's last event
  // This is a simplified version - in production you'd want to optimize this
  const lastEvents = await Promise.all(
    sessions.slice(0, 1000).map(async (session) => {
      const event = await db.uXEvent.findFirst({
        where: {
          sessionId: session.sessionId,
          timestamp: session._max.timestamp!,
        },
        select: {
          pagePath: true,
          eventName: true,
        },
      });
      return event;
    })
  );
  
  // Count occurrences
  const dropOffCounts: Record<string, number> = {};
  for (const event of lastEvents) {
    if (event) {
      const key = `${event.pagePath}:${event.eventName}`;
      dropOffCounts[key] = (dropOffCounts[key] || 0) + 1;
    }
  }
  
  return Object.entries(dropOffCounts)
    .map(([key, count]) => {
      const [pagePath, eventName] = key.split(':');
      return { pagePath, eventName, count };
    })
    .sort((a, b) => b.count - a.count);
}

/**
 * Clean up old UX events (retention policy)
 */
export async function cleanupOldUXEvents(retentionDays: number) {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
  
  return db.uXEvent.deleteMany({
    where: {
      timestamp: { lt: cutoffDate },
    },
  });
}

/**
 * Get summary statistics for UX dashboard
 */
export async function getUXDashboardStats(options: {
  startDate?: Date;
  endDate?: Date;
} = {}) {
  const { startDate, endDate } = options;
  
  const where = {
    ...(startDate && { timestamp: { gte: startDate } }),
    ...(endDate && { timestamp: { lte: endDate } }),
  };
  
  const [totalEvents, uniqueSessions, uniqueUsers, topEvents, deviceBreakdown] = await Promise.all([
    db.uXEvent.count({ where }),
    db.uXEvent.groupBy({ by: ['sessionId'], where }).then(r => r.length),
    db.uXEvent.groupBy({ by: ['userId'], where: { ...where, userId: { not: null } } }).then(r => r.length),
    db.uXEvent.groupBy({
      by: ['eventName'],
      where,
      _count: true,
      orderBy: { _count: { eventName: 'desc' } },
      take: 10,
    }),
    db.uXEvent.groupBy({
      by: ['deviceType'],
      where: { ...where, deviceType: { not: null } },
      _count: true,
    }),
  ]);
  
  return {
    totalEvents,
    uniqueSessions,
    uniqueUsers,
    topEvents: topEvents.map(e => ({ eventName: e.eventName, count: e._count })),
    deviceBreakdown: deviceBreakdown.map(d => ({ deviceType: d.deviceType, count: d._count })),
  };
}
