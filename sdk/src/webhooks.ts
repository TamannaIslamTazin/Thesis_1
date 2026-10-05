/**
 * SSI Healthcare SDK - Webhook Types and Utilities
 *
 * Types and helpers for webhook event handling.
 */

import { z } from 'zod';

// ============================================================
// Webhook Event Types
// ============================================================

/**
 * All possible webhook event types
 */
export type WebhookEventType =
  | 'consent.granted'
  | 'consent.revoked'
  | 'consent.expired'
  | 'credential.received'
  | 'credential.expired'
  | 'credential.revoked'
  | 'presentation.created'
  | 'presentation.verified'
  | 'identity.created'
  | 'identity.updated'
  | 'emergency.access.requested'
  | 'emergency.access.granted';

/**
 * Base webhook event structure
 */
export interface WebhookEvent<T = unknown> {
  /** Unique event ID */
  id: string;
  /** Event type */
  type: WebhookEventType;
  /** Timestamp (ISO 8601) */
  timestamp: string;
  /** API version */
  apiVersion: string;
  /** Event payload */
  data: T;
  /** Related object IDs */
  references: {
    userId?: string;
    credentialId?: string;
    consentId?: string;
    presentationId?: string;
    verifierId?: string;
  };
}

// ============================================================
// Event Payloads
// ============================================================

/** Consent granted event data */
export interface ConsentGrantedData {
  consentId: string;
  verifierDid: string;
  verifierName: string;
  dataTypes: string[];
  expiresAt: string;
  grantedAt: string;
}

/** Consent revoked event data */
export interface ConsentRevokedData {
  consentId: string;
  verifierDid: string;
  verifierName: string;
  revokedAt: string;
  reason?: string;
}

/** Consent expired event data */
export interface ConsentExpiredData {
  consentId: string;
  verifierDid: string;
  verifierName: string;
  expiredAt: string;
}

/** Credential received event data */
export interface CredentialReceivedData {
  credentialId: string;
  credentialType: string;
  issuerDid: string;
  issuerName: string;
  issuedAt: string;
  expiresAt?: string;
}

/** Credential expired event data */
export interface CredentialExpiredData {
  credentialId: string;
  credentialType: string;
  issuerDid: string;
  expiredAt: string;
}

/** Credential revoked event data */
export interface CredentialRevokedData {
  credentialId: string;
  credentialType: string;
  issuerDid: string;
  revokedAt: string;
  reason?: string;
}

/** Presentation created event data */
export interface PresentationCreatedData {
  presentationId: string;
  verifierDid: string;
  verifierName: string;
  credentialIds: string[];
  disclosedFields: Record<string, string[]>;
  createdAt: string;
}

/** Presentation verified event data */
export interface PresentationVerifiedData {
  presentationId: string;
  verifierDid: string;
  verifierName: string;
  verified: boolean;
  verifiedAt: string;
  failureReason?: string;
}

/** Emergency access requested event data */
export interface EmergencyAccessRequestedData {
  requestId: string;
  requesterDid: string;
  requesterName: string;
  requesterType: 'paramedic' | 'nurse' | 'doctor' | 'emergency_contact';
  requestedDataTypes: string[];
  location?: {
    latitude: number;
    longitude: number;
  };
  requestedAt: string;
}

/** Emergency access granted event data */
export interface EmergencyAccessGrantedData {
  requestId: string;
  requesterDid: string;
  requesterName: string;
  grantedDataTypes: string[];
  expiresAt: string;
  grantedAt: string;
}

// ============================================================
// Webhook Verification
// ============================================================

/**
 * Verify a webhook signature
 *
 * @param payload - Raw request body
 * @param signature - Value of X-SSI-Signature header
 * @param secret - Your webhook secret
 * @returns true if signature is valid
 *
 * @example
 * ```typescript
 * app.post('/webhooks/ssi', (req, res) => {
 *   const signature = req.headers['x-ssi-signature'];
 *   const isValid = verifyWebhookSignature(
 *     req.rawBody,
 *     signature,
 *     process.env.WEBHOOK_SECRET
 *   );
 *
 *   if (!isValid) {
 *     return res.status(401).send('Invalid signature');
 *   }
 *
 *   const event = JSON.parse(req.body);
 *   // Handle event...
 * });
 * ```
 */
export async function verifyWebhookSignature(
  payload: string,
  signature: string,
  secret: string
): Promise<boolean> {
  // Signature format: t=timestamp,v1=hash
  const parts = signature.split(',');
  const timestampPart = parts.find((p) => p.startsWith('t='));
  const hashPart = parts.find((p) => p.startsWith('v1='));

  if (!timestampPart || !hashPart) {
    return false;
  }

  const timestamp = timestampPart.slice(2);
  const receivedHash = hashPart.slice(3);

  // Check timestamp is within 5 minutes
  const timestampMs = parseInt(timestamp, 10) * 1000;
  const now = Date.now();
  const FIVE_MINUTES_MS = 5 * 60 * 1000;

  if (Math.abs(now - timestampMs) > FIVE_MINUTES_MS) {
    return false;
  }

  // Compute expected hash
  const signedPayload = `${timestamp}.${payload}`;
  const expectedHash = await computeHmac(signedPayload, secret);

  // Constant-time comparison
  return secureCompare(receivedHash, expectedHash);
}

/**
 * Compute HMAC-SHA256
 */
async function computeHmac(data: string, secret: string): Promise<string> {
  // Check if we're in browser with Web Crypto API
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    // Web Crypto API (browser or Node.js 15+)
    const encoder = new TextEncoder();
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signature = await globalThis.crypto.subtle.sign('HMAC', key, encoder.encode(data));
    return Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Fallback for older Node.js
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nodeCrypto = require('crypto');
  return nodeCrypto.createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
function secureCompare(a: string, b: string): boolean {
  // Use constant-time comparison that doesn't leak length information
  const maxLength = Math.max(a.length, b.length);
  let result = a.length ^ b.length; // XOR lengths into result

  for (let i = 0; i < maxLength; i++) {
    const aChar = i < a.length ? a.charCodeAt(i) : 0;
    const bChar = i < b.length ? b.charCodeAt(i) : 0;
    result |= aChar ^ bChar;
  }

  return result === 0;
}

// ============================================================
// Zod Schemas for Validation
// ============================================================

export const WebhookEventSchema = z.object({
  id: z.string().uuid(),
  type: z.enum([
    'consent.granted',
    'consent.revoked',
    'consent.expired',
    'credential.received',
    'credential.expired',
    'credential.revoked',
    'presentation.created',
    'presentation.verified',
    'identity.created',
    'identity.updated',
    'emergency.access.requested',
    'emergency.access.granted',
  ]),
  timestamp: z.string().datetime(),
  apiVersion: z.string(),
  data: z.unknown(),
  references: z.object({
    userId: z.string().optional(),
    credentialId: z.string().optional(),
    consentId: z.string().optional(),
    presentationId: z.string().optional(),
    verifierId: z.string().optional(),
  }),
});

export const ConsentGrantedDataSchema = z.object({
  consentId: z.string(),
  verifierDid: z.string(),
  verifierName: z.string(),
  dataTypes: z.array(z.string()),
  expiresAt: z.string().datetime(),
  grantedAt: z.string().datetime(),
});

export const ConsentRevokedDataSchema = z.object({
  consentId: z.string(),
  verifierDid: z.string(),
  verifierName: z.string(),
  revokedAt: z.string().datetime(),
  reason: z.string().optional(),
});

// ============================================================
// Webhook Handler Helpers
// ============================================================

export type WebhookHandler<T> = (event: WebhookEvent<T>) => Promise<void>;

export interface WebhookHandlers {
  'consent.granted'?: WebhookHandler<ConsentGrantedData>;
  'consent.revoked'?: WebhookHandler<ConsentRevokedData>;
  'consent.expired'?: WebhookHandler<ConsentExpiredData>;
  'credential.received'?: WebhookHandler<CredentialReceivedData>;
  'credential.expired'?: WebhookHandler<CredentialExpiredData>;
  'credential.revoked'?: WebhookHandler<CredentialRevokedData>;
  'presentation.created'?: WebhookHandler<PresentationCreatedData>;
  'presentation.verified'?: WebhookHandler<PresentationVerifiedData>;
  'emergency.access.requested'?: WebhookHandler<EmergencyAccessRequestedData>;
  'emergency.access.granted'?: WebhookHandler<EmergencyAccessGrantedData>;
}

/**
 * Create a webhook handler function
 *
 * @example
 * ```typescript
 * const handleWebhook = createWebhookHandler({
 *   'consent.granted': async (event) => {
 *     console.log('New consent:', event.data.verifierName);
 *     await sendNotification(event.references.userId!, 'New access granted');
 *   },
 *   'consent.revoked': async (event) => {
 *     console.log('Consent revoked:', event.data.verifierName);
 *     await revokeUserSession(event.references.userId!, event.data.verifierDid);
 *   },
 * });
 *
 * // In your Express route:
 * app.post('/webhooks', async (req, res) => {
 *   try {
 *     await handleWebhook(req.body);
 *     res.sendStatus(200);
 *   } catch (error) {
 *     console.error('Webhook error:', error);
 *     res.sendStatus(500);
 *   }
 * });
 * ```
 */
export function createWebhookHandler(handlers: WebhookHandlers) {
  return async (event: WebhookEvent): Promise<void> => {
    // Validate event structure
    const validationResult = WebhookEventSchema.safeParse(event);
    if (!validationResult.success) {
      throw new Error(`Invalid webhook event: ${validationResult.error.message}`);
    }

    // Get handler for this event type
    const handler = handlers[event.type as keyof WebhookHandlers];
    if (!handler) {
      // No handler registered, skip silently
      return;
    }

    // Call handler with proper typing - the handler union allows any valid event type
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await (handler as (event: WebhookEvent<any>) => Promise<void>)(event);
  };
}

// ============================================================
// Express Middleware
// ============================================================

/**
 * Express middleware for webhook verification
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { webhookMiddleware } from '@ssi-healthcare/sdk/webhooks';
 *
 * const app = express();
 *
 * app.post(
 *   '/webhooks',
 *   express.raw({ type: 'application/json' }),
 *   webhookMiddleware(process.env.WEBHOOK_SECRET!),
 *   async (req, res) => {
 *     const event = req.ssiEvent;
 *     // Handle event...
 *     res.sendStatus(200);
 *   }
 * );
 * ```
 */
export function webhookMiddleware(secret: string) {
  return async (
    req: { headers: Record<string, string | string[] | undefined>; body: Buffer | string },
    res: { status: (code: number) => { send: (msg: string) => void } },
    next: () => void
  ): Promise<void> => {
    const signature = req.headers['x-ssi-signature'];

    if (!signature || typeof signature !== 'string') {
      res.status(401).send('Missing signature');
      return;
    }

    const payload = typeof req.body === 'string' ? req.body : req.body.toString('utf-8');
    const isValid = await verifyWebhookSignature(payload, signature, secret);

    if (!isValid) {
      res.status(401).send('Invalid signature');
      return;
    }

    // Parse and attach event to request
    try {
      const event = JSON.parse(payload);
      (req as Record<string, unknown>).ssiEvent = event;
      next();
    } catch {
      res.status(400).send('Invalid JSON');
    }
  };
}
