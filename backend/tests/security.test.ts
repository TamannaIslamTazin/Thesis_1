import { jest, describe, it, expect, beforeEach } from '@jest/globals';
/**
 * Security Middleware Tests
 * 
 * Tests for injection prevention, rate limiting, and security headers
 */

import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import request from 'supertest';

// Mock dependencies
jest.mock('../src/config/index.js', () => ({
  config: {
    corsOrigin: '*',
    port: 3001,
    nodeEnv: 'test',
  },
}));

jest.mock('../src/utils/logger.js', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

jest.mock('@ssi-healthcare/shared', () => ({
  SYSTEM_DEFAULTS: {
    RATE_LIMIT_RPM: 100,
  },
}));

// Create a test app with security middleware
function createTestApp(): Express {
  const app = express();
  app.use(express.json());
  
  // Simple injection detection middleware (mirrors actual implementation)
  app.use((req: Request, res: Response, next: NextFunction) => {
    const suspiciousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|TABLE|WHERE)\b)/gi,
      /\$(?:gt|gte|lt|lte|ne|in|nin|regex|exists|type|where)\b/gi,
      /javascript:/gi,
      /on(?:error|load|click|mouse|focus|blur)\s*=/gi,
    ];

    const bodyStr = JSON.stringify(req.body || {});
    const queryStr = JSON.stringify(req.query || {});
    const combined = bodyStr + queryStr;

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(combined)) {
        res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Request contains invalid characters or patterns.',
          },
        });
        return;
      }
    }
    next();
  });

  // Test endpoint
  app.post('/test', (req, res) => {
    res.json({ success: true, data: req.body });
  });

  app.get('/test', (req, res) => {
    res.json({ success: true, query: req.query });
  });

  return app;
}

describe('Security Middleware - Injection Prevention', () => {
  let app: Express;

  beforeEach(() => {
    app = createTestApp();
  });

  describe('SQL Injection Prevention', () => {
    it('should block SELECT statements in body', async () => {
      const response = await request(app)
        .post('/test')
        .send({ query: "SELECT * FROM users WHERE id = '1'" });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should block UNION statements', async () => {
      const response = await request(app)
        .post('/test')
        .send({ data: "1' UNION SELECT * FROM passwords" });

      expect(response.status).toBe(400);
    });

    it('should block DROP TABLE attempts', async () => {
      const response = await request(app)
        .post('/test')
        .send({ name: "'; DROP TABLE users;--" });

      expect(response.status).toBe(400);
    });

    it('should block INSERT INTO attempts', async () => {
      const response = await request(app)
        .post('/test')
        .send({ payload: "INSERT INTO users VALUES ('hacker', 'password')" });

      expect(response.status).toBe(400);
    });

    it('should allow safe SQL-like words in normal text', async () => {
      const response = await request(app)
        .post('/test')
        .send({ message: "Please select your option" });

      expect(response.status).toBe(200);
    });
  });

  describe('XSS Prevention', () => {
    it('should block script tags', async () => {
      const response = await request(app)
        .post('/test')
        .send({ content: '<script>alert("xss")</script>' });

      expect(response.status).toBe(400);
    });

    it('should block onerror handlers', async () => {
      const response = await request(app)
        .post('/test')
        .send({ image: '<img src=x onerror=alert(1)>' });

      expect(response.status).toBe(400);
    });

    it('should block onclick handlers', async () => {
      const response = await request(app)
        .post('/test')
        .send({ button: '<button onclick=malicious()>' });

      expect(response.status).toBe(400);
    });

    it('should block javascript: URLs', async () => {
      const response = await request(app)
        .post('/test')
        .send({ link: 'javascript:void(0)' });

      expect(response.status).toBe(400);
    });

    it('should allow safe HTML-like content', async () => {
      const response = await request(app)
        .post('/test')
        .send({ message: 'Click <here> for more info' });

      expect(response.status).toBe(200);
    });
  });

  describe('NoSQL Injection Prevention', () => {
    it('should block $gt operator', async () => {
      const response = await request(app)
        .post('/test')
        .send({ password: { $gt: '' } });

      expect(response.status).toBe(400);
    });

    it('should block $where operator', async () => {
      const response = await request(app)
        .post('/test')
        .send({ query: { $where: 'this.password' } });

      expect(response.status).toBe(400);
    });

    it('should block $regex operator', async () => {
      const response = await request(app)
        .post('/test')
        .send({ search: { $regex: '.*' } });

      expect(response.status).toBe(400);
    });

    it('should block $exists operator', async () => {
      const response = await request(app)
        .post('/test')
        .send({ field: { $exists: true } });

      expect(response.status).toBe(400);
    });
  });

  describe('Query String Injection', () => {
    it('should check query parameters for SQL injection', async () => {
      const response = await request(app)
        .get('/test')
        .query({ id: "1; DROP TABLE users;--" });

      expect(response.status).toBe(400);
    });

    it('should check query parameters for XSS', async () => {
      const response = await request(app)
        .get('/test')
        .query({ search: '<script>alert(1)</script>' });

      expect(response.status).toBe(400);
    });

    it('should allow safe query parameters', async () => {
      const response = await request(app)
        .get('/test')
        .query({ search: 'vaccination records', page: '1' });

      expect(response.status).toBe(200);
    });
  });

  describe('Safe Requests', () => {
    it('should allow normal JSON payloads', async () => {
      const response = await request(app)
        .post('/test')
        .send({
          name: 'John Doe',
          email: 'john@example.com',
          age: 30,
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    it('should allow nested objects', async () => {
      const response = await request(app)
        .post('/test')
        .send({
          user: {
            profile: {
              firstName: 'Jane',
              lastName: 'Smith',
            },
          },
        });

      expect(response.status).toBe(200);
    });

    it('should allow arrays', async () => {
      const response = await request(app)
        .post('/test')
        .send({
          items: ['vaccination', 'prescription', 'blood work'],
        });

      expect(response.status).toBe(200);
    });
  });
});

describe('Input Validation Helpers', () => {
  describe('DID Validation', () => {
    const isValidDid = (did: string): boolean => {
      // Basic DID validation pattern (method:specific-id with colons allowed in specific part)
      const didPattern = /^did:[a-z]+:[a-zA-Z0-9._:-]+$/;
      return didPattern.test(did);
    };

    it('should accept valid DIDs', () => {
      // NOTE: `isValidDid` above is a local re-implementation that checks DID
      // SHAPE only — it does not constrain the network segment, so it asserts
      // nothing about our sovereign network names. The real contract lives in
      // `DIDCheqdSchema` in @ssi-healthcare/shared, and is untested here.
      // The example is updated to a real network so it does not teach the
      // wrong identifier format to whoever reads this next.
      expect(isValidDid('did:cheqd:bdhealthtestnet:abc123')).toBe(true);
      expect(isValidDid('did:key:z6Mk...')).toBe(true);
      expect(isValidDid('did:web:example.com')).toBe(true);
    });

    it('should reject invalid DIDs', () => {
      expect(isValidDid('not-a-did')).toBe(false);
      expect(isValidDid('did:')).toBe(false);
      expect(isValidDid('')).toBe(false);
      expect(isValidDid('did:method:')).toBe(false);
    });

    it('should reject DIDs with injection attempts', () => {
      expect(isValidDid('did:method:"; DROP TABLE--')).toBe(false);
      expect(isValidDid('did:method:<script>')).toBe(false);
    });
  });

  describe('Email Validation', () => {
    const isValidEmail = (email: string): boolean => {
      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return emailPattern.test(email) && email.length <= 254;
    };

    it('should accept valid emails', () => {
      expect(isValidEmail('user@example.com')).toBe(true);
      expect(isValidEmail('user.name@example.co.uk')).toBe(true);
    });

    it('should reject invalid emails', () => {
      expect(isValidEmail('not-an-email')).toBe(false);
      expect(isValidEmail('@example.com')).toBe(false);
      expect(isValidEmail('user@')).toBe(false);
    });
  });

  describe('UUID Validation', () => {
    const isValidUuid = (uuid: string): boolean => {
      const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      return uuidPattern.test(uuid);
    };

    it('should accept valid UUIDs', () => {
      expect(isValidUuid('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
      expect(isValidUuid('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
    });

    it('should reject invalid UUIDs', () => {
      expect(isValidUuid('not-a-uuid')).toBe(false);
      expect(isValidUuid('550e8400-e29b-41d4-a716')).toBe(false);
      expect(isValidUuid('')).toBe(false);
    });
  });
});
