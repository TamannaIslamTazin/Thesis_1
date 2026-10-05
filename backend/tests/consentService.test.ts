/**
 * SSI Healthcare Backend - Consent Service Unit Tests
 *
 * Tests consent management: grant, revoke, query, verify, and audit.
 */

// Mock the Prisma generated types before any imports
import { jest } from '@jest/globals';

jest.mock('../prisma/generated/client/index.js', () => ({
  ConsentPurpose: {
    TREATMENT: 'TREATMENT',
    INSURANCE_CLAIM: 'INSURANCE_CLAIM',
    RESEARCH: 'RESEARCH',
    EMERGENCY: 'EMERGENCY',
    REFERRAL: 'REFERRAL',
  },
  AuditEventType: {
    CONSENT_GRANTED: 'CONSENT_GRANTED',
    CONSENT_REVOKED: 'CONSENT_REVOKED',
    DID_CREATED: 'DID_CREATED',
    CREDENTIAL_ISSUED: 'CREDENTIAL_ISSUED',
    CREDENTIAL_REVOKED: 'CREDENTIAL_REVOKED',
    PRESENTATION_VERIFIED: 'PRESENTATION_VERIFIED',
    EMERGENCY_ACCESS_ACTIVATED: 'EMERGENCY_ACCESS_ACTIVATED',
    USER_LOGIN: 'USER_LOGIN',
  },
}));

// Mock the Prisma client before any imports
jest.mock('../src/lib/prisma.js', () => ({
  prisma: {
    consent: {
      create: jest.fn(),
      update: jest.fn(),
      findUnique: jest.fn(),
      findFirst: jest.fn(),
      findMany: jest.fn(),
      updateMany: jest.fn(),
    },
    user: {
      findUnique: jest.fn(),
    },
    auditLog: {
      create: jest.fn(),
      findMany: jest.fn(),
      groupBy: jest.fn(),
    },
    consentAccessLog: {
      create: jest.fn(),
    },
  },
}));

// Mock the logger
jest.mock('../src/utils/logger.js', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

import {
  grantConsent,
  revokeConsent,
  queryConsent,
  verifyConsent,
  queryAuditLog,
  getAuditSummary,
} from '../src/services/consentService.js';
import { ConsentPurpose, AuditEventType } from '@ssi-healthcare/shared';

describe('Consent Service', () => {
  const holderDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const verifierDid = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
  const credentialIds = ['urn:uuid:cred-001', 'urn:uuid:cred-002'];

  describe('grantConsent', () => {
    it('should create a consent record', async () => {
      const record = await grantConsent({
        holderDid,
        verifierDid,
        verifierName: 'Dr. Smith',
        credentialIds,
        purpose: ConsentPurpose.TREATMENT,
        durationDays: 30,
      });

      expect(record).toBeDefined();
      expect(record.id).toBeTruthy();
      expect(record.holderDid).toBe(holderDid);
      expect(record.verifierDid).toBe(verifierDid);
      expect(record.isActive).toBe(true);
      expect(record.credentialIds).toEqual(credentialIds);
      expect(record.purpose).toBe(ConsentPurpose.TREATMENT);
      expect(record.expiresAt).toBeDefined();
    });

    it('should create consent without expiry', async () => {
      const record = await grantConsent({
        holderDid,
        verifierDid,
        verifierName: 'General Hospital',
        credentialIds: ['urn:uuid:cred-003'],
        purpose: ConsentPurpose.EMERGENCY,
      });

      expect(record.expiresAt).toBeUndefined();
      expect(record.isActive).toBe(true);
    });
  });

  describe('revokeConsent', () => {
    it('should revoke an active consent', async () => {
      const record = await grantConsent({
        holderDid,
        verifierDid,
        verifierName: 'Dr. Jones',
        credentialIds,
        purpose: ConsentPurpose.INSURANCE_CLAIM,
      });

      const revoked = await revokeConsent(record.id, holderDid);

      expect(revoked.isActive).toBe(false);
    });

    it('should reject revoking by non-holder', async () => {
      const record = await grantConsent({
        holderDid,
        verifierDid,
        verifierName: 'Dr. Lee',
        credentialIds,
        purpose: ConsentPurpose.RESEARCH,
      });

      await expect(
        revokeConsent(record.id, 'did:key:some-other-did'),
      ).rejects.toThrow('Only the holder can revoke');
    });

    it('should reject revoking already-revoked consent', async () => {
      const record = await grantConsent({
        holderDid,
        verifierDid,
        verifierName: 'Dr. Park',
        credentialIds,
        purpose: ConsentPurpose.REFERRAL,
      });

      await revokeConsent(record.id, holderDid);
      await expect(revokeConsent(record.id, holderDid)).rejects.toThrow(
        'already been revoked',
      );
    });

    it('should reject revoking non-existent consent', async () => {
      await expect(
        revokeConsent('00000000-0000-0000-0000-000000000000', holderDid),
      ).rejects.toThrow('not found');
    });
  });

  describe('queryConsent', () => {
    it('should return active consents for a holder', async () => {
      const records = await queryConsent(holderDid, true);
      expect(Array.isArray(records)).toBe(true);
    });

    it('should return all consents when activeOnly is false', async () => {
      const allRecords = await queryConsent(holderDid, false);
      const activeRecords = await queryConsent(holderDid, true);
      expect(allRecords.length).toBeGreaterThanOrEqual(activeRecords.length);
    });
  });

  describe('verifyConsent', () => {
    it('should verify active consent exists', async () => {
      await grantConsent({
        holderDid,
        verifierDid,
        verifierName: 'Dr. Verify',
        credentialIds: ['urn:uuid:verify-cred'],
        purpose: ConsentPurpose.TREATMENT,
      });

      const result = await verifyConsent(
        holderDid,
        verifierDid,
        'urn:uuid:verify-cred',
      );

      expect(result.hasConsent).toBe(true);
      expect(result.consentRecord).toBeDefined();
    });

    it('should return false for non-existent consent', async () => {
      const result = await verifyConsent(
        holderDid,
        'did:key:unknown-verifier',
        'urn:uuid:no-consent-cred',
      );

      expect(result.hasConsent).toBe(false);
    });
  });

  describe('auditLog', () => {
    it('should record audit entries for consent operations', async () => {
      const entries = await queryAuditLog(holderDid);
      expect(entries.length).toBeGreaterThan(0);

      const hasGrantEntry = entries.some(
        (e) => e.eventType === AuditEventType.CONSENT_GRANTED,
      );
      expect(hasGrantEntry).toBe(true);
    });

    it('should return audit summary', async () => {
      const summary = await getAuditSummary(holderDid);
      expect(summary).toBeDefined();
      expect(typeof summary).toBe('object');
    });
  });
});
