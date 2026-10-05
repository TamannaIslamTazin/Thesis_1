/**
 * SSI Healthcare Backend - Emergency Access Service Unit Tests
 *
 * Tests break-glass emergency access: request, revoke, check, query.
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
  EmergencyAccessStatus: {
    REQUESTED: 'REQUESTED',
    GRANTED: 'GRANTED',
    EXPIRED: 'EXPIRED',
    REVOKED: 'REVOKED',
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
    emergencyAccessRecord: {
      create: jest.fn(),
      update: jest.fn(),
      findUnique: jest.fn(),
      findFirst: jest.fn(),
      findMany: jest.fn(),
      updateMany: jest.fn(),
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
  requestEmergencyAccess,
  revokeEmergencyAccess,
  checkEmergencyAccess,
  queryEmergencyRecords,
} from '../src/services/emergencyService.js';
import { EmergencyAccessStatus } from '@ssi-healthcare/shared';

describe('Emergency Access Service', () => {
  const providerDid = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
  const patientDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const familyDid = 'did:key:z6MkFamily12345';

  describe('requestEmergencyAccess', () => {
    it('should auto-grant emergency access', async () => {
      const record = await requestEmergencyAccess({
        providerDid,
        providerName: 'Dr. Emergency',
        patientDid,
        reason: 'Patient is unconscious, need medical history',
        credentialIds: ['urn:uuid:cred-001'],
      });

      expect(record).toBeDefined();
      expect(record.status).toBe(EmergencyAccessStatus.GRANTED);
      expect(record.grantedAt).toBeTruthy();
      expect(record.expiresAt).toBeTruthy();
      expect(record.providerDid).toBe(providerDid);
      expect(record.patientDid).toBe(patientDid);
    });

    it('should notify family when contact DID is provided', async () => {
      const record = await requestEmergencyAccess({
        providerDid,
        providerName: 'Dr. Urgent',
        patientDid,
        reason: 'Severe allergic reaction, need allergy records',
        credentialIds: ['urn:uuid:cred-002'],
        familyContactDid: familyDid,
      });

      expect(record.familyContactDid).toBe(familyDid);
      expect(record.familyNotifiedAt).toBeTruthy();
    });
  });

  describe('revokeEmergencyAccess', () => {
    it('should revoke active emergency access', async () => {
      const record = await requestEmergencyAccess({
        providerDid,
        providerName: 'Dr. Revoke',
        patientDid,
        reason: 'Emergency situation resolved, revoking access',
        credentialIds: ['urn:uuid:cred-003'],
      });

      const revoked = await revokeEmergencyAccess(record.id, patientDid);
      expect(revoked.status).toBe(EmergencyAccessStatus.REVOKED);
    });

    it('should reject revoking non-existent record', async () => {
      await expect(
        revokeEmergencyAccess('00000000-0000-0000-0000-000000000000', patientDid),
      ).rejects.toThrow('not found');
    });

    it('should reject revoking already-revoked access', async () => {
      const record = await requestEmergencyAccess({
        providerDid,
        providerName: 'Dr. Double',
        patientDid,
        reason: 'Testing double revoke scenario',
        credentialIds: ['urn:uuid:cred-004'],
      });

      await revokeEmergencyAccess(record.id, patientDid);
      await expect(
        revokeEmergencyAccess(record.id, patientDid),
      ).rejects.toThrow('Cannot revoke');
    });
  });

  describe('checkEmergencyAccess', () => {
    it('should detect active emergency access', async () => {
      const uniqueProvider = 'did:key:z6MkCheckAccess';

      await requestEmergencyAccess({
        providerDid: uniqueProvider,
        providerName: 'Dr. Check',
        patientDid,
        reason: 'Checking active emergency access status',
        credentialIds: ['urn:uuid:cred-005'],
      });

      const result = await checkEmergencyAccess(uniqueProvider, patientDid);
      expect(result.isActive).toBe(true);
      expect(result.record).toBeDefined();
    });

    it('should return false when no access exists', async () => {
      const result = await checkEmergencyAccess(
        'did:key:unknown-provider',
        'did:key:unknown-patient',
      );
      expect(result.isActive).toBe(false);
    });
  });

  describe('queryEmergencyRecords', () => {
    it('should return records for a patient', async () => {
      const records = await queryEmergencyRecords(patientDid);
      expect(Array.isArray(records)).toBe(true);
      expect(records.length).toBeGreaterThan(0);
    });

    it('should sort records by most recent first', async () => {
      const records = await queryEmergencyRecords(patientDid);

      if (records.length >= 2) {
        const first = new Date(records[0].requestedAt).getTime();
        const second = new Date(records[1].requestedAt).getTime();
        expect(first).toBeGreaterThanOrEqual(second);
      }
    });
  });
});
