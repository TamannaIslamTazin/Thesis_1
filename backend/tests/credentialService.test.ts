import { jest, describe, it, expect } from '@jest/globals';
/**
 * SSI Healthcare Backend - Credential Service Unit Tests
 *
 * Tests the OID4VCI Pre-Authorized Code Flow and credential verification.
 */

import {
  createCredentialOffer,
  issueCredentialWithCode,
  verifyCredential,
} from '../src/services/credentialService.js';
import { HealthcareCredentialCategory, CREDENTIAL_TYPES } from '@ssi-healthcare/shared';
import type { VerifiableCredential } from '@ssi-healthcare/shared';

// Mock the agent module since tests run without a real Credo agent
jest.mock('../src/agent/index.js', () => ({
  getAgent: jest.fn(() => ({})),
}));

// Mock the logger to suppress output during tests
jest.mock('../src/utils/logger.js', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

describe('Credential Service', () => {
  const mockCredentialData = {
    issuerDid: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
    subjectDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    credentialType: CREDENTIAL_TYPES.HEALTH_RECORD,
    category: HealthcareCredentialCategory.GENERAL,
    claims: {
      patientName: 'Test Patient',
      bloodType: 'A+',
      allergies: ['Penicillin'],
    },
  };

  describe('createCredentialOffer', () => {
    it('should create a valid credential offer with pre-authorized code', async () => {
      const offer = await createCredentialOffer(mockCredentialData);

      expect(offer).toBeDefined();
      expect(offer.credentialIssuer).toBe(mockCredentialData.issuerDid);
      expect(offer.credentials).toContain(mockCredentialData.credentialType);
      expect(
        offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
      ).toBeDefined();
      expect(
        offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
          'pre-authorized_code'
        ],
      ).toBeTruthy();
      expect(
        offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'].user_pin_required,
      ).toBe(false);
    });
  });

  describe('issueCredentialWithCode', () => {
    it('should issue a credential when given a valid pre-authorized code', async () => {
      const offer = await createCredentialOffer(mockCredentialData);
      const code =
        offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
          'pre-authorized_code'
        ];

      const result = await issueCredentialWithCode(code);

      expect(result.credential).toBeDefined();
      expect(result.credential.type).toContain(CREDENTIAL_TYPES.BASE);
      expect(result.credential.type).toContain(CREDENTIAL_TYPES.HEALTH_RECORD);
      expect(result.credential.issuer).toBe(mockCredentialData.issuerDid);
      expect(result.credential.credentialSubject.id).toBe(mockCredentialData.subjectDid);
      expect(result.credential.credentialSubject.patientName).toBe('Test Patient');
    });

    it('should reject an invalid pre-authorized code', async () => {
      await expect(
        issueCredentialWithCode('00000000-0000-0000-0000-000000000000'),
      ).rejects.toThrow('Invalid pre-authorized code');
    });

    it('should reject a code that has already been used', async () => {
      const offer = await createCredentialOffer(mockCredentialData);
      const code =
        offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
          'pre-authorized_code'
        ];

      // First use should succeed
      await issueCredentialWithCode(code);

      // Second use should fail (code consumed)
      await expect(issueCredentialWithCode(code)).rejects.toThrow(
        'Invalid pre-authorized code',
      );
    });
  });

  describe('verifyCredential', () => {
    it('should validate a well-formed credential', async () => {
      const offer = await createCredentialOffer(mockCredentialData);
      const code =
        offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
          'pre-authorized_code'
        ];
      const { credential } = await issueCredentialWithCode(code);

      const result = await verifyCredential(credential);

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject a credential with missing issuer', async () => {
      const badCredential = {
        '@context': [],
        id: 'test',
        type: [CREDENTIAL_TYPES.BASE],
        issuer: '',
        issuanceDate: new Date().toISOString(),
        credentialSubject: { id: 'did:key:test' },
      } as VerifiableCredential;

      const result = await verifyCredential(badCredential);

      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject an expired credential', async () => {
      const expiredCredential = {
        '@context': [],
        id: 'test',
        type: [CREDENTIAL_TYPES.BASE],
        issuer: 'did:key:test',
        issuanceDate: '2020-01-01T00:00:00Z',
        expirationDate: '2020-12-31T00:00:00Z',
        credentialSubject: { id: 'did:key:test' },
      } as VerifiableCredential;

      const result = await verifyCredential(expiredCredential);

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Credential has expired');
    });
  });
});
