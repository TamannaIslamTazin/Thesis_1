/**
 * SSI Healthcare - Credential Repository
 * 
 * Database operations for verifiable credentials
 */

import { db } from './index.js';
import type { Prisma, CredentialCategory, CredentialStatus } from '../../prisma/generated/client/index.js';

export type CredentialCreateInput = Prisma.CredentialCreateInput;
export type CredentialUpdateInput = Prisma.CredentialUpdateInput;
export type CredentialWhereInput = Prisma.CredentialWhereInput;

/**
 * Create a new credential
 */
export async function createCredential(data: CredentialCreateInput) {
  return db.credential.create({
    data,
  });
}

/**
 * Find credential by ID
 */
export async function findCredentialById(id: string) {
  return db.credential.findUnique({
    where: { id },
    include: {
      holder: {
        select: {
          id: true,
          email: true,
          displayName: true,
          did: true,
        },
      },
      schema: true,
    },
  });
}

/**
 * Find credential by hash (for duplicate detection)
 */
export async function findCredentialByHash(credentialHash: string) {
  return db.credential.findUnique({
    where: { credentialHash },
  });
}

/**
 * List credentials for a holder.
 *
 * REVOKED AND EXPIRED CREDENTIALS ARE INCLUDED BY DEFAULT. This used to
 * default to `status: 'ACTIVE'`, which put the query in direct contradiction
 * with the contract it serves: `WalletCredential` carries `status`,
 * `revokedAt` and `revocationReason` specifically so a client can render a
 * credential AS revoked, and both clients already have code to do it
 * (packages/mobile/src/store/credentialStore.ts toMobileStatus(), and
 * packages/web/src/app/wallet/credential/[id]/page.tsx). None of it could ever
 * run, because the row never reached them.
 *
 * The product argument for including them is stronger than the tidiness
 * argument for hiding them. Filtering made a revoked credential and a deleted
 * credential look identical to the holder — it simply vanished from the
 * wallet, with no indication that it had been revoked, by whom, or why. In a
 * healthcare wallet that is actively unsafe: a patient whose prescription
 * credential was revoked needs to see that it was revoked, not to quietly find
 * it missing and assume a sync bug. Revocation is information the holder is
 * entitled to.
 *
 * Callers that genuinely want only usable credentials pass `status: 'ACTIVE'`
 * explicitly, which is now a visible decision at the call site rather than an
 * invisible default here.
 */
export async function listCredentialsByHolder(
  holderDid: string,
  options: {
    category?: CredentialCategory;
    status?: CredentialStatus;
    types?: string[];
    skip?: number;
    take?: number;
  } = {}
) {
  const { category, status, types, skip = 0, take = 50 } = options;

  return db.credential.findMany({
    where: {
      holderDid,
      ...(status && { status }),
      ...(category && { category }),
      // FINDING-028: filter by credential type array in DB; avoids O(n) client scan
      ...(types && types.length > 0 && { type: { hasSome: types } }),
    },
    orderBy: { issuedAt: 'desc' },
    skip,
    take,
  });
}

/**
 * List credentials by issuer
 */
export async function listCredentialsByIssuer(
  issuerDid: string,
  options: {
    category?: CredentialCategory;
    status?: CredentialStatus;
    skip?: number;
    take?: number;
  } = {}
) {
  const { category, status, skip = 0, take = 50 } = options;
  
  return db.credential.findMany({
    where: {
      issuerDid,
      ...(status && { status }),
      ...(category && { category }),
    },
    orderBy: { issuedAt: 'desc' },
    skip,
    take,
    include: {
      holder: {
        select: {
          id: true,
          displayName: true,
          email: true,
        },
      },
    },
  });
}

/**
 * Update credential status
 */
export async function updateCredentialStatus(
  id: string,
  status: CredentialStatus,
  reason?: string
) {
  const data: CredentialUpdateInput = { status };
  
  if (status === 'REVOKED') {
    data.revokedAt = new Date();
    data.revocationReason = reason;
  }
  
  return db.credential.update({
    where: { id },
    data,
  });
}

/**
 * Increment credential usage count
 */
export async function incrementCredentialUsage(id: string) {
  return db.credential.update({
    where: { id },
    data: {
      useCount: { increment: 1 },
      lastUsedAt: new Date(),
    },
  });
}

/**
 * Delete credential
 */
export async function deleteCredential(id: string) {
  return db.credential.delete({ where: { id } });
}

/**
 * Count credentials by category for a holder
 */
export async function countCredentialsByCategory(holderDid: string) {
  const results = await db.credential.groupBy({
    by: ['category'],
    where: {
      holderDid,
      status: 'ACTIVE',
    },
    _count: true,
  });
  
  return results.reduce((acc, item) => {
    acc[item.category] = item._count;
    return acc;
  }, {} as Record<CredentialCategory, number>);
}

/**
 * Get credential statistics for a holder
 */
export async function getCredentialStats(holderDid: string) {
  const [total, active, expired, revoked, byCategory] = await Promise.all([
    db.credential.count({ where: { holderDid } }),
    db.credential.count({ where: { holderDid, status: 'ACTIVE' } }),
    db.credential.count({ where: { holderDid, status: 'EXPIRED' } }),
    db.credential.count({ where: { holderDid, status: 'REVOKED' } }),
    countCredentialsByCategory(holderDid),
  ]);
  
  return { total, active, expired, revoked, byCategory };
}

/**
 * Find expiring credentials
 */
export async function findExpiringCredentials(daysUntilExpiry: number) {
  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + daysUntilExpiry);
  
  return db.credential.findMany({
    where: {
      status: 'ACTIVE',
      expiresAt: {
        lte: expiryDate,
        gt: new Date(),
      },
    },
    include: {
      holder: {
        select: {
          id: true,
          email: true,
          displayName: true,
        },
      },
    },
  });
}

/**
 * Mark expired credentials
 */
export async function markExpiredCredentials() {
  return db.credential.updateMany({
    where: {
      status: 'ACTIVE',
      expiresAt: { lt: new Date() },
    },
    data: {
      status: 'EXPIRED',
    },
  });
}

// Credential Schema operations

/**
 * Create credential schema
 */
export async function createCredentialSchema(data: Prisma.CredentialSchemaCreateInput) {
  return db.credentialSchema.create({ data });
}

/**
 * Find schema by name and version
 */
export async function findCredentialSchema(name: string, version: string) {
  return db.credentialSchema.findUnique({
    where: {
      name_version: { name, version },
    },
  });
}

/**
 * List public schemas
 */
export async function listPublicSchemas() {
  return db.credentialSchema.findMany({
    where: { isPublic: true },
    orderBy: { name: 'asc' },
  });
}

// Credential Offer operations

/**
 * Create credential offer
 */
export async function createCredentialOffer(data: Prisma.CredentialOfferCreateInput) {
  return db.credentialOffer.create({ data });
}

/**
 * Find credential offer by pre-authorized code
 */
export async function findCredentialOfferByCode(preAuthorizedCode: string) {
  return db.credentialOffer.findUnique({
    where: { preAuthorizedCode },
  });
}

/**
 * List pending offers for a holder
 */
export async function listPendingOffers(holderDid: string) {
  return db.credentialOffer.findMany({
    where: {
      holderDid,
      status: 'PENDING',
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
  });
}

/**
 * Update offer status
 */
export async function updateOfferStatus(
  id: string,
  status: 'ACCEPTED' | 'REJECTED' | 'EXPIRED' | 'REVOKED' | 'PENDING'
) {
  return db.credentialOffer.update({
    where: { id },
    data: {
      status,
      ...(status === 'ACCEPTED' && { acceptedAt: new Date() }),
    },
  });
}

// Alias for OID4VCI route compatibility
export const updateCredentialOfferStatus = updateOfferStatus;

/**
 * Find credential offer by ID
 */
export async function findCredentialOfferById(id: string) {
  return db.credentialOffer.findUnique({
    where: { id },
  });
}

/**
 * Mark expired offers
 */
export async function markExpiredOffers() {
  return db.credentialOffer.updateMany({
    where: {
      status: 'PENDING',
      expiresAt: { lt: new Date() },
    },
    data: {
      status: 'EXPIRED',
    },
  });
}
