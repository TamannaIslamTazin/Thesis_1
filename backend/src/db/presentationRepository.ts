/**
 * SSI Healthcare - Presentation Repository
 * 
 * Database operations for verifiable presentations (OID4VP)
 */

import { db } from './index.js';
import type { Prisma, PresentationType, PresentationStatus } from '../../prisma/generated/client/index.js';

export type PresentationCreateInput = Prisma.PresentationCreateInput;
export type PresentationUpdateInput = Prisma.PresentationUpdateInput;

/**
 * Create a new presentation request
 */
export async function createPresentationRequest(data: PresentationCreateInput) {
  return db.presentation.create({
    data,
  });
}

/**
 * Find presentation by ID
 */
export async function findPresentationById(id: string) {
  return db.presentation.findUnique({
    where: { id },
    include: {
      credentials: {
        include: {
          credential: true,
        },
      },
      consent: true,
    },
  });
}

/**
 * Find presentation by request ID
 */
export async function findPresentationByRequestId(requestId: string) {
  return db.presentation.findUnique({
    where: { requestId },
    include: {
      credentials: {
        include: {
          credential: true,
        },
      },
    },
  });
}

/**
 * List presentations for a holder
 */
export async function listPresentationsByHolder(
  holderDid: string,
  options: {
    status?: PresentationStatus;
    type?: PresentationType;
    skip?: number;
    take?: number;
  } = {}
) {
  const { status, type, skip = 0, take = 50 } = options;
  
  return db.presentation.findMany({
    where: {
      holderDid,
      ...(status && { status }),
      ...(type && { presentationType: type }),
    },
    orderBy: { requestedAt: 'desc' },
    skip,
    take,
    include: {
      credentials: {
        include: {
          credential: {
            select: {
              id: true,
              name: true,
              category: true,
            },
          },
        },
      },
    },
  });
}

/**
 * List presentations for a verifier
 */
export async function listPresentationsByVerifier(
  verifierDid: string,
  options: {
    status?: PresentationStatus;
    skip?: number;
    take?: number;
  } = {}
) {
  const { status, skip = 0, take = 50 } = options;
  
  return db.presentation.findMany({
    where: {
      verifierDid,
      ...(status && { status }),
    },
    orderBy: { requestedAt: 'desc' },
    skip,
    take,
  });
}

/**
 * List pending presentation requests for a holder
 */
export async function listPendingRequests(holderDid: string) {
  return db.presentation.findMany({
    where: {
      holderDid,
      status: 'PENDING',
      expiresAt: { gt: new Date() },
    },
    orderBy: { requestedAt: 'desc' },
  });
}

/**
 * Update presentation status
 */
export async function updatePresentationStatus(
  id: string,
  status: PresentationStatus,
  additionalData?: Partial<PresentationUpdateInput>
) {
  const data: PresentationUpdateInput = {
    status,
    ...additionalData,
  };
  
  // Set appropriate timestamps based on status
  if (status === 'PRESENTED') {
    data.presentedAt = new Date();
  } else if (status === 'VERIFIED') {
    data.verifiedAt = new Date();
  }
  
  return db.presentation.update({
    where: { id },
    data,
  });
}

/**
 * Submit a presentation (add credentials and update status)
 */
export async function submitPresentation(
  id: string,
  credentials: Array<{
    credentialId: string;
    disclosedAttributes: string[];
  }>,
  selectedDisclosure?: object
) {
  return db.$transaction(async (tx) => {
    // Add credentials to presentation
    await tx.presentationCredential.createMany({
      data: credentials.map((c) => ({
        presentationId: id,
        credentialId: c.credentialId,
        disclosedAttributes: c.disclosedAttributes,
      })),
    });
    
    // Update presentation status
    return tx.presentation.update({
      where: { id },
      data: {
        status: 'PRESENTED',
        presentedAt: new Date(),
        selectedDisclosure: selectedDisclosure as Prisma.InputJsonValue,
      },
      include: {
        credentials: {
          include: {
            credential: true,
          },
        },
      },
    });
  });
}

/**
 * Record verification result
 */
export async function recordVerificationResult(
  id: string,
  success: boolean,
  result: object
) {
  return db.presentation.update({
    where: { id },
    data: {
      status: success ? 'VERIFIED' : 'FAILED',
      verifiedAt: new Date(),
      verificationResult: result as Prisma.InputJsonValue,
    },
  });
}

/**
 * Get presentation statistics for a holder
 */
export async function getPresentationStats(holderDid: string) {
  const [total, verified, pending, rejected] = await Promise.all([
    db.presentation.count({ where: { holderDid } }),
    db.presentation.count({ where: { holderDid, status: 'VERIFIED' } }),
    db.presentation.count({ where: { holderDid, status: 'PENDING' } }),
    db.presentation.count({ where: { holderDid, status: 'REJECTED' } }),
  ]);
  
  return { total, verified, pending, rejected };
}

/**
 * Mark expired presentation requests
 */
export async function markExpiredPresentations() {
  return db.presentation.updateMany({
    where: {
      status: 'PENDING',
      expiresAt: { lt: new Date() },
    },
    data: {
      status: 'EXPIRED',
    },
  });
}

/**
 * Get recent presentations for a holder
 */
export async function getRecentPresentations(holderDid: string, limit = 5) {
  return db.presentation.findMany({
    where: { holderDid },
    orderBy: { requestedAt: 'desc' },
    take: limit,
    select: {
      id: true,
      verifierDid: true,
      status: true,
      presentationType: true,
      requestedAt: true,
      verifiedAt: true,
    },
  });
}
