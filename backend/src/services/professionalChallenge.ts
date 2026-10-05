/**
 * SSI Healthcare Backend — challenges for professional-authority presentations.
 *
 * Verifier-side state, and the reason the guard can make a replay claim at all.
 * A nonce the presenter supplies is not a nonce; it has to be generated here,
 * stored here, and spent here.
 *
 * SINGLE USE, BY COMPARE-AND-SWAP. `consumeChallenge` moves the row out of
 * REQUESTED in one conditional UPDATE and reports whether it was the one that
 * moved it. Two requests arriving with the same captured presentation therefore
 * cannot both proceed, which a read-then-write could not promise. The cost is a
 * round trip per protected request — see the note in `requireProfessional`.
 */

import { randomUUID } from 'node:crypto';
import {
  PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
  type PresentationDefinition,
  type PracticeScope,
  type Profession,
} from '@ssi-healthcare/shared';
import { db } from '../db/index.js';
import { logger } from '../utils/logger.js';
import type { Prisma } from '../../prisma/generated/client/index.js';

/** How long a challenge stays open. Long enough to tap approve, not to shop it around. */
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;

export interface ProfessionalChallenge {
  requestId: string;
  nonce: string;
  /** The DID the holder must name as `aud`. Ours, never the caller's. */
  audience: string;
  expiresAt: string;
  definition: PresentationDefinition;
}

/**
 * What the wallet is being asked for.
 *
 * Emitted so the holder app can build a presentation frame without hardcoding
 * our claim names, and so the *user* can be shown what is about to be revealed.
 */
export function professionalPresentationDefinition(requirement: {
  profession?: Profession;
  scope: readonly PracticeScope[];
}): PresentationDefinition {
  return {
    id: `professional-authority-${requirement.profession ?? 'any'}`,
    name: 'Professional licence',
    purpose: `Prove authority to ${requirement.scope.join(', ')}`,
    inputDescriptors: [
      {
        id: 'professional-licence',
        name: PROFESSIONAL_LICENCE_CREDENTIAL_TYPE,
        constraints: {
          fields: [
            {
              path: ['$.type'],
              filter: { type: 'string', const: PROFESSIONAL_LICENCE_CREDENTIAL_TYPE },
            },
            // Named individually so the wallet discloses exactly these. Every
            // one is required by `ProfessionalLicenceSubjectSchema`, so a frame
            // built from this definition is one the guard will accept.
            { path: ['$.credentialSubject.profession'] },
            { path: ['$.credentialSubject.licenceNumber'] },
            { path: ['$.credentialSubject.register'] },
            { path: ['$.credentialSubject.practiceScope'] },
            { path: ['$.credentialSubject.licenceValidFrom'] },
            { path: ['$.credentialSubject.licenceValidUntil'] },
          ],
        },
      },
    ],
  };
}

export async function createChallenge(params: {
  audience: string;
  holderDid?: string;
  requirement: { profession?: Profession; scope: readonly PracticeScope[] };
}): Promise<ProfessionalChallenge> {
  const requestId = randomUUID();
  const nonce = randomUUID();
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
  const definition = professionalPresentationDefinition(params.requirement);

  await db.presentation.create({
    data: {
      holderDid: params.holderDid ?? null,
      verifierDid: params.audience,
      requestId,
      nonce,
      // The licence is presented under selective disclosure; the holder reveals
      // the licence claims and nothing else the credential may carry.
      presentationType: 'SELECTIVE',
      requestedCredentials: JSON.parse(JSON.stringify(definition)) as Prisma.InputJsonValue,
      status: 'REQUESTED',
      expiresAt,
    },
  });

  logger.info('Professional authority challenge issued', {
    requestId,
    holderDid: params.holderDid,
    requirement: params.requirement,
  });

  return {
    requestId,
    nonce,
    audience: params.audience,
    expiresAt: expiresAt.toISOString(),
    definition,
  };
}

export type ChallengeConsumption =
  | { ok: true; nonce: string; audience: string; presentationId: string; holderDid: string | null }
  | { ok: false; reason: string };

/**
 * Spend a challenge, atomically.
 *
 * Returns the nonce ONLY to the caller that won the swap. Everything else — an
 * unknown id, an expired row, a second use — is a refusal with a reason the
 * guard can log but should not echo verbatim to the client.
 */
export async function consumeChallenge(requestId: string): Promise<ChallengeConsumption> {
  const row = await db.presentation.findUnique({ where: { requestId } });

  if (!row) return { ok: false, reason: 'unknown challenge' };

  if (row.expiresAt <= new Date()) {
    // Best-effort bookkeeping; the refusal does not depend on it landing.
    await db.presentation
      .updateMany({ where: { id: row.id, status: 'REQUESTED' }, data: { status: 'EXPIRED' } })
      .catch(() => undefined);
    return { ok: false, reason: 'challenge expired' };
  }

  const claimed = await db.presentation.updateMany({
    where: { id: row.id, status: 'REQUESTED' },
    data: { status: 'PRESENTED', presentedAt: new Date() },
  });

  if (claimed.count !== 1) {
    return { ok: false, reason: `challenge already ${row.status.toLowerCase()}` };
  }

  return {
    ok: true,
    nonce: row.nonce,
    audience: row.verifierDid,
    presentationId: row.id,
    holderDid: row.holderDid,
  };
}

export interface ChallengeOutcome {
  verified: boolean;
  reasons: string[];
  /** Per-check verdicts, persisted verbatim as audit JSON and never read back. */
  checks: object;
}

/** Record the verdict against the spent challenge, for audit. Never gates anything. */
export async function recordChallengeOutcome(
  presentationId: string,
  outcome: ChallengeOutcome,
): Promise<void> {
  await db.presentation
    .update({
      where: { id: presentationId },
      data: {
        status: outcome.verified ? 'VERIFIED' : 'FAILED',
        verifiedAt: outcome.verified ? new Date() : null,
        verificationResult: JSON.parse(JSON.stringify(outcome)) as Prisma.InputJsonValue,
      },
    })
    .catch((error: unknown) => {
      logger.warn('Could not record professional challenge outcome', { presentationId, error });
    });
}
