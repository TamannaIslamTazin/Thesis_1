/**
 * SSI Healthcare Backend - DID Service
 *
 * Business logic for creating and resolving Decentralized Identifiers.
 * Supports did:key (ephemeral, local) and did:cheqd (on-ledger, persistent).
 *
 * Updated for Credo TS 0.6.x (new KMS-based key creation)
 */

import { getAgent } from '../agent/index.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES, isSsiError } from '@ssi-healthcare/shared';
import type { DIDDocument } from '@ssi-healthcare/shared';
import { createCheqdDID, type CreateCheqdDIDSpec } from './cheqdDid.js';

export interface CreateDIDResult {
  did: string;
  didDocument: DIDDocument;
}

/**
 * What a caller must state to get a DID.
 *
 * A DISCRIMINATED UNION RATHER THAN `(method, spec?)`, deliberately. The whole
 * defect this shape exists to prevent — see `cheqdDid.ts` — was a required
 * decision that had a silent default, so "you may omit the cheqd spec and
 * something reasonable will happen" is precisely the affordance that must not
 * exist. With the union, `{ method: 'cheqd' }` does not typecheck, and the
 * runtime guard in {@link createDID} covers the untyped HTTP boundary where the
 * type system is not present.
 */
export type CreateDIDRequest =
  | { readonly method: 'key' }
  | { readonly method: 'cheqd'; readonly spec: CreateCheqdDIDSpec };

/**
 * The key spec for the did:key branch.
 *
 * Ed25519 for both methods, but the cheqd branch owns its own copy in
 * `cheqdDid.ts` because there the constraint is not a preference: our chain's
 * `validateSpecCompliantPayload` accepts only Ed25519/JWK verification material,
 * so a divergence there is a runtime failure on the ledger path — the path that
 * is hardest to exercise and easiest to ship broken.
 */
const ED25519_KEY_SPEC = {
  type: {
    kty: 'OKP',
    crv: 'Ed25519',
  },
} as const;

/**
 * Create a new DID.
 *
 * `did:key` is local, ephemeral and self-describing — the identifier IS the key,
 * so there is nothing to control and nothing to rotate, and no controller
 * question arises.
 *
 * `did:cheqd` is the opposite: an on-ledger identifier whose governance is
 * decided once, at creation, and can never be repaired. It therefore does not
 * go through `agent.dids.create` at all. Credo's `CheqdDidRegistrar` leaves
 * `verificationMethod[0].controller` at the `@cheqd/sdk` default — the subject
 * itself — which makes the DID permanently unrecoverable the moment its key is
 * lost, and it cannot produce the external-controller signatures that the
 * correct shape requires. See `cheqdDid.ts` for the executed evidence.
 */
export async function createDID(request: CreateDIDRequest): Promise<CreateDIDResult> {
  const agent = getAgent();

  // Runtime guard for the untyped HTTP boundary. `request` arrives from a Zod
  // parse in the route layer, and a future edit to that schema must not be able
  // to reintroduce a spec-less cheqd creation.
  if (request?.method === 'cheqd' && !request.spec) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      'A did:cheqd cannot be created without an explicit CreateCheqdDIDSpec naming its ' +
        'controller set and its verification-method controller. There is no default: the ' +
        'SDK default self-controls the verification method, and a self-controlled ' +
        'verification method can never be replaced without the key it names.',
      400,
    );
  }

  try {
    if (request.method === 'cheqd') {
      const result = await createCheqdDID(agent, request.spec);
      return { did: result.did, didDocument: result.didDocument };
    }

    logger.info('Creating DID', { method: 'key' });

    const result = await agent.dids.create({
      method: 'key',
      options: {
        createKey: ED25519_KEY_SPEC,
      },
    });

    if (result.didState.state !== 'finished' || !result.didState.did) {
      const reason = (result.didState as { reason?: string }).reason ?? result.didState.state;
      throw new AppError(
        ERROR_CODES.DID_CREATION_FAILED,
        `DID creation failed: ${reason}`,
        500,
      );
    }

    logger.info('DID created successfully', { did: result.didState.did, method: 'key' });

    return {
      did: result.didState.did,
      didDocument: result.didState.didDocument as unknown as DIDDocument,
    };
  } catch (error) {
    if (isSsiError(error)) throw error;

    logger.error('DID creation error', { method: request.method, error });
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Failed to create DID: ${error instanceof Error ? error.message : 'Unknown error'}`,
      500,
    );
  }
}

/**
 * Resolve a DID to its DID Document.
 *
 * @param did - The DID URI to resolve
 * @returns The resolved DID Document
 */
export async function resolveDID(did: string): Promise<DIDDocument> {
  const agent = getAgent();

  try {
    logger.info('Resolving DID', { did });

    const result = await agent.dids.resolve(did);

    if (!result.didDocument) {
      throw new AppError(ERROR_CODES.DID_NOT_FOUND, `DID not found: ${did}`, 404);
    }

    logger.info('DID resolved successfully', { did });

    return result.didDocument as unknown as DIDDocument;
  } catch (error) {
    if (isSsiError(error)) throw error;

    logger.error('DID resolution error', { did, error });
    throw new AppError(
      ERROR_CODES.DID_RESOLUTION_FAILED,
      `Failed to resolve DID: ${error instanceof Error ? error.message : 'Unknown error'}`,
      500,
    );
  }
}
