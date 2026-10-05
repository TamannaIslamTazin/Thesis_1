/**
 * SSI Healthcare Backend - DID Routes
 *
 * REST endpoints for DID creation and resolution.
 *
 * POST /api/dids          - Create a new DID
 * GET  /api/dids/:did     - Resolve a DID to its DID Document
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { createDID, resolveDID } from '../services/didService.js';
import { resolveStatusListCredential } from '../services/statusListService.js';
import type { ApiResponse } from '@ssi-healthcare/shared';
import { requireWallet } from '../middleware/auth.js';

export const didRouter = Router();

// -- Validation schemas --

/**
 * `cheqd` IS DELIBERATELY ABSENT FROM THIS ENUM.
 *
 * A did:cheqd's governance — its controller set and the controller of its
 * verification method — is fixed at creation and can never be repaired
 * afterwards. There is no correct value this endpoint could infer from an HTTP
 * body: a request that says only "make me a cheqd DID" is a request to guess,
 * and guessing here mints a permanently unrecoverable identity that looks
 * healthy until the day its key is lost. See `services/cheqdDid.ts`.
 *
 * Removing the option rather than accepting-and-rejecting it is intentional:
 * the schema is the documentation, and Zod's own "invalid enum value" error
 * names the permitted set without anyone maintaining a second message.
 * On-ledger identities are minted by the flows that know their controller
 * policy, not by a generic factory endpoint.
 */
const createDIDSchema = z.object({
  method: z.literal('key').default('key'),
});

// -- Routes --

/**
 * POST /api/dids
 * Create a new local, ephemeral `did:key`.
 * Requires wallet: ensures DID is created for an authenticated, wallet-owning user.
 */
didRouter.post('/', requireWallet, async (req: Request, res: Response, next: NextFunction) => {
  try {
    // requireWallet already validates the authenticated user; no further user data needed here
    const { method } = createDIDSchema.parse(req.body);
    const result = await createDID({ method });

    const response: ApiResponse<typeof result> = {
      success: true,
      data: result,
      timestamp: new Date().toISOString(),
    };

    res.status(201).json(response);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/dids/status-list?url=<status-list DID URL>
 *
 * Dereference a Bitstring Status List that credentials point at, over plain
 * HTTP, for relying parties that cannot resolve a cheqd DID URL themselves.
 *
 * DECLARED BEFORE `/:did` ON PURPOSE. Express matches in declaration order, so
 * registering it after the parameterised route would make `status-list` resolve
 * as a DID named "status-list" and this endpoint would be unreachable.
 *
 * Deliberately unauthenticated: a revocation list is public by construction —
 * that is what lets a verifier check it without contacting the issuer, which is
 * the whole point of publishing it. It carries bits, not names.
 */
didRouter.get('/status-list', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const url = typeof req.query.url === 'string' ? req.query.url : '';
    if (!url.startsWith('did:')) {
      res.status(400).json({
        success: false,
        error: 'url must be a status-list DID URL, e.g. did:cheqd:…?resourceName=…&resourceType=…',
        timestamp: new Date().toISOString(),
      });
      return;
    }

    const resource = await resolveStatusListCredential(url);
    if (!resource) {
      // 404, never an empty list. An unreadable list must not be able to reach
      // a caller as "nothing is revoked" — the caller has to see the absence.
      res.status(404).json({
        success: false,
        error: `Status list '${url}' does not resolve on this ledger`,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    // The status list credential itself, at the top level: this is a published
    // W3C credential and a reader expects `credentialSubject.encodedList`
    // without unwrapping one of our envelopes first.
    res.json(resource);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/dids/:did
 * Resolve a DID to its DID Document.
 *
 * The :did parameter should be URL-encoded since DIDs contain colons.
 * Example: GET /api/dids/did%3Akey%3Az6Mkp...
 */
didRouter.get('/:did', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const did = decodeURIComponent(req.params.did as string);
    const didDocument = await resolveDID(did);

    const response: ApiResponse<typeof didDocument> = {
      success: true,
      data: didDocument,
      timestamp: new Date().toISOString(),
    };

    res.json(response);
  } catch (error) {
    next(error);
  }
});
