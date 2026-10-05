/**
 * Round 5's custody broker — operations a real device-held key would perform
 * locally, performed here instead because today's wallet is CLOUD-custodied.
 *
 * Read __docs__/frontend/WALLET-CUSTODY-NOTE.md before touching this file. In
 * short: `POST /api/auth/wallet/setup` mints the patient DID with the Credo
 * agent holding `#key-1` in its own KMS (`walletType: 'CLOUD'` — see that
 * route's own comment and `cheqdDid.ts`'s `createCheqdDID`, which only takes
 * an externally-supplied key when a caller passes `spec.subjectKey`, which
 * nothing in this codebase does yet). OFFICER-DOCUMENT-ACCESS.md's capability
 * ("signed by the holder's DID key") and the locker's own DID
 * challenge-response both assume the device holds that key. It does not, so
 * this backend performs the signature ON THE CALLER'S BEHALF, authenticated
 * by their own session — the same shape `packages/issuer-console`'s
 * `/console/locker/object` route already uses for the INSTITUTION side
 * (private key stays server-side; the client only ever receives ciphertext
 * and short-lived tokens), applied here to the holder side because the
 * custody reality is symmetric: both parties' real keys live behind a
 * server today, not on a device or in a browser.
 *
 * Two operations, both narrowly scoped — this is deliberately NOT "sign
 * these bytes with my key" as a general oracle:
 *
 *   POST /locker-session   completes DID challenge-response against a locker
 *                           the caller names (checked against an allowlist)
 *                           and returns a bearer token. Ciphertext itself
 *                           never touches this backend — the wallet uses the
 *                           token to talk to the locker directly, preserving
 *                           OFFICER-DOCUMENT-ACCESS.md's "keeps documents out
 *                           of our backend entirely".
 *
 *   POST /capability       mints ONE locker capability
 *                           (`@ssi-healthcare/shared` `mintLockerCapability`)
 *                           naming the caller's own DID as issuer. The
 *                           payload that gets signed is built entirely by
 *                           that shared function from caller-supplied claim
 *                           VALUES, never caller-supplied bytes — so this
 *                           route can never be asked to sign something that
 *                           is not, in shape, a locker capability.
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';

import { AppError } from '../middleware/errorHandler.js';
import {
  ERROR_CODES,
  mintLockerCapability,
  documentTypeById,
  DOCUMENT_TYPES,
} from '@ssi-healthcare/shared';
import { requireWallet, type AuthenticatedRequest } from '../middleware/auth.js';
import { getAgent } from '../agent/index.js';
import { agentSigner } from '../services/cheqdLedger.js';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

export const walletCustodyRouter = Router();

// ---------------------------------------------------------------------------
// POST /locker-session
// ---------------------------------------------------------------------------

const lockerSessionSchema = z.object({
  lockerBaseUrl: z.string().url(),
});

const AUTH_PAYLOAD_DOMAIN = 'bdhealthtrust/locker-auth/v1';

function lockerAuthPayload(args: {
  readonly audience: string;
  readonly did: string;
  readonly nonce: string;
  readonly issuedAtSeconds: number;
}): Uint8Array {
  const canonical =
    `${AUTH_PAYLOAD_DOMAIN}\n` +
    `aud:${args.audience}\n` +
    `did:${args.did}\n` +
    `nonce:${args.nonce}\n` +
    `iat:${args.issuedAtSeconds}\n`;
  return new TextEncoder().encode(canonical);
}

/**
 * POST /api/wallet/locker-session
 *
 * Completes the locker's DID challenge-response (`packages/locker/src/didAuth.ts`)
 * as the caller's own DID, using the CLOUD-custodied key this agent holds for
 * it, and returns the resulting bearer token. `lockerBaseUrl` must be on the
 * configured allowlist (`config.walletLockerAllowedUrls`) — this route
 * authenticates to a locker of the caller's choosing (self-hosting is a
 * design goal — see `packages/locker/src/config.ts`), not to an arbitrary URL.
 */
walletCustodyRouter.post(
  '/locker-session',
  requireWallet,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const { lockerBaseUrl } = lockerSessionSchema.parse(req.body);
      const normalised = lockerBaseUrl.replace(/\/+$/, '');

      if (!config.walletLockerAllowedUrls.includes(normalised)) {
        throw new AppError(
          ERROR_CODES.VALIDATION_FAILED,
          `'${lockerBaseUrl}' is not on this deployment's locker allowlist.`,
          400,
        );
      }

      const agent = getAgent();

      const challengeRes = await fetch(`${normalised}/v1/auth/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ did: user.did }),
      });
      if (!challengeRes.ok) {
        throw new AppError(
          ERROR_CODES.WALLET_CUSTODY_OPERATION_FAILED,
          `The locker refused the auth challenge (status ${challengeRes.status}).`,
          502,
        );
      }
      const challenge = (await challengeRes.json()) as { nonce: string; audience: string };

      const signer = await agentSigner(agent, user.did!);
      const issuedAtSeconds = Math.floor(Date.now() / 1000);
      const payload = lockerAuthPayload({
        audience: challenge.audience,
        did: user.did!,
        nonce: challenge.nonce,
        issuedAtSeconds,
      });
      const signature = await signer.sign(payload);

      const tokenRes = await fetch(`${normalised}/v1/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          nonce: challenge.nonce,
          signature: Buffer.from(signature).toString('base64url'),
          verificationMethodId: signer.verificationMethodId,
          iat: issuedAtSeconds,
        }),
      });
      if (!tokenRes.ok) {
        const body = await tokenRes.json().catch(() => ({}));
        logger.warn('wallet_locker_session_refused', { userId: user.id, status: tokenRes.status, body });
        throw new AppError(
          ERROR_CODES.WALLET_CUSTODY_OPERATION_FAILED,
          `The locker refused the signed challenge (status ${tokenRes.status}).`,
          502,
        );
      }
      const token = (await tokenRes.json()) as { token: string; expiresAt: string };

      logger.info('wallet_locker_session_issued', { userId: user.id, lockerBaseUrl: normalised });

      res.json({
        success: true,
        data: { token: token.token, expiresAt: token.expiresAt, lockerBaseUrl: normalised },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      next(error);
    }
  },
);

// ---------------------------------------------------------------------------
// POST /capability
// ---------------------------------------------------------------------------

const capabilitySchema = z.object({
  documentType: z.string().min(1),
  objectIds: z.array(z.string().min(1)).min(1).max(10),
  issuanceRequestId: z.string().min(16).max(64),
  validitySeconds: z.number().int().positive().optional(),
});

/**
 * POST /api/wallet/capability
 *
 * Mints a locker capability naming the caller's own DID as `iss`. `aud` is
 * NOT caller-supplied — it is read from `DOCUMENT_TYPES` for the given
 * `documentType`, the same registry `POST /api/issuance/requests` already
 * trusts as the one place an authority DID comes from, so this route cannot
 * be asked to mint a capability admitting an arbitrary DID.
 */
walletCustodyRouter.post(
  '/capability',
  requireWallet,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as AuthenticatedRequest).user;
      const data = capabilitySchema.parse(req.body);

      const documentType = documentTypeById(data.documentType);
      if (!documentType) {
        throw new AppError(
          ERROR_CODES.DOCUMENT_TYPE_UNKNOWN,
          `Unknown document type '${data.documentType}'. Known: ${DOCUMENT_TYPES.map((d) => d.id).join(', ')}.`,
          400,
        );
      }

      const agent = getAgent();
      const signer = await agentSigner(agent, user.did!);

      const token = await mintLockerCapability({
        holderDid: user.did!,
        authorityDid: documentType.issuingAuthorityDid,
        objectIds: data.objectIds,
        issuanceRequestId: data.issuanceRequestId,
        verificationMethodId: signer.verificationMethodId,
        validitySeconds: data.validitySeconds,
        sign: (payload) => signer.sign(payload),
      });

      logger.info('wallet_capability_minted', {
        userId: user.id,
        documentType: documentType.id,
        issuanceRequestId: data.issuanceRequestId,
        objectCount: data.objectIds.length,
      });

      res.status(201).json({ success: true, data: token, timestamp: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  },
);
