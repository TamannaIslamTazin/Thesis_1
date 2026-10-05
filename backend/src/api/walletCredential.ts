/**
 * SSI Healthcare Backend - Wallet Credential Response Mapper
 *
 * Translates a Prisma `Credential` row into the `WalletCredential` envelope
 * defined in `@ssi-healthcare/shared`.
 *
 * This module is the boundary between the database schema and the HTTP
 * contract. Before it existed, `GET /api/users/me/credentials` returned raw
 * Prisma rows, which meant:
 *
 *   - every client had to know the signed VC lives in a column called
 *     `credentialData`, and had to know its internal encoding;
 *   - renaming a column was a breaking API change;
 *   - `null` (Prisma's absent-value representation) leaked onto the wire where
 *     the clients' optional fields expect the key to be missing.
 *
 * Keeping the translation in one place means the wallet contract can outlive
 * the schema, which is the whole point of the planned finance / agriculture /
 * education verticals reusing this stack.
 */

import type {
  WalletCredential,
  WalletCredentialCategory,
  WalletCredentialStatus,
  WalletCredentialStats,
} from '@ssi-healthcare/shared';
import { storedCredentialToW3cJson, credentialEnvelopeJwt } from '../services/jwtVc.js';
import { credentialEnvelopeFormat } from '../services/sdJwtVc.js';
import { logger } from '../utils/logger.js';

/**
 * The subset of the Prisma `Credential` model this mapper reads.
 *
 * Declared structurally rather than as the generated `Credential` type so that
 * rows fetched with `include: { holder, schema }` (the single-credential path)
 * and rows fetched plain (the list path) both satisfy it.
 */
export interface CredentialRow {
  id: string;
  holderDid: string;
  issuerDid: string;
  type: string[];
  category: string;
  name: string;
  description: string | null;
  credentialData: unknown;
  /**
   * The enveloping proof. Optional on this interface so callers that select a
   * narrower column set still typecheck; `credentialEnvelopeJwt` falls back to
   * the legacy VC 1.1 location when it is absent.
   */
  credentialJwt?: string | null;
  /**
   * Which securing mechanism {@link credentialJwt} uses. Optional for the same
   * reason as the column above, and absent on legacy VC 1.1 rows.
   */
  credentialFormat?: string | null;
  credentialHash: string;
  status: string;
  issuedAt: Date;
  expiresAt: Date | null;
  revokedAt: Date | null;
  revocationReason: string | null;
  lastUsedAt: Date | null;
  useCount: number;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Map one row to the wallet envelope.
 *
 * Returns `null` when `credentialData` cannot be read as a Verifiable
 * Credential. A row without a readable VC is not a wallet credential — it is a
 * storage defect — and emitting an envelope with an empty `credential` would
 * push that defect out to every client as a runtime dereference. Dropping it
 * and logging at ERROR keeps the failure visible to operators and harmless to
 * the holder's other credentials.
 */
export function toWalletCredential(row: CredentialRow): WalletCredential | null {
  const credential = storedCredentialToW3cJson(row.credentialData);

  if (!credential) {
    logger.error('Credential row has unreadable credentialData — omitted from response', {
      credentialId: row.id,
      holderDid: row.holderDid,
      issuerDid: row.issuerDid,
    });
    return null;
  }

  const envelopeJwt = credentialEnvelopeJwt(row);
  const envelopeFormat = credentialEnvelopeFormat(row);

  return {
    id: row.id,
    holderDid: row.holderDid,
    issuerDid: row.issuerDid,
    type: row.type,
    category: row.category as WalletCredentialCategory,
    name: row.name,
    // Prisma reports an absent column as `null`; the envelope's optional
    // fields mean "key absent", so omit rather than send an explicit null.
    ...(row.description !== null && { description: row.description }),
    credentialHash: row.credentialHash,
    status: row.status as WalletCredentialStatus,
    issuedAt: row.issuedAt.toISOString(),
    ...(row.expiresAt !== null && { expiresAt: row.expiresAt.toISOString() }),
    ...(row.revokedAt !== null && { revokedAt: row.revokedAt.toISOString() }),
    ...(row.revocationReason !== null && { revocationReason: row.revocationReason }),
    ...(row.lastUsedAt !== null && { lastUsedAt: row.lastUsedAt.toISOString() }),
    useCount: row.useCount,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    credential,
    // The enveloping proof. THIS is what a holder presents to a verifier — the
    // `credential` above is the data model and, for VC 2.0, carries no
    // signature at all. Omitted when the row predates the column and has no
    // recoverable JWT (a Data Integrity credential), rather than sent as null.
    ...(envelopeJwt !== null && { credentialJwt: envelopeJwt }),
    // WHICH mechanism that envelope uses. A holder cannot present an SD-JWT the
    // same way as a JWT — it needs a disclosure frame chosen first — so a
    // wallet that receives the artifact without its format has to guess, and
    // the guess fails at presentation time rather than here.
    ...(envelopeFormat !== null && { credentialFormat: envelopeFormat }),
  };
}

/** Map a list of rows, dropping any that carry unreadable credential data. */
export function toWalletCredentialList(rows: CredentialRow[]): WalletCredential[] {
  return rows
    .map(toWalletCredential)
    .filter((credential): credential is WalletCredential => credential !== null);
}

/**
 * Shape the repository's stats aggregate for the wire.
 *
 * `getCredentialStats` already returns exactly these counts; this function
 * exists so the envelope's `stats` field has a single owner and so the
 * `byCategory` key type is asserted in one place rather than at each caller.
 */
export function toWalletCredentialStats(stats: {
  total: number;
  active: number;
  expired: number;
  revoked: number;
  byCategory: Record<string, number>;
}): WalletCredentialStats {
  return {
    total: stats.total,
    active: stats.active,
    expired: stats.expired,
    revoked: stats.revoked,
    byCategory: stats.byCategory as WalletCredentialStats['byCategory'],
  };
}
