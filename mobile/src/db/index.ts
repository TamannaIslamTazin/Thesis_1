/**
 * The wallet's local database: one import surface.
 *
 * Callers use `getDb` for ad-hoc queries and the repositories for anything
 * with a consumer. Repositories are re-exported by name so screens never
 * import a subpath.
 */
export { getDb, closeDb, withDbTransaction, SqlCipherUnavailableError } from './open';
export { getOrCreateDbKeyHex, deleteDbKey, DbKeyError } from './keys';
export {
  listCredentialEnvelopes,
  replaceCredentialEnvelopes,
  clearCredentialEnvelopes,
} from './repositories/credentialRepository';
export {
  listConsentRecords,
  replaceConsentRecords,
  revokeConsentRecord,
  clearConsentRecords,
} from './repositories/consentRepository';
export type { ConsentApiRecord } from './repositories/consentRepository';
export { enqueueObject, countPendingObjects, type OutboxEntry } from './sync/outbox';
