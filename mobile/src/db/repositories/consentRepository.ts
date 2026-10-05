/**
 * Consent records, on device.
 *
 * The row holds the wire record exactly as `GET /users/me/consents` sent it;
 * `consentStore.transformConsent` derives the view model at read time, so a
 * mapping fix applies to rows already on disk.
 *
 * WHY THIS INTERFACE LIVES HERE and not in the SDK: the SDK `Consent` type
 * still declares `credentialTypes`, `credentialIds`, `attributes` and
 * `isActive`, none of which the endpoint sends — it sends `scope`,
 * `allowedFields` and a server-derived `status`. The store previously read
 * `sharedAttributes` off the SDK type, which has never existed on either side,
 * so the scope shown to users was always undefined. Correcting the SDK type is
 * a cross-package change with web consumers; this is the accurate contract
 * until then, and it lives beside the storage that depends on it.
 */
import { getDb, withDbTransaction } from '../open';
import { enqueueObject } from '../sync/outbox';

export interface ConsentApiRecord {
  id: string;
  holderDid: string;
  verifierDid: string;
  verifierName: string;
  purpose: string;
  /** Credential types covered by the grant. */
  scope: string[];
  /** Individual attributes the verifier may read. */
  allowedFields: string[];
  status: 'active' | 'revoked' | 'expired';
  grantedAt: string;
  expiresAt?: string;
  revokedAt?: string;
  accessCount?: number;
  lastAccessedAt?: string;
  /**
   * Whether access CONTINUES, or this documents an act already finished.
   *
   * A presentation is a completed disclosure: the verifier holds the claims
   * and nothing re-fetches them. Treating those as standing grants is what
   * made the wallet show a red "Expires in 24 hours" on a record seconds old
   * and offer a "Revoke Access" that cannot un-send what was sent.
   */
  standingAccess?: boolean;
}

interface ConsentRow {
  readonly record_json: string;
}

export async function listConsentRecords(): Promise<ConsentApiRecord[]> {
  const db = await getDb();
  const rows = await db.getAllAsync<ConsentRow>(
    'SELECT record_json FROM consents ORDER BY updated_at DESC;',
  );
  return rows.map((row) => JSON.parse(row.record_json) as ConsentApiRecord);
}

export async function replaceConsentRecords(
  records: readonly ConsentApiRecord[],
): Promise<void> {
  const now = Date.now();
  await withDbTransaction(async (db) => {
    await db.runAsync('DELETE FROM consents;');
    for (const record of records) {
      await db.runAsync(
        'INSERT INTO consents (id, record_json, updated_at) VALUES (?, ?, ?);',
        record.id,
        JSON.stringify(record),
        now,
      );
      await enqueueObject(db, `consent:${record.id}`, now);
    }
  });
}

/**
 * Patch one stored record after a successful revoke. Read-modify-write in one
 * transaction: a revoke that reached the server must be reflected locally even
 * if the app dies before the next fetch.
 */
export async function revokeConsentRecord(id: string, revokedAt: string): Promise<void> {
  await withDbTransaction(async (db) => {
    const row = await db.getFirstAsync<ConsentRow>(
      'SELECT record_json FROM consents WHERE id = ?;',
      id,
    );
    if (row === null) return;
    const record = JSON.parse(row.record_json) as ConsentApiRecord;
    const updated: ConsentApiRecord = { ...record, status: 'revoked', revokedAt };
    const now = Date.now();
    await db.runAsync(
      'UPDATE consents SET record_json = ?, updated_at = ? WHERE id = ?;',
      JSON.stringify(updated),
      now,
      id,
    );
    await enqueueObject(db, `consent:${id}`, now);
  });
}

export async function clearConsentRecords(): Promise<void> {
  const db = await getDb();
  await db.runAsync('DELETE FROM consents;');
}
