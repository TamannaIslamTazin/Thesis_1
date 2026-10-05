/**
 * Credential envelopes, on device.
 *
 * The row holds the envelope EXACTLY as the server sent it and nothing
 * derived. Derivation is `credentialTransform.ts`'s job: it is pure, it is
 * unit-testable without React Native, and re-running it at read time means a
 * mapping fix applies to data already on disk instead of requiring a
 * migration.
 *
 * Replace semantics mirror the store's current whole-array cache (#440) for
 * now: a successful network fetch is authoritative for the rows it returns.
 * The per-row dirty journal and tombstones arrive with the sync engine
 * (#453), and the revoked-credential display gap (#81) is a separate fix.
 */
import type { WalletCredential } from '@ssi-healthcare/sdk';
import { getDb, withDbTransaction } from '../open';
import { enqueueObject } from '../sync/outbox';

interface CredentialRow {
  readonly envelope_json: string;
}

export async function listCredentialEnvelopes(): Promise<WalletCredential[]> {
  const db = await getDb();
  const rows = await db.getAllAsync<CredentialRow>(
    'SELECT envelope_json FROM credentials ORDER BY updated_at DESC;',
  );
  // A malformed row throws here on purpose: one corrupt row is evidence of a
  // real problem, and there is no repair tool that could make up for skipping
  // it silently.
  return rows.map((row) => JSON.parse(row.envelope_json) as WalletCredential);
}

export async function replaceCredentialEnvelopes(
  envelopes: readonly WalletCredential[],
): Promise<void> {
  const now = Date.now();
  await withDbTransaction(async (db) => {
    await db.runAsync('DELETE FROM credentials;');
    for (const envelope of envelopes) {
      await db.runAsync(
        'INSERT INTO credentials (id, envelope_json, updated_at) VALUES (?, ?, ?);',
        envelope.id,
        JSON.stringify(envelope),
        now,
      );
      await enqueueObject(db, `credential:${envelope.id}`, now);
    }
  });
}

export async function clearCredentialEnvelopes(): Promise<void> {
  const db = await getDb();
  await db.runAsync('DELETE FROM credentials;');
}
