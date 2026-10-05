/**
 * R5 PHASE C — backend-side client for the guardian-share backup vault
 * (packages/backup-vault). Deposits ONLY the INSTITUTION guardian's SLIP-39
 * share as a durability copy — never any other guardian's share, and never
 * the RCK seed itself (private keys are not backed up as key material, per
 * the owner's R5 ruling; only guardian shares are).
 *
 * ===========================================================================
 * THE ENCRYPTION BOUNDARY IS HERE, NOT IN THE VAULT
 * ===========================================================================
 * The vault must never receive plaintext or hold a key that can decrypt what
 * it stores (R5 Phase C brief, property 1). So this module — not the vault —
 * holds `BACKUP_VAULT_KEK` and does the AES-256-GCM wrap before anything
 * crosses the network. The vault's own source code has no decrypt routine at
 * all; that is what makes "the operator can't decrypt" a structural fact
 * rather than a policy this deployment could accidentally flip on.
 *
 * ===========================================================================
 * WHY A FAILED DEPOSIT DOES NOT THROW (owner amendment 2)
 * ===========================================================================
 * The guardian share physically exists with the guardian regardless of
 * whether this durability copy landed, so a vault outage must not fail
 * enrolment. But silently doing nothing is a fail-open with a delay fuse: it
 * would surface only during a recovery attempt, the worst possible moment to
 * discover it. So every outcome — success or failure — is written to
 * `InstitutionShareBackupJob` in this backend's own Postgres. "How many
 * patients are missing their institutional share copy?" is then a query
 * (`SELECT COUNT(*) WHERE status = 'PENDING'`), not an unknown.
 */

import { gcm } from '@noble/ciphers/aes';
import { createHash, randomBytes } from 'node:crypto';

import type { GuardianShare } from '@ssi-healthcare/shared';

import { config } from '../config/index.js';
import { db } from '../db/index.js';
import { logger } from '../utils/logger.js';

export class BackupVaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BackupVaultError';
  }
}

const NONCE_BYTES = 12;

interface VaultEnvelope {
  readonly nonce: string;
  readonly ciphertext: string;
  readonly contentHash: string;
}

/**
 * ===========================================================================
 * SLOT BINDING — WHY AES-GCM HERE TAKES AAD (locker Phase 1 finding)
 * ===========================================================================
 * The original Phase C envelope called `gcm(kek, nonce).encrypt(plaintext)`
 * with no additional authenticated data. That makes each ciphertext
 * self-contained and therefore INTERCHANGEABLE: an operator who cannot read
 * two envelopes can still SWAP them between slots — patient A's share into
 * patient B's row, or index 0's into index 1's — and the backend would
 * decrypt the wrong one SUCCESSFULLY, with a valid tag and no error. Blind
 * to the content is not the same as unable to rearrange it.
 *
 * Binding the slot identity as AAD closes that: a ciphertext moved to any
 * other slot fails on the GHASH tag exactly as a tampered one does.
 *
 * WHY THE SLOT, AND NOT THE contentHash. The obvious instinct is to bind the
 * contentHash too, but that is circular — `contentHash` is the SHA-256 of the
 * CIPHERTEXT, which does not exist until encryption has already happened.
 * Binding a hash of the PLAINTEXT instead would be worse: AAD is authenticated
 * but not secret, so a stored plaintext digest is a confirmation oracle
 * against a guessable secret. Slot identity is the right binding because it is
 * the thing an attacker would rearrange, and because both sides can
 * reconstruct it from context without it ever being transmitted.
 *
 * NO MIGRATION IS NEEDED. Verified against the live vault at
 * packages/backup-vault/data/vault.sqlite on 26 Aug 2026: `shares` held ZERO
 * rows (only 3 erasure_receipts, residue of the Phase 3 store->fetch->erase
 * proving run). No envelope has ever been deposited that this change would
 * render undecryptable, so there is no v0 format to negotiate and the domain
 * string below can be a plain compile-time constant.
 */
const VAULT_AAD_DOMAIN = 'bdhealthtrust/vault-share/v1';

/**
 * Which slot an envelope belongs to. REQUIRED, not optional, at both the
 * encrypt and decrypt boundary — an optional slot would let a caller silently
 * fall back to the unbound behaviour this exists to remove, which is the
 * "discouraged rather than unconstructable" shape.
 */
export interface VaultSlot {
  readonly recoveryControllerDid: string;
  readonly shareIndex: number;
}

function slotAad(slot: VaultSlot): Uint8Array {
  return new TextEncoder().encode(
    `${VAULT_AAD_DOMAIN}|${slot.recoveryControllerDid}|${slot.shareIndex}`,
  );
}

/** Exported for direct testing of the encryption boundary without a live vault. */
export function encryptForVault(
  plaintext: string,
  kek: Uint8Array,
  slot: VaultSlot,
): VaultEnvelope {
  const nonce = randomBytes(NONCE_BYTES);
  const ciphertextBytes = gcm(kek, nonce, slotAad(slot)).encrypt(
    new TextEncoder().encode(plaintext),
  );
  const ciphertext = Buffer.from(ciphertextBytes).toString('base64url');
  return {
    nonce: nonce.toString('base64url'),
    ciphertext,
    // Same hash the vault recomputes and checks on write (owner amendment 4)
    // — computed over the wire representation, not the plaintext.
    contentHash: createHash('sha256').update(ciphertext, 'utf8').digest('hex'),
  };
}

/**
 * The inverse of {@link encryptForVault}. Exported for the recovery path to
 * use once it is wired up (not yet — see the R5 Phase C report; deposit-only
 * is the approved Phase 2 scope). AES-GCM authenticates, so a wrong KEK, a
 * tampered envelope, or an envelope lifted from a DIFFERENT SLOT all fail on
 * the tag rather than returning plausible garbage.
 */
export function decryptFromVault(
  envelope: VaultEnvelope,
  kek: Uint8Array,
  slot: VaultSlot,
): string {
  const nonce = Buffer.from(envelope.nonce, 'base64url');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64url');
  try {
    const plaintextBytes = gcm(kek, nonce, slotAad(slot)).decrypt(ciphertext);
    return new TextDecoder().decode(plaintextBytes);
  } catch (error) {
    throw new BackupVaultError(
      `vault envelope did not authenticate against this KEK and slot ` +
        `(${slot.recoveryControllerDid} index ${slot.shareIndex}): ${
          error instanceof Error ? error.message : String(error)
        }`,
    );
  }
}

function isConfigured(): boolean {
  return Boolean(config.backupVaultUrl && config.backupVaultSharedSecret && config.backupVaultKekBase64);
}

function getKek(): Uint8Array {
  if (!config.backupVaultKekBase64) {
    throw new BackupVaultError('BACKUP_VAULT_KEK is not configured');
  }
  return Buffer.from(config.backupVaultKekBase64, 'base64url');
}

async function vaultFetch(path: string, init: RequestInit): Promise<Response> {
  return fetch(`${config.backupVaultUrl}${path}`, {
    ...init,
    headers: { ...(init.headers ?? {}), Authorization: `Bearer ${config.backupVaultSharedSecret}` },
  });
}

async function registerPolicyOnVault(recoveryControllerDid: string, threshold: number): Promise<void> {
  const res = await vaultFetch(`/v1/patients/${encodeURIComponent(recoveryControllerDid)}/policy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ threshold }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new BackupVaultError(`vault policy registration failed: ${res.status} ${body}`);
  }
}

async function recordOutcome(
  recoveryControllerDid: string,
  status: 'PENDING' | 'SUCCEEDED',
  lastError: string | null,
): Promise<void> {
  await db.institutionShareBackupJob.upsert({
    where: { recoveryControllerDid },
    create: {
      recoveryControllerDid,
      status,
      attempts: 1,
      lastError,
      lastAttemptAt: new Date(),
      succeededAt: status === 'SUCCEEDED' ? new Date() : null,
    },
    update: {
      status,
      attempts: { increment: 1 },
      lastError,
      lastAttemptAt: new Date(),
      ...(status === 'SUCCEEDED' ? { succeededAt: new Date() } : {}),
    },
  });
}

/**
 * Deposit the INSTITUTION guardian's share as a durability copy. BEST
 * EFFORT and NEVER THROWS — see the module docblock. Every outcome is
 * recorded in `InstitutionShareBackupJob`, including "not configured", so a
 * deployment that never set up the vault is still countable rather than
 * silently degraded.
 */
export async function depositInstitutionShare(
  recoveryControllerDid: string,
  share: GuardianShare,
  threshold: number,
): Promise<void> {
  if (share.guardian.role !== 'INSTITUTION') {
    // A caller passing the wrong guardian's share is a programming error,
    // not an operational one — refuse loudly rather than silently depositing
    // a share that was never meant to leave the guardian who holds it.
    throw new BackupVaultError(
      `depositInstitutionShare called with a ${share.guardian.role} share, not INSTITUTION`,
    );
  }

  try {
    if (!isConfigured()) {
      throw new BackupVaultError(
        'backup vault is not configured (BACKUP_VAULT_URL / BACKUP_VAULT_SHARED_SECRET / ' +
          'BACKUP_VAULT_KEK unset) — the institutional share exists only with the institution',
      );
    }

    await registerPolicyOnVault(recoveryControllerDid, threshold);
    const envelope = encryptForVault(share.mnemonic, getKek(), {
      recoveryControllerDid,
      shareIndex: share.index,
    });
    const res = await vaultFetch(
      `/v1/patients/${encodeURIComponent(recoveryControllerDid)}/shares/${share.index}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      },
    );
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new BackupVaultError(`vault deposit failed: ${res.status} ${body}`);
    }

    await recordOutcome(recoveryControllerDid, 'SUCCEEDED', null);
    logger.info('institution_share_backed_up', { recoveryControllerDid });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn('institution_share_backup_failed', { recoveryControllerDid, error: message });
    // Never rethrown: the ceremony must complete regardless (owner amendment
    // 2). This row is what keeps the gap countable instead of silent.
    await recordOutcome(recoveryControllerDid, 'PENDING', message).catch((dbError) => {
      logger.error('institution_share_backup_job_write_failed', {
        recoveryControllerDid,
        error: dbError instanceof Error ? dbError.message : String(dbError),
      });
    });
  }
}

/**
 * Retrieve and decrypt a previously deposited share. NOT wired into the
 * recovery flow in this phase (deposit-only was the approved scope) — kept
 * here because a client with only a write path is an odd shape, and any
 * future recovery integration needs exactly this call. Throws rather than
 * degrading: unlike deposit, a caller asking to READ a share back needs to
 * know unambiguously whether it succeeded.
 */
export async function fetchInstitutionShare(
  recoveryControllerDid: string,
  index: number,
): Promise<string> {
  if (!isConfigured()) {
    throw new BackupVaultError('backup vault is not configured');
  }
  const res = await vaultFetch(
    `/v1/patients/${encodeURIComponent(recoveryControllerDid)}/shares/${index}`,
    { method: 'GET' },
  );
  if (res.status === 404) {
    throw new BackupVaultError(`no backed-up share at index ${index} for '${recoveryControllerDid}'`);
  }
  if (!res.ok) {
    throw new BackupVaultError(`vault fetch failed: ${res.status} ${await res.text().catch(() => '')}`);
  }
  const envelope = (await res.json()) as VaultEnvelope;
  return decryptFromVault(envelope, getKek(), { recoveryControllerDid, shareIndex: index });
}

/**
 * Erase a deposited share. Also throws rather than degrading, for the same
 * reason as {@link fetchInstitutionShare} — erasure must be provable, and a
 * caller that cannot tell success from failure cannot prove anything.
 */
export async function eraseInstitutionShare(
  recoveryControllerDid: string,
  index: number,
  deletedByActorRef: string,
  reason: string,
): Promise<{ readonly id: string; readonly deletedAt: string }> {
  if (!isConfigured()) {
    throw new BackupVaultError('backup vault is not configured');
  }
  const res = await vaultFetch(
    `/v1/patients/${encodeURIComponent(recoveryControllerDid)}/shares/${index}`,
    {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deletedByActorRef, reason }),
    },
  );
  if (!res.ok) {
    throw new BackupVaultError(`vault erase failed: ${res.status} ${await res.text().catch(() => '')}`);
  }
  return (await res.json()) as { id: string; deletedAt: string };
}
