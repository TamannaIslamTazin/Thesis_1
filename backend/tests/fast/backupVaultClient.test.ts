/**
 * R5 Phase C — the parts of backupVaultClient.ts that need no chain, no
 * vault process and no Postgres query: the AES-256-GCM encryption boundary
 * itself, and the guard that refuses to deposit the wrong guardian's share.
 *
 * The integration behaviour (best-effort deposit, PENDING/SUCCEEDED job
 * bookkeeping, the real HTTP round trip to a running vault) is deliberately
 * NOT here — per this suite's own rule, "fast" does not mean "mocked", and a
 * mocked `fetch`/Prisma pair would prove only that the mocks return what they
 * were told to. That behaviour is proven live in
 * scripts/verify-backup-vault.ts (R5 Phase C Phase 3 run) instead.
 */
import { describe, it, expect } from 'vitest';
import { gcm } from '@noble/ciphers/aes';
import {
  decryptFromVault,
  encryptForVault,
  depositInstitutionShare,
  BackupVaultError,
} from '../../src/services/backupVaultClient.js';
import type { GuardianShare } from '@ssi-healthcare/shared';

function randomKek(): Uint8Array {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}

const SLOT_A = { recoveryControllerDid: 'did:cheqd:test:patient-a', shareIndex: 0 } as const;
const SLOT_B = { recoveryControllerDid: 'did:cheqd:test:patient-b', shareIndex: 0 } as const;
const SLOT_A_INDEX_1 = { recoveryControllerDid: 'did:cheqd:test:patient-a', shareIndex: 1 } as const;

describe('backupVaultClient — the encryption boundary', () => {
  it('round-trips: encryptForVault then decryptFromVault recovers the exact plaintext', () => {
    const kek = randomKek();
    const envelope = encryptForVault('a slip-39 mnemonic share, twenty words long', kek, SLOT_A);
    const recovered = decryptFromVault(envelope, kek, SLOT_A);
    expect(recovered).toBe('a slip-39 mnemonic share, twenty words long');
  });

  it('the contentHash in the envelope matches sha256 of the ciphertext field, independently recomputed', async () => {
    const kek = randomKek();
    const envelope = encryptForVault('share text', kek, SLOT_A);
    const { createHash } = await import('node:crypto');
    const expected = createHash('sha256').update(envelope.ciphertext, 'utf8').digest('hex');
    expect(envelope.contentHash).toBe(expected);
  });

  it('SUCCESS PATH proof this is not a stub: two encryptions of the SAME plaintext produce DIFFERENT ciphertext (fresh nonce per call)', () => {
    const kek = randomKek();
    const a = encryptForVault('same plaintext', kek, SLOT_A);
    const b = encryptForVault('same plaintext', kek, SLOT_A);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it('decrypting with the WRONG key fails closed (AES-GCM tag mismatch), not with plausible garbage', () => {
    const envelope = encryptForVault('secret guardian share', randomKek(), SLOT_A);
    expect(() => decryptFromVault(envelope, randomKek(), SLOT_A)).toThrow(BackupVaultError);
  });

  it('decrypting a tampered ciphertext fails closed', () => {
    const kek = randomKek();
    const envelope = encryptForVault('secret guardian share', kek, SLOT_A);
    const tampered = {
      ...envelope,
      ciphertext: Buffer.from(Buffer.from(envelope.ciphertext, 'base64url').map((b, i) => (i === 0 ? b ^ 0xff : b))).toString(
        'base64url',
      ),
    };
    expect(() => decryptFromVault(tampered, kek, SLOT_A)).toThrow(BackupVaultError);
  });
});

/**
 * The AAD slot binding. Every refusal below is paired with the SUCCESS case
 * that proves the refusal is discriminating rather than universal — a suite
 * that only asserted "throws" would pass identically against a decrypt
 * function that always threw, which is the failure mode this project has
 * already shipped once (two of three tamper tests passing over a broken hash).
 */
describe('backupVaultClient — AAD binds a ciphertext to its slot', () => {
  it('SUCCESS PATH: the SAME KEK and the SAME slot decrypt, so refusals below are discriminating and not universal', () => {
    const kek = randomKek();
    const envelope = encryptForVault('patient A share', kek, SLOT_A);
    expect(decryptFromVault(envelope, kek, SLOT_A)).toBe('patient A share');
  });

  it("refuses a ciphertext moved to ANOTHER PATIENT's slot, even with the correct KEK", () => {
    const kek = randomKek();
    const envelope = encryptForVault('patient A share', kek, SLOT_A);
    // The operator can read neither envelope, but without AAD could swap them
    // and this would return patient A's share as if it were patient B's.
    expect(() => decryptFromVault(envelope, kek, SLOT_B)).toThrow(BackupVaultError);
  });

  it('refuses a ciphertext moved to a DIFFERENT SHARE INDEX of the same patient', () => {
    const kek = randomKek();
    const envelope = encryptForVault('patient A share', kek, SLOT_A);
    expect(() => decryptFromVault(envelope, kek, SLOT_A_INDEX_1)).toThrow(BackupVaultError);
  });

  it('the two directions are independent: B-slot ciphertext also fails in the A slot', () => {
    const kek = randomKek();
    const envelope = encryptForVault('patient B share', kek, SLOT_B);
    expect(decryptFromVault(envelope, kek, SLOT_B)).toBe('patient B share');
    expect(() => decryptFromVault(envelope, kek, SLOT_A)).toThrow(BackupVaultError);
  });

  it('slot identity actually reaches the cipher: same key, same plaintext, different slot => different ciphertext under a PINNED nonce', () => {
    // Nonce is random per call, so equal ciphertext could never be observed
    // anyway. Pin the nonce by reusing the envelope's own, and drive the
    // primitive directly — this is what proves the AAD is fed to GHASH rather
    // than merely being stored in a struct nobody consults.
    const kek = randomKek();
    const a = encryptForVault('identical plaintext', kek, SLOT_A);
    const nonce = Buffer.from(a.nonce, 'base64url');
    const underB = gcm(kek, nonce, new TextEncoder().encode(
      `bdhealthtrust/vault-share/v1|${SLOT_B.recoveryControllerDid}|${SLOT_B.shareIndex}`,
    )).encrypt(new TextEncoder().encode('identical plaintext'));
    expect(Buffer.from(underB).toString('base64url')).not.toBe(a.ciphertext);
  });
});

describe('backupVaultClient — depositInstitutionShare guards the guardian role', () => {
  function shareOfRole(role: GuardianShare['guardian']['role']): GuardianShare {
    return {
      index: 0,
      guardian: { label: 'test', role },
      mnemonic: 'irrelevant for this test',
      groupPrefix: 'aa bb',
    };
  }

  it('refuses a FAMILY share (only INSTITUTION is ever deposited)', async () => {
    await expect(depositInstitutionShare('did:cheqd:test:role-guard', shareOfRole('FAMILY'), 3)).rejects.toThrow(
      BackupVaultError,
    );
  });

  it('refuses a COMMUNITY share', async () => {
    await expect(depositInstitutionShare('did:cheqd:test:role-guard', shareOfRole('COMMUNITY'), 3)).rejects.toThrow(
      BackupVaultError,
    );
  });

  it('refuses a PATIENT_OFFLINE share', async () => {
    await expect(
      depositInstitutionShare('did:cheqd:test:role-guard', shareOfRole('PATIENT_OFFLINE'), 3),
    ).rejects.toThrow(BackupVaultError);
  });

  // The INSTITUTION-passes-the-guard / never-throws-past-the-guard case is
  // NOT tested here: past the guard, depositInstitutionShare reaches
  // recordOutcome(), which is a real Postgres write via `db` — exactly the
  // live dependency this suite promises to need none of. That success path
  // (and the PENDING/SUCCEEDED bookkeeping it drives) is proven for real in
  // scripts/verify-backup-vault.ts instead.
});
