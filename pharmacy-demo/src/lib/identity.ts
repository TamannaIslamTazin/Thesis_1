/**
 * This pharmacy's own identity: the key it will sign dispensing records with.
 *
 * ===========================================================================
 * WHY THE PHARMACY GENERATES ITS OWN KEY
 * ===========================================================================
 * An institutional DID always carries one agent-held slot (#key-officer-1) — the
 * SDK guard demands the ledger-signing key be one the issuing agent can sign
 * with. If that were the only slot, the ministry's backend would hold this
 * pharmacy's whole identity, which is custody under another name.
 *
 * So the pharmacy generates a keypair HERE, sends only the PUBLIC half when it
 * claims the enrolment code, and keeps the private half. The minted document then
 * carries it as #key-officer-2 (see institutionMinting.ts), and the pharmacy is a
 * 2-of-N it genuinely controls.
 *
 * ===========================================================================
 * THE PRIVATE KEY IS ENCRYPTED, AND WITH NODE'S OWN PRIMITIVES
 * ===========================================================================
 * A passphrase the admin sets at pairing wraps it: scrypt for the KDF,
 * AES-256-GCM for the cipher. NOT a bespoke scheme — this key will sign
 * dispensing records, and a hand-rolled construction next to key material is the
 * class of thing this project refuses to write by hand.
 *
 * The passphrase is never stored. A lost passphrase means a re-pair, which is the
 * honest consequence and matches the DID's own repairability rules (#286: the
 * verification-method set can be grown while a surviving key lives).
 *
 * ===========================================================================
 * WHAT IS NOT WIRED
 * ===========================================================================
 * Fingerprint. The owner's instruction is explicit: hospitals may have their own
 * readers, unlike the Android class-3 problem, so leave the door open — but do
 * not present it as working. Nothing here touches biometrics.
 */
import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  scryptSync,
  sign as ed25519Sign,
} from 'node:crypto';
import { base58 } from '@scure/base';

import { getDb } from './db';
import { ENROLMENT_URI_PREFIX, parseEnrolmentUri } from './enrolmentUri';

// Re-exported for existing server-side importers. The DEFINITION lives in
// enrolmentUri.ts because a client component needs it too, and a module that
// pulls `node:sqlite` into the browser breaks React entirely.
export { ENROLMENT_URI_PREFIX, parseEnrolmentUri };

const SCRYPT_KEYLEN = 32;
const GCM_IV_BYTES = 12;

export interface PharmacyIdentity {
  readonly publicKeyMultibase: string;
  readonly did: string | null;
}

interface StoredIdentity {
  public_key_multibase: string;
  private_key_ciphertext: string;
  kdf_salt: string;
  did: string | null;
}

/**
 * Ed25519 public key -> multibase. `z` is base58btc and `0xed01` is the Ed25519
 * multicodec, which is the same encoding the issuer's own helper produces — so
 * the two sides cannot disagree about what a key looks like on the wire.
 */
function ed25519MultibaseFromRaw(publicKeyRaw: Uint8Array): string {
  const multicodec = new Uint8Array([0xed, 0x01, ...publicKeyRaw]);
  return `z${base58.encode(multicodec)}`;
}

function deriveKey(passphrase: string, salt: Uint8Array): Buffer {
  return scryptSync(passphrase, salt, SCRYPT_KEYLEN);
}

function encryptPrivateKey(privateKeyPkcs8: Buffer, passphrase: string) {
  const salt = randomBytes(16);
  const iv = randomBytes(GCM_IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', deriveKey(passphrase, salt), iv);
  const ciphertext = Buffer.concat([cipher.update(privateKeyPkcs8), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    // iv || tag || ciphertext, so the blob is self-contained. Splitting them
    // across columns would invite a reader to reassemble them in the wrong order.
    packed: Buffer.concat([iv, tag, ciphertext]).toString('base64'),
    salt: Buffer.from(salt).toString('base64'),
  };
}

/**
 * Generate this pharmacy's identity and store it under a passphrase.
 *
 * REFUSES IF ONE ALREADY EXISTS. A second identity would mean two keys claiming
 * the same premises, and the DID's controller set cannot be repaired afterwards —
 * so re-pairing is a deliberate act (remove the row and pair again), not
 * something a stray scan performs.
 */
export function createIdentity(passphrase: string): PharmacyIdentity {
  if (passphrase.trim().length < 8) {
    throw new Error('Choose a passphrase of at least 8 characters. It protects the key that signs your dispensing records.');
  }

  const db = getDb();
  const existing = db.prepare('SELECT public_key_multibase, did FROM pharmacy_identity WHERE id = 1').get() as
    | { public_key_multibase: string; did: string | null }
    | undefined;
  if (existing) {
    return { publicKeyMultibase: existing.public_key_multibase, did: existing.did };
  }

  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPublic = publicKey.export({ format: 'jwk' }).x;
  if (typeof rawPublic !== 'string') {
    throw new Error('Ed25519 public key did not export as JWK x.');
  }
  const publicKeyMultibase = ed25519MultibaseFromRaw(Buffer.from(rawPublic, 'base64url'));

  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  const sealed = encryptPrivateKey(pkcs8 as Buffer, passphrase);

  db.prepare(
    `INSERT INTO pharmacy_identity (id, public_key_multibase, private_key_ciphertext, kdf_salt, created_at, did)
     VALUES (1, ?, ?, ?, ?, NULL)`,
  ).run(publicKeyMultibase, sealed.packed, sealed.salt, new Date().toISOString());

  console.log('[pharmacy] generated its own identity key (private half sealed under the admin passphrase)');
  return { publicKeyMultibase, did: null };
}

export function getIdentity(): PharmacyIdentity | null {
  const row = getDb()
    .prepare('SELECT public_key_multibase, did FROM pharmacy_identity WHERE id = 1')
    .get() as { public_key_multibase: string; did: string | null } | undefined;
  return row ? { publicKeyMultibase: row.public_key_multibase, did: row.did } : null;
}

/**
 * Recover the private key for signing.
 *
 * A WRONG PASSPHRASE FAILS THE GCM TAG, not a string comparison — so there is no
 * oracle and no stored verifier to leak. The error is deliberately the same for
 * "wrong passphrase" and "corrupt blob": the two are indistinguishable to an
 * attacker and the operator's next action is identical either way.
 */
export function unlockPrivateKey(passphrase: string): Buffer {
  const row = getDb()
    .prepare('SELECT private_key_ciphertext, kdf_salt FROM pharmacy_identity WHERE id = 1')
    .get() as StoredIdentity | undefined;
  if (!row) throw new Error('This pharmacy has no identity yet — pair with an officer first.');

  const packed = Buffer.from(row.private_key_ciphertext, 'base64');
  const iv = packed.subarray(0, GCM_IV_BYTES);
  const tag = packed.subarray(GCM_IV_BYTES, GCM_IV_BYTES + 16);
  const ciphertext = packed.subarray(GCM_IV_BYTES + 16);

  const decipher = createDecipheriv('aes-256-gcm', deriveKey(passphrase, Buffer.from(row.kdf_salt, 'base64')), iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('That passphrase did not unlock this pharmacy’s key.');
  }
}

/** Record the DID once the officer has confirmed and the institution exists. */
export function recordDid(did: string): void {
  getDb().prepare('UPDATE pharmacy_identity SET did = ? WHERE id = 1').run(did);
}

// ===========================================================================
// Signing dispensing records
// ===========================================================================
//
// The counter signs unattended — nobody types a passphrase per customer — so the
// unlocked key is held IN MEMORY for the life of this process, and only in
// memory. It is never written unsealed, and a restart requires the passphrase
// again, which is the correct default: a key that survives a reboot in plaintext
// is a key that leaks with the machine.
//
// THIS IS THE DEMO'S CUSTODY, AND IT HAS A KNOWN CEILING (#277). A real counter
// would hold this in an HSM or a hardware token so the key is never in process
// memory at all. That is deferred, not overlooked.
/**
 * The unlocked key lives on globalThis, NOT in a module-level variable.
 *
 * WHY (measured 28 Sep 2026). Next.js dev does not reliably share module state
 * across route handlers or across hot reloads. The admin route that UNLOCKS and
 * the dispense route that SIGNS ended up holding DIFFERENT instances of this
 * module, so unlocking reported success and dispensing still reported the key
 * locked. That contradiction was measured directly: GET /api/admin/pair said
 * unlocked:true while POST /api/dispense answered "signing key is locked" on the
 * same running server.
 *
 * globalThis is the place for server state that must outlive a reload and be seen
 * by every route. A production counter holds this in an HSM so the key is never
 * in process memory at all (#277); this is the demo's custody and its ceiling is
 * known.
 */
const KEY_HOLDER = Symbol.for('pharmacy.signingKeyHolder');
type SigningKeyHolder = { key: ReturnType<typeof createPrivateKey> | null };
const keyHolder: SigningKeyHolder = ((globalThis as Record<symbol, unknown>)[KEY_HOLDER] as SigningKeyHolder | undefined)
  ?? (((globalThis as Record<symbol, unknown>)[KEY_HOLDER] = { key: null }) as SigningKeyHolder);

export function isUnlocked(): boolean {
  return keyHolder.key !== null;
}

/** Unlock and remember, so the counter can sign without asking again. */
export function unlockForSigning(passphrase: string): void {
  const pkcs8 = unlockPrivateKey(passphrase);
  keyHolder.key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

/**
 * Sign a dispense append.
 *
 * THE SIGNED BYTES ARE A JSON ARRAY, NOT AN OBJECT — see the backend's
 * `dispenseAppend.ts`, which is the other half of this protocol. `JSON.stringify`
 * of an object depends on key order, so two implementations that agree on the
 * fields can still disagree on the bytes. Field order is protocol:
 *
 *   [prescriptionId, quantity, dispenseId, dispensedAt, pharmacyDid]
 */
/**
 * Sign a SETTLEMENT, the same way the dispense append is signed.
 *
 * The settle endpoint first required a wallet session, which the pharmacy does
 * not have, so every settlement was refused with "Wallet setup required"
 * (measured 28 Sep). An institution is authenticated by its signature against a
 * chain-resolved DID, so settlement is signed exactly like the dispense.
 *
 * Order is protocol; it must match `canonicalSettleMessage` in the backend.
 */
export function signSettle(payload: {
  dispenseId: string;
  outcome: 'paid' | 'not-paid';
  settledAt: string;
  pharmacyDid: string;
}): string {
  if (!keyHolder.key) {
    throw new Error(
      'This pharmacy\'s signing key is locked. Unlock it with your passphrase before settling.',
    );
  }
  const message = Buffer.from(
    JSON.stringify([
      payload.dispenseId,
      payload.outcome,
      payload.settledAt,
      payload.pharmacyDid,
    ]),
    'utf8',
  );
  return ed25519Sign(null, message, keyHolder.key).toString('base64url');
}

export function signAppend(payload: {
  prescriptionId: string;
  quantity: number;
  dispenseId: string;
  dispensedAt: string;
  pharmacyDid: string;
  holderDid: string;
}): string {
  if (!keyHolder.key) {
    throw new Error(
      'This pharmacy\'s signing key is locked. Unlock it with your passphrase before dispensing.',
    );
  }
  const message = Buffer.from(
    JSON.stringify([
      payload.prescriptionId,
      payload.quantity,
      payload.dispenseId,
      payload.dispensedAt,
      payload.pharmacyDid,
      payload.holderDid,
    ]),
    'utf8',
  );
  return ed25519Sign(null, message, keyHolder.key).toString('base64url');
}
