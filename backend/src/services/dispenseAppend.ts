/**
 * A dispense append, signed by the pharmacy that performed it.
 *
 * ===========================================================================
 * WHY THE APPEND IS SIGNED, AND NOT JUST POSTED
 * ===========================================================================
 * The owner's decision on the dispense-ledger review (attack 2): every append is
 * signed by the pharmacy's own DID, and an unlicensed DID must not be able to
 * append at all. Without that, the tally is only as good as whoever holds the
 * endpoint — and the whole point of the register being a VERIFIABLE STORE rather
 * than a trusted service is that a pharmacy can be held to what it recorded.
 *
 * The pharmacy holds `#key-officer-2` — its own key, minted at onboarding (see
 * institutionMinting.ts). This verifies against that key, resolved from the
 * CHAIN, so a compromised backend cannot invent a dispense and a dishonest
 * pharmacy cannot deny one.
 *
 * ===========================================================================
 * THE SIGNED BYTES ARE A JSON ARRAY, NOT AN OBJECT
 * ===========================================================================
 * `JSON.stringify` of an object depends on key insertion order, so two
 * implementations that agree on the fields can still disagree on the bytes.
 * A POSITIONAL ARRAY has one serialisation, so the signer and the verifier cannot
 * drift. The field order is part of the protocol:
 *
 *   [prescriptionId, quantity, dispenseId, dispensedAt, pharmacyDid]
 *
 * ===========================================================================
 * WHAT THIS DOES NOT PROVE
 * ===========================================================================
 * That the quantity dispensed was the quantity handed over. A pharmacy can sign
 * a false figure; the signature makes the figure ATTRIBUTABLE, which is what
 * makes fraud detectable after the fact rather than deniable. That is the same
 * trade the custody design makes everywhere (#276): detection latency is the
 * control, not prevention.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';

export interface AppendPayload {
  readonly prescriptionId: string;
  readonly quantity: number;
  readonly dispenseId: string;
  readonly dispensedAt: string;
  readonly pharmacyDid: string;
  /**
   * WHO the dispense is about.
   *
   * Added 27 Sep 2026 (A1). The append previously named the pharmacy and the
   * prescription but not the person, which left the wallet with no way to find
   * its own dispenses. It is SIGNED, not merely carried, because the wallet uses
   * it to read its own tokens: an unsigned field used for authorisation would let
   * a pharmacy attribute a dispense to someone else.
   *
   * Appended at the END of the array, so the five-field order that came before is
   * unchanged. That is an extension, not a reorder.
   */
  readonly holderDid: string;
}

/** The exact bytes a pharmacy signs. Order is protocol; do not reorder. */
export function canonicalAppendMessage(payload: AppendPayload): string {
  return JSON.stringify([
    payload.prescriptionId,
    payload.quantity,
    payload.dispenseId,
    payload.dispensedAt,
    payload.pharmacyDid,
    payload.holderDid,
  ]);
}

/**
 * Multibase Ed25519 public key -> raw 32 bytes.
 *
 * Returns null for anything that is not a `z`-prefixed, 0xed01-prefixed Ed25519
 * key. Refusing rather than coercing matters: a key of the wrong type or length
 * that happened to decode would let a signature verify against bytes the signer
 * never held.
 */
function rawEd25519FromMultibase(multibase: string): Uint8Array | null {
  if (!multibase.startsWith('z')) return null;
  let decoded: Uint8Array;
  try {
    decoded = base58.decode(multibase.slice(1));
  } catch {
    return null;
  }
  // 0xed01 is the Ed25519 multicodec; 34 = 2 prefix bytes + 32 key bytes.
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) return null;
  return decoded.subarray(2);
}

export interface VerifyAppendInput {
  readonly payload: AppendPayload;
  /** base64url signature over `canonicalAppendMessage(payload)`. */
  readonly signature: string;
  /** Every verification method on the signing DID, straight from the chain. */
  readonly publicKeyMultibase: readonly string[];
}

/**
 * A settlement, signed by the pharmacy that performed it.
 *
 * WHY THIS IS SIGNED AND DOES NOT USE A WALLET SESSION (A1, 28 Sep 2026).
 *
 * The first version of the settle endpoint required `requireWallet`, on the
 * assumption that the caller would be a citizen. It is not: the caller is the
 * PHARMACY, whose account deliberately has no wallet, so the middleware refused
 * with "Wallet setup required" and no settlement could ever land. A pharmacy is
 * an accountable institution, and the way this system authenticates an
 * institution is by its SIGNATURE against a chain-resolved DID — the same rule
 * the dispense append already follows. A session would also be the wrong thing:
 * the append is signed so a pharmacy can be held to what it recorded, and a
 * settlement is exactly such a record.
 *
 * Order is protocol, as with the append.
 */
export interface SettlePayload {
  readonly dispenseId: string;
  readonly outcome: 'paid' | 'not-paid';
  readonly settledAt: string;
  readonly pharmacyDid: string;
}

export function canonicalSettleMessage(payload: SettlePayload): string {
  return JSON.stringify([
    payload.dispenseId,
    payload.outcome,
    payload.settledAt,
    payload.pharmacyDid,
  ]);
}

/** Verify any signature over an already-canonicalised message. */
export function verifySignatureOver(
  message: string,
  signature: string,
  publicKeyMultibase: readonly string[],
): boolean {
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = Buffer.from(signature, 'base64url');
  } catch {
    return false;
  }
  if (signatureBytes.length !== 64) return false;
  const bytes = new TextEncoder().encode(message);
  for (const multibase of publicKeyMultibase) {
    const raw = rawEd25519FromMultibase(multibase);
    if (!raw) continue;
    try {
      if (ed25519.verify(signatureBytes, bytes, raw)) return true;
    } catch {
      continue;
    }
  }
  return false;
}

/**
 * Verify the append against any key on the signing DID.
 *
 * ANY key, because the DID is the institution: whether the counter PC signed with
 * `#key-officer-2` or an officer signed with a sibling slot is not this function's
 * business — the DID is the accountable party, and 1-of-N custody says its keys
 * are interchangeable for attribution (#276).
 */
export function verifyAppendSignature(input: VerifyAppendInput): boolean {
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = Buffer.from(input.signature, 'base64url');
  } catch {
    return false;
  }
  if (signatureBytes.length !== 64) return false;

  const message = new TextEncoder().encode(canonicalAppendMessage(input.payload));

  for (const multibase of input.publicKeyMultibase) {
    const raw = rawEd25519FromMultibase(multibase);
    if (!raw) continue;
    try {
      if (ed25519.verify(signatureBytes, message, raw)) return true;
    } catch {
      // A malformed key is skipped, not fatal: one bad slot must not stop a good
      // sibling from verifying.
      continue;
    }
  }
  return false;
}
