/**
 * SSI Healthcare Backend — reading DID-module traffic out of a committed block.
 *
 * Pure functions over bytes and JSON. No network, no database, no clock, so the
 * classification rules can be exercised in `tests/fast`.
 *
 * ===========================================================================
 * WHY BLOCK BYTES AND NOT AN EVENT SUBSCRIPTION
 * ===========================================================================
 * The x/did module emits no domain event naming the DID that changed, so a
 * `tm.event='Tx'` subscription filtered by attribute cannot tell an eviction on
 * OUR institutional DID from any other DID write. The message itself can, and
 * it carries more: `MsgUpdateDidDoc.signatures[].verificationMethodId` names
 * WHICH OFFICER KEY SIGNED, straight from the chain. Under 1-of-N that is the
 * whole of attribution, and getting it from the chain rather than from our own
 * records is the point — our records are what an inside attacker would edit.
 */

import { decodeTxRaw } from '@cosmjs/proto-signing';
import { fromBase64, toHex } from '@cosmjs/encoding';
import { createHash } from 'node:crypto';
import {
  MsgCreateDidDoc,
  MsgDeactivateDidDoc,
  MsgUpdateDidDoc,
} from '@cheqd/ts-proto/cheqd/did/v2/index.js';

export const MSG_UPDATE_DID_DOC = '/cheqd.did.v2.MsgUpdateDidDoc' as const;
export const MSG_DEACTIVATE_DID_DOC = '/cheqd.did.v2.MsgDeactivateDidDoc' as const;
export const MSG_CREATE_DID_DOC = '/cheqd.did.v2.MsgCreateDidDoc' as const;

/**
 * The two the ALARM is about. Creating a new DID cannot harm an existing one.
 */
export const ALARMING_TYPE_URLS: readonly string[] = [MSG_UPDATE_DID_DOC, MSG_DEACTIVATE_DID_DOC];

/**
 * What is RECORDED, which is a wider set than what is alarmed on.
 *
 * Creation is observed but never alarmed. It has to be observed, because
 * reconciliation asks "did the transaction we recorded as broadcast actually
 * reach the chain" — and a provisioning write is a `MsgCreateDidDoc`. Leaving
 * creates out made every single institution provisioned raise a CRITICAL
 * `BROADCAST_NOT_ON_CHAIN` for a write that had plainly succeeded, which is the
 * fastest possible way to make an alarm channel worthless.
 */
export const OBSERVED_TYPE_URLS: readonly string[] = [
  MSG_CREATE_DID_DOC,
  MSG_UPDATE_DID_DOC,
  MSG_DEACTIVATE_DID_DOC,
];

export interface DecodedDidMessage {
  readonly txHash: string;
  readonly msgIndex: number;
  readonly typeUrl: string;
  readonly subjectDid: string;
  readonly versionId: string | null;
  readonly signerVerificationMethodIds: readonly string[];
  readonly controllers: readonly string[];
  readonly verificationMethods: readonly {
    id: string;
    controller: string;
    publicKeyMultibase: string;
    type: string;
  }[];
  readonly authentication: readonly string[];
  readonly assertionMethod: readonly string[];
}

/**
 * CometBFT's transaction hash: sha256 over the raw tx bytes, uppercase hex.
 *
 * Computed here rather than taken from an indexer response so that the watcher
 * works on a node with the tx indexer switched off. Verified against S-4 H1 —
 * block 86424's single transaction hashes to `67D682DE…9DC0`, the value S-4
 * recorded.
 */
export function cometTxHash(rawTx: Uint8Array): string {
  return toHex(createHash('sha256').update(rawTx).digest()).toUpperCase();
}

/**
 * Decode every DID-module message in one base64 transaction from `/block`.
 *
 * A transaction this decoder cannot parse must not stop the scan of the block:
 * an unparseable transaction is not evidence that nothing happened, and a
 * watcher that dies on the first unfamiliar message is a watcher that an
 * attacker can silence by broadcasting junk. Failures are returned, not thrown.
 */
export function decodeDidMessagesInTx(base64Tx: string): {
  txHash: string;
  messages: DecodedDidMessage[];
  decodeError: string | null;
} {
  const rawTx = fromBase64(base64Tx);
  const txHash = cometTxHash(rawTx);

  try {
    const tx = decodeTxRaw(rawTx);
    const messages: DecodedDidMessage[] = [];

    for (const [msgIndex, message] of tx.body.messages.entries()) {
      if (message.typeUrl === MSG_UPDATE_DID_DOC) {
        const decoded = MsgUpdateDidDoc.decode(message.value);
        messages.push({
          txHash,
          msgIndex,
          typeUrl: message.typeUrl,
          subjectDid: decoded.payload?.id ?? '',
          versionId: decoded.payload?.versionId || null,
          signerVerificationMethodIds: decoded.signatures.map((s) => s.verificationMethodId),
          controllers: decoded.payload?.controller ?? [],
          verificationMethods: (decoded.payload?.verificationMethod ?? []).map((vm) => ({
            id: vm.id,
            controller: vm.controller,
            publicKeyMultibase: vm.verificationMaterial,
            type: vm.verificationMethodType,
          })),
          authentication: decoded.payload?.authentication ?? [],
          assertionMethod: decoded.payload?.assertionMethod ?? [],
        });
      } else if (message.typeUrl === MSG_DEACTIVATE_DID_DOC) {
        const decoded = MsgDeactivateDidDoc.decode(message.value);
        messages.push({
          txHash,
          msgIndex,
          typeUrl: message.typeUrl,
          subjectDid: decoded.payload?.id ?? '',
          versionId: decoded.payload?.versionId || null,
          signerVerificationMethodIds: decoded.signatures.map((s) => s.verificationMethodId),
          controllers: [],
          verificationMethods: [],
          authentication: [],
          assertionMethod: [],
        });
      } else if (message.typeUrl === MSG_CREATE_DID_DOC) {
        // Recorded so that a watched DID's first version can be seeded from the
        // chain itself. Never alarming on its own — creating a DID cannot harm
        // one that already exists.
        const decoded = MsgCreateDidDoc.decode(message.value);
        messages.push({
          txHash,
          msgIndex,
          typeUrl: message.typeUrl,
          subjectDid: decoded.payload?.id ?? '',
          versionId: decoded.payload?.versionId || null,
          signerVerificationMethodIds: decoded.signatures.map((s) => s.verificationMethodId),
          controllers: decoded.payload?.controller ?? [],
          verificationMethods: (decoded.payload?.verificationMethod ?? []).map((vm) => ({
            id: vm.id,
            controller: vm.controller,
            publicKeyMultibase: vm.verificationMaterial,
            type: vm.verificationMethodType,
          })),
          authentication: decoded.payload?.authentication ?? [],
          assertionMethod: decoded.payload?.assertionMethod ?? [],
        });
      }
    }

    return { txHash, messages, decodeError: null };
  } catch (error) {
    return {
      txHash,
      messages: [],
      decodeError: error instanceof Error ? error.message : String(error),
    };
  }
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

export type DidChangeKind =
  | 'deactivation'
  | 'eviction'
  | 'controller-change'
  | 'rotation'
  | 'addition'
  | 'no-key-change';

export interface DidChange {
  readonly kind: DidChangeKind;
  readonly removedVerificationMethodIds: readonly string[];
  readonly addedVerificationMethodIds: readonly string[];
  readonly rotatedVerificationMethodIds: readonly string[];
  readonly controllersBefore: readonly string[];
  readonly controllersAfter: readonly string[];
}

export interface KnownDidState {
  readonly verificationMethodIds: readonly string[];
  /** id → publicKeyMultibase, so a same-id key swap reads as a rotation. */
  readonly verificationMethodDigest: string;
  readonly controllers: readonly string[];
}

/** id→key map, canonicalised, so "same slots, different key" is one comparison. */
export function verificationMethodDigestOf(
  methods: readonly { id: string; publicKeyMultibase: string }[],
): string {
  const canonical = [...methods]
    .map((vm) => `${vm.id}=${vm.publicKeyMultibase}`)
    .sort()
    .join('\n');
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * What this message DID to the document, given what we last saw.
 *
 * ORDER OF PRECEDENCE IS THE POINT. A single `MsgUpdateDidDoc` can remove one
 * slot and add another at once; reporting that as an "addition" because an
 * addition also happened would file an eviction as routine growth. So removals
 * outrank everything, then controller changes, then additions, then rotations.
 *
 * `previous` is the watcher's running picture, advanced strictly in block order
 * and never skipping a height — which is what makes a removal detectable at all
 * without a second chain query. Pass `null` when the DID's prior state was
 * never observed: the message alone cannot prove a removal (we do not know what
 * was there), so it degrades honestly to `no-key-change` rather than guessing.
 */
export function classifyDidChange(
  message: DecodedDidMessage,
  previous: KnownDidState | null,
): DidChange {
  if (message.typeUrl === MSG_DEACTIVATE_DID_DOC) {
    return {
      kind: 'deactivation',
      removedVerificationMethodIds: previous?.verificationMethodIds ?? [],
      addedVerificationMethodIds: [],
      rotatedVerificationMethodIds: [],
      controllersBefore: previous?.controllers ?? [],
      controllersAfter: [],
    };
  }

  const after = message.verificationMethods;
  const afterIds = after.map((vm) => vm.id);

  if (previous === null) {
    return {
      kind: 'no-key-change',
      removedVerificationMethodIds: [],
      addedVerificationMethodIds: [],
      rotatedVerificationMethodIds: [],
      controllersBefore: [],
      controllersAfter: message.controllers,
    };
  }

  const beforeIds = new Set(previous.verificationMethodIds);
  const afterIdSet = new Set(afterIds);
  const removed = previous.verificationMethodIds.filter((id) => !afterIdSet.has(id));
  const added = afterIds.filter((id) => !beforeIds.has(id));

  const controllersChanged =
    [...previous.controllers].sort().join('|') !== [...message.controllers].sort().join('|');

  // Slots present before AND after whose key material moved. Only reportable as
  // a set when nothing was added or removed: the stored state is a DIGEST of
  // the whole id→key map, not the map itself, so with the slot set changing we
  // can say THAT keys changed but not WHICH. Naming the wrong slot in an alarm
  // is worse than naming none.
  const survivingIds = afterIds.filter((id) => beforeIds.has(id));
  const digestChanged = verificationMethodDigestOf(after) !== previous.verificationMethodDigest;
  const rotated =
    removed.length === 0 && added.length === 0 && digestChanged
      ? survivingIds
      : ([] as string[]);

  const kind: DidChangeKind =
    removed.length > 0
      ? 'eviction'
      : controllersChanged
        ? 'controller-change'
        : added.length > 0
          ? 'addition'
          : rotated.length > 0
            ? 'rotation'
            : 'no-key-change';

  return {
    kind,
    removedVerificationMethodIds: removed,
    addedVerificationMethodIds: added,
    rotatedVerificationMethodIds: rotated,
    controllersBefore: previous.controllers,
    controllersAfter: message.controllers,
  };
}
