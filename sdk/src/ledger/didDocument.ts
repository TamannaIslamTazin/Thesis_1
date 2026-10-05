/**
 * did:cheqd document vocabulary, and the chain's own signer-set rules restated
 * as pure functions.
 *
 * MOVED FROM packages/backend/src/services/cheqdDidShapes.ts, verbatim. Only
 * the subset that needs neither Credo nor the backend's AppError came across;
 * the assertions that throw AppError, and `ed25519PublicKeyFromMultibase` with
 * its `MultiBaseEncoder.decode`, stay behind until there is an SDK-native error
 * type and a portable base58 decoder to receive them.
 *
 * ===========================================================================
 * WHY THIS BELONGS ON A HANDSET
 * ===========================================================================
 * These are the rules that decide whether an identity is RECOVERABLE, and every
 * one was established by execution against `bd-health-trust-1` rather than by
 * reading the spec:
 *
 *   S1-DID-CONTROLLER-SEMANTICS.md  — AND over controllers; the VM `controller`
 *                                     field decides who may replace a VM
 *   S4-MULTI-VM-RECOVERY.md         — OR within one controller DID; attribution
 *                                     by id prefix; the X1 bulk-rotation trap
 *
 * A wallet that is about to rotate its own key needs to predict what the chain
 * will demand BEFORE it broadcasts, because the decision is irreversible once it
 * does. Leaving these rules on the server meant the device could only find out
 * by asking, or by guessing. They have no I/O and no ledger, so nothing stopped
 * them being portable except where they lived.
 *
 * ===========================================================================
 * TWO FIELDS NAMED `controller`, FAILING IN OPPOSITE DIRECTIONS
 * ===========================================================================
 * A document's `controller` ARRAY says who may update the document (AND, no
 * threshold). A verification method's `controller` FIELD says who may replace
 * that one method — and by S-4 V2 it does NOT decide whose signature that
 * method's key counts as; the id prefix does. Read every mention below with the
 * qualifier attached.
 */

// ---------------------------------------------------------------------------
// Document model
// ---------------------------------------------------------------------------

export const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1';
export const ED25519_2020_CONTEXT = 'https://w3id.org/security/suites/ed25519-2020/v1';

/**
 * The only verification-method type our chain's `validateSpecCompliantPayload`
 * accepts alongside `publicKeyMultibase`.
 */
export const ED25519_VERIFICATION_KEY_2020 = 'Ed25519VerificationKey2020';

export interface VerificationMethodSlot {
  /** Absolute DID URL, e.g. `did:cheqd:bdhealthtestnet:<uuid>#key-officer-1`. */
  readonly id: string;
  readonly type: typeof ED25519_VERIFICATION_KEY_2020;
  /** Who may REPLACE this slot. Not who may use it. */
  readonly controller: string;
  readonly publicKeyMultibase: string;
}

export interface CheqdDidDocumentShape {
  readonly '@context': readonly string[];
  readonly id: string;
  readonly controller: readonly string[];
  readonly verificationMethod: readonly VerificationMethodSlot[];
  readonly authentication: readonly string[];
  readonly assertionMethod?: readonly string[];
}

/**
 * The multicodec prefix `toMultibaseRaw` puts in front of an Ed25519 public key.
 *
 * VERIFIED, never skipped: a document carrying an X25519 key under an
 * `Ed25519VerificationKey2020` type would otherwise be truncated into 32 bytes
 * of something else, and a later `verify` would return false for a reason that
 * looks like a bad signature rather than a bad key.
 */
export const ED25519_MULTICODEC_PREFIX = Uint8Array.from([0xed, 0x01]);
export const ED25519_RAW_KEY_LENGTH = 32;

/** Matches what the patched `parseCheqdDid` accepts for our namespace. */
const CHEQD_DID_PATTERN = /^did:cheqd:[a-zA-Z0-9]+:[a-zA-Z0-9.:-]+$/;

export function isCheqdDid(value: unknown): value is string {
  return typeof value === 'string' && CHEQD_DID_PATTERN.test(value);
}

/** The DID part of a DID URL — what `FindSignInfosBySigner` compares. */
export function didPartOf(didUrl: string): string {
  const hash = didUrl.indexOf('#');
  return hash === -1 ? didUrl : didUrl.slice(0, hash);
}

/** The `#fragment` of a DID URL. `GetSignerDIDsForDIDUpdate` matches on this, not on the full id. */
export function fragmentOf(didUrl: string): string {
  const hash = didUrl.indexOf('#');
  return hash === -1 ? '' : didUrl.slice(hash);
}

/** Unique, sorted — the normalisation `utils.UniqueSorted` applies on-chain. */
export function uniqueSorted(dids: readonly string[]): string[] {
  return Array.from(new Set(dids)).sort();
}

/**
 * `GetControllersOrSubject` (`diddoc_diddoc.go:65-73`): an absent or empty
 * controller list means "the subject controls itself", NOT "uncontrolled".
 */
export function controllersOrSubject(
  controller: readonly string[] | string | undefined,
  subjectDid: string,
): string[] {
  if (!controller) return [subjectDid];
  const list = Array.isArray(controller) ? controller : [controller];
  return list.length > 0 ? [...list] : [subjectDid];
}

// ---------------------------------------------------------------------------
// The chain's signer-set rules
// ---------------------------------------------------------------------------

/**
 * `GetSignerDIDsForDIDCreation` (`msg_server_create_diddoc.go:76-81`):
 * controllers ∪ ALL verification-method controllers.
 *
 * `msg_server_deactivate_diddoc.go:53-54` uses the SAME set, which is why
 * deactivation of a self-controlled DID needs one of that DID's own keys even
 * when an external controller is present (S-1 D1).
 */
export function signerDidsForCreate(document: {
  id: string;
  controller?: readonly string[];
  verificationMethod?: readonly { controller: string }[];
}): string[] {
  return uniqueSorted([
    ...controllersOrSubject(document.controller, document.id),
    ...(document.verificationMethod ?? []).map((vm) => vm.controller),
  ]);
}

/**
 * Exported because `assertRotationIsSurvivable` and the patient-shape assertions
 * stayed in the backend and still need to name it. It was file-private before
 * the move; widening it is the smallest change that keeps one definition rather
 * than two.
 */
export interface SignerSetInputDocument {
  readonly id: string;
  readonly controller?: readonly string[];
  readonly verificationMethod?: readonly {
    id: string;
    type?: string;
    controller: string;
    publicKeyMultibase: string;
  }[];
}

/**
 * `GetSignerDIDsForDIDUpdate` (`msg_server_update_diddoc.go:127-171`), ported
 * whole rather than special-cased.
 *
 * The union of the old and new controller sets, plus — for every slot ADDED,
 * CHANGED or REMOVED — that slot's `controller` field, taken from both the old
 * and the new document where both exist.
 *
 * NOTE THE MATCHING KEY IS THE FRAGMENT, not the full id
 * (`VerificationMethodListToMapByFragment`). A slot whose id changed DID but
 * kept its fragment reads as "changed", not as "removed and added".
 */
export function signerDidsForUpdate(
  existing: SignerSetInputDocument,
  updated: SignerSetInputDocument,
): string[] {
  const signers: string[] = [
    ...controllersOrSubject(existing.controller, existing.id),
    ...controllersOrSubject(updated.controller, updated.id),
  ];

  const existingByFragment = new Map(
    (existing.verificationMethod ?? []).map((vm) => [fragmentOf(vm.id), vm]),
  );
  const updatedFragments = new Set(
    (updated.verificationMethod ?? []).map((vm) => fragmentOf(vm.id)),
  );

  for (const updatedVm of updated.verificationMethod ?? []) {
    const previous = existingByFragment.get(fragmentOf(updatedVm.id));

    if (!previous) {
      signers.push(updatedVm.controller); // added
      continue;
    }

    if (verificationMethodChanged(previous, updatedVm, existing.id, updated.id)) {
      signers.push(previous.controller, updatedVm.controller); // changed
    }
  }

  for (const existingVm of existing.verificationMethod ?? []) {
    if (!updatedFragments.has(fragmentOf(existingVm.id))) {
      signers.push(existingVm.controller); // removed
    }
  }

  return uniqueSorted(signers);
}

/**
 * The chain rewrites the incoming document's self-references to `<did>-updated`
 * and undoes that rename before comparing (`:149`), so comparison is on the
 * document's own DID rather than on the literal strings. Reproduced here so a
 * slot that only "changed" by that rename is not counted as changed.
 */
/**
 * Exported because `assertRotationIsSurvivable` stayed in the backend and calls
 * it directly. It was file-private before the move; one exported definition
 * beats a second private copy on the other side of the boundary.
 */
export function verificationMethodChanged(
  previous: { id: string; type?: string; controller: string; publicKeyMultibase: string },
  next: { id: string; type?: string; controller: string; publicKeyMultibase: string },
  existingDid: string,
  updatedDid: string,
): boolean {
  const normalise = (value: string): string => value.split(updatedDid).join(existingDid);
  return (
    normalise(next.id) !== previous.id ||
    normalise(next.controller) !== previous.controller ||
    next.publicKeyMultibase !== previous.publicKeyMultibase ||
    (next.type ?? ED25519_VERIFICATION_KEY_2020) !==
      (previous.type ?? ED25519_VERIFICATION_KEY_2020)
  );
}

// ---------------------------------------------------------------------------
// The X1 trap — never rotate every key in one transaction
// ---------------------------------------------------------------------------

export interface VerificationMethodDelta {
  readonly added: readonly string[];
  readonly changed: readonly string[];
  readonly removed: readonly string[];
}

export function verificationMethodDelta(
  existing: SignerSetInputDocument,
  updated: SignerSetInputDocument,
): VerificationMethodDelta {
  const existingByFragment = new Map(
    (existing.verificationMethod ?? []).map((vm) => [fragmentOf(vm.id), vm]),
  );
  const updatedFragments = new Set(
    (updated.verificationMethod ?? []).map((vm) => fragmentOf(vm.id)),
  );

  const added: string[] = [];
  const changed: string[] = [];

  for (const updatedVm of updated.verificationMethod ?? []) {
    const previous = existingByFragment.get(fragmentOf(updatedVm.id));
    if (!previous) added.push(updatedVm.id);
    else if (verificationMethodChanged(previous, updatedVm, existing.id, updated.id))
      changed.push(updatedVm.id);
  }

  const removed = (existing.verificationMethod ?? [])
    .filter((vm) => !updatedFragments.has(fragmentOf(vm.id)))
    .map((vm) => vm.id);

  return { added, changed, removed };
}
