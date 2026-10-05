/**
 * SSI Healthcare Backend — institutional DID custody: 1-of-N verification methods.
 *
 * ===========================================================================
 * THE RULING THIS IMPLEMENTS, AND WHY THE SHAPE IS NOT A PREFERENCE
 * ===========================================================================
 * Steno #276 (owner): institutional custody is **1-of-N verification methods**.
 * k-of-n and FROST were rejected on threat-model grounds — they are built for
 * "destroy the institution rather than let the key leak", and that is not this
 * system's failure mode. Under S-1 §8.3 a patient's controller set is
 * `[patient RCK, institutional DID]` with AND semantics, so a frozen
 * institutional DID freezes every patient enrolled under it.
 *
 * The mechanism is the only OR in the system: AND across controller DIDs, OR
 * across the keys of ONE controller DID (S-1 §3.1, measured again in S-4 M1).
 *
 * ===========================================================================
 * THE CONDITION 1-of-N DEPENDS ON — ENFORCED HERE, NOT DOCUMENTED HERE
 * ===========================================================================
 * S-4 §6.1 and steno #292: every verification method must declare the
 * institution's OWN DID as its `controller`. A slot naming any other DID needs
 * THAT DID's signature to rotate (`GetSignerDIDsForDIDUpdate:152`), so 1-of-N
 * silently becomes 1-of-(N−1) plus one slot the institution can never recover —
 * discovered only on the day it matters.
 *
 * **There is therefore no `controller` parameter anywhere in this module's API.**
 * Not optional, not defaulted — absent. The value is derived from the DID being
 * created, and `assertInstitutionalShape` re-checks the assembled document
 * immediately before broadcast. A wrong-shaped institutional DID is not
 * discouraged here; it is unconstructable.
 *
 * The mirror hazard is enforced too: by S-4 V2 attribution is by the signing
 * VM's ID PREFIX and never by its `controller` field, so a foreign-held key
 * placed under this DID's namespace has full authority over the institution
 * regardless of what `controller` says. Importing a public key whose private
 * half this agent does not hold therefore requires
 * {@link ACKNOWLEDGE_FOREIGN_HELD_INSTITUTIONAL_KEY} and a named custodian.
 *
 * ===========================================================================
 * EXACTLY ONE `authentication` SLOT, AND THAT IS FORCED BY THE SDK, NOT CHOSEN
 * ===========================================================================
 * `@cheqd/sdk`'s `DIDModule.validateAuthenticationAgainstSignatures`
 * (`modules/did.js`) requires the supplied signatures to EQUAL the union of the
 * `authentication` sets of the document and of every external controller —
 * missing one is rejected, and so is an extra one. When this institution
 * co-signs a patient DID creation it is an external controller of that
 * document, so every key in ITS `authentication` array would have to sign.
 *
 * All N officers in `authentication` would therefore make patient enrolment
 * N-of-N in practice — precisely the availability failure #276 chose 1-of-N to
 * avoid — even though consensus needs only one. S-4 M4/M5 measured that
 * verification-relationship membership is irrelevant to `x/did` authorisation:
 * a bare `verificationMethod` rotates its sibling just fine. So the ledger
 * signing slot is a single named `authentication` entry, every officer sits in
 * `assertionMethod` and can issue credentials, and all N retain full 1-of-N
 * authority over the document. The signing slot is itself rotatable by any
 * officer, so it is not a single point of failure.
 */

import type { Agent } from '@credo-ts/core';
import { DidDocument, DidDocumentRole, DidRecord, JsonTransformer, utils } from '@credo-ts/core';
import { createMsgCreateDidDocPayloadToSign, createMsgUpdateDidDocPayloadToSign } from '@cheqd/sdk/utils';

import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';

import {
  DID_V1_CONTEXT,
  ED25519_2020_CONTEXT,
  ED25519_VERIFICATION_KEY_2020,
  fragmentOf,
  signerDidsForCreate,
  signerDidsForUpdate,
  verificationMethodDelta,
  type CheqdDidDocumentShape,
  type VerificationMethodSlot,
  assertInstitutionalShape,
  assertRotationIsSurvivable,
} from '@ssi-healthcare/sdk/ledger';
import {
  agentSigner,
  assertDelivered,
  assertSignersCoverRequiredSet,
  collectSignatures,
  didRepositoryOf,
  generateEd25519Key,
  kmsSigner,
  ledgerServiceOf,
  newCheqdDid,
  requireLiveDidOnChain,
  type CheqdSigner,
  type GeneratedKey,
  type LedgerWriteResult,
  type ResolvedCheqdDid,
} from './cheqdLedger.js';
import { recordSigningAttempt } from './custody/signingAuditLog.js';
import { registerWatchedInstitutionalDid } from './custody/institutionalWatchList.js';

/**
 * The token that must be named to place a key this agent does not hold under
 * the institution's DID namespace.
 *
 * Deliberately unpleasant to type and trivially greppable, and it is NOT a
 * rubber stamp: by S-4 V2 the holder of that key can rotate every other slot
 * (H1), and can deactivate the institution permanently and irreversibly
 * (G2 + T1, `code 1207`). Whoever is named as custodian is, cryptographically,
 * the whole institution.
 */
export const ACKNOWLEDGE_FOREIGN_HELD_INSTITUTIONAL_KEY =
  'I-ACCEPT-THAT-THIS-KEY-HOLDER-IS-CRYPTOGRAPHICALLY-THE-WHOLE-INSTITUTION' as const;

/**
 * The single `authentication` slot. See the SDK note in the module header.
 *
 * KNOWN RESIDUAL, MEASURED FROM THE SDK SOURCE AND NOT FROM THE CHAIN. The
 * chain is happy for any sibling to act (S-4 M1), but `@cheqd/sdk`'s
 * `validateAuthenticationAgainstSignaturesKeyRotation` computes its required
 * set from `authentication` on BOTH document versions. Moving `authentication`
 * to a different slot is a "key replacement" in its terms and requires a
 * signature from the OUTGOING authentication key. So if this slot's key is
 * genuinely LOST, the client library blocks every further update even though
 * consensus would accept a sibling's signature.
 *
 * Consequences, all deliberate: this slot is always agent-held and never
 * imported; it is rotatable while alive via the X2 co-signature; and it must
 * never be retired, only rotated. Lifting the residual entirely means
 * broadcasting `MsgUpdateDidDoc` without the SDK's client-side validator,
 * which is a second broadcast path and was not built here.
 */
export const LEDGER_SIGNING_FRAGMENT = '#key-officer-1';

const OFFICER_FRAGMENT_PATTERN = /^#key-officer-[0-9]+$/;

// ---------------------------------------------------------------------------
// Officer key sources
// ---------------------------------------------------------------------------

/**
 * Where an officer slot's key material comes from.
 *
 * Note what is NOT here: a `controller`. See the module header.
 */
export type OfficerKeySource =
  /** Generated in this agent's key store. The only Phase-A custody that exists. */
  | { readonly kind: 'agent-generated' }
  /**
   * A public key whose private half lives elsewhere — an HSM, a hardware token,
   * another officer's machine. This is the shape #277's deferred hardening will
   * use; it is accepted now so the document does not have to be re-issued then.
   */
  | {
      readonly kind: 'imported';
      readonly publicKeyMultibase: string;
      readonly acknowledgement: typeof ACKNOWLEDGE_FOREIGN_HELD_INSTITUTIONAL_KEY;
      /** Recorded in the log. Under 1-of-N this IS the fraud-attribution record. */
      readonly custodian: string;
    };

export interface ProvisionInstitutionalDidSpec {
  /**
   * One entry per officer. N ≥ 2 is strongly preferred (S-4 §6.2) but N = 1 is
   * permitted, because the verification-method set is repairable in place
   * (S-4 R1, height 86534) — unlike the controller set. A 1-of-1 institution
   * can be grown later while its key still lives.
   *
   * `officers[0]` becomes the ledger signing slot and must therefore be a key
   * this agent holds: it is the one signature the create transaction needs, and
   * — see {@link LEDGER_SIGNING_FRAGMENT} — the one the SDK guard demands for
   * every later update too.
   */
  readonly officers: readonly OfficerKeySource[];
  /** Free text recorded in the log; not written to the ledger. */
  readonly purpose: string;
}

export interface InstitutionalDidResult extends LedgerWriteResult {
  readonly did: string;
  readonly document: CheqdDidDocumentShape;
  readonly officerSlots: readonly string[];
  readonly ledgerSigningSlot: string;
}

interface PreparedSlot {
  readonly slot: VerificationMethodSlot;
  readonly signer: CheqdSigner;
  readonly kmsKeyId?: string;
  readonly custody: string;
}

// ---------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------

export async function provisionInstitutionalDid(
  agent: Agent,
  spec: ProvisionInstitutionalDidSpec,
): Promise<InstitutionalDidResult> {
  if (!Array.isArray(spec.officers) || spec.officers.length === 0) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      'An institutional DID needs at least one officer key. With none it can never sign ' +
        'anything, and the verification-method set cannot be grown from empty — S-4 R1 ' +
        'requires a surviving key to authorise the growth.',
      400,
    );
  }
  if (typeof spec.purpose !== 'string' || spec.purpose.trim().length === 0) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      'provisionInstitutionalDid requires a non-empty `purpose`. Under 1-of-N the record of ' +
        'why a key exists is a fraud-detection control, not paperwork (#277).',
      400,
    );
  }

  const did = newCheqdDid();
  const prepared: PreparedSlot[] = [];

  for (const [index, officer] of spec.officers.entries()) {
    prepared.push(await prepareSlot(agent, did, `#key-officer-${index + 1}`, officer));
  }

  const document = institutionalDocument(did, prepared.map((p) => p.slot));

  // The last gate. Every constructor path lands here, so a future call site
  // that forgets a check still cannot emit a wrong-shaped institution.
  assertInstitutionalShape(document);

  const signingSlot = prepared.find((p) => fragmentOf(p.slot.id) === LEDGER_SIGNING_FRAGMENT);
  if (!signingSlot) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Internal: no '${LEDGER_SIGNING_FRAGMENT}' slot was prepared for '${did}'.`,
      500,
    );
  }

  // Only the signing slot is offered: consensus needs `{did}` and any key under
  // that namespace satisfies it (attribution is by id prefix, S-4 V2), and the
  // imported slots cannot sign by construction.
  const required = signerDidsForCreate(document);
  assertSignersCoverRequiredSet(required, [signingSlot.signer], `create institutional DID ${did}`);

  logger.info('institutional_did_create_requested', {
    did,
    purpose: spec.purpose,
    officerCount: prepared.length,
    officerSlots: prepared.map((p) => p.slot.id),
    custody: prepared.map((p) => ({ slot: p.slot.id, custody: p.custody })),
    consensusRequiredSigners: required,
    ledgerSigningSlot: `${did}${LEDGER_SIGNING_FRAGMENT}`,
  });

  const versionId = utils.uuid();
  const payload = await createMsgCreateDidDocPayloadToSign(document as never, versionId);

  // The SDK guard wants the signature set to EQUAL `authentication`, which is
  // exactly the one signing slot.
  const signInputs = [
    {
      verificationMethodId: signingSlot.signer.verificationMethodId,
      signature: await signingSlot.signer.sign(payload),
    },
  ];

  // Fails closed: no signing-log entry, no broadcast. Under 1-of-N the log is
  // the detection control the custody model rests on (#293), not a report about
  // one, so signing with it unavailable is signing with the safety argument off.
  const write = await recordSigningAttempt(
    {
      subjectDid: did,
      operation: 'provision-institutional-did',
      versionId,
      signedByVerificationMethodId: signingSlot.signer.verificationMethodId,
      payload: {
        purpose: spec.purpose,
        document: document as unknown as Record<string, unknown>,
        custody: prepared.map((p) => ({ slot: p.slot.id, custody: p.custody })),
        consensusRequiredSigners: required,
      },
    },
    async () =>
      assertDelivered(
        await ledgerServiceOf(agent).create(document as never, signInputs as never, versionId),
        `create of institutional DID ${did}`,
      ),
  );

  await recordInstitutionalDid(agent, document, prepared);

  // Arm the silent alarm from the height this DID first existed at, so the
  // window the watcher claims to have covered is the DID's whole lifetime.
  await armWatch(did, spec.purpose, write.height, document, versionId);

  logger.info('institutional_did_created', {
    did,
    officerCount: prepared.length,
    transactionHash: write.transactionHash,
    height: write.height,
  });

  return {
    ...write,
    did,
    document,
    officerSlots: prepared.map((p) => p.slot.id),
    ledgerSigningSlot: `${did}${LEDGER_SIGNING_FRAGMENT}`,
  };
}

/**
 * Arm the chain watch on a newly provisioned institutional DID.
 *
 * NOT FATAL IF IT FAILS, and that is a judgement call worth stating: the DID is
 * already on chain and irreversible, so throwing here would report a failure
 * for a write that succeeded and invite a retry that mints a second identity.
 * An unwatched institutional DID is a serious gap, so it is logged at ERROR and
 * `armInstitutionalWatch` exists to repair it without re-issuing anything.
 */
async function armWatch(
  did: string,
  label: string,
  height: number,
  document: CheqdDidDocumentShape,
  versionId: string,
): Promise<void> {
  try {
    await registerWatchedInstitutionalDid({
      did,
      label,
      fromHeight: height,
      verificationMethods: document.verificationMethod.map((vm) => ({
        id: vm.id,
        publicKeyMultibase: vm.publicKeyMultibase,
      })),
      controllers: document.controller,
      versionId,
    });
  } catch (error) {
    logger.error('institutional_did_watch_arm_failed', {
      did,
      height,
      error: error instanceof Error ? error.message : String(error),
      consequence:
        'This institutional DID is LIVE BUT UNWATCHED: an eviction (S-4 H1) or deactivation ' +
        '(code 1207) against it would raise no alarm. Call armInstitutionalWatch to repair.',
    });
  }
}

/**
 * Arm the watch on an institutional DID that was provisioned before this
 * component existed, or whose arming failed.
 *
 * `fromHeight` is the CURRENT height, not the DID's creation height, and the
 * registry records it: this system must never imply it observed blocks it never
 * read.
 */
export async function armInstitutionalWatch(
  agent: Agent,
  did: string,
  label: string,
  fromHeight: number,
): Promise<void> {
  const resolved = await requireLiveDidOnChain(agent, did, `arm the chain watch on '${did}'`);
  await registerWatchedInstitutionalDid({
    did,
    label,
    fromHeight,
    verificationMethods: resolved.verificationMethod.map((vm) => ({
      id: vm.id,
      publicKeyMultibase: vm.publicKeyMultibase,
    })),
    controllers: resolved.controller.length > 0 ? resolved.controller : [did],
  });
}

async function prepareSlot(
  agent: Agent,
  did: string,
  fragment: string,
  officer: OfficerKeySource,
): Promise<PreparedSlot> {
  const id = `${did}${fragment}`;

  if (officer.kind === 'imported') {
    if (fragment === LEDGER_SIGNING_FRAGMENT) {
      throw new AppError(
        ERROR_CODES.DID_CREATION_FAILED,
        `Slot '${id}' is the ledger signing slot, so it must be a key this agent holds — it ` +
          'is the one signature the create transaction needs and the one @cheqd/sdk demands ' +
          'for every later update. Put the foreign-held keys in the later slots.',
        400,
      );
    }
    assertImportIsDeliberate(did, fragment, officer);
    return {
      slot: {
        id,
        type: ED25519_VERIFICATION_KEY_2020,
        controller: did, // Derived, never supplied. See the module header.
        publicKeyMultibase: officer.publicKeyMultibase,
      },
      // Cannot sign here — that is what "imported" means. It is a slot, not a
      // signer; the create signature comes from the slot this agent holds.
      signer: unusableSigner(did, id),
      custody: `foreign:${officer.custodian}`,
    };
  }

  const key = await generateEd25519Key(agent);
  return {
    slot: {
      id,
      type: ED25519_VERIFICATION_KEY_2020,
      controller: did, // Derived, never supplied. See the module header.
      publicKeyMultibase: key.publicKeyMultibase,
    },
    signer: kmsSigner(agent, {
      did,
      verificationMethodId: id,
      kmsKeyId: key.kmsKeyId,
      signatureAlgorithm: key.signatureAlgorithm,
    }),
    kmsKeyId: key.kmsKeyId,
    custody: 'agent-key-store',
  };
}

function unusableSigner(did: string, verificationMethodId: string): CheqdSigner {
  return {
    did,
    verificationMethodId,
    sign() {
      return Promise.reject(
        new AppError(
          ERROR_CODES.DID_CREATION_FAILED,
          `'${verificationMethodId}' is held elsewhere; this agent cannot produce its ` +
            'signature. Sign with a slot the agent holds — that is what 1-of-N is for.',
          500,
        ),
      );
    },
  };
}

function assertImportIsDeliberate(
  did: string,
  fragment: string,
  officer: Extract<OfficerKeySource, { kind: 'imported' }>,
): void {
  if (officer.acknowledgement !== ACKNOWLEDGE_FOREIGN_HELD_INSTITUTIONAL_KEY) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Importing a foreign-held key into '${did}${fragment}' requires the literal ` +
        `acknowledgement '${ACKNOWLEDGE_FOREIGN_HELD_INSTITUTIONAL_KEY}'. By S-4 V2 that ` +
        "key's holder can evict every other officer (H1) and deactivate this institution " +
        'permanently and irreversibly (G2 + T1).',
      400,
    );
  }
  if (typeof officer.custodian !== 'string' || officer.custodian.trim().length === 0) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      'An imported institutional key requires a named `custodian`. Under 1-of-N the record of ' +
        'who holds which key is the only thing that turns a fraudulent signature into an ' +
        'attributable one (#277).',
      400,
    );
  }
  if (!/^z[1-9A-HJ-NP-Za-km-z]{40,}$/.test(officer.publicKeyMultibase)) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `'${officer.publicKeyMultibase}' is not a base58btc multibase Ed25519 public key.`,
      400,
    );
  }
  logger.warn('institutional_did_foreign_key_imported', {
    did,
    slot: `${did}${fragment}`,
    custodian: officer.custodian,
    hazard:
      'By S-4 V2 this key is authorised AS the institution for every purpose regardless of ' +
      'its controller field: it can evict every other officer (H1) and deactivate the ' +
      'institution irreversibly (G2 + T1).',
  });
}

function institutionalDocument(
  did: string,
  slots: readonly VerificationMethodSlot[],
): CheqdDidDocumentShape {
  const signingSlotId = slots.find(
    (slot) => fragmentOf(slot.id) === LEDGER_SIGNING_FRAGMENT,
  )?.id;

  return {
    '@context': [DID_V1_CONTEXT, ED25519_2020_CONTEXT],
    id: did,
    // Explicit [self] rather than omitted. M6 measured them behaviourally
    // identical, but a reader of the resolved document should not have to know
    // about the GetControllersOrSubject fallback to know who governs it.
    controller: [did],
    verificationMethod: [...slots],
    authentication: signingSlotId ? [signingSlotId] : [],
    // Every officer can ISSUE. Only the signing slot authenticates — see header.
    assertionMethod: slots.map((slot) => slot.id),
  };
}

async function recordInstitutionalDid(
  agent: Agent,
  document: CheqdDidDocumentShape,
  prepared: readonly PreparedSlot[],
): Promise<void> {
  const held = prepared.filter((p) => p.kmsKeyId !== undefined);
  await didRepositoryOf(agent).save(
    agent.context,
    new DidRecord({
      did: document.id,
      role: DidDocumentRole.Created,
      didDocument: JsonTransformer.fromJSON(document, DidDocument),
      keys: held.map((p) => ({
        kmsKeyId: p.kmsKeyId as string,
        didDocumentRelativeKeyId: fragmentOf(p.slot.id),
      })),
    }),
  );
}

// ---------------------------------------------------------------------------
// Lifecycle — grow, rotate, retire. One slot per transaction, always.
// ---------------------------------------------------------------------------

export interface OfficerSlotChangeSpec {
  readonly institutionalDid: string;
  /**
   * Which slot signs. Any officer will do — that is what 1-of-N means (S-4 M1) —
   * but it must not be the slot being changed, because the chain verifies the
   * signature a second time against the UPDATED document (S-4 §3.4, X1).
   */
  readonly signWithFragment?: string;
  readonly reason: string;
}

export interface AddOfficerKeySpec extends OfficerSlotChangeSpec {
  readonly key: OfficerKeySource;
  /** Defaults to the next free `#key-officer-N`. */
  readonly fragment?: string;
}

export interface RotateOfficerKeySpec extends OfficerSlotChangeSpec {
  readonly fragment: string;
  /** Absent means "generate the replacement in this agent's key store". */
  readonly nextPublicKeyMultibase?: string;
}

export interface RetireOfficerKeySpec extends OfficerSlotChangeSpec {
  readonly fragment: string;
}

export interface OfficerSlotChangeResult extends LedgerWriteResult {
  readonly did: string;
  readonly slots: readonly string[];
  readonly signedBy: string;
}

/**
 * Grow the officer set. This is the repair path for an institution already
 * issued as 1-of-1 (S-4 R1, height 86534): the VM set, unlike the controller
 * set, is repairable in place while at least one key lives, so such a DID does
 * NOT need re-issuing.
 */
export async function addInstitutionalOfficerKey(
  agent: Agent,
  spec: AddOfficerKeySpec,
): Promise<OfficerSlotChangeResult> {
  const current = await requireLiveDidOnChain(
    agent,
    spec.institutionalDid,
    `add an officer key to '${spec.institutionalDid}'`,
  );
  assertIsSelfControlledInstitution(current);

  const fragment = spec.fragment ?? nextFreeOfficerFragment(current);
  assertFragmentIsOfficerShaped(fragment);

  if (current.verificationMethod.some((vm) => fragmentOf(vm.id) === fragment)) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `'${spec.institutionalDid}' already has a slot '${fragment}'. The chain maps slots by ` +
        'fragment, so adding it again would silently replace the existing key rather than ' +
        'grow the set.',
      409,
    );
  }

  const added = await materialiseOfficerKey(agent, spec.institutionalDid, fragment, spec.key);

  const next = [
    ...current.verificationMethod.map(toSlot),
    {
      id: `${spec.institutionalDid}${fragment}`,
      type: ED25519_VERIFICATION_KEY_2020 as typeof ED25519_VERIFICATION_KEY_2020,
      controller: spec.institutionalDid,
      publicKeyMultibase: added.publicKeyMultibase,
    },
  ];

  const result = await applySlotChange(agent, current, next, spec, 'add');
  if (added.kmsKeyId) {
    await rememberHeldKey(agent, spec.institutionalDid, fragment, added.kmsKeyId);
  }
  return result;
}

/**
 * Replace one officer's key material. Any surviving officer signs (S-4 M1).
 */
export async function rotateInstitutionalOfficerKey(
  agent: Agent,
  spec: RotateOfficerKeySpec,
): Promise<OfficerSlotChangeResult> {
  const current = await requireLiveDidOnChain(
    agent,
    spec.institutionalDid,
    `rotate '${spec.fragment}' of '${spec.institutionalDid}'`,
  );
  assertIsSelfControlledInstitution(current);

  const existing = current.verificationMethod.find((vm) => fragmentOf(vm.id) === spec.fragment);
  if (!existing) {
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `'${spec.institutionalDid}' has no slot '${spec.fragment}'. It holds ` +
        `[${current.verificationMethod.map((vm) => fragmentOf(vm.id)).join(', ')}].`,
      404,
    );
  }

  const rotatingSigningSlot = spec.fragment === LEDGER_SIGNING_FRAGMENT;

  if (!rotatingSigningSlot && current.verificationMethod.length < 2) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `'${spec.institutionalDid}' has a single verification method, so rotating it would ` +
        'require a signature from the key being replaced — which is only possible while that ' +
        'key still works. GROW the set first (addInstitutionalOfficerKey, S-4 R1); then any ' +
        'sibling can rotate this slot without it (S-4 M1).',
      409,
    );
  }

  // A caller-supplied replacement is the hardware-token case (#277): the key is
  // born inside the token and only its public half ever leaves.
  const replacement: Partial<GeneratedKey> & { publicKeyMultibase: string } =
    spec.nextPublicKeyMultibase
      ? { publicKeyMultibase: spec.nextPublicKeyMultibase }
      : await generateEd25519Key(agent);

  if (replacement.publicKeyMultibase === existing.publicKeyMultibase) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Rotation of '${spec.fragment}' would install the key it already carries. A no-op ` +
        'update still consumes a block and would leave a compromised key in place.',
      400,
    );
  }

  // Rotating the signing slot is the X2 case: the SDK's key-rotation validator
  // demands a signature under this id from BOTH the outgoing and the incoming
  // key, so both halves must be here. A hardware-token replacement cannot
  // satisfy that from this process.
  if (rotatingSigningSlot && !replacement.kmsKeyId) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Rotating '${LEDGER_SIGNING_FRAGMENT}' requires the incoming key to co-sign under the ` +
        'same verification-method id (S-4 X2), so its private half must live in this agent. ' +
        'Omit `nextPublicKeyMultibase` to have it generated here, or rotate a non-signing ' +
        'slot instead.',
      400,
    );
  }

  const next = current.verificationMethod.map((vm) =>
    fragmentOf(vm.id) === spec.fragment
      ? { ...toSlot(vm), publicKeyMultibase: replacement.publicKeyMultibase }
      : toSlot(vm),
  );

  const result = await applySlotChange(
    agent,
    current,
    next,
    spec,
    'rotate',
    rotatingSigningSlot && replacement.kmsKeyId && replacement.signatureAlgorithm
      ? kmsSigner(agent, {
          did: spec.institutionalDid,
          verificationMethodId: `${spec.institutionalDid}${LEDGER_SIGNING_FRAGMENT}`,
          kmsKeyId: replacement.kmsKeyId,
          signatureAlgorithm: replacement.signatureAlgorithm,
        })
      : undefined,
  );
  if (replacement.kmsKeyId) {
    await rememberHeldKey(agent, spec.institutionalDid, spec.fragment, replacement.kmsKeyId);
  }
  return result;
}

/**
 * Remove an officer slot outright (S-4 D2, height 86329 — the dead key is gone,
 * not shadowed).
 *
 * NOTE WHAT THIS OPERATION IS. S-4 H1 measured that one key alone can evict its
 * siblings and the module has no concept of a key objecting to its own removal.
 * This function is therefore also the eviction primitive an attacker would want,
 * which is why every call is logged with the signing slot named. Detection
 * latency is a load-bearing control here, not an operational nicety (#291).
 */
export async function retireInstitutionalOfficerKey(
  agent: Agent,
  spec: RetireOfficerKeySpec,
): Promise<OfficerSlotChangeResult> {
  const current = await requireLiveDidOnChain(
    agent,
    spec.institutionalDid,
    `retire '${spec.fragment}' of '${spec.institutionalDid}'`,
  );
  assertIsSelfControlledInstitution(current);

  if (!current.verificationMethod.some((vm) => fragmentOf(vm.id) === spec.fragment)) {
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `'${spec.institutionalDid}' has no slot '${spec.fragment}'.`,
      404,
    );
  }

  if (current.verificationMethod.length < 2) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Refusing to retire the only verification method of '${spec.institutionalDid}'. The ` +
        'document would then have no key at all, and #291 is explicit that "remediable by ' +
        'rotation" is unavailable to an institution holding no key.',
      409,
    );
  }

  const next = current.verificationMethod
    .filter((vm) => fragmentOf(vm.id) !== spec.fragment)
    .map(toSlot);

  return applySlotChange(agent, current, next, spec, 'retire');
}

// ---------------------------------------------------------------------------
// The one path every slot change goes through
// ---------------------------------------------------------------------------

async function applySlotChange(
  agent: Agent,
  current: ResolvedCheqdDid,
  nextSlots: readonly VerificationMethodSlot[],
  spec: OfficerSlotChangeSpec,
  operation: 'add' | 'rotate' | 'retire',
  /**
   * The X2 remedy, supplied only when the transaction rotates the ledger
   * signing slot itself. S-4 X1 rejects a bulk rotation signed by outgoing keys
   * with `code 1100`; X2 (height 86331) shows the incoming key co-signing under
   * the SAME verification-method id is the fix. Consensus is satisfied either
   * way — the inner loop of `VerifyAllSignersHaveAtLeastOneValidSignature` is
   * existential — so this exists to satisfy both the `<did>-updated` twin and
   * the SDK's own key-rotation validator.
   */
  incomingCoSigner?: CheqdSigner,
): Promise<OfficerSlotChangeResult> {
  if (typeof spec.reason !== 'string' || spec.reason.trim().length === 0) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      'Every institutional key change requires a non-empty `reason`. It is the audit record ' +
        'that #277 defers the automation of, not the requirement for.',
      400,
    );
  }

  const did = current.did;
  const updated = institutionalDocument(did, keepSigningSlotAlive(did, nextSlots));

  // Same gate as creation. The shape must survive every edit, not only birth.
  assertInstitutionalShape(updated);

  const existingDocument = {
    id: did,
    controller: current.controller,
    verificationMethod: current.verificationMethod,
  };

  const required = signerDidsForUpdate(existingDocument, updated);
  assertRotationIsSurvivable(existingDocument, updated, required);

  const delta = verificationMethodDelta(existingDocument, updated);
  const signer = incomingCoSigner
    ? await agentSigner(agent, did, LEDGER_SIGNING_FRAGMENT)
    : await officerSigner(agent, did, spec.signWithFragment, updated, current);

  if (!incomingCoSigner && [...delta.changed, ...delta.removed].includes(signer.verificationMethodId)) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Refusing to sign with '${signer.verificationMethodId}', the very slot this ` +
        'transaction changes. The chain verifies that signature a second time against the ' +
        'updated document, where the key no longer matches (code 1100, S-4 X1). Sign with a ' +
        'sibling slot instead — that is what 1-of-N is for.',
      400,
    );
  }

  assertSignersCoverRequiredSet(required, [signer], `${operation} a slot of ${did}`);

  logger.warn('institutional_did_key_change_requested', {
    did,
    operation,
    reason: spec.reason,
    signedBy: signer.verificationMethodId,
    coSignedByIncomingKey: incomingCoSigner !== undefined,
    added: delta.added,
    changed: delta.changed,
    removed: delta.removed,
    slotsBefore: current.verificationMethod.map((vm) => vm.id),
    slotsAfter: updated.verificationMethod.map((vm) => vm.id),
    consensusRequiredSigners: required,
  });

  const versionId = utils.uuid();
  const payload = await createMsgUpdateDidDocPayloadToSign(updated as never, versionId);
  const signInputs = [
    ...(await collectSignatures(required, new Map([[did, signer]]), payload)),
    ...(incomingCoSigner
      ? [
          {
            verificationMethodId: incomingCoSigner.verificationMethodId,
            signature: await incomingCoSigner.sign(payload),
          },
        ]
      : []),
  ];

  // This is the eviction primitive when `operation` is 'retire' (S-4 H1). The
  // audit entry is written BEFORE the broadcast and names the signing slot, the
  // whole before/after document and the caller's IP and device — under 1-of-N
  // that record is the only thing turning a fraudulent signature into an
  // attributable one. It fails closed.
  const write = await recordSigningAttempt(
    {
      subjectDid: did,
      operation: `${operation}-officer-slot`,
      versionId,
      signedByVerificationMethodId: signer.verificationMethodId,
      payload: {
        reason: spec.reason,
        documentBefore: existingDocument as unknown as Record<string, unknown>,
        documentAfter: updated as unknown as Record<string, unknown>,
        added: delta.added,
        changed: delta.changed,
        removed: delta.removed,
        consensusRequiredSigners: required,
        coSignedByIncomingKey: incomingCoSigner !== undefined,
      },
    },
    async () =>
      assertDelivered(
        await ledgerServiceOf(agent).update(updated as never, signInputs as never, versionId),
        `${operation} of a slot of ${did}`,
      ),
  );

  await refreshRecordedDocument(agent, updated);

  logger.warn('institutional_did_key_changed', {
    did,
    operation,
    signedBy: signer.verificationMethodId,
    transactionHash: write.transactionHash,
    height: write.height,
  });

  return {
    ...write,
    did,
    slots: updated.verificationMethod.map((vm) => vm.id),
    signedBy: signer.verificationMethodId,
  };
}

/**
 * The `authentication` array must never point at a slot that no longer exists,
 * or the SDK's own validator rejects every subsequent transaction locally.
 * Retiring `#key-officer-1` therefore promotes the lowest surviving slot into
 * that fragment's role by re-deriving the document from the survivors.
 */
function keepSigningSlotAlive(
  did: string,
  slots: readonly VerificationMethodSlot[],
): VerificationMethodSlot[] {
  const ordered = [...slots].sort((a, b) => a.id.localeCompare(b.id));
  if (ordered.some((slot) => fragmentOf(slot.id) === LEDGER_SIGNING_FRAGMENT)) return ordered;

  // No `#key-officer-1` survives. `institutionalDocument` would then emit an
  // empty `authentication`, which `validateAuthenticationAgainstSignatures`
  // rejects outright. Surface it rather than emit an unusable document.
  throw new AppError(
    ERROR_CODES.DID_CREATION_FAILED,
    `Refusing to leave '${did}' without its '${LEDGER_SIGNING_FRAGMENT}' slot: it is the ` +
      'single `authentication` entry, and @cheqd/sdk refuses to build any transaction for a ' +
      'document with no authentication key. Rotate that slot to a new key instead of ' +
      'retiring it — rotation replaces the key while keeping the slot.',
    409,
  );
}

async function officerSigner(
  agent: Agent,
  did: string,
  requestedFragment: string | undefined,
  updated: CheqdDidDocumentShape,
  current: ResolvedCheqdDid,
): Promise<CheqdSigner> {
  if (requestedFragment) return agentSigner(agent, did, requestedFragment);

  // Prefer a slot this transaction leaves alone, which is the X1-safe choice.
  const untouched = current.verificationMethod.filter((vm) =>
    updated.verificationMethod.some(
      (next) => next.id === vm.id && next.publicKeyMultibase === vm.publicKeyMultibase,
    ),
  );

  for (const candidate of untouched) {
    try {
      return await agentSigner(agent, did, fragmentOf(candidate.id));
    } catch {
      // This agent does not hold that slot — an imported, foreign-held officer
      // key. Try the next one rather than failing on the first miss.
    }
  }

  throw new AppError(
    ERROR_CODES.DID_CREATION_FAILED,
    `This agent holds no key for any slot of '${did}' that survives this transaction ` +
      `unchanged. Slots on chain: [${current.verificationMethod
        .map((vm) => fragmentOf(vm.id))
        .join(', ')}].`,
    400,
  );
}

async function materialiseOfficerKey(
  agent: Agent,
  did: string,
  fragment: string,
  source: OfficerKeySource,
): Promise<{ publicKeyMultibase: string; kmsKeyId?: string }> {
  if (source.kind === 'imported') {
    assertImportIsDeliberate(did, fragment, source);
    return { publicKeyMultibase: source.publicKeyMultibase };
  }
  const key = await generateEd25519Key(agent);
  return { publicKeyMultibase: key.publicKeyMultibase, kmsKeyId: key.kmsKeyId };
}

function assertIsSelfControlledInstitution(resolved: ResolvedCheqdDid): void {
  const controllers = resolved.controller.length > 0 ? resolved.controller : [resolved.did];
  if (controllers.length !== 1 || controllers[0] !== resolved.did) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `'${resolved.did}' is controlled by [${controllers.join(', ')}], not by itself, so it ` +
        'is not an institutional DID in the sense of #276/#292. Its controller set cannot be ' +
        'repaired (S-1 §5.4) and this module will not pretend otherwise.',
      409,
    );
  }
}

function assertFragmentIsOfficerShaped(fragment: string): void {
  if (!OFFICER_FRAGMENT_PATTERN.test(fragment)) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `'${fragment}' is not an officer slot fragment (expected '#key-officer-<n>').`,
      400,
    );
  }
}

function nextFreeOfficerFragment(resolved: ResolvedCheqdDid): string {
  const used = new Set(resolved.verificationMethod.map((vm) => fragmentOf(vm.id)));
  for (let index = 1; index <= used.size + 1; index += 1) {
    const candidate = `#key-officer-${index}`;
    if (!used.has(candidate)) return candidate;
  }
  return `#key-officer-${used.size + 1}`;
}

function toSlot(vm: {
  id: string;
  controller: string;
  publicKeyMultibase: string;
}): VerificationMethodSlot {
  return {
    id: vm.id,
    type: ED25519_VERIFICATION_KEY_2020,
    controller: vm.controller,
    publicKeyMultibase: vm.publicKeyMultibase,
  };
}

async function rememberHeldKey(
  agent: Agent,
  did: string,
  fragment: string,
  kmsKeyId: string,
): Promise<void> {
  const repository = didRepositoryOf(agent);
  const record = await repository.findCreatedDid(agent.context, did);
  if (!record) return;
  const keys = (record.keys ?? []).filter((k) => k.didDocumentRelativeKeyId !== fragment);
  record.keys = [...keys, { kmsKeyId, didDocumentRelativeKeyId: fragment }];
  await repository.update(agent.context, record);
}

async function refreshRecordedDocument(
  agent: Agent,
  document: CheqdDidDocumentShape,
): Promise<void> {
  const repository = didRepositoryOf(agent);
  const record = await repository.findCreatedDid(agent.context, document.id);
  if (!record) return;
  record.didDocument = JsonTransformer.fromJSON(document, DidDocument);
  await repository.update(agent.context, record);
}

// ---------------------------------------------------------------------------
// Custody report
// ---------------------------------------------------------------------------

export interface InstitutionalCustodyReport {
  readonly did: string;
  readonly n: number;
  readonly deactivated: boolean;
  readonly selfControlled: boolean;
  readonly foreignControlledSlots: readonly { id: string; controller: string }[];
  readonly slotsOutsideNamespace: readonly string[];
  readonly slotsThisAgentHolds: readonly string[];
  readonly findings: readonly string[];
}

/**
 * Describe an institutional DID's actual custody as the chain holds it.
 *
 * S-4 §6.4: a 1-of-1 institution is not a finding — it is growable in place
 * (R1). A slot with a foreign `controller`, or a key under this namespace that
 * the institution does not hold, IS the finding.
 */
export async function describeInstitutionalCustody(
  agent: Agent,
  did: string,
): Promise<InstitutionalCustodyReport> {
  const resolved = await requireLiveDidOnChain(agent, did, `audit custody of '${did}'`);
  const controllers = resolved.controller.length > 0 ? resolved.controller : [resolved.did];

  const foreignControlledSlots = resolved.verificationMethod
    .filter((vm) => vm.controller !== did)
    .map((vm) => ({ id: vm.id, controller: vm.controller }));

  const slotsOutsideNamespace = resolved.verificationMethod
    .filter((vm) => !vm.id.startsWith(`${did}#`))
    .map((vm) => vm.id);

  const record = await didRepositoryOf(agent).findCreatedDid(agent.context, did);
  const heldFragments = new Set((record?.keys ?? []).map((k) => k.didDocumentRelativeKeyId));
  const slotsThisAgentHolds = resolved.verificationMethod
    .filter((vm) => heldFragments.has(fragmentOf(vm.id)))
    .map((vm) => vm.id);

  const findings: string[] = [];
  const selfControlled = controllers.length === 1 && controllers[0] === did;

  if (!selfControlled) {
    findings.push(
      `controller is [${controllers.join(', ')}], not self. Every update needs those DIDs ` +
        'to co-sign (AND), and the controller set is not repairable (S-1 §5.4).',
    );
  }
  if (resolved.verificationMethod.length < 2) {
    findings.push(
      'N = 1. Not a defect — the VM set is repairable in place (S-4 R1) — but losing this ' +
        'one key loses the institution. Grow it with addInstitutionalOfficerKey.',
    );
  }
  for (const slot of foreignControlledSlots) {
    findings.push(
      `slot '${slot.id}' names '${slot.controller}' as its controller, so rotating it needs ` +
        `a signature from '${slot.controller}'. 1-of-N is really 1-of-` +
        `${resolved.verificationMethod.length - foreignControlledSlots.length} plus an ` +
        'unrecoverable slot (S-4 §6.1).',
    );
  }
  for (const id of slotsOutsideNamespace) {
    findings.push(
      `slot '${id}' is outside this DID's namespace, so its signature is attributed to ` +
        'another DID entirely (S-4 V2).',
    );
  }
  const unheld = resolved.verificationMethod.length - slotsThisAgentHolds.length;
  if (unheld > 0) {
    findings.push(
      `${unheld} of ${resolved.verificationMethod.length} slots are keys this agent does not ` +
        'hold. Each of them can independently evict every other officer (S-4 H1) and ' +
        'deactivate this DID permanently (G2 + T1).',
    );
  }

  return {
    did,
    n: resolved.verificationMethod.length,
    deactivated: resolved.deactivated,
    selfControlled,
    foreignControlledSlots,
    slotsOutsideNamespace,
    slotsThisAgentHolds,
    findings,
  };
}
