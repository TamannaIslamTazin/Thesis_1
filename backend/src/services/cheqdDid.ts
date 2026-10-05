/**
 * SSI Healthcare Backend — did:cheqd creation and verification-method rotation
 * with an EXPLICIT verification-method controller.
 *
 * ===========================================================================
 * WHY THIS MODULE EXISTS: THE SELF-CONTROLLED VERIFICATION METHOD IS FATAL
 * ===========================================================================
 * `x/did/keeper/msg_server_update_diddoc.go:152` (`GetSignerDIDsForDIDUpdate`)
 * appends a verification method's OWN `controller` field to the required-signer
 * set whenever that verification method is added, changed or removed. The
 * `@cheqd/sdk` default — `createDidVerificationMethod`, reached through Credo's
 * `CheqdDidRegistrar` → `generateDidDoc` → `createDidPayload` — emits
 * `verificationMethod[0].controller = <the subject DID>`.
 *
 * Compose those two facts and you get: REPLACING A LOST DEVICE KEY REQUIRES A
 * SIGNATURE FROM THE LOST DEVICE KEY. The DID's controller set is irrelevant.
 *
 * That is not a hypothesis. It was executed against this project's own chain
 * (`bd-health-trust-1`) and written up in
 * `/home/ahsan/Work/Project/BDHealthTrust/S1-DID-CONTROLLER-SEMANTICS.md`:
 *
 *   R0  rotate a DID whose VM controller is itself, signed by EVERY controller
 *       -> REJECTED `code 1101` at height 46229, demanding the subject's own key
 *   R2  the identical rotation on a DID whose VM controller is external,
 *       signed by the controllers only -> ACCEPTED at height 46231
 *
 * There is NO RETROFIT. Repairing the VM controller later is itself a VM change,
 * so it needs the key that is by then lost. A DID minted in the wrong shape
 * works perfectly right up until the first day recovery is needed, and is
 * unrecoverable from the moment it is written. Re-issuance is the only remedy.
 *
 * ===========================================================================
 * THE RULE THIS MODULE ENFORCES
 * ===========================================================================
 * The verification method's controller is SUPPLIED BY THE CALLER OR THE CALL
 * FAILS. There is no default — not the subject DID, and deliberately not any
 * other value either. A silent default is precisely what produced this defect;
 * replacing it with a different silent default repeats the mistake one layer
 * over. Self-control remains reachable, because an ORGANISATIONAL controller
 * DID legitimately governs itself, but only by naming
 * {@link ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL} at the call site, where it
 * reads as the deliberate choice it has to be.
 *
 * ===========================================================================
 * WHY THIS BYPASSES `CheqdDidRegistrar` RATHER THAN CONFIGURING IT
 * ===========================================================================
 * `CheqdDidRegistrar.create` signs the create payload with the AUTHENTICATION
 * verification methods of the document being created and with nothing else
 * (`CheqdDidRegistrar.mjs:145` → `signPayload` at :421). But creation is checked
 * against `GetSignerDIDsForDIDCreation` = controllers ∪ ALL vm-controllers
 * (`msg_server_create_diddoc.go:58-59`), so a document whose VM controller is an
 * external DID needs a signature from that external DID — a signature the
 * registrar structurally cannot produce. Passing `options.didDocument` does not
 * help; the signing step is the part that cannot express the requirement.
 *
 * So the document is assembled here and broadcast through Credo's own
 * `CheqdLedgerService`, which accepts arbitrary sign inputs. That keeps the
 * patched, sovereign-fork-aware network configuration (`rpcUrl` mandatory, no
 * `DefaultRPCUrl`, our `bdhealthtestnet` namespace) as the single source of
 * ledger truth instead of standing up a second, divergent SDK client.
 *
 * ===========================================================================
 * THE SIGNER SET IS COMPUTED LOCALLY, ON PURPOSE
 * ===========================================================================
 * `msg_server.go:136` returns on the FIRST unsatisfied signer over a sorted
 * list, so a rejection names one missing signature even when several are
 * missing. Discovering the required set by iterating on chain errors therefore
 * costs one consumed block per missing signer and still misleads. Both flows
 * below reproduce the chain's own signer-set rule in
 * {@link signerDidsForCreate} / {@link signerDidsForVerificationMethodRotation}
 * and refuse to broadcast until every one of them can sign.
 */

import {
  DidDocument,
  DidDocumentRole,
  DidRecord,
  DidRepository,
  JsonTransformer,
  Kms,
  TypedArrayEncoder,
  utils,
} from '@credo-ts/core';
import { CheqdLedgerService } from '@credo-ts/cheqd';
import { MsgCreateResourcePayload } from '@cheqd/ts-proto/cheqd/resource/v2/index.js';
import {
  createMsgCreateDidDocPayloadToSign,
  createMsgDeactivateDidDocPayloadToSign,
  createMsgUpdateDidDocPayloadToSign,
  toMultibaseRaw,
} from '@cheqd/sdk/utils';
import type { Agent } from '@credo-ts/core';

import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import type { DIDDocument } from '@ssi-healthcare/shared';
import type { CheqdDidDocumentShape } from '@ssi-healthcare/sdk/ledger';
import { assertEd25519Multibase } from '@ssi-healthcare/sdk/ledger';
import { resolveOnChain } from './cheqdLedger.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1';
const ED25519_2020_CONTEXT = 'https://w3id.org/security/suites/ed25519-2020/v1';

/**
 * The only verification-method type our chain's `x/did` module and
 * `validateSpecCompliantPayload` accept alongside `publicKeyMultibase`.
 */
const ED25519_VERIFICATION_KEY_2020 = 'Ed25519VerificationKey2020';

/** The key spec for every did:cheqd key. The registrar rejects anything else. */
const ED25519_KEY_SPEC = { type: { kty: 'OKP', crv: 'Ed25519' } } as const;

/**
 * The relative id of the subject's single verification method.
 *
 * Not a safety property — the chain reads the `controller` FIELD, not the
 * fragment — but it matches what `CheqdDidRegistrar` emits, so records written
 * before and after this module are dereferenced the same way by Credo.
 */
export const DEVICE_KEY_FRAGMENT = '#key-1';

/**
 * The token a caller must name to mint a DID whose verification method controls
 * itself.
 *
 * Deliberately unpleasant to type and trivially greppable. Legitimate uses are
 * ORGANISATIONAL controller DIDs — a hospital, a ministry, a recovery service —
 * which hold their own keys in custody and are not recovered by anyone else. It
 * is never correct for a patient DID: see #209, and R0 above.
 */
export const ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL =
  'I-ACCEPT-THAT-THIS-DID-IS-UNRECOVERABLE-IF-ITS-OWN-KEY-IS-LOST' as const;

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

/**
 * The price of asking for self-governance.
 *
 * Both governance decisions below — the controller set and the
 * verification-method controller — are permanent, and both have a "the subject
 * governs itself" option that is correct for an organisational DID and fatal for
 * a patient one. The acknowledgement and the reason are demanded identically in
 * both places so that neither can be the one you get by not thinking.
 */
export interface SelfGovernance {
  readonly kind: 'self';
  readonly acknowledgement: typeof ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL;
  /** Free text recorded in the log so the choice is auditable after the fact. */
  readonly reason: string;
}

/**
 * Who may UPDATE the DID document at all.
 *
 * cheqd's semantics are AND over this set with no threshold anywhere in the
 * module (S-1 §2), and the set is mutable only with the unanimous consent of
 * old ∪ new — so a lost or hostile controller can never be removed. It is
 * mutable but not repairable, which for planning purposes means it must be
 * right at creation.
 *
 * An omitted `controller` on chain does NOT mean "uncontrolled": it means the
 * subject controls itself (`diddoc_diddoc.go:65-73`). That is the same trap as
 * the self-controlled verification method one level up, so it is modelled as a
 * variant that must be asked for rather than as an empty array.
 */
export type ControllerSet =
  | { readonly kind: 'dids'; readonly controllerDids: readonly string[] }
  | SelfGovernance;

/**
 * Who may REPLACE the subject's verification method.
 *
 * Note what this field does NOT mean. Naming an external DID here does not hand
 * that DID the private key — the key is generated in the subject's own custody
 * and never exported. The field governs who may swap the verification method
 * out, not who may use it (S-1 §6).
 *
 * There is no third "unspecified" variant, and that is the entire point of
 * modelling this as a union rather than an optional string.
 */
export type VerificationMethodControl =
  | {
      /** The recoverable shape. Rotation is possible without the device key. */
      readonly kind: 'external';
      /** The DID that may replace this verification method. Must not be the subject. */
      readonly controllerDid: string;
    }
  /**
   * The unrecoverable shape. Correct only for a DID that is its own custodian —
   * an organisational controller — and never for a patient.
   */
  | SelfGovernance;

/**
 * A DID that can produce a signature the cheqd `x/did` module will attribute to
 * it.
 *
 * `FindSignInfosBySigner` (`x/did/types/tx_sign_info.go:47-59`) attributes a
 * signature by splitting the DID URL at `#` and comparing the DID part, and
 * SILENTLY IGNORES signatures belonging to no required signer. A signer whose
 * `verificationMethodId` does not begin with its own `did` therefore does not
 * fail loudly — it simply does not count. {@link assertSignerIsWellFormed}
 * closes that gap before anything is broadcast.
 */
export interface CheqdSigner {
  /** The controller DID this signature will be attributed to. */
  readonly did: string;
  /** An absolute DID URL under {@link did}, e.g. `did:cheqd:...#key-1`. */
  readonly verificationMethodId: string;
  sign(payload: Uint8Array): Promise<Uint8Array>;
}

/**
 * A subject key this agent does NOT hold.
 *
 * S-1 §8.1 requires the patient's device key be "generated on-device and never
 * exported", and #240 requires the same of the RCK. Neither is expressible while
 * `createCheqdDID` mints the subject key in the agent's own KMS — which is the
 * gap S-2 §9(3) named as blocking honest device custody.
 *
 * Supplying this moves the private half out of the backend entirely. The
 * consequence is deliberate and must not be "fixed": the resulting `DidRecord`
 * carries NO key mapping, so `agentSigner` will refuse for this DID. The backend
 * being unable to sign is the property, not a defect.
 */
export interface ExternalSubjectKey {
  readonly publicKeyMultibase: string;
  sign(payload: Uint8Array): Promise<Uint8Array>;
  /** Recorded in the log so an audit can tell device custody from agent custody. */
  readonly custody: string;
}

/** Everything that must be decided BEFORE a did:cheqd exists. */
export interface CreateCheqdDIDSpec {
  /** Required. No default exists, by design. */
  readonly controllers: ControllerSet;

  /**
   * When present, the subject's key material comes from the caller and its
   * private half never enters this process's key store.
   *
   * When absent the agent generates the key, which remains correct for
   * server-held identities — an issuer, an institutional controller — and is
   * wrong for anything a patient is supposed to own.
   */
  readonly subjectKey?: ExternalSubjectKey;

  /** Required. No default exists, by design. */
  readonly verificationMethodControl: VerificationMethodControl;

  /**
   * Signers for every required signer OTHER THAN THE SUBJECT ITSELF.
   *
   * The subject's signature — needed whenever the subject appears in its own
   * create-time signer set, i.e. whenever either governance choice above is
   * `self` — cannot come from the caller: the key does not exist until this
   * function generates it. It is supplied internally and is the only signature
   * that is ever implicit here, because it is the only one whose availability is
   * guaranteed by construction rather than assumed.
   *
   * Completeness of the rest is checked before broadcast rather than discovered
   * from a `1101`.
   */
  readonly signers: readonly CheqdSigner[];

  /**
   * A caller-supplied invariant over the ASSEMBLED document, run before the
   * payload is built and therefore before anything is broadcast.
   *
   * REQUIRED. No default exists, by design — the same design as `controllers`
   * and `verificationMethodControl` above. This module knows what a well-formed
   * did:cheqd is; it deliberately does not know what a *patient*, an
   * *institutional*, or a *recovery-controller* DID is. Inverting the
   * dependency lets each role's own constructor assert its own shape (S-1 §8.1,
   * S-4 §6.2, #240) at the only moment the assertion is still free — a
   * wrong-shaped DID cannot be repaired once it is on the ledger, only
   * re-issued.
   *
   * MEASURED GAP (steno #313's inventory round): this field used to be
   * optional, and one real call site — the recovery-controller DID minted by
   * `agentHeldRecoveryController` / `deviceHeldRecoveryController` — omitted it
   * entirely. Patient and institutional DIDs already went through dedicated
   * constructors that always supplied one; the recovery-controller role did
   * not have one and fell through the gap. Making this required turns "the
   * caller remembered to check" into "the caller could not have avoided
   * stating what they expect," which is what every other field in this
   * interface already does. A negative-control fixture that must mint a
   * knowingly-broken document names
   * {@link SHAPE_ASSERTION_DELIBERATELY_OMITTED} instead of writing a fresh
   * inline no-op — so the complete list of unchecked mints stays one `rg` away.
   */
  readonly assertShape: (document: CheqdDidDocumentShape) => void;
}

export interface CheqdDIDResult {
  readonly did: string;
  readonly didDocument: DIDDocument;
  readonly transactionHash: string;
  readonly height: number;
}

// ---------------------------------------------------------------------------
// Signer-set rules — the chain's own predicates, restated locally
// ---------------------------------------------------------------------------

/** Unique, sorted — the same normalisation `utils.UniqueSorted` applies on-chain. */
function uniqueSorted(dids: readonly string[]): string[] {
  return Array.from(new Set(dids)).sort();
}

/**
 * `GetSignerDIDsForDIDCreation` (`msg_server_create_diddoc.go:76-81`):
 * controllers ∪ ALL verification-method controllers.
 */
export function signerDidsForCreate(document: {
  id: string;
  controller?: readonly string[];
  verificationMethod?: readonly { controller: string }[];
}): string[] {
  const controllers =
    document.controller && document.controller.length > 0
      ? document.controller
      : [document.id];
  const vmControllers = (document.verificationMethod ?? []).map((vm) => vm.controller);
  return uniqueSorted([...controllers, ...vmControllers]);
}

/**
 * `GetSignerDIDsForDIDUpdate` (`msg_server_update_diddoc.go:127-171`) restricted
 * to the one update this module performs: replacing the key material of a single
 * verification method, leaving the controller set alone.
 *
 * The union of the OLD and NEW controller sets (`:128-129`) plus, because the
 * verification method CHANGED (`:152`), both its old and its new `controller`
 * field. Passing the old VM controller is what makes the R0/R2 distinction
 * visible here rather than on-chain: with a self-controlled VM the subject's own
 * DID lands in this set and the caller is told it cannot sign, before a block is
 * consumed.
 */
export function signerDidsForVerificationMethodRotation(args: {
  readonly subjectDid: string;
  readonly controllers: readonly string[];
  readonly previousVerificationMethodController: string;
  readonly nextVerificationMethodController: string;
}): string[] {
  const controllers =
    args.controllers.length > 0 ? args.controllers : [args.subjectDid];
  return uniqueSorted([
    ...controllers,
    args.previousVerificationMethodController,
    args.nextVerificationMethodController,
  ]);
}

// ---------------------------------------------------------------------------
// Validation — every one of these is a fail-closed precondition
// ---------------------------------------------------------------------------

/** Matches what the patched `parseCheqdDid` will accept for our namespace. */
const CHEQD_DID_PATTERN = /^did:cheqd:[a-zA-Z0-9]+:[a-zA-Z0-9.:-]+$/;

function assertIsCheqdDid(value: string, role: string): void {
  if (!CHEQD_DID_PATTERN.test(value)) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `${role} is not a did:cheqd identifier: '${value}'`,
      400,
    );
  }
}

function assertSignerIsWellFormed(signer: CheqdSigner): void {
  if (!signer.verificationMethodId.startsWith(`${signer.did}#`)) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Signer for '${signer.did}' offers verification method ` +
        `'${signer.verificationMethodId}', which belongs to a different DID. The ledger ` +
        `attributes a signature by the DID part of this URL and silently IGNORES ` +
        `signatures it cannot attribute, so this would have produced a missing-signature ` +
        `rejection naming an unrelated DID.`,
      400,
    );
  }
}

/**
 * Shared by both governance choices, because both are permanent and both have a
 * self variant that is right for an institution and fatal for a patient.
 */
function assertSelfGovernanceIsDeliberate(value: SelfGovernance, field: string): void {
  if (value.acknowledgement !== ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `${field}.kind 'self' requires the literal acknowledgement ` +
        `'${ACKNOWLEDGE_UNRECOVERABLE_SELF_CONTROL}'. A DID that governs itself cannot be ` +
        'recovered by anyone once its own key is gone, so this is not a state anyone ' +
        'reaches by omission.',
      400,
    );
  }
  if (typeof value.reason !== 'string' || value.reason.trim().length === 0) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `${field}.kind 'self' requires a non-empty 'reason'. The choice is permanent and is ` +
        'recorded so a later audit can tell a considered decision from an accident.',
      400,
    );
  }
}

/**
 * Runtime guard for the untyped boundary. TypeScript is not present by the time
 * a parsed HTTP body reaches this module, so "the union has no unspecified
 * variant" has to be enforced twice: once by the compiler, once here.
 */
function assertChoiceWasMade(value: unknown, field: string, consequence: string): void {
  if (value === null || typeof value !== 'object' || !('kind' in value)) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `No ${field} was supplied. There is no default, deliberately: ${consequence} ` +
        'See S1-DID-CONTROLLER-SEMANTICS.md.',
      400,
    );
  }
}

/**
 * Resolve the caller's choice into the literal `controller` array of the
 * document.
 */
function resolveControllerSet(controllers: ControllerSet, subjectDid: string): string[] {
  assertChoiceWasMade(
    controllers,
    'controller set',
    'an absent controller list is read by the chain as "the subject controls itself", and a ' +
      'controller set can never be repaired afterwards without the unanimous consent of the ' +
      'set it already has.',
  );

  if (controllers.kind === 'dids') {
    if (!Array.isArray(controllers.controllerDids) || controllers.controllerDids.length === 0) {
      throw new AppError(
        ERROR_CODES.DID_CREATION_FAILED,
        "controllers.kind 'dids' requires at least one controller DID. An empty list is not " +
          '"no controller" — the chain would read it as self-control.',
        400,
      );
    }
    for (const controller of controllers.controllerDids) {
      assertIsCheqdDid(controller, 'controller');
    }
    return [...controllers.controllerDids];
  }

  if (controllers.kind === 'self') {
    assertSelfGovernanceIsDeliberate(controllers, 'controllers');
    return [subjectDid];
  }

  throw new AppError(
    ERROR_CODES.DID_CREATION_FAILED,
    `Unknown controllers.kind '${(controllers as { kind: string }).kind}'`,
    400,
  );
}

/**
 * Resolve the caller's choice into the literal value of `verificationMethod[0].controller`.
 *
 * Every rejection path in here is the point of the module. If this function can
 * ever return the subject DID without the caller having said so in as many
 * words, the defect is back.
 */
function resolveVerificationMethodController(
  control: VerificationMethodControl,
  subjectDid: string,
): string {
  assertChoiceWasMade(
    control,
    'verification-method controller',
    'a did:cheqd whose verification method controls itself can never have that key ' +
      'replaced, because the chain demands a signature from the key being replaced ' +
      '(experiment R0).',
  );

  if (control.kind === 'external') {
    assertIsCheqdDid(control.controllerDid, 'verificationMethodControl.controllerDid');
    if (control.controllerDid === subjectDid) {
      throw new AppError(
        ERROR_CODES.DID_CREATION_FAILED,
        `verificationMethodControl.kind is 'external' but names the subject '${subjectDid}' ` +
          `itself, which is the unrecoverable shape wearing the recoverable shape's label. ` +
          `Use kind 'self' with an acknowledgement if that is genuinely intended.`,
        400,
      );
    }
    return control.controllerDid;
  }

  if (control.kind === 'self') {
    assertSelfGovernanceIsDeliberate(control, 'verificationMethodControl');
    return subjectDid;
  }

  throw new AppError(
    ERROR_CODES.DID_CREATION_FAILED,
    `Unknown verificationMethodControl.kind '${(control as { kind: string }).kind}'`,
    400,
  );
}

/**
 * Fail with the WHOLE missing set, not the first element of it.
 *
 * The chain reports one missing signer per rejected transaction, so a caller
 * that learns its gaps from the ledger burns a block per gap. This is the same
 * information, for free, before anything is broadcast.
 */
function assertSignersCoverRequiredSet(
  required: readonly string[],
  signers: readonly CheqdSigner[],
  operation: string,
): Map<string, CheqdSigner> {
  const bySigner = new Map<string, CheqdSigner>();
  for (const signer of signers) {
    assertSignerIsWellFormed(signer);
    bySigner.set(signer.did, signer);
  }

  const missing = required.filter((did) => !bySigner.has(did));
  if (missing.length > 0) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Cannot ${operation}: cheqd requires a signature from EVERY required signer (AND, no ` +
        `threshold exists in the module). ${missing.length} of ${required.length} cannot ` +
        `sign here: ${missing.join(', ')}. Broadcasting anyway would consume a block and ` +
        `return code 1101 naming only the first of them.`,
      400,
    );
  }

  return bySigner;
}

// ---------------------------------------------------------------------------
// Ledger interaction
// ---------------------------------------------------------------------------

interface SignInfo {
  readonly verificationMethodId: string;
  readonly signature: Uint8Array;
}

async function collectSignatures(
  required: readonly string[],
  bySigner: ReadonlyMap<string, CheqdSigner>,
  payload: Uint8Array,
): Promise<SignInfo[]> {
  return Promise.all(
    required.map(async (did) => {
      // Non-null asserted only because assertSignersCoverRequiredSet ran first
      // and throws on any gap; it is the sole way to reach this line.
      const signer = bySigner.get(did) as CheqdSigner;
      return {
        verificationMethodId: signer.verificationMethodId,
        signature: await signer.sign(payload),
      };
    }),
  );
}

/**
 * `DeliverTx`, not the broadcast result.
 *
 * In Cosmos SDK v0.50 `CheckTx` does not execute the message, so a sync-mode
 * broadcast reports `code: 0` for a transaction the DID module will reject.
 * `CheqdLedgerService` broadcasts and waits, so `response.code` here is already
 * the delivery code — but the distinction is worth naming, because reading the
 * wrong one produced the wrong answer for every rejection during spike S-1.
 */
function assertDelivered(
  response: { code: number; rawLog?: string; transactionHash: string; height: number },
  operation: string,
): void {
  if (response.code !== 0) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Ledger rejected ${operation} with code ${response.code}: ${response.rawLog ?? ''}`,
      502,
    );
  }
}

function ledgerServiceOf(agent: Agent): CheqdLedgerService {
  return agent.dependencyManager.resolve(CheqdLedgerService);
}

function kmsOf(agent: Agent): Kms.KeyManagementApi {
  return agent.dependencyManager.resolve(Kms.KeyManagementApi);
}

// ---------------------------------------------------------------------------
// Signers backed by the agent's own key store
// ---------------------------------------------------------------------------

/**
 * A {@link CheqdSigner} for a did:cheqd this agent created and still holds keys
 * for.
 *
 * This is the only signer implementation today, and it is deliberately a
 * separate concept from the interface: a patient-held recovery controller key
 * or an HSM-backed institutional controller are different implementations of
 * the same contract, and neither of them belongs in this file.
 */
export async function agentSigner(agent: Agent, did: string): Promise<CheqdSigner> {
  const didRepository = agent.dependencyManager.resolve(DidRepository);
  const record = await didRepository.findCreatedDid(agent.context, did);

  if (!record) {
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `This agent holds no created-DID record for '${did}', so it cannot sign for it.`,
      404,
    );
  }

  const entry = record.keys?.[0];
  if (!entry) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `DID record for '${did}' carries no key mapping, so it cannot sign.`,
      500,
    );
  }

  const kms = kmsOf(agent);
  const publicJwk = await kms.getPublicKey({ keyId: entry.kmsKeyId });
  if (!publicJwk) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Key '${entry.kmsKeyId}' for DID '${did}' is not in this agent's key store.`,
      500,
    );
  }

  // `getPublicKey` is typed across every key type the KMS supports, including
  // symmetric ones that cannot sign at all. Narrowing here rather than casting
  // means a DID record pointing at the wrong key fails with the key named,
  // instead of throwing something unreadable from inside the signature call.
  if (publicJwk.kty !== 'OKP' || publicJwk.crv !== 'Ed25519') {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Key '${entry.kmsKeyId}' for DID '${did}' is ${Kms.getJwkHumanDescription(publicJwk)}, ` +
        'which did:cheqd cannot use. Every cheqd verification method is Ed25519.',
      500,
    );
  }

  const algorithm = Kms.PublicJwk.fromPublicJwk(publicJwk).signatureAlgorithm;

  return {
    did,
    verificationMethodId: `${did}${entry.didDocumentRelativeKeyId}`,
    async sign(payload: Uint8Array): Promise<Uint8Array> {
      const { signature } = await kms.sign({
        data: payload,
        algorithm,
        keyId: entry.kmsKeyId,
      });
      return signature;
    },
  };
}

/**
 * Publish a DID-Linked Resource, signed by ONE key this agent holds.
 *
 * ===========================================================================
 * WHY THIS EXISTS INSTEAD OF `agent.modules.cheqd.createResource`
 * ===========================================================================
 * Credo's registrar signs a resource with EVERY verification method in the DID
 * document:
 *
 *   CheqdDidRegistrar.mjs:398
 *     signPayload(agentContext, payload, didDocumentInstance.verificationMethod, ...)
 *   CheqdDidRegistrar.mjs:422
 *     Promise.all(verificationMethod.map(...))   // all of them, not one
 *
 * That is STRICTER THAN CONSENSUS, and it is the same class of client-side
 * over-requirement as the `@cheqd/sdk` create path in #219. On chain, keys
 * within one controller are OR (#206) — a single valid signature from any
 * published method authorises the write. Credo demands all N.
 *
 * The consequence is severe and was measured, not predicted: a 1-of-N
 * institutional DID with ANY foreign-held verification method cannot publish a
 * resource at all, so it cannot issue a credential, because issuance publishes
 * a status list first. BMDC was grown with the issuer console's own key —
 * deliberately, so the ministry cannot act as the council (#424) — and that
 * single addition made every BMDC issuance fail with:
 *
 *   Status list publish failed: unknownError: Key with key id
 *   'GugyeY4uHVdn2QTo1Hv7z9e5CefjJZNrKvg3pxoRPjCB' not found in backend 'askar'
 *
 * naming a key the backend is not supposed to hold, from a call site that
 * mentions neither the DID nor the officer. The two properties — "the council
 * holds its own key" and "the council can issue" — were in direct conflict
 * only because of a client-side detail, and 1-of-N custody is meaningless if
 * adding the Nth key removes the ability to issue.
 *
 * So this signs with the agent's own key, exactly as every DID write in this
 * file already does. It is not a workaround around an authorisation check: the
 * chain applies the SUBJECT's controller set to `x/resource` (#313), and that
 * check is unchanged here — a DID this agent cannot legitimately sign for is
 * still refused, by the ledger, with the same code it always returned.
 *
 * NOTE the asymmetry with DID *updates*: those need every required CONTROLLER
 * (AND across controller DIDs), which is why `collectSignatures` exists and
 * why it refuses on a gap. A resource needs one signature from the subject's
 * controller set, and for a self-controlled institution that is one key.
 */
export async function publishResourceSignedByAgent(
  agent: Agent,
  did: string,
  resource: {
    readonly id: string;
    readonly name: string;
    readonly resourceType: string;
    readonly version: string;
    readonly data: unknown;
  },
): Promise<void> {
  // Refuses with the DID named if this agent holds no key for it, BEFORE a
  // payload is built or a block is spent.
  const signer = await agentSigner(agent, did);

  const data =
    typeof resource.data === 'string'
      ? TypedArrayEncoder.fromBase64(resource.data)
      : new TextEncoder().encode(JSON.stringify(resource.data));

  const payload = MsgCreateResourcePayload.fromPartial({
    collectionId: did.split(':')[3],
    id: resource.id,
    resourceType: resource.resourceType,
    name: resource.name,
    version: resource.version,
    data,
  });

  const signInputs: SignInfo[] = [
    {
      verificationMethodId: signer.verificationMethodId,
      signature: await signer.sign(MsgCreateResourcePayload.encode(payload).finish()),
    },
  ];

  const ledger = ledgerServiceOf(agent);
  const response = await ledger.createResource(did, payload, signInputs as never);
  // DeliverTx, not the broadcast code — see assertDelivered.
  assertDelivered(response as never, `publish resource '${resource.name}' for ${did}`);

  logger.info('Resource published', {
    did,
    resourceId: resource.id,
    name: resource.name,
    signedBy: signer.verificationMethodId,
    height: (response as { height?: number }).height,
  });
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

/**
 * Mint a did:cheqd whose verification-method controller was chosen by the
 * caller.
 *
 * The subject's signing key is generated in this agent's key store and is
 * recorded so Credo can use the DID for issuance and presentation. That is a
 * separate question from CONTROL: the key in the store is what signs
 * credentials; `verificationMethodControl` is what decides who may replace it.
 */
export async function createCheqdDID(
  agent: Agent,
  spec: CreateCheqdDIDSpec,
): Promise<CheqdDIDResult> {
  // Runtime guard for the untyped boundary — same reasoning as
  // `assertChoiceWasMade` below, restated here because `assertShape` sits
  // outside the `controllers` / `verificationMethodControl` union and would
  // otherwise be the one required field nothing actually enforces at runtime.
  // Checked FIRST, before any key is generated: a caller that cannot state
  // what shape it expects should not get as far as spending KMS work either.
  if (typeof spec.assertShape !== 'function') {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      'No assertShape was supplied. There is no default, deliberately: a mint that is never ' +
        'checked against a named shape predicate is exactly how a wrong-shaped DID reaches an ' +
        'immutable ledger unnoticed (steno #313). Pass the role-specific assertion this DID ' +
        'must satisfy, or SHAPE_ASSERTION_DELIBERATELY_OMITTED from @ssi-healthcare/sdk/ledger if this ' +
        'is a negative-control fixture minting a knowingly-broken document on purpose.',
      400,
    );
  }

  // The identifier is minted locally rather than by the SDK because both
  // governance choices may need to refer to it, and both are resolved before any
  // key exists.
  const did = `did:cheqd:${config.cheqdNetwork}:${utils.uuid()}`;
  const verificationMethodId = `${did}${DEVICE_KEY_FRAGMENT}`;

  const controllers = resolveControllerSet(spec.controllers, did);
  const vmController = resolveVerificationMethodController(
    spec.verificationMethodControl,
    did,
  );

  const kms = kmsOf(agent);

  // The private half exists in exactly one of these two places, never both.
  const agentHeldKey = spec.subjectKey ? null : await kms.createKey(ED25519_KEY_SPEC);
  const publicKeyMultibase = spec.subjectKey
    ? assertEd25519Multibase(spec.subjectKey.publicKeyMultibase)
    : toMultibaseRaw(Kms.PublicJwk.fromPublicJwk(agentHeldKey!.publicJwk).publicKey.publicKey);

  const didDocument = {
    '@context': [DID_V1_CONTEXT, ED25519_2020_CONTEXT],
    id: did,
    controller: controllers,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: ED25519_VERIFICATION_KEY_2020,
        controller: vmController,
        publicKeyMultibase,
      },
    ],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
  };

  // The caller's invariant, at the last moment it is still free to fail.
  spec.assertShape(didDocument as CheqdDidDocumentShape);

  // The subject's own signature over its own creation.
  //
  // Not available to any caller — the key is a dozen lines old — so it is the
  // one signature this module supplies itself.
  const subjectSigner: CheqdSigner = spec.subjectKey
    ? {
        did,
        verificationMethodId,
        sign: (payload) => spec.subjectKey!.sign(payload),
      }
    : {
        did,
        verificationMethodId,
        sign: async (payload) =>
          (
            await kms.sign({
              data: payload,
              algorithm: Kms.PublicJwk.fromPublicJwk(agentHeldKey!.publicJwk).signatureAlgorithm,
              keyId: agentHeldKey!.keyId,
            })
          ).signature,
      };

  const required = signerDidsForCreate(didDocument);
  const bySigner = assertSignersCoverRequiredSet(
    required,
    [...spec.signers, subjectSigner],
    `create ${did}`,
  );

  logger.info('cheqd_did_create_requested', {
    did,
    controllers,
    verificationMethodController: vmController,
    verificationMethodIsSelfControlled: vmController === did,
    consensusRequiredSigners: required,
    subjectRequiredByConsensus: required.includes(did),
  });

  const versionId = utils.uuid();
  const payload = await createMsgCreateDidDocPayloadToSign(
    didDocument as never,
    versionId,
  );

  // ===================================================================
  // THE CLIENT GUARD IS STRICTER THAN CONSENSUS, AND ONLY AT CREATION
  // ===================================================================
  // `DIDModule.validateAuthenticationAgainstSignatures` (@cheqd/sdk
  // `modules/did.js:930-1017`) refuses to BUILD the transaction unless every
  // `authentication` key of the new document has signed, on top of each external
  // controller's authentication key. The chain does not require that — S-1 R1
  // created exactly this shape with the device key signing nothing — but the SDK
  // will not let the message be constructed, so the create call fails locally
  // with "signature from key <subject>#key-1 is missing" before any broadcast.
  //
  // Adding the subject's signature satisfies the guard and costs nothing on
  // chain: `VerifyAllSignersHaveAllValidSignatures` (`msg_server.go:112-129`)
  // loops over the REQUIRED signers and looks up signatures by signer, so a
  // signature attributed to a DID outside that set is never examined. Extra
  // signatures are ignored, not rejected.
  //
  // AND IT DOES NOT WEAKEN RECOVERY, which is the only thing that matters here.
  // Recoverability is a property of UPDATE, decided by the verification method's
  // `controller` field. At enrolment the device key demonstrably exists — that is
  // what is being enrolled — so signing once at birth is always possible. What
  // must never be required is its signature LATER, and the rotation path below
  // proves that it is not. R1 showed the device key NEED NOT sign creation; it
  // never showed that it must not.
  const creationSignerDids = uniqueSorted([...required, did]);
  const signInputs = await collectSignatures(creationSignerDids, bySigner, payload);

  const response = await ledgerServiceOf(agent).create(
    didDocument as never,
    signInputs as never,
    versionId,
  );
  assertDelivered(response, `create of ${did}`);

  // Register the DID with Credo so `agent.dids` can dereference and sign with
  // it. Without this, the DID exists on-chain but the agent that minted it
  // cannot issue with it — the exact split-brain the DidRecord prevents.
  //
  // An externally-held subject key records NO key mapping. `agentSigner` will
  // then refuse for this DID, which is exactly right: the backend genuinely
  // cannot sign for a key it does not have, and a record claiming otherwise
  // would be a lie this process would later act on.
  const didRepository = agent.dependencyManager.resolve(DidRepository);
  await didRepository.save(
    agent.context,
    new DidRecord({
      did,
      role: DidDocumentRole.Created,
      didDocument: JsonTransformer.fromJSON(didDocument, DidDocument),
      keys: agentHeldKey
        ? [{ kmsKeyId: agentHeldKey.keyId, didDocumentRelativeKeyId: DEVICE_KEY_FRAGMENT }]
        : [],
    }),
  );

  logger.info('cheqd_did_created', {
    did,
    verificationMethodController: vmController,
    subjectKeyCustody: spec.subjectKey?.custody ?? 'backend-agent-key-store',
    subjectPrivateKeyHeldByBackend: !spec.subjectKey,
    transactionHash: response.transactionHash,
    height: response.height,
  });

  return {
    did,
    didDocument: didDocument as unknown as DIDDocument,
    transactionHash: response.transactionHash,
    height: response.height,
  };
}

// ---------------------------------------------------------------------------
// Rotate
// ---------------------------------------------------------------------------

export interface RotateVerificationMethodSpec {
  readonly did: string;
  /**
   * The replacement public key, multibase-encoded (`z6Mk...`).
   *
   * Supplied by the caller because the real flow generates it on the new device
   * and never exports the private half. When absent the agent generates one, so
   * that server-held identities (an issuer, a controller) can also be rotated.
   */
  readonly nextPublicKeyMultibase?: string;
  readonly signers: readonly CheqdSigner[];
}

export interface RotationResult {
  readonly did: string;
  readonly previousPublicKeyMultibase: string;
  readonly nextPublicKeyMultibase: string;
  readonly transactionHash: string;
  readonly height: number;
}

/**
 * Replace the key material of the subject's verification method WITHOUT a
 * signature from the key being replaced.
 *
 * This is the operation that the self-controlled default makes impossible and
 * that this module's `external` shape makes possible — the code path behind
 * seedless recovery. On a DID minted with a self-controlled verification method
 * it fails here, locally, with the subject named in the missing-signer list,
 * rather than after a consumed block.
 *
 * The verification method's `controller` is CARRIED FORWARD unchanged. Changing
 * it in the same transaction would pull the new controller into the signer set
 * as well (`:152` appends both the old and the new value) and is a distinct
 * decision that deserves its own operation.
 */
export async function rotateVerificationMethod(
  agent: Agent,
  spec: RotateVerificationMethodSpec,
): Promise<RotationResult> {
  assertIsCheqdDid(spec.did, 'did');

  const ledger = ledgerServiceOf(agent);
  // Via `resolveOnChain` so that a DID which was never written surfaces as a
  // clean 404 rather than as a raw ABCI `Query failed with (6)` — and so that
  // an unreachable node still fails loudly instead of masquerading as absence.
  const current = await resolveOnChain(agent, spec.did);

  if (!current || current.deactivated) {
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `Cannot rotate '${spec.did}': the chain returns no live DID document for it.`,
      404,
    );
  }

  const currentVm = (current.verificationMethod ?? [])[0];
  if (!currentVm) {
    throw new AppError(
      ERROR_CODES.DID_RESOLUTION_FAILED,
      `DID '${spec.did}' has no verification method to rotate.`,
      409,
    );
  }

  const controllers = normaliseControllers(current.controller, spec.did);
  const vmController = currentVm.controller as string;

  let nextPublicKeyMultibase = spec.nextPublicKeyMultibase;
  let nextKmsKeyId: string | undefined;
  if (!nextPublicKeyMultibase) {
    const kms = kmsOf(agent);
    const created = await kms.createKey(ED25519_KEY_SPEC);
    nextKmsKeyId = created.keyId;
    nextPublicKeyMultibase = toMultibaseRaw(
      Kms.PublicJwk.fromPublicJwk(created.publicJwk).publicKey.publicKey,
    );
  }

  const previousPublicKeyMultibase = currentVm.publicKeyMultibase as string;
  if (previousPublicKeyMultibase === nextPublicKeyMultibase) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Rotation of '${spec.did}' would install the key it already carries. A no-op update ` +
        'still consumes a block and would leave a lost key in place.',
      400,
    );
  }

  const updated = {
    '@context': [DID_V1_CONTEXT, ED25519_2020_CONTEXT],
    id: spec.did,
    controller: controllers,
    verificationMethod: [
      {
        id: currentVm.id,
        type: ED25519_VERIFICATION_KEY_2020,
        controller: vmController,
        publicKeyMultibase: nextPublicKeyMultibase,
      },
    ],
    authentication: [currentVm.id],
    assertionMethod: [currentVm.id],
  };

  const required = signerDidsForVerificationMethodRotation({
    subjectDid: spec.did,
    controllers,
    previousVerificationMethodController: vmController,
    nextVerificationMethodController: vmController,
  });

  if (required.includes(spec.did) && vmController === spec.did) {
    logger.warn('cheqd_did_rotation_blocked_by_self_controlled_vm', {
      did: spec.did,
      detail:
        'This DID was minted with a self-controlled verification method, so the chain ' +
        'requires the key being replaced to authorise its own replacement. It is ' +
        'unrecoverable and can only be re-issued.',
    });
  }

  const bySigner = assertSignersCoverRequiredSet(
    required,
    spec.signers,
    `rotate the verification method of ${spec.did}`,
  );

  const versionId = utils.uuid();
  const payload = await createMsgUpdateDidDocPayloadToSign(updated as never, versionId);
  const signInputs = await collectSignatures(required, bySigner, payload);

  const response = await ledger.update(updated as never, signInputs as never, versionId);
  assertDelivered(response, `rotation of ${spec.did}`);

  // The local record is updated on BOTH paths, and the difference between them
  // is the point.
  //
  // When this module generated the key it records the mapping, so the agent can
  // keep signing. When the CALLER supplied the key — a handset that kept the
  // private half — the mapping must be REMOVED. Skipping the update in that
  // case, which is what this did, left the agent holding the superseded key and
  // still answering `agentSigner` for the DID: it would sign, and the signature
  // would not verify against the key now on chain. A backend that cannot sign
  // must also know it cannot, or its confidence is the defect.
  const didRepository = agent.dependencyManager.resolve(DidRepository);
  const record = await didRepository.findCreatedDid(agent.context, spec.did);
  if (record) {
    record.didDocument = JsonTransformer.fromJSON(updated, DidDocument);
    record.keys = nextKmsKeyId
      ? [
          {
            kmsKeyId: nextKmsKeyId,
            didDocumentRelativeKeyId: currentVm.id.slice(spec.did.length),
          },
        ]
      : [];
    await didRepository.update(agent.context, record);
  }

  logger.info('cheqd_did_verification_method_rotated', {
    did: spec.did,
    verificationMethodController: vmController,
    signedBy: required,
    deviceKeyParticipated: required.includes(spec.did),
    transactionHash: response.transactionHash,
    height: response.height,
  });

  return {
    did: spec.did,
    previousPublicKeyMultibase,
    nextPublicKeyMultibase,
    transactionHash: response.transactionHash,
    height: response.height,
  };
}

/**
 * An absent or empty controller list means "the subject controls itself" on
 * chain, so it is expanded here rather than passed through as an empty array —
 * an update that dropped the controller list would silently rewrite the
 * controller set to the subject.
 */
function normaliseControllers(
  controller: string | string[] | undefined,
  subjectDid: string,
): string[] {
  if (!controller) return [subjectDid];
  const list = Array.isArray(controller) ? controller : [controller];
  return list.length > 0 ? list : [subjectDid];
}

// ---------------------------------------------------------------------------
// Deactivate
// ---------------------------------------------------------------------------

export interface DeactivationResult {
  readonly did: string;
  readonly transactionHash: string;
  readonly height: number;
}

/**
 * Deactivate a did:cheqd. TERMINAL — there is no revival path.
 *
 * ===========================================================================
 * READ THIS BEFORE CALLING IT
 * ===========================================================================
 * `UpdateDidDoc:41-43` checks `Metadata.Deactivated` before it looks at any
 * signature, so a deactivated DID can never be updated again by anyone holding
 * any key (S-4 T1, `code 1207` at height 86535). Deactivation is also itself a
 * transaction that can fail, so it is not a reliable last step for anything.
 *
 * AND IT IS UNAVAILABLE EXACTLY WHEN IT WOULD BE MOST USEFUL. The signer set is
 * the CREATION set — controllers ∪ ALL verification-method controllers
 * (`msg_server_deactivate_diddoc.go:53-54`), which is stricter than the update
 * set. S-1 §5.6 D1 measured the consequence: a recovery service holding every
 * controller key still could not deactivate, because the subject's own device
 * key was a VM controller. For the unrecoverable single-self-controlled shape
 * that set is `{the DID itself}` — the lost key. So a DID that has become
 * unrecoverable through key loss ALSO CANNOT BE DEACTIVATED. Any workflow whose
 * tombstone depends on this call is a workflow that cannot run on the day it is
 * needed; see `services/reissuance/reissuanceService.ts`, where it is an
 * optional extra and nothing depends on it.
 */
export async function deactivateCheqdDID(
  agent: Agent,
  did: string,
): Promise<DeactivationResult> {
  const current = await resolveOnChain(agent, did);

  if (!current) {
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `Cannot deactivate '${did}': the chain returns no document for it. Note that this is ` +
        'ABSENCE, not unreachability — a stopped node throws instead of reaching here.',
      404,
    );
  }

  if (current.deactivated) {
    // Not an error worth a failed transaction. Deactivation is idempotent in
    // effect but not on chain: a second attempt is rejected 1207 and costs a
    // block, so it is short-circuited here.
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `'${did}' is already deactivated. Re-submitting would be rejected with code 1207 and ` +
        'consume a block to tell you what you already know.',
      409,
    );
  }

  // The CREATION signer set, not the update one. This is the whole difference
  // S-1 D1 identified.
  const required = signerDidsForCreate({
    id: current.did,
    controller: current.controller,
    verificationMethod: current.verificationMethod,
  });

  const signers: CheqdSigner[] = [];
  const unavailable: string[] = [];
  for (const signerDid of required) {
    try {
      signers.push(await agentSigner(agent, signerDid));
    } catch {
      unavailable.push(signerDid);
    }
  }

  if (unavailable.length > 0) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Cannot deactivate '${did}': deactivation needs a signature from EVERY controller AND ` +
        `every verification-method controller (S-1 §5.6 D1), and this agent holds no key for ` +
        `${unavailable.join(', ')}. Broadcasting anyway would consume a block and return ` +
        '1101 naming only the first of them.',
      400,
    );
  }

  const bySigner = assertSignersCoverRequiredSet(required, signers, `deactivate ${did}`);

  logger.warn('cheqd_did_deactivate_requested', {
    did,
    consensusRequiredSigners: required,
    terminal: 'No revival path exists in x/did (S-4 T1).',
  });

  // THE FULL DOCUMENT, NOT `{ id }`. `createMsgDeactivateDidDocPayloadToSign`
  // only reads `.id`, so a bare identifier signs correctly and looks right —
  // but `CheqdLedgerService.deactivate` runs the payload through
  // `validateSpecCompliantPayload` first and rejects it locally with
  // "DID payload is not spec compliant: verificationMethod is required",
  // before any broadcast. Measured on the first R5 migration run (steno #314).
  const documentForValidation = {
    id: current.did,
    controller: current.controller,
    verificationMethod: current.verificationMethod,
    authentication: current.authentication,
    ...(current.assertionMethod.length > 0 ? { assertionMethod: current.assertionMethod } : {}),
  };

  const versionId = utils.uuid();
  const payload = createMsgDeactivateDidDocPayloadToSign(documentForValidation as never, versionId);
  const signInputs = await collectSignatures(required, bySigner, payload);

  const response = await ledgerServiceOf(agent).deactivate(
    documentForValidation as never,
    signInputs as never,
    versionId,
  );
  assertDelivered(response, `deactivate of ${did}`);

  // THE LEDGER, NOT THE RESPONSE. A code-0 delivery is necessary but the
  // metadata flag is what every resolver actually reads.
  const after = await resolveOnChain(agent, did);
  if (!after?.deactivated) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `'${did}' was reported deactivated at height ${response.height} but still resolves as ` +
        'live. Refusing to report a tombstone that is not there.',
      502,
    );
  }

  logger.warn('cheqd_did_deactivated', {
    did,
    transactionHash: response.transactionHash,
    height: response.height,
  });

  return { did, transactionHash: response.transactionHash, height: response.height };
}
