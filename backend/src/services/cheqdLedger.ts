/**
 * SSI Healthcare Backend — the low-level did:cheqd write path.
 *
 * Signing, signer-set completeness, key generation and broadcast. Nothing in
 * here knows what an institution or a patient is; the shapes those concepts
 * require live in `@ssi-healthcare/sdk/ledger` and the flows that use them live in
 * `institutionalDid.ts` / `patientEnrolment.ts`.
 *
 * ===========================================================================
 * WHY BROADCAST GOES THROUGH `CheqdLedgerService` AND NOT `CheqdDidRegistrar`
 * ===========================================================================
 * `CheqdDidRegistrar.create` signs a create payload with the AUTHENTICATION
 * verification methods of the document being created and with nothing else
 * (`CheqdDidRegistrar.mjs:145` → `signPayload` at :421). Creation is checked
 * against `GetSignerDIDsForDIDCreation` = controllers ∪ ALL vm-controllers
 * (`msg_server_create_diddoc.go:58-59`), so any document with an external
 * controller needs a signature the registrar structurally cannot produce.
 *
 * `CheqdLedgerService` accepts arbitrary sign inputs, and keeps the patched,
 * sovereign-fork-aware network configuration (`rpcUrl` mandatory, no
 * `DefaultRPCUrl`, our `bdhealthtestnet` namespace) as the single source of
 * ledger truth instead of standing up a second, divergent SDK client.
 */

import { DidRepository, Kms, utils } from '@credo-ts/core';
import { CheqdLedgerService } from '@credo-ts/cheqd';
import { toMultibaseRaw } from '@cheqd/sdk/utils';
import type { Agent } from '@credo-ts/core';

import { config } from '../config/index.js';
import { AppError } from '../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import { didPartOf } from '@ssi-healthcare/sdk/ledger';

/** The key spec for every did:cheqd key. The chain accepts nothing else. */
export const ED25519_KEY_SPEC = { type: { kty: 'OKP', crv: 'Ed25519' } } as const;

/**
 * A DID that can produce a signature the cheqd `x/did` module will attribute
 * to it.
 *
 * `FindSignInfosBySigner` (`x/did/types/tx_sign_info.go:47-59`) attributes a
 * signature by splitting the DID URL at `#` and comparing the DID part, and
 * SILENTLY IGNORES signatures belonging to no required signer. A signer whose
 * `verificationMethodId` does not begin with its own `did` therefore does not
 * fail loudly — it simply does not count.
 */
export interface CheqdSigner {
  readonly did: string;
  /** An absolute DID URL under {@link did}, e.g. `did:cheqd:...#key-1`. */
  readonly verificationMethodId: string;
  sign(payload: Uint8Array): Promise<Uint8Array>;
}

export interface SignInfo {
  readonly verificationMethodId: string;
  readonly signature: Uint8Array;
}

export interface LedgerWriteResult {
  readonly transactionHash: string;
  readonly height: number;
}

// ---------------------------------------------------------------------------
// Agent plumbing
// ---------------------------------------------------------------------------

export function ledgerServiceOf(agent: Agent): CheqdLedgerService {
  return agent.dependencyManager.resolve(CheqdLedgerService);
}

export function kmsOf(agent: Agent): Kms.KeyManagementApi {
  return agent.dependencyManager.resolve(Kms.KeyManagementApi);
}

export function didRepositoryOf(agent: Agent): DidRepository {
  return agent.dependencyManager.resolve(DidRepository);
}

export function newCheqdDid(): string {
  return `did:cheqd:${config.cheqdNetwork}:${utils.uuid()}`;
}

export interface GeneratedKey {
  readonly kmsKeyId: string;
  readonly publicKeyMultibase: string;
  readonly signatureAlgorithm: Kms.KnownJwaSignatureAlgorithm;
}

/** Generate an Ed25519 key in the agent's own store and describe it as the chain wants it. */
export async function generateEd25519Key(agent: Agent): Promise<GeneratedKey> {
  const { keyId, publicJwk } = await kmsOf(agent).createKey(ED25519_KEY_SPEC);
  const jwk = Kms.PublicJwk.fromPublicJwk(publicJwk);
  return {
    kmsKeyId: keyId,
    publicKeyMultibase: toMultibaseRaw(jwk.publicKey.publicKey),
    signatureAlgorithm: jwk.signatureAlgorithm,
  };
}

/** A {@link CheqdSigner} over a key this agent holds, bound to a chosen VM id. */
export function kmsSigner(
  agent: Agent,
  args: {
    readonly did: string;
    readonly verificationMethodId: string;
    readonly kmsKeyId: string;
    readonly signatureAlgorithm: Kms.KnownJwaSignatureAlgorithm;
  },
): CheqdSigner {
  return {
    did: args.did,
    verificationMethodId: args.verificationMethodId,
    async sign(payload: Uint8Array): Promise<Uint8Array> {
      const { signature } = await kmsOf(agent).sign({
        data: payload,
        algorithm: args.signatureAlgorithm,
        keyId: args.kmsKeyId,
      });
      return signature;
    },
  };
}

/**
 * A {@link CheqdSigner} for a did:cheqd this agent created and still holds keys
 * for.
 *
 * `slotFragment` selects which verification method to sign with, which matters
 * from the moment a DID has more than one — a 1-of-N institutional DID has N,
 * and by S-4 M1 any one of them satisfies the requirement.
 */
export async function agentSigner(
  agent: Agent,
  did: string,
  slotFragment?: string,
): Promise<CheqdSigner> {
  const record = await didRepositoryOf(agent).findCreatedDid(agent.context, did);

  if (!record) {
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `This agent holds no created-DID record for '${did}', so it cannot sign for it.`,
      404,
    );
  }

  const entries = record.keys ?? [];
  const entry = slotFragment
    ? entries.find((key) => key.didDocumentRelativeKeyId === slotFragment)
    : entries[0];

  if (!entry) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      slotFragment
        ? `DID record for '${did}' carries no key for slot '${slotFragment}'. It holds ` +
          `[${entries.map((k) => k.didDocumentRelativeKeyId).join(', ') || 'nothing'}].`
        : `DID record for '${did}' carries no key mapping, so it cannot sign.`,
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
  // symmetric ones that cannot sign at all. Narrowing here means a DID record
  // pointing at the wrong key fails with the key named.
  if (publicJwk.kty !== 'OKP' || publicJwk.crv !== 'Ed25519') {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Key '${entry.kmsKeyId}' for DID '${did}' is ${Kms.getJwkHumanDescription(publicJwk)}, ` +
        'which did:cheqd cannot use. Every cheqd verification method is Ed25519.',
      500,
    );
  }

  return kmsSigner(agent, {
    did,
    verificationMethodId: `${did}${entry.didDocumentRelativeKeyId}`,
    kmsKeyId: entry.kmsKeyId,
    signatureAlgorithm: Kms.PublicJwk.fromPublicJwk(publicJwk).signatureAlgorithm,
  });
}

// ---------------------------------------------------------------------------
// Signer-set completeness — computed locally, never learned from the chain
// ---------------------------------------------------------------------------

export function assertSignerIsWellFormed(signer: CheqdSigner): void {
  if (didPartOf(signer.verificationMethodId) !== signer.did) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Signer for '${signer.did}' offers verification method ` +
        `'${signer.verificationMethodId}', which belongs to a different DID. The ledger ` +
        'attributes a signature by the DID part of this URL and silently IGNORES signatures ' +
        'it cannot attribute, so this would have produced a missing-signature rejection ' +
        'naming an unrelated DID.',
      400,
    );
  }
}

/**
 * Fail with the WHOLE missing set, not the first element of it.
 *
 * `msg_server.go:136` returns on the FIRST unsatisfied signer over a sorted
 * list, so a rejection names one missing signature even when several are
 * missing (S-1 §5.2's operational gotcha, and S-4 U2 which named only `A`).
 * A caller that learns its gaps from the ledger burns a block per gap and is
 * misled about which one mattered.
 */
export function assertSignersCoverRequiredSet(
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
        'return code 1101 naming only the first of them.',
      400,
    );
  }

  return bySigner;
}

export async function collectSignatures(
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

// ---------------------------------------------------------------------------
// Broadcast
// ---------------------------------------------------------------------------

/**
 * `DeliverTx`, not the broadcast result.
 *
 * In Cosmos SDK v0.50 `CheckTx` does not execute the message, so a sync-mode
 * broadcast reports `code: 0` for a transaction the DID module will reject.
 * `CheqdLedgerService` broadcasts and waits, so `response.code` here is already
 * the delivery code — but the distinction is named because reading the wrong
 * one produced the wrong answer for every rejection during spikes S-1 and S-4.
 */
export function assertDelivered(
  response: { code: number; rawLog?: string; transactionHash: string; height: number },
  operation: string,
): LedgerWriteResult {
  if (response.code !== 0) {
    throw new AppError(
      ERROR_CODES.DID_CREATION_FAILED,
      `Ledger rejected ${operation} with code ${response.code}: ${response.rawLog ?? ''}`,
      502,
    );
  }
  return { transactionHash: response.transactionHash, height: response.height };
}

export interface ResolvedCheqdDid {
  readonly did: string;
  readonly controller: string[];
  readonly verificationMethod: {
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase: string;
  }[];
  readonly authentication: string[];
  readonly assertionMethod: string[];
  readonly deactivated: boolean;
}

/**
 * Read the CHAIN, never the agent's cache.
 *
 * Credo will happily return a well-formed document from its own store for a
 * DID that never changed on chain, which is exactly how a failed write looks
 * like a successful one.
 */
/**
 * A DID that has never been written produces an ABCI error rather than an empty
 * result. Verbatim:
 *
 *   `Query failed with (6): did:cheqd:bdhealthtestnet:<uuid>: not found: unknown request`
 *
 * ABSENCE AND UNREACHABILITY MUST NOT COLLAPSE INTO ONE ANSWER. That error is
 * proof the node answered — a stopped validator produces a transport failure
 * (`fetch failed`, ECONNREFUSED) with no ABCI code at all. Treating both as
 * "no such DID" would let a stopped container silently report every patient
 * identity as missing, which is the same transient/permanent conflation
 * `assertHolderBound` exists to keep apart.
 */
function isDefinitivelyNotFound(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes('Query failed with (6)') && message.includes(': not found');
}

export async function resolveOnChain(agent: Agent, did: string): Promise<ResolvedCheqdDid | null> {
  let resolved: Awaited<ReturnType<CheqdLedgerService['resolve']>>;
  try {
    resolved = await ledgerServiceOf(agent).resolve(did);
  } catch (error) {
    if (isDefinitivelyNotFound(error)) return null;
    throw error;
  }

  const document = resolved.didDocument as
    | {
        id?: string;
        controller?: string[] | string;
        verificationMethod?: {
          id: string;
          type: string;
          controller: string;
          publicKeyMultibase: string;
        }[];
        authentication?: string[];
        assertionMethod?: string[];
      }
    | undefined;

  if (!document?.id) return null;

  const controller = document.controller
    ? Array.isArray(document.controller)
      ? document.controller
      : [document.controller]
    : [];

  return {
    did: document.id,
    controller,
    verificationMethod: document.verificationMethod ?? [],
    authentication: document.authentication ?? [],
    assertionMethod: document.assertionMethod ?? [],
    deactivated: resolved.didDocumentMetadata?.deactivated === true,
  };
}

export async function requireLiveDidOnChain(
  agent: Agent,
  did: string,
  operation: string,
): Promise<ResolvedCheqdDid> {
  const resolved = await resolveOnChain(agent, did);

  if (!resolved) {
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `Cannot ${operation}: the chain returns no DID document for '${did}'.`,
      404,
    );
  }

  if (resolved.deactivated) {
    // `UpdateDidDoc:41-43` checks Deactivated before it looks at signatures, so
    // this is terminal and no signature can help (S-4 T1, code 1207).
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `Cannot ${operation}: '${did}' is DEACTIVATED. Deactivation is terminal — the module ` +
        'has no revival path (S-4 T1, code 1207 at height 86535).',
      409,
    );
  }

  return resolved;
}
