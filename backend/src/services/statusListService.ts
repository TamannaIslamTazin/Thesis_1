/**
 * SSI Healthcare Backend — Bitstring Status List (revocation) service.
 *
 * This module is the whole of credential revocation: it publishes an issuer's
 * revocation list to the cheqd ledger as a DID-Linked Resource, hands out the
 * bit positions that `credentialStatus` points at, and reads a bit back off
 * the chain when someone asks whether a credential is still good.
 *
 * ---------------------------------------------------------------------------
 * WHY BitstringStatusList AND NOT StatusList2021
 * ---------------------------------------------------------------------------
 * `StatusList2021` was renamed to `BitstringStatusList` when the W3C work item
 * became a Recommendation, and VC Data Model 2.0 references the new name. The
 * two are the same bitmap with different labels, so building on the old name
 * would mean redoing this when the VC 2.0 / SD-JWT migration lands.
 *
 * Nothing blocks the new name here, and the reason is that neither layer
 * validates it:
 *
 *   - cheqd's `resourceType` is a free-form client-defined string. The proto
 *     comment (@cheqd/ts-proto/cheqd/resource/v2/resource.ts:48-50) calls it
 *     "Defined client-side" and lists `AnonCredsSchema, StatusList2021` only as
 *     EXAMPLES. The chain stores whatever string it is given.
 *   - Credo never inspects the type either. See the note on
 *     `verifyCredentialStatus` below — it does not implement status checking
 *     for JWT VCs at all, so it has no opinion about which flavour we use.
 *
 * So `BitstringStatusListRevocation` is written to the ledger and
 * `BitstringStatusListEntry` into the credential, and the migration to VC 2.0
 * will not have to touch this file.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS DOES NOT USE Credo's `verifyCredentialStatus: true`
 * ---------------------------------------------------------------------------
 * Because Credo 0.6 cannot do it. The check is not unimplemented-and-failing,
 * it is a hard-coded refusal:
 *
 *   node_modules/@credo-ts/core/build/modules/vc/jwt-vc/W3cJwtCredentialService.mjs:114
 *     if (verifyCredentialStatus && !credential.credentialStatus)
 *       validations.credentialStatus = { isValid: true }
 *     else if (verifyCredentialStatus && credential.credentialStatus)
 *       validations.credentialStatus = { isValid: false,
 *         error: new CredoError('Verifying credential status is not supported for JWT VCs') }
 *
 * Note the shape of that: a credential with NO status passes, and a credential
 * WITH a status fails unconditionally. There is no third branch and no
 * resolver to plug in. Turning the flag on therefore does not "enable
 * revocation checking" — it makes exactly the credentials that carry
 * revocation information fail, and only those. Every credential this system
 * issues now carries one, so it would fail all of them.
 *
 * `checkStatusOnLedger()` below is the replacement: it dereferences the status
 * list from the chain and reads the bit. That is a stronger check than the
 * flag would have given us even if it worked, because it is backed by the
 * ledger rather than by this server's own database.
 */

import { gzipSync, gunzipSync } from 'node:zlib';
import { randomUUID } from 'node:crypto';
import { W3cCredentialStatus, W3cV2CredentialStatus } from '@credo-ts/core';
import { VC_CONTEXTS } from '@ssi-healthcare/shared';
import { getAgent } from '../agent/index.js';
import { publishResourceSignedByAgent } from './cheqdDid.js';
import { logger } from '../utils/logger.js';
import { db } from '../db/index.js';
import type { CredentialStatusList } from '../../prisma/generated/client/index.js';

/**
 * Bits per list. 131,072 (16 KiB uncompressed) is the minimum the W3C
 * Bitstring Status List spec mandates, and the reason is privacy rather than
 * capacity: a verifier that fetches the list must not be able to infer WHICH
 * credential is being checked. An all-zero list of this size gzips to ~150
 * bytes, so the herd-privacy floor is nearly free.
 */
export const STATUS_LIST_LENGTH = 131072;

/** cheqd DLR `resourceType`. Free-form on-chain; this is our convention. */
export const STATUS_LIST_RESOURCE_TYPE = 'BitstringStatusListRevocation';
/** cheqd DLR `name`. Stable across versions — see the model doc comment. */
export const STATUS_LIST_RESOURCE_NAME = 'revocation';

/** `credentialStatus.type` written into every issued credential. */
export const STATUS_ENTRY_TYPE = 'BitstringStatusListEntry';

/** JSON-LD context for the status list credential itself. */
export const BITSTRING_STATUS_LIST_CONTEXT = 'https://www.w3.org/ns/credentials/status/v1';

/** The shape Credo's `W3cCredentialStatus` cannot express on its own. */
export interface BitstringStatusListEntry {
  id: string;
  type: typeof STATUS_ENTRY_TYPE;
  statusPurpose: string;
  statusListIndex: string;
  statusListCredential: string;
}

// ---------------------------------------------------------------------------
// Bitstring encoding
// ---------------------------------------------------------------------------

/**
 * Encode a set of revoked indices as a Bitstring Status List `encodedList`.
 *
 * The spec requires a MULTIBASE-encoded, GZIP-compressed bitstring — note the
 * multibase part, which is where this differs from StatusList2021. The
 * `credentials/status/v1` context types `encodedList` as
 * `https://w3id.org/security#multibase`, so the value carries a `u` prefix
 * identifying base64url-without-padding. StatusList2021 used bare base64url
 * with no prefix; emitting the bare form under the new type would be a subtly
 * malformed credential that most verifiers would still accept, which is the
 * worst kind of wrong.
 *
 * Bit order within a byte is most-significant-first: index 0 is 0x80 of byte
 * 0, index 7 is 0x01 of byte 0, index 8 is 0x80 of byte 1.
 */
export function encodeStatusList(revokedIndices: Iterable<number>, length = STATUS_LIST_LENGTH): string {
  const bytes = new Uint8Array(Math.ceil(length / 8));

  for (const index of revokedIndices) {
    if (!Number.isInteger(index) || index < 0 || index >= length) {
      // A caller that hands us an out-of-range index has a bug that would
      // otherwise corrupt an unrelated credential's bit, or silently do
      // nothing. Neither is acceptable for a revocation primitive.
      throw new Error(`Status list index ${index} is outside the list (length ${length})`);
    }
    // eslint-disable-next-line no-bitwise
    bytes[index >>> 3]! |= 0x80 >>> (index & 7);
  }

  return `u${gzipSync(Buffer.from(bytes)).toString('base64url')}`;
}

/**
 * Decode an `encodedList` back to its raw bitstring bytes.
 *
 * Accepts both the multibase `u`-prefixed form this module writes and the bare
 * base64url a StatusList2021 producer would emit, so a credential issued
 * against another implementation's list can still be checked.
 */
export function decodeStatusList(encodedList: string): Uint8Array {
  const body = encodedList.startsWith('u') ? encodedList.slice(1) : encodedList;
  return new Uint8Array(gunzipSync(Buffer.from(body, 'base64url')));
}

/** Read one bit. `true` means the status is set — for `revocation`, revoked. */
export function readStatusBit(bytes: Uint8Array, index: number): boolean {
  const byte = bytes[index >>> 3];
  if (byte === undefined) return false;
  // eslint-disable-next-line no-bitwise
  return (byte & (0x80 >>> (index & 7))) !== 0;
}

// ---------------------------------------------------------------------------
// DID URLs
// ---------------------------------------------------------------------------

/**
 * The DID URL that dereferences to the CURRENT version of a status list.
 *
 * This deliberately uses `?resourceName=&resourceType=` rather than the
 * pinned `did/resources/<uuid>` form. cheqd versions a resource by
 * (collectionId, name, resourceType), and Credo's resolver
 * (dids/CheqdDidResolver.mjs:56-67) treats a name+type query by listing the
 * collection, filtering to that name and type, and picking the version closest
 * to `resourceVersionTime` — defaulting to *now*, i.e. the latest.
 *
 * That is the entire reason revocation works after the fact: credentials
 * already issued and sitting in wallets point at this URL, so when we publish
 * a new version of the list, every one of them starts resolving to the new
 * bitmap without being reissued. A `/resources/<uuid>` URL would pin each
 * credential to the list as it existed the day it was issued, which would make
 * revocation permanently invisible.
 */
export function statusListCredentialUrl(list: Pick<CredentialStatusList, 'issuerDid' | 'resourceName' | 'resourceType'>): string {
  return `${list.issuerDid}?resourceName=${list.resourceName}&resourceType=${list.resourceType}`;
}

/** The per-credential entry URL: the list URL with the bit index as fragment. */
export function statusEntryId(list: Pick<CredentialStatusList, 'issuerDid' | 'resourceName' | 'resourceType'>, index: number): string {
  return `${statusListCredentialUrl(list)}#${index}`;
}

// ---------------------------------------------------------------------------
// Allocation
// ---------------------------------------------------------------------------

/** Get the issuer's revocation list row, creating it on first use. */
export async function getOrCreateStatusList(
  issuerDid: string,
  purpose = 'revocation',
): Promise<CredentialStatusList> {
  const existing = await db.credentialStatusList.findUnique({
    where: { issuerDid_purpose: { issuerDid, purpose } },
  });
  if (existing) return existing;

  return db.credentialStatusList.create({
    data: {
      issuerDid,
      purpose,
      resourceName: STATUS_LIST_RESOURCE_NAME,
      resourceType: STATUS_LIST_RESOURCE_TYPE,
      length: STATUS_LIST_LENGTH,
    },
  });
}

/**
 * Reserve the next free bit for a credential about to be issued.
 *
 * The increment runs inside a transaction with the read, because two
 * concurrent issuances that both read `nextIndex = n` would both write
 * `n + 1` and hand the same bit to two different credentials — revoking
 * either would then revoke both. The `@@unique([statusListId,
 * statusListIndex])` constraint on `Credential` is the second line of defence
 * if that ever slips through.
 */
export async function allocateStatusIndex(
  issuerDid: string,
  purpose = 'revocation',
): Promise<{ list: CredentialStatusList; index: number }> {
  return db.$transaction(async (tx) => {
    let list = await tx.credentialStatusList.findUnique({
      where: { issuerDid_purpose: { issuerDid, purpose } },
    });

    if (!list) {
      list = await tx.credentialStatusList.create({
        data: {
          issuerDid,
          purpose,
          resourceName: STATUS_LIST_RESOURCE_NAME,
          resourceType: STATUS_LIST_RESOURCE_TYPE,
          length: STATUS_LIST_LENGTH,
        },
      });
    }

    const index = list.nextIndex;
    if (index >= list.length) {
      // Refusing is correct: wrapping around would reuse a live credential's
      // bit. A full list needs a new list (a `revocation-2` resource), which
      // is a deliberate operation, not something to do implicitly mid-issuance.
      throw new Error(
        `Status list for ${issuerDid} is exhausted (${list.length} entries). A new list must be provisioned.`,
      );
    }

    const updated = await tx.credentialStatusList.update({
      where: { id: list.id },
      data: { nextIndex: index + 1 },
    });

    return { list: updated, index };
  });
}

/** Build the `credentialStatus` object for an allocated index. */
export function buildStatusEntry(list: CredentialStatusList, index: number): BitstringStatusListEntry {
  return {
    id: statusEntryId(list, index),
    type: STATUS_ENTRY_TYPE,
    statusPurpose: list.purpose,
    statusListIndex: String(index),
    statusListCredential: statusListCredentialUrl(list),
  };
}

/**
 * Adapt a `BitstringStatusListEntry` into the object Credo will actually sign.
 *
 * This exists because of a real gap in Credo 0.6's VC 1.1 model. Its
 * `W3cCredentialStatus` class declares exactly two members and its constructor
 * copies exactly two:
 *
 *   node_modules/@credo-ts/core/build/modules/vc/models/credential/W3cCredentialStatus.mjs
 *     constructor(options) { if (options) { this.id = options.id; this.type = options.type } }
 *
 * A BitstringStatusListEntry needs three more (`statusPurpose`,
 * `statusListIndex`, `statusListCredential`). Passing them to the constructor
 * drops them on the floor — silently, which is how you end up shipping a
 * credential whose status points nowhere.
 *
 * Constructing first and assigning after works, and works for a specific
 * reason worth recording: `W3cCredential` validates this field with
 * `IsInstance(W3cCredentialStatus)` (satisfied — it IS an instance) and
 * serializes it with `JsonTransformer.toJSON`, which calls class-transformer's
 * `instanceToPlain` WITHOUT `excludeExtraneousValues`. That includes every own
 * enumerable property, not just the decorated ones, so the extra three survive
 * into the JWT `vc` claim. Verified end to end: all five members appear in the
 * signed token and the credential still verifies.
 *
 * If Credo ever tightens that to `excludeExtraneousValues: true`, this breaks
 * loudly (the members vanish) rather than subtly, and the fix is to move to
 * the VC 2.0 stack whose `W3cV2CredentialStatus` models these natively.
 */
export function toCredoCredentialStatus(entry: BitstringStatusListEntry): W3cCredentialStatus {
  const status = new W3cCredentialStatus({ id: entry.id, type: entry.type });
  Object.assign(status, {
    statusPurpose: entry.statusPurpose,
    statusListIndex: entry.statusListIndex,
    statusListCredential: entry.statusListCredential,
  });
  return status;
}

/**
 * The VC 2.0 equivalent, and the one issuance actually uses now.
 *
 * This is the "fix" the note above predicted. `W3cV2CredentialStatus` declares
 * `[property: string]: unknown` and its constructor copies every option, so all
 * five members of a `BitstringStatusListEntry` are modelled natively — no
 * construct-then-assign, and no dependence on class-transformer's default
 * `excludeExtraneousValues: false` to smuggle them through serialization.
 *
 * `toCredoCredentialStatus` above is kept for the VC 1.1 path, which still
 * exists for credentials issued before the migration.
 */
export function toCredoV2CredentialStatus(
  entry: BitstringStatusListEntry,
): W3cV2CredentialStatus {
  return new W3cV2CredentialStatus({
    id: entry.id,
    type: entry.type,
    statusPurpose: entry.statusPurpose,
    statusListIndex: entry.statusListIndex,
    statusListCredential: entry.statusListCredential,
  });
}

// ---------------------------------------------------------------------------
// Publishing
// ---------------------------------------------------------------------------

/**
 * Build the status list credential document, deriving the bitmap from the
 * database rather than from any cached copy.
 *
 * Regenerating from `status = REVOKED` on every publish is what makes the
 * ledger copy incapable of drifting: there is no separate revocation state to
 * fall out of sync, because the bitmap has no independent existence.
 */
export async function buildStatusListCredential(list: CredentialStatusList) {
  const revoked = await db.credential.findMany({
    where: { statusListId: list.id, status: 'REVOKED' },
    select: { statusListIndex: true },
  });

  const indices = revoked
    .map((r) => r.statusListIndex)
    .filter((i): i is number => i !== null);

  const encodedList = encodeStatusList(indices, list.length);
  const listUrl = statusListCredentialUrl(list);

  return {
    document: {
      // VC 2.0, matching what the system issues. BitstringStatusList is itself
      // specified against VC 2.0, so this is the context the spec's own
      // examples use — the v1 context here was the odd one out even before the
      // migration.
      //
      // Safe to change: the only reader of this document, `checkStatusOnLedger`
      // below, dereferences `credentialSubject.encodedList` and never inspects
      // `@context` or `type`. The encoding of `encodedList` is unchanged, and
      // `decodeStatusList` already accepts both the multibase `u`-prefixed form
      // and the bare base64url form, so lists published before this commit keep
      // resolving. That matters more than usual here: credentials already in
      // wallets point at these lists by name+type URL, so a list that stopped
      // being readable would take revocation down for them.
      '@context': [
        VC_CONTEXTS.W3C_CREDENTIALS_V2,
        BITSTRING_STATUS_LIST_CONTEXT,
      ],
      id: listUrl,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: list.issuerDid,
      validFrom: new Date().toISOString(),
      credentialSubject: {
        id: `${listUrl}#list`,
        type: 'BitstringStatusList',
        statusPurpose: list.purpose,
        encodedList,
      },
    },
    revokedIndices: indices,
  };
}

/**
 * Write the issuer's current status list to the ledger as a new DLR version.
 *
 * Every call creates a NEW resource UUID under the SAME name and type, which
 * is how cheqd expresses a new version of an existing resource rather than an
 * unrelated one. Resolvers asking for the name+type URL then see this one.
 */
export async function publishStatusList(list: CredentialStatusList): Promise<{
  resourceId: string;
  version: number;
  revokedIndices: number[];
  encodedList: string;
}> {
  const { document, revokedIndices } = await buildStatusListCredential(list);
  const resourceId = randomUUID();
  const version = list.version + 1;

  logger.info('Publishing status list to ledger', {
    issuerDid: list.issuerDid,
    resourceId,
    version,
    revokedCount: revokedIndices.length,
  });

  // NOT `agent.modules.cheqd.createResource`: that signs with EVERY
  // verification method in the document, which a 1-of-N institutional DID
  // holding a foreign key cannot satisfy — see publishResourceSignedByAgent
  // for the measurement and why signing with one held key is correct.
  await publishResourceSignedByAgent(getAgent(), list.issuerDid, {
    id: resourceId,
    name: list.resourceName,
    resourceType: list.resourceType,
    version: String(version),
    data: document,
  });

  await db.credentialStatusList.update({
    where: { id: list.id },
    data: { latestResourceId: resourceId, version, publishedAt: new Date() },
  });

  logger.info('Status list published', { resourceId, version, revokedCount: revokedIndices.length });

  return {
    resourceId,
    version,
    revokedIndices,
    encodedList: document.credentialSubject.encodedList,
  };
}

/**
 * Ensure the issuer has a status list ON THE LEDGER before a credential that
 * points at it is issued.
 *
 * Order matters. If the credential were issued first, it would carry a
 * `statusListCredential` URL that dereferences to nothing until the first
 * revocation happened to publish one — and a verifier is required to treat an
 * unresolvable status list as an error, so those credentials would be
 * unverifiable in the window between issuance and first revocation.
 */
export async function ensureStatusListPublished(list: CredentialStatusList): Promise<CredentialStatusList> {
  if (list.publishedAt && list.latestResourceId) return list;

  await publishStatusList(list);

  const refreshed = await db.credentialStatusList.findUnique({ where: { id: list.id } });
  return refreshed ?? list;
}

// ---------------------------------------------------------------------------
// Checking
// ---------------------------------------------------------------------------

export interface StatusCheckResult {
  /** `true` when the bit is set — for a revocation list, the credential is revoked. */
  revoked: boolean;
  /** `false` when the list could not be dereferenced or parsed. */
  checked: boolean;
  /** The list URL that was dereferenced. */
  statusListCredential?: string;
  index?: number;
  error?: string;
}

/**
 * Dereference a credential's status list from the ledger and read its bit.
 *
 * This is what replaces Credo's unusable `verifyCredentialStatus` flag. It
 * reads the CHAIN, not this server's database, so it gives the same answer to
 * a third-party verifier as it does to us — which is the entire point of
 * publishing the list rather than exposing a revocation endpoint.
 *
 * Returns `checked: false` rather than throwing when the list cannot be
 * resolved. The caller decides what an unresolvable list means; this function
 * does not get to make that policy choice silently, and in particular does not
 * get to report "not revoked" for a list it never read.
 */
export async function checkStatusOnLedger(
  credentialStatus: { id?: string; type?: string; statusListIndex?: string; statusListCredential?: string } | undefined,
): Promise<StatusCheckResult> {
  if (!credentialStatus) {
    return { revoked: false, checked: false, error: 'Credential carries no credentialStatus' };
  }

  const { statusListCredential, statusListIndex } = credentialStatus;
  if (!statusListCredential || statusListIndex === undefined) {
    return { revoked: false, checked: false, error: 'credentialStatus is missing statusListCredential or statusListIndex' };
  }

  const index = Number(statusListIndex);
  if (!Number.isInteger(index) || index < 0) {
    return { revoked: false, checked: false, error: `Invalid statusListIndex '${statusListIndex}'` };
  }

  try {
    const agent = getAgent();
    const resolved = await agent.modules.cheqd.resolveResource(statusListCredential);

    if ('error' in resolved && resolved.error) {
      return {
        revoked: false,
        checked: false,
        statusListCredential,
        index,
        error: `Could not resolve status list: ${resolved.message ?? resolved.error}`,
      };
    }

    const doc = (resolved as { resource?: Record<string, unknown> }).resource;
    const subject = doc?.credentialSubject as { encodedList?: string } | undefined;
    const encodedList = subject?.encodedList;

    if (typeof encodedList !== 'string') {
      return {
        revoked: false,
        checked: false,
        statusListCredential,
        index,
        error: 'Resolved resource has no credentialSubject.encodedList',
      };
    }

    const bytes = decodeStatusList(encodedList);
    return {
      revoked: readStatusBit(bytes, index),
      checked: true,
      statusListCredential,
      index,
    };
  } catch (error) {
    return {
      revoked: false,
      checked: false,
      statusListCredential,
      index,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Dereference a status-list DID URL to the Bitstring Status List credential.
 *
 * WHY THIS EXISTS. `statusListCredential` is a cheqd DID URL
 * (`did:cheqd:…?resourceName=…&resourceType=…`), not an HTTP URL — see
 * `statusListCredentialUrl` above for why that indirection is what makes
 * after-the-fact revocation work at all. A relying party that speaks only HTTP
 * therefore cannot read it, and a revocation check it cannot perform is one it
 * must refuse rather than wave through. Measured: the HMS's `RevocationPort`
 * fetched the DID URL directly and every professional authorisation failed with
 * `notRevoked: checked=false`.
 *
 * Publishing the list over HTTP costs nothing in trust: the bitmap is public by
 * design, carries no personal data, and is served here exactly as the ledger
 * holds it. A verifier that wants to avoid trusting our transport can still
 * resolve the same DID URL itself; this is a convenience, not an authority.
 *
 * Returns null when the resource does not resolve, so the caller answers with a
 * 404 rather than an empty list that would read as "nothing is revoked".
 */
export async function resolveStatusListCredential(
  statusListDidUrl: string,
): Promise<Record<string, unknown> | null> {
  const agent = getAgent();
  const resolved = await agent.modules.cheqd.resolveResource(statusListDidUrl);
  if ('error' in resolved && resolved.error) return null;
  const resource = (resolved as { resource?: Record<string, unknown> }).resource;
  return resource ?? null;
}
