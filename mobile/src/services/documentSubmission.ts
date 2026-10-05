/**
 * Holder-side document submission (IDENTITY-AND-ISSUANCE-SPEC.md §3,
 * OFFICER-DOCUMENT-ACCESS.md §3/§6a).
 *
 * Order of operations:
 *   1. Pick + read the file (local only).
 *   2. Encrypt client-side with a fresh per-submission content key.
 *   3. Get a locker session and PUT the ciphertext.
 *   4. Wrap the content key to the authority's public key.
 *   5. Mint the capability naming this submission's client-generated id.
 *   6. POST the issuance request, carrying the SAME id.
 *
 * Nothing here is persisted between steps; a failure at any step is a clean
 * retry from step 1. See __docs__/frontend/WALLET-CUSTODY-NOTE.md §2 and
 * `SubmitIssuanceRequestError` below.
 */
import {
  DOCUMENT_TYPES,
  encryptLockerObject,
  wrapContentKey,
  base64UrlToBytes,
  bytesToBase64Url,
  assertWellFormedLockerCapabilityClaims,
  canonicalCapabilityPayload,
  DEFAULT_CAPABILITY_WINDOW_SECONDS,
  type DocumentTypeDefinition,
} from '@ssi-healthcare/shared';
import * as Crypto from 'expo-crypto';

import { apiService, type IssuanceRequestSummary } from './api';
import {
  openLockerSession,
  putLockerObject,
  resolveLockerBase,
  forgetResolvedBase,
  LockerClientError,
} from './lockerClient';
import { signPayload } from './deviceSigner';

/** 16 random bytes for the capability's jti, from the same CSPRNG the seeds use. */
function randomJti(): Uint8Array {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export class SubmitIssuanceRequestError extends Error {
  constructor(
    message: string,
    /** Which stage failed, so the UI can say something more specific than "failed". */
    readonly stage: 'locker-session' | 'upload' | 'capability' | 'submit',
  ) {
    super(message);
    this.name = 'SubmitIssuanceRequestError';
  }
}

export interface PickedDocument {
  readonly uri: string;
  readonly name: string;
  readonly mimeType: string;
  readonly bytes: Uint8Array;
}

const CONTENT_KEY_BYTES = 32;

function randomRequestId(): string {
  return `req_${bytesToBase64Url(Crypto.getRandomBytes(16))}`;
}

function randomObjectId(documentTypeId: string, index: number): string {
  return `${documentTypeId}-doc${index}-${bytesToBase64Url(Crypto.getRandomBytes(12))}`;
}

/** `GET /issuance/document-types` — the ONE place a document type is looked up. Never hardcode an authority. */
export async function fetchDocumentType(documentTypeId: string): Promise<DocumentTypeDefinition> {
  const { documentTypes } = await apiService.getDocumentTypes();
  const match = documentTypes.find((d) => d.id === documentTypeId);
  if (!match) {
    throw new SubmitIssuanceRequestError(
      `'${documentTypeId}' is not a known document type. Known: ${DOCUMENT_TYPES.map((d) => d.id).join(', ')}.`,
      'submit',
    );
  }
  return match as DocumentTypeDefinition;
}

export async function submitIssuanceDocuments(
  documentType: DocumentTypeDefinition,
  documents: readonly PickedDocument[],
  /**
   * The holder's own DID. Required, because every signature in this flow is now
   * made on this device by the key that DID names — the locker session and the
   * capability both. Passing it in rather than reading it here keeps this module
   * free of the auth context.
   */
  holderDid: string,
): Promise<IssuanceRequestSummary> {
  if (!holderDid) {
    throw new SubmitIssuanceRequestError(
      'This wallet has no identifier yet, so it cannot sign for the locker.',
      'locker-session',
    );
  }
  if (documents.length === 0) {
    throw new SubmitIssuanceRequestError('At least one document is required.', 'submit');
  }

  const requestId = randomRequestId();
  const contentKey = Crypto.getRandomBytes(CONTENT_KEY_BYTES);

  // Step 3: locker session + upload.
  let lockerBaseUrl: string;
  try {
    lockerBaseUrl = await resolveLockerBase();
  } catch (error) {
    throw new SubmitIssuanceRequestError(
      error instanceof Error ? error.message : String(error),
      'locker-session',
    );
  }

  let sessionToken: string;
  try {
    // Signed HERE, not by the issuer's backend. The broker at
    // /api/wallet/locker-session existed only because the holder's key used to
    // live on that server; it does not any more, and a server that signs for the
    // holder is a custodian with extra steps.
    const session = await openLockerSession(lockerBaseUrl, holderDid, signPayload);
    sessionToken = session.token;
  } catch (error) {
    // A TRANSPORT failure means the base we resolved has stopped answering, not
    // that the holder did anything wrong. The resolved base was cached with no
    // expiry, so a handset that picked a USB port-forward kept posting there
    // after the cable re-enumerated — three consecutive submissions failed here
    // while a reachable LAN address sat next in the candidate list.
    //
    // Forget it and probe once more. Only for a transport error: a refusal from
    // the locker is an ANSWER, and re-scanning on one would turn a clear "you
    // are not authorised" into a confusing hunt for a different server.
    const transportFailed =
      error instanceof TypeError || /network request failed|fetch failed/i.test(String(error));

    if (transportFailed) {
      forgetResolvedBase('datastore locker');
      try {
        lockerBaseUrl = await resolveLockerBase();
        const session = await openLockerSession(lockerBaseUrl, holderDid, signPayload);
        sessionToken = session.token;
      } catch (retryError) {
        throw new SubmitIssuanceRequestError(
          `Could not open a locker session, and re-probing did not find another: ${
            retryError instanceof Error ? retryError.message : String(retryError)
          }`,
          'locker-session',
        );
      }
    } else {
      throw new SubmitIssuanceRequestError(
        `Could not open a locker session: ${error instanceof Error ? error.message : String(error)}`,
        'locker-session',
      );
    }
  }

  const uploaded: Array<{ lockerObjectId: string; contentHash: string; mediaType: string }> = [];
  for (const [index, doc] of documents.entries()) {
    const objectId = randomObjectId(documentType.id, index);
    const ciphertext = encryptLockerObject(objectId, contentKey, doc.bytes);
    try {
      const { contentHash } = await putLockerObject(lockerBaseUrl, sessionToken, objectId, ciphertext);
      uploaded.push({ lockerObjectId: objectId, contentHash, mediaType: doc.mimeType });
    } catch (error) {
      throw new SubmitIssuanceRequestError(
        error instanceof LockerClientError ? error.message : String(error),
        'upload',
      );
    }
  }

  // Step 4: wrap the content key to the authority's public key.
  let wrappedContentKey;
  try {
    wrappedContentKey = wrapContentKey({
      recipientPublicKey: base64UrlToBytes(documentType.contentKeyPublicKey),
      contentKey,
      wrappedToVerificationMethodId: `${documentType.issuingAuthorityDid}#key-1`,
      issuanceRequestId: requestId,
    });
  } catch (error) {
    throw new SubmitIssuanceRequestError(
      `Could not wrap the content key: ${error instanceof Error ? error.message : String(error)}`,
      'capability',
    );
  }

  // Step 5: mint the capability (server-signed on this CLOUD-custodied
  // wallet's behalf — see walletMintCapability's own doc comment).
  let capability: unknown;
  try {
    // Minted on the handset. The holder is the only party who may authorise
    // reading their own objects, so the signature has to be theirs.
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: holderDid,
      aud: documentType.issuingAuthorityDid,
      obj: uploaded.map((d) => d.lockerObjectId),
      sub: requestId,
      jti: bytesToBase64Url(randomJti()),
      nbf: now,
      exp: now + DEFAULT_CAPABILITY_WINDOW_SECONDS,
    };
    assertWellFormedLockerCapabilityClaims(claims);
    capability = {
      claims,
      signature: await signPayload(canonicalCapabilityPayload(claims)),
      verificationMethodId: `${holderDid}#key-1`,
    };
  } catch (error) {
    throw new SubmitIssuanceRequestError(
      `Could not mint the locker capability: ${error instanceof Error ? error.message : String(error)}`,
      'capability',
    );
  }

  // Step 6: file the request.
  try {
    return await apiService.submitIssuanceRequest({
      requestId,
      documentType: documentType.id,
      documents: uploaded,
      wrappedContentKey,
      capability,
    });
  } catch (error) {
    throw new SubmitIssuanceRequestError(
      error instanceof Error ? error.message : String(error),
      'submit',
    );
  }
}
