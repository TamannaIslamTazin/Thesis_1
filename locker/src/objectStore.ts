/**
 * The S3 layer. Every byte the locker holds passes through here, and none of
 * it is ever interpreted.
 *
 * ===========================================================================
 * THERE IS NO DECRYPTION ROUTINE IN THIS PACKAGE
 * ===========================================================================
 * Not "there is one but it is disabled", not "the key is not configured" —
 * there is no code here that could decrypt an object even if an operator
 * wanted it to, because the locker never receives a key. That is the Phase C
 * property worth copying: operator-blindness as an ABSENT CAPABILITY rather
 * than a policy toggle someone could flip on under pressure or by accident.
 *
 * The wallet encrypts before upload and decrypts after download. The DEK is
 * wrapped under the KEK, the KEK is wrapped twice (device/PIN and
 * guardian-reconstructable recovery key), and none of those three ever crosses
 * this boundary in openable form.
 *
 * SCOPE, STATED HONESTLY: this is zero-knowledge WITH RESPECT TO THE OPERATOR.
 * It is not zero-knowledge absolutely — a guardian quorum plus access to the
 * keystore can recover contents, which is the deliberate #340 trade. And even
 * against the operator, object COUNT, SIZE and WRITE TIME per subject remain
 * observable from a bucket listing. Padding blunts that; it does not remove it.
 *
 * ===========================================================================
 * THE PARTIAL-UPLOAD FAILSAFE IS NATIVE, AND IT IS THE #328 PROPERTY
 * ===========================================================================
 * Measured against MinIO RELEASE.2025-09-07: an interrupted multipart upload
 * is INVISIBLE in the object namespace. `HeadObject` on the key returns "does
 * not exist" and a normal listing does not show it; the object appears
 * atomically only on CompleteMultipartUpload.
 *
 * So a partial upload cannot become a corrupt backup the user believes in,
 * because until Complete it is not an object at all. We get the property that
 * #328 was about for free from S3 semantics rather than from anything we
 * write — and the wallet's read-back verification sits on top of it.
 *
 * ===========================================================================
 * THE REAPER EXISTS BECAUSE THE STANDARD TOOL LIES
 * ===========================================================================
 * Interrupting a 286MB upload left 65MB in `.minio.sys/multipart`. Measured,
 * on this machine:
 *
 *   `mc rm --incomplete --force`  -> FAILED, "Object does not exist",
 *                                    and left all 65MB in place
 *   `mc ls --incomplete --json`   -> reported size 0B, and did NOT expose the
 *                                    uploadId, so it cannot even name what to abort
 *   `mc ilm rule add`             -> has NO abort-incomplete-multipart flag
 *
 * Delegating residue cleanup to `mc` would therefore report success while
 * doing nothing — the #310 docker-context shape in a new tool. The locker owns
 * the reaper via the S3 API directly (ListMultipartUploads -> ListParts ->
 * AbortMultipartUpload) and COUNTS what it aborts into the append-only receipt
 * log, so residue stays countable instead of merely absent from a listing.
 */

import {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  CreateMultipartUploadCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  ListMultipartUploadsCommand,
  ListObjectsV2Command,
  ListPartsCommand,
  PutObjectCommand,
  S3Client,
  UploadPartCommand,
} from '@aws-sdk/client-s3';
import type { Readable } from 'node:stream';

import type { LockerConfig } from './config.js';
import { LockerError } from './db.js';

/** S3 requires every part but the last to be at least 5 MiB. */
export const MIN_PART_BYTES = 5 * 1024 * 1024;

export function createS3Client(config: LockerConfig): S3Client {
  return new S3Client({
    endpoint: config.s3Endpoint,
    region: config.s3Region,
    // MinIO serves `host/bucket/key`. Virtual-host style fails against it in a
    // way that reads as a credentials error, which is a long detour.
    forcePathStyle: config.s3ForcePathStyle,
    credentials: {
      accessKeyId: config.s3AccessKeyId,
      secretAccessKey: config.s3SecretAccessKey,
    },
  });
}

/**
 * Object keys are `<subjectRef>/<role>/<objectId>/v<generation>`.
 *
 * subjectRef is HMAC(pepper, did) — never the raw DID. An operator reading a
 * bucket listing should not get a census of who holds a locker and how much
 * each of them stores; they cannot read the bytes, but a raw DID prefix would
 * hand them the membership roll for free.
 */
export function objectKey(subjectRef: string, objectId: string, generation: number): string {
  return `${subjectRef}/objects/${objectId}/v${generation}`;
}

export function objectPrefix(subjectRef: string, objectId?: string): string {
  return objectId ? `${subjectRef}/objects/${objectId}/` : `${subjectRef}/objects/`;
}

/** Readiness, by effect. A bucket we cannot HEAD is a locker that cannot serve. */
export async function assertBucketReachable(client: S3Client, bucket: string): Promise<void> {
  await client.send(new HeadBucketCommand({ Bucket: bucket }));
}

export interface StoredObjectSummary {
  readonly key: string;
  readonly size: number;
  readonly lastModified: string | null;
}

export async function listObjects(
  client: S3Client,
  bucket: string,
  prefix: string,
): Promise<readonly StoredObjectSummary[]> {
  const results: StoredObjectSummary[] = [];
  let continuationToken: string | undefined;

  do {
    const page = await client.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: continuationToken,
      }),
    );
    for (const item of page.Contents ?? []) {
      if (!item.Key) continue;
      results.push({
        key: item.Key,
        size: item.Size ?? 0,
        lastModified: item.LastModified?.toISOString() ?? null,
      });
    }
    continuationToken = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (continuationToken);

  return results;
}

/**
 * Bytes a subject currently holds. Recomputed from the listing rather than
 * kept as a counter, because a counter drifts and a drifted quota either
 * refuses valid writes or silently stops enforcing — #315's rule that a phase
 * re-establishes its precondition from OBSERVABLE STATE rather than inheriting
 * it from bookkeeping that a prior phase maintained.
 */
export async function usedBytes(
  client: S3Client,
  bucket: string,
  subjectRef: string,
): Promise<number> {
  const objects = await listObjects(client, bucket, objectPrefix(subjectRef));
  return objects.reduce((total, item) => total + item.size, 0);
}

export async function assertWithinQuota(
  client: S3Client,
  bucket: string,
  subjectRef: string,
  incomingBytes: number,
  quotaBytes: number,
): Promise<void> {
  const used = await usedBytes(client, bucket, subjectRef);
  if (used + incomingBytes > quotaBytes) {
    throw new LockerError(
      `this write would put the subject at ${used + incomingBytes} bytes, over the ` +
        `${quotaBytes}-byte quota (currently ${used}). Refusing rather than accepting a ` +
        'write the disk cannot sustain.',
      507,
      'QUOTA_EXCEEDED',
    );
  }
}

// ---------------------------------------------------------------------------
// Single-shot write (keystore, and small datastore objects)
// ---------------------------------------------------------------------------

export async function putObject(
  client: S3Client,
  bucket: string,
  key: string,
  body: Buffer,
): Promise<void> {
  await client.send(
    new PutObjectCommand({ Bucket: bucket, Key: key, Body: body, ContentLength: body.length }),
  );
}

export async function getObject(
  client: S3Client,
  bucket: string,
  key: string,
): Promise<Buffer | null> {
  try {
    const result = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    if (!result.Body) return null;
    const chunks: Buffer[] = [];
    for await (const chunk of result.Body as Readable) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
  } catch (error) {
    if (isNotFound(error)) return null;
    throw error;
  }
}

export async function headObject(
  client: S3Client,
  bucket: string,
  key: string,
): Promise<{ size: number } | null> {
  try {
    const result = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    return { size: result.ContentLength ?? 0 };
  } catch (error) {
    if (isNotFound(error)) return null;
    throw error;
  }
}

export async function deleteObject(client: S3Client, bucket: string, key: string): Promise<void> {
  await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
}

function isNotFound(error: unknown): boolean {
  const name = (error as { name?: string })?.name;
  const status = (error as { $metadata?: { httpStatusCode?: number } })?.$metadata?.httpStatusCode;
  return name === 'NotFound' || name === 'NoSuchKey' || status === 404;
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

export interface MultipartHandle {
  readonly uploadId: string;
  readonly key: string;
}

export async function beginMultipart(
  client: S3Client,
  bucket: string,
  key: string,
): Promise<MultipartHandle> {
  const result = await client.send(
    new CreateMultipartUploadCommand({ Bucket: bucket, Key: key }),
  );
  if (!result.UploadId) {
    throw new LockerError('object storage did not return an upload id', 502, 'NO_UPLOAD_ID');
  }
  return { uploadId: result.UploadId, key };
}

export async function uploadPart(
  client: S3Client,
  bucket: string,
  handle: MultipartHandle,
  partNumber: number,
  body: Buffer,
): Promise<{ partNumber: number; etag: string }> {
  const result = await client.send(
    new UploadPartCommand({
      Bucket: bucket,
      Key: handle.key,
      UploadId: handle.uploadId,
      PartNumber: partNumber,
      Body: body,
      ContentLength: body.length,
    }),
  );
  if (!result.ETag) {
    throw new LockerError(`part ${partNumber} returned no ETag`, 502, 'NO_PART_ETAG');
  }
  return { partNumber, etag: result.ETag };
}

/**
 * Re-establish the precondition from observable state before committing
 * (#315). The completion phase does NOT trust that the upload phase ran
 * correctly just because it ran: it asks object storage which parts actually
 * landed, and refuses if that disagrees with what the caller claims.
 *
 * A multi-phase procedure is only failsafe if each phase checks for itself.
 */
export async function completeMultipart(
  client: S3Client,
  bucket: string,
  handle: MultipartHandle,
  expectedParts: readonly { partNumber: number; etag: string }[],
): Promise<void> {
  const observed = await client.send(
    new ListPartsCommand({ Bucket: bucket, Key: handle.key, UploadId: handle.uploadId }),
  );
  const observedParts = (observed.Parts ?? []).map((part) => ({
    partNumber: part.PartNumber ?? -1,
    etag: part.ETag ?? '',
  }));

  if (observedParts.length !== expectedParts.length) {
    throw new LockerError(
      `object storage holds ${observedParts.length} parts but the upload claims ` +
        `${expectedParts.length}. Refusing to complete an upload whose parts do not match ` +
        'what actually landed — a completed-but-short object is exactly the corrupt backup ' +
        'a user would then believe in.',
      409,
      'PART_COUNT_MISMATCH',
    );
  }

  const observedByNumber = new Map(observedParts.map((part) => [part.partNumber, part.etag]));
  for (const expected of expectedParts) {
    const actual = observedByNumber.get(expected.partNumber);
    if (actual !== expected.etag) {
      throw new LockerError(
        `part ${expected.partNumber} has ETag ${actual ?? '(absent)'} in object storage but ` +
          `${expected.etag} was expected. Refusing to complete.`,
        409,
        'PART_ETAG_MISMATCH',
      );
    }
  }

  await client.send(
    new CompleteMultipartUploadCommand({
      Bucket: bucket,
      Key: handle.key,
      UploadId: handle.uploadId,
      MultipartUpload: {
        Parts: expectedParts
          .slice()
          .sort((a, b) => a.partNumber - b.partNumber)
          .map((part) => ({ PartNumber: part.partNumber, ETag: part.etag })),
      },
    }),
  );
}

export async function abortMultipart(
  client: S3Client,
  bucket: string,
  handle: MultipartHandle,
): Promise<void> {
  await client.send(
    new AbortMultipartUploadCommand({
      Bucket: bucket,
      Key: handle.key,
      UploadId: handle.uploadId,
    }),
  );
}

export interface IncompleteUpload {
  readonly key: string;
  readonly uploadId: string;
  readonly initiatedAtMs: number;
  readonly byteCount: number;
}

/**
 * Enumerate residue, WITH its byte count.
 *
 * The byte count comes from ListParts, not from the upload listing — measured
 * reason: `mc ls --incomplete` reports 0B for an upload holding 65MB. An
 * unmeasured residue figure is worse than none, because it gets believed.
 */
export async function listIncompleteUploads(
  client: S3Client,
  bucket: string,
): Promise<readonly IncompleteUpload[]> {
  const listed = await client.send(new ListMultipartUploadsCommand({ Bucket: bucket }));
  const results: IncompleteUpload[] = [];

  for (const upload of listed.Uploads ?? []) {
    if (!upload.Key || !upload.UploadId) continue;

    let byteCount = 0;
    try {
      const parts = await client.send(
        new ListPartsCommand({ Bucket: bucket, Key: upload.Key, UploadId: upload.UploadId }),
      );
      byteCount = (parts.Parts ?? []).reduce((total, part) => total + (part.Size ?? 0), 0);
    } catch {
      // The upload vanished between listing and inspection, or storage
      // hiccuped. Report it with an unknown size rather than dropping it from
      // the count — residue we cannot size is still residue.
      byteCount = 0;
    }

    results.push({
      key: upload.Key,
      uploadId: upload.UploadId,
      initiatedAtMs: upload.Initiated?.getTime() ?? 0,
      byteCount,
    });
  }

  return results;
}
