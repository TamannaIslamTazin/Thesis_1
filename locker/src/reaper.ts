/**
 * The residue reaper.
 *
 * Interrupted uploads are NORMAL — a phone loses signal mid-backup and that is
 * an ordinary Tuesday, not an incident. What must not happen is that the
 * residue accumulates invisibly until the disk fills, on a machine already at
 * 85%.
 *
 * ===========================================================================
 * WHY THIS IS OURS AND NOT THE STORAGE LAYER'S
 * ===========================================================================
 * Measured, not assumed. `mc rm --incomplete --force` reported failure and
 * left 65MB in place; `mc ls --incomplete --json` reported 0B for that same
 * 65MB and did not expose the uploadId at all; `mc ilm rule add` has no
 * abort-incomplete flag. A lifecycle rule carrying
 * AbortIncompleteMultipartUpload can only be installed as raw XML and is
 * UNVERIFIED here, so it is not what durability rests on.
 *
 * Every one of those failure modes is silent-success shaped — the #310
 * lesson, where `docker compose stop` cheerfully reported success against the
 * wrong daemon. So the reaper aborts through the S3 API itself and writes what
 * it aborted into the append-only receipt log. Residue stays COUNTABLE, which
 * is the actual requirement; "absent from a listing" is not the same thing.
 *
 * ===========================================================================
 * IT ONLY REAPS WHAT IS OLDER THAN THE TTL
 * ===========================================================================
 * An upload in progress right now looks exactly like an abandoned one. Age is
 * the only signal that distinguishes them, so the TTL must comfortably exceed
 * the slowest realistic upload; the datastore's is six hours. Reaping an
 * in-flight upload would turn a working backup into a failed one — a failsafe
 * that causes the failure it exists to contain.
 */

import type { S3Client } from '@aws-sdk/client-s3';
import type { DatabaseSync } from 'node:sqlite';

import { abortMultipart, listIncompleteUploads } from './objectStore.js';
import { listOpenIntents, recordReceipt, settleUploadIntent } from './db.js';

export interface ReapSummary {
  readonly inspected: number;
  readonly aborted: number;
  readonly bytesReclaimed: number;
  readonly skippedTooYoung: number;
  readonly failures: number;
}

export async function reapAbandonedUploads(args: {
  client: S3Client;
  db: DatabaseSync;
  bucket: string;
  ttlMs: number;
  now?: number;
}): Promise<ReapSummary> {
  const now = args.now ?? Date.now();
  const incomplete = await listIncompleteUploads(args.client, args.bucket);

  let aborted = 0;
  let bytesReclaimed = 0;
  let skippedTooYoung = 0;
  let failures = 0;

  for (const upload of incomplete) {
    const ageMs = now - upload.initiatedAtMs;
    if (upload.initiatedAtMs > 0 && ageMs < args.ttlMs) {
      skippedTooYoung += 1;
      continue;
    }

    try {
      await abortMultipart(args.client, args.bucket, {
        uploadId: upload.uploadId,
        key: upload.key,
      });

      // The receipt is written AFTER the abort succeeds. A receipt for an
      // abort that did not happen is a false claim about destroyed data, which
      // is the same class of lie as a backup timestamp for a backup that does
      // not exist.
      recordReceipt(args.db, {
        kind: 'ABANDONED_UPLOAD_REAPED',
        // The key already begins with the subjectRef, so the receipt is
        // pseudonymous without any extra work.
        subjectRef: upload.key.split('/')[0] ?? 'unknown',
        objectKey: upload.key,
        byteCount: upload.byteCount,
        actorRef: 'locker-reaper',
        reason: `abandoned multipart upload older than ${args.ttlMs}ms`,
      });

      settleUploadIntent(args.db, upload.uploadId, 'ABANDONED');
      aborted += 1;
      bytesReclaimed += upload.byteCount;
    } catch {
      // Counted, never thrown. One stuck upload must not stop the sweep of the
      // rest, and an uncounted failure is the invisible accumulation this
      // exists to prevent.
      failures += 1;
    }
  }

  // Intents whose storage-side upload is already gone: settle the bookkeeping
  // so `UPLOADING` means "actually in flight" rather than "ever started".
  const liveUploadIds = new Set(incomplete.map((upload) => upload.uploadId));
  for (const intent of listOpenIntents(args.db)) {
    if (liveUploadIds.has(intent.uploadId)) continue;
    if (now - new Date(intent.startedAt).getTime() < args.ttlMs) continue;
    settleUploadIntent(args.db, intent.uploadId, 'ABANDONED');
  }

  return {
    inspected: incomplete.length,
    aborted,
    bytesReclaimed,
    skippedTooYoung,
    failures,
  };
}
