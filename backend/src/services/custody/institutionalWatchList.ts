/**
 * SSI Healthcare Backend — which DIDs the silent alarm is armed on.
 *
 * A patient DID rotating its device key is normal traffic. An institutional DID
 * losing a verification method is the event S-4 measured and #291 named as the
 * thing detection has to catch. The watcher therefore filters by subject, and
 * this module owns that list and the running picture of each entry's document.
 *
 * `lastSeen*` IS NOT A CACHE. It is the only reason an eviction is
 * distinguishable from a rotation without a second chain query per event: a
 * `MsgUpdateDidDoc` payload states the document AFTER the change and says
 * nothing about what was there before. The watcher advances this strictly in
 * block order and never skips a height, so the comparison is exact rather than
 * approximate.
 *
 * `watchedFromHeight` exists so the system can never imply it saw something it
 * did not. Anything before that height was not observed, full stop.
 */

import { db } from '../../db/index.js';
import { logger } from '../../utils/logger.js';
import { verificationMethodDigestOf, type KnownDidState } from './didTxDecode.js';

export interface WatchedDid extends KnownDidState {
  readonly did: string;
  readonly label: string;
  readonly watchedFromHeight: number;
  readonly lastSeenVersionId: string | null;
  readonly lastSeenHeight: number | null;
  readonly deactivated: boolean;
}

export interface RegisterWatchInput {
  readonly did: string;
  readonly label: string;
  readonly fromHeight: number;
  readonly verificationMethods: readonly { id: string; publicKeyMultibase: string }[];
  readonly controllers: readonly string[];
  readonly versionId?: string | null;
}

/**
 * Arm the alarm on a DID.
 *
 * Idempotent by design: re-registering an already-watched DID must not reset
 * `watchedFromHeight` forward, or a restart would quietly narrow the window the
 * system claims to have covered. Only the label is refreshed.
 */
export async function registerWatchedInstitutionalDid(
  input: RegisterWatchInput,
): Promise<WatchedDid> {
  const digest = verificationMethodDigestOf(input.verificationMethods);
  const ids = input.verificationMethods.map((vm) => vm.id);

  const row = await db.watchedInstitutionalDid.upsert({
    where: { did: input.did },
    create: {
      did: input.did,
      label: input.label,
      watchedFromHeight: input.fromHeight,
      lastSeenVerificationMethodIds: ids,
      lastSeenVerificationMethodDigest: digest,
      lastSeenControllers: [...input.controllers],
      lastSeenVersionId: input.versionId ?? null,
      lastSeenHeight: input.fromHeight,
    },
    update: { label: input.label },
  });

  logger.info('custody_watch_armed', {
    did: row.did,
    label: row.label,
    watchedFromHeight: row.watchedFromHeight,
    verificationMethodIds: row.lastSeenVerificationMethodIds,
    note:
      'MsgUpdateDidDoc and MsgDeactivateDidDoc against this DID now raise alarms. Nothing ' +
      `before height ${row.watchedFromHeight} was observed.`,
  });

  return toWatchedDid(row);
}

export async function listWatchedDids(): Promise<WatchedDid[]> {
  const rows = await db.watchedInstitutionalDid.findMany({ orderBy: { registeredAt: 'asc' } });
  return rows.map(toWatchedDid);
}

/** Keyed by DID for the scanner's per-block filter. */
export async function watchedDidMap(): Promise<Map<string, WatchedDid>> {
  return new Map((await listWatchedDids()).map((watched) => [watched.did, watched]));
}

export interface WatchStateAdvance {
  readonly did: string;
  readonly height: number;
  readonly versionId: string | null;
  readonly verificationMethods: readonly { id: string; publicKeyMultibase: string }[];
  readonly controllers: readonly string[];
  readonly deactivated: boolean;
}

/**
 * Advance the running picture after an observed, COMMITTED change.
 *
 * Takes a Prisma transaction handle so the state advance, the observation row
 * and the alarm all commit together. If they did not, a crash could advance the
 * picture past an event whose alarm was never raised — after which the eviction
 * looks like it was always the state of the world.
 */
export async function advanceWatchState(
  tx: {
    watchedInstitutionalDid: {
      update(args: { where: { did: string }; data: Record<string, unknown> }): Promise<unknown>;
    };
  },
  advance: WatchStateAdvance,
): Promise<void> {
  await tx.watchedInstitutionalDid.update({
    where: { did: advance.did },
    data: {
      lastSeenHeight: advance.height,
      lastSeenVersionId: advance.versionId,
      lastSeenVerificationMethodIds: advance.verificationMethods.map((vm) => vm.id),
      lastSeenVerificationMethodDigest: verificationMethodDigestOf(advance.verificationMethods),
      lastSeenControllers: [...advance.controllers],
      deactivated: advance.deactivated,
    },
  });
}

function toWatchedDid(row: {
  did: string;
  label: string;
  watchedFromHeight: number;
  lastSeenVerificationMethodIds: string[];
  lastSeenVerificationMethodDigest: string;
  lastSeenControllers: string[];
  lastSeenVersionId: string | null;
  lastSeenHeight: number | null;
  deactivated: boolean;
}): WatchedDid {
  return {
    did: row.did,
    label: row.label,
    watchedFromHeight: row.watchedFromHeight,
    verificationMethodIds: row.lastSeenVerificationMethodIds,
    verificationMethodDigest: row.lastSeenVerificationMethodDigest,
    controllers: row.lastSeenControllers,
    lastSeenVersionId: row.lastSeenVersionId,
    lastSeenHeight: row.lastSeenHeight,
    deactivated: row.deactivated,
  };
}
