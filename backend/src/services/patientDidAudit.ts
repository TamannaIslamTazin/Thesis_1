/**
 * SSI Healthcare Backend — audit of already-issued patient DIDs (S-1 §8.4).
 *
 * ===========================================================================
 * WHAT IS BEING LOOKED FOR, AND WHY IT IS NOT REPAIRABLE
 * ===========================================================================
 * A patient DID whose single verification method declares ITSELF as that
 * method's `controller` is permanently unrecoverable. Replacing the device key
 * requires `GetSignerDIDsForDIDUpdate:152` to see a signature from the VM's own
 * controller — which is the key being replaced. S-1 R0 measured the rejection
 * (`1101`, height 46229) with EVERY controller co-signing, and S-4 NC2
 * reproduced it independently on the same commit.
 *
 * S-4's sibling-rescue result does NOT save these. A sibling can rotate a lost
 * slot only when a sibling exists; a single-VM self-controlled DID is exactly
 * the NC2 control that was rejected. So the remedy is RE-ISSUANCE, not repair.
 *
 * ===========================================================================
 * THIS MODULE DOES NOT RE-ISSUE ANYTHING
 * ===========================================================================
 * Re-issuing mints a new identifier, and credentials are stored against
 * `holderDid` — so a re-issue orphans every credential the patient holds unless
 * it is accompanied by a migration nobody has designed. It is also the owner's
 * call, not a maintenance job. This module reads, classifies and reports.
 */

import type { Agent } from '@credo-ts/core';

import { db } from '../db/index.js';
import { logger } from '../utils/logger.js';

import {
  isCheqdDid,
  classifyPatientDid,
  type PatientDidRecoverability,
} from '@ssi-healthcare/sdk/ledger';
import { resolveOnChain } from './cheqdLedger.js';

export interface AuditedPatientDid {
  readonly did: string;
  /** Where the identifier was found. A DID can be reachable from several. */
  readonly sources: readonly string[];
  readonly userId?: string;
  /** `null` for an account enrolled through the DID-only signup path, which has no mailbox. */
  readonly email?: string | null;
  readonly credentialCount: number;
  readonly verdict: PatientDidRecoverability['verdict'] | 'unresolvable';
  readonly detail: string;
}

export interface PatientDidAuditReport {
  readonly scanned: number;
  readonly cheqd: number;
  readonly skippedNonCheqd: number;
  readonly unrecoverable: readonly AuditedPatientDid[];
  readonly indeterminate: readonly AuditedPatientDid[];
  readonly recoverable: readonly AuditedPatientDid[];
  readonly unresolvable: readonly AuditedPatientDid[];
}

/**
 * Collect every identifier that could be a patient DID.
 *
 * Three sources, because they can disagree and the disagreement is itself a
 * finding: `User.did` is the wallet identity, `Credential.holderDid` is what
 * credentials were actually bound to, and `DIDDocument` is the local cache. A
 * DID present only in the second is one whose user row was changed underneath
 * it — the exact hazard `/wallet/setup`'s idempotence guard exists to prevent.
 */
async function collectCandidates(): Promise<Map<string, Set<string>>> {
  const candidates = new Map<string, Set<string>>();

  const add = (did: string | null | undefined, source: string): void => {
    if (!did) return;
    const sources = candidates.get(did) ?? new Set<string>();
    sources.add(source);
    candidates.set(did, sources);
  };

  const users = await db.user.findMany({
    where: { did: { not: null } },
    select: { id: true, did: true, email: true },
  });
  for (const user of users) add(user.did, 'User.did');

  const holders = await db.credential.findMany({
    where: { holderDid: { not: '' } },
    select: { holderDid: true },
    distinct: ['holderDid'],
  });
  for (const holder of holders) add(holder.holderDid, 'Credential.holderDid');

  const cached = await db.dIDDocument.findMany({ select: { did: true, method: true } });
  for (const document of cached) {
    if (document.method === 'CHEQD') add(document.did, 'DIDDocument');
  }

  return candidates;
}

export async function auditPatientDids(agent: Agent): Promise<PatientDidAuditReport> {
  const candidates = await collectCandidates();

  const users = await db.user.findMany({
    where: { did: { not: null } },
    select: { id: true, did: true, email: true },
  });
  const userByDid = new Map(users.map((user) => [user.did as string, user]));

  const unrecoverable: AuditedPatientDid[] = [];
  const indeterminate: AuditedPatientDid[] = [];
  const recoverable: AuditedPatientDid[] = [];
  const unresolvable: AuditedPatientDid[] = [];
  let cheqd = 0;
  let skippedNonCheqd = 0;

  for (const [did, sources] of candidates) {
    if (!isCheqdDid(did)) {
      // did:key has no controller and nothing to rotate — the identifier IS the
      // key. It is not recoverable either, but it is not this finding, and
      // `/wallet/setup` deliberately never migrates those rows.
      skippedNonCheqd += 1;
      continue;
    }
    cheqd += 1;

    const user = userByDid.get(did);
    const credentialCount = await db.credential.count({ where: { holderDid: did } });
    const base = {
      did,
      sources: [...sources].sort(),
      ...(user ? { userId: user.id, email: user.email } : {}),
      credentialCount,
    };

    // Read the CHAIN. The local DIDDocument cache is exactly what would be
    // wrong if a write had silently failed.
    let resolved: Awaited<ReturnType<typeof resolveOnChain>>;
    try {
      resolved = await resolveOnChain(agent, did);
    } catch (error) {
      unresolvable.push({
        ...base,
        verdict: 'unresolvable',
        detail: `resolution threw: ${error instanceof Error ? error.message : String(error)}`,
      });
      continue;
    }

    if (!resolved) {
      unresolvable.push({
        ...base,
        verdict: 'unresolvable',
        detail: 'the chain returns no document for this DID',
      });
      continue;
    }

    if (resolved.deactivated) {
      unresolvable.push({
        ...base,
        verdict: 'unresolvable',
        detail: 'DEACTIVATED on chain; terminal, no revival path (S-4 T1)',
      });
      continue;
    }

    const classification = classifyPatientDid({ ...resolved, id: resolved.did });
    const entry: AuditedPatientDid = {
      ...base,
      verdict: classification.verdict,
      detail:
        classification.verdict === 'recoverable'
          ? `verification method controller is '${classification.verificationMethodController}'`
          : classification.reason,
    };

    if (classification.verdict === 'unrecoverable') unrecoverable.push(entry);
    else if (classification.verdict === 'indeterminate') indeterminate.push(entry);
    else recoverable.push(entry);
  }

  const report: PatientDidAuditReport = {
    scanned: candidates.size,
    cheqd,
    skippedNonCheqd,
    unrecoverable,
    indeterminate,
    recoverable,
    unresolvable,
  };

  logger.warn('patient_did_shape_audit', {
    scanned: report.scanned,
    cheqd: report.cheqd,
    skippedNonCheqd: report.skippedNonCheqd,
    unrecoverableCount: unrecoverable.length,
    unrecoverableDids: unrecoverable.map((entry) => entry.did),
    indeterminateCount: indeterminate.length,
    recoverableCount: recoverable.length,
    unresolvableCount: unresolvable.length,
    remedy:
      'An unrecoverable patient DID must be RE-ISSUED, not repaired (S-1 §8.4). This audit ' +
      're-issues nothing: re-issuance mints a new identifier and credentials are bound to ' +
      'holderDid, so it orphans everything the patient holds. Owner decision.',
  });

  return report;
}
