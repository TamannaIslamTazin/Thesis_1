/**
 * SSI Healthcare Backend — "which visas were in the old passport?"
 *
 * ===========================================================================
 * THE TRACKING MODEL, AND THE FINDING THAT MAKES IT CHEAP
 * ===========================================================================
 * Research question 1 is how an issuer knows what it issued to a DID that is
 * now dead. The answer turns out to require no new bookkeeping, because the
 * issuer already keeps it for a different reason:
 *
 *   TO REVOKE A CREDENTIAL, AN ISSUER MUST ALREADY KNOW WHICH BIT OF ITS
 *   STATUS LIST BELONGS TO IT. That is (issuerDid, holderDid, statusListId,
 *   statusListIndex) — which is exactly the tuple re-issuance needs.
 *
 * So the revocation ledger IS the re-issuance ledger. Any issuer that can
 * revoke can enumerate; an issuer that cannot enumerate could never have
 * revoked either, and that is a pre-existing defect this workflow only reveals.
 *
 * It reveals it precisely: a credential with a null `statusListIndex` is
 * {@link ReissuanceOutcome.UNTRACKABLE}. It cannot be revoked, so the old copy
 * cannot be retired, so issuing a replacement would put TWO live credentials
 * into the world making the same claim about the same person under two
 * different identifiers. Fail closed — refuse it, count it, name it in the
 * report.
 *
 * ===========================================================================
 * THE MIGRATION SET IS NOT THE CREDENTIAL SET
 * ===========================================================================
 * The instinct is "re-issue everything bound to the old DID". That is wrong in
 * two directions, and both are decisions rather than mechanics:
 *
 *   REVOKED  — carrying it forward re-issues a statement the issuer withdrew.
 *              A migration must not be a laundering mechanism for revocation.
 *   EXPIRED  — re-issuing mints a fresh validity window, silently extending an
 *              expiry the issuer never granted.
 *
 * Both are RECORDED, not dropped. A row saying "not carried forward, because
 * the issuer had already revoked it" is the interesting row in an audit; a
 * missing row is indistinguishable from a bug.
 */

import type { ReissuanceOutcome } from '../../../prisma/generated/client/index.js';

/** The subset of a `Credential` row this decision actually depends on. */
export interface MigratableCredential {
  readonly id: string;
  readonly credentialHash: string;
  readonly status: string;
  readonly credentialFormat: string | null;
  readonly statusListId: string | null;
  readonly statusListIndex: number | null;
  readonly expiresAt: Date | null;
}

export type WorklistDecision =
  | { readonly action: 'REISSUE' }
  | { readonly action: 'SKIP'; readonly outcome: ReissuanceOutcome; readonly detail: string };

/**
 * Decide the fate of one credential. Pure, total, and covered by `tests/fast`,
 * because this predicate decides what a patient walks out of the hospital
 * holding.
 *
 * ORDER MATTERS. Revocation is checked before expiry so a credential that is
 * both reads as revoked — the stronger statement, and the one an auditor cares
 * about. Trackability is checked LAST so that an untrackable credential which
 * was already revoked is reported as revoked rather than as a tracking gap: the
 * gap is only consequential for credentials we would otherwise have carried
 * forward.
 */
export function decideCredentialFate(
  credential: MigratableCredential,
  now: Date,
): WorklistDecision {
  if (credential.status === 'REVOKED') {
    return {
      action: 'SKIP',
      outcome: 'SKIPPED_REVOKED',
      detail:
        'The issuer had already revoked this credential. Re-issuing it against the new ' +
        'identity would reinstate a statement the issuer deliberately withdrew.',
    };
  }

  if (credential.status === 'SUSPENDED') {
    return {
      action: 'SKIP',
      outcome: 'SKIPPED_REVOKED',
      detail:
        'Suspended at migration time. A suspension is a live decision by the issuer and ' +
        'cannot be carried across an identifier change without the issuer re-making it; ' +
        're-issuing would silently lift it.',
    };
  }

  if (credential.status === 'PENDING') {
    return {
      action: 'SKIP',
      outcome: 'SKIPPED_REVOKED',
      detail:
        'Never accepted by the holder — it is an outstanding offer, not a held credential. ' +
        'The offer should be re-made to the new identity by the issuer, not migrated.',
    };
  }

  if (credential.expiresAt !== null && credential.expiresAt.getTime() <= now.getTime()) {
    return {
      action: 'SKIP',
      outcome: 'SKIPPED_EXPIRED',
      detail:
        `Expired at ${credential.expiresAt.toISOString()}. Re-issuing would mint a fresh ` +
        'validity window and silently extend an expiry the issuer never granted.',
    };
  }

  if (credential.statusListId === null || credential.statusListIndex === null) {
    return {
      action: 'SKIP',
      outcome: 'UNTRACKABLE',
      detail:
        'The issuer holds no revocation coordinates for this credential (statusListIndex is ' +
        'null), so the old copy cannot be revoked. Issuing a replacement would leave two ' +
        'live credentials asserting the same thing about the same person under two ' +
        'identifiers. This is a pre-existing gap in the issuer’s records, surfaced here ' +
        'rather than created here.',
    };
  }

  return { action: 'REISSUE' };
}

export interface WorklistSummary {
  readonly found: number;
  readonly toReissue: number;
  readonly skipped: number;
  readonly byOutcome: Readonly<Record<string, number>>;
}

export function summariseWorklist(
  decisions: readonly { readonly decision: WorklistDecision }[],
): WorklistSummary {
  const byOutcome: Record<string, number> = {};
  let toReissue = 0;

  for (const { decision } of decisions) {
    if (decision.action === 'REISSUE') {
      toReissue += 1;
      byOutcome.PENDING = (byOutcome.PENDING ?? 0) + 1;
      continue;
    }
    byOutcome[decision.outcome] = (byOutcome[decision.outcome] ?? 0) + 1;
  }

  return {
    found: decisions.length,
    toReissue,
    skipped: decisions.length - toReissue,
    byOutcome,
  };
}
