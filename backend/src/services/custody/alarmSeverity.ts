/**
 * SSI Healthcare Backend — the alarm taxonomy: severity and headline.
 *
 * ===========================================================================
 * THE ONE RULE THIS FILE EXISTS TO ENFORCE
 * ===========================================================================
 * A chain event WE CANNOT ACCOUNT FOR is more serious than one we can — never
 * less. An officer key rotating through this backend is Tuesday; the same
 * rotation appearing on chain with no audit entry means someone holds an
 * officer key and is not using our signing path, which is the entire threat
 * S-4 measured (#291). {@link severityFor} is monotone in that direction and
 * has no branch that can lower a severity for an unmatched event.
 *
 * The second rule: EVICTION AND DEACTIVATION ARE NOT ROTATION. All three are
 * `MsgUpdateDidDoc`-shaped traffic and a naive watcher would report them
 * identically. Eviction (H1, height 86424) leaves the institution with fewer
 * keys and, repeated, with none — after which "remediate by rotating the
 * compromised key" is impossible because rotation requires a key. Deactivation
 * (code 1207) has no on-chain remedy at all. Rotation is the operation the
 * custody model is *built* around. They get different severities because an
 * operator has different amounts of time to act.
 *
 * PURE, AND SEPARATE FROM `custodyAlarm.ts` FOR THAT REASON. Nothing here
 * touches the database or the clock, so `tests/fast` can hold the taxonomy to
 * both rules without a Postgres running — which is precisely when a regression
 * in it would otherwise go unnoticed.
 */

import {
  AlarmAttribution,
  AlarmKind,
  AlarmSeverity,
} from '../../../prisma/generated/client/index.js';

export { AlarmAttribution, AlarmKind, AlarmSeverity };

export interface AlarmInput {
  readonly kind: AlarmKind;
  readonly attribution: AlarmAttribution;
  readonly subjectDid?: string | null;
  readonly txHash?: string | null;
  readonly height?: number | null;
  readonly signerVerificationMethodIds?: readonly string[];
  readonly detail: Record<string, unknown>;
  readonly matchedAuditSeq?: number | null;
  /** Overrides the derived headline. Used only where the default reads wrong. */
  readonly headline?: string;
}

// ---------------------------------------------------------------------------
// Severity — pure, so `tests/fast` can hold it to the rule above
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<AlarmSeverity, number> = {
  [AlarmSeverity.INFO]: 0,
  [AlarmSeverity.WARNING]: 1,
  [AlarmSeverity.CRITICAL]: 2,
};

export function strongerOf(a: AlarmSeverity, b: AlarmSeverity): AlarmSeverity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/**
 * Severity of the event ITSELF, before anyone asks whether we authorised it.
 *
 * Read this as "how much of the institution is gone, and how fast must someone
 * move", not as "how suspicious does it look".
 */
export function baseSeverityFor(kind: AlarmKind): AlarmSeverity {
  switch (kind) {
    // No on-chain remedy exists. `UpdateDidDoc` checks Deactivated before it
    // looks at signatures (S-4 T1), so no key, however legitimate, revives it.
    case AlarmKind.DID_DEACTIVATED:
    // Each eviction narrows the officer set toward zero, and at zero the
    // institution can no longer rotate anything (#291).
    case AlarmKind.OFFICER_EVICTED:
    // The controller set is not repairable (S-1 §5.4).
    case AlarmKind.CONTROLLER_CHANGED:
    // We believe we broadcast something the chain never showed us. Either the
    // write silently failed, or the watcher is not seeing the chain we write to.
    case AlarmKind.BROADCAST_NOT_ON_CHAIN:
    // The watcher cannot read blocks it was down for. Anything could have
    // happened in that window and this system can no longer find out.
    case AlarmKind.WATCH_GAP_UNRECOVERABLE:
    // The append-only log does not verify. The primary detection control is
    // itself compromised.
    case AlarmKind.AUDIT_CHAIN_TAMPERED:
      return AlarmSeverity.CRITICAL;

    // The watcher is alive but not advancing. Detection latency is a load-
    // bearing control here, so a stalled watcher is a degraded control — but it
    // is not yet evidence that anything happened.
    case AlarmKind.WATCHER_STALLED:
    // An intent with no result and no rejection: probably a crash between the
    // two appends, possibly a broadcast we lost track of.
    case AlarmKind.INTENT_UNRESOLVED:
      return AlarmSeverity.WARNING;

    // The operations 1-of-N exists to make possible. Routine BY DESIGN.
    case AlarmKind.OFFICER_ROTATED:
    case AlarmKind.OFFICER_ADDED:
    case AlarmKind.UPDATE_WITHOUT_KEY_CHANGE:
    // The chain refused it, so nothing changed — but see `severityFor`: an
    // unattributed refused attempt is somebody probing our institutional DID.
    case AlarmKind.REJECTED_ATTEMPT:
      return AlarmSeverity.INFO;
  }
}

/**
 * Final severity. ESCALATION ONLY.
 *
 * There is deliberately no path here that returns something weaker than
 * {@link baseSeverityFor}. "We found a matching audit entry, so relax" is the
 * exact reasoning that would let an attacker who compromised the backend AND an
 * officer key hide behind their own log entry — and it is also how a legitimate
 * but catastrophic eviction gets filed as routine.
 */
export function severityFor(kind: AlarmKind, attribution: AlarmAttribution): AlarmSeverity {
  const base = baseSeverityFor(kind);
  return attribution === AlarmAttribution.UNMATCHED
    ? strongerOf(base, AlarmSeverity.CRITICAL)
    : base;
}

// ---------------------------------------------------------------------------
// Headline — the sentence an operator reads at 03:00
// ---------------------------------------------------------------------------

const UNMATCHED_SUFFIX =
  'NO SIGNING AUDIT ENTRY ACCOUNTS FOR THIS. It was not broadcast through this backend, so ' +
  'whoever did it holds an officer key directly. Treat the key set as compromised.';

export function headlineFor(input: AlarmInput): string {
  const did = input.subjectDid ?? 'an unnamed DID';
  const signers = input.signerVerificationMethodIds?.length
    ? input.signerVerificationMethodIds.join(', ')
    : 'an unrecorded key';

  const body = ((): string => {
    switch (input.kind) {
      case AlarmKind.DID_DEACTIVATED:
        return (
          `${did} was DEACTIVATED on chain by ${signers}. This is irreversible — the DID module ` +
          'has no revival path (code 1207). The institution can no longer sign anything. ' +
          'Enrolled patients are NOT frozen (S-4 K1/K2), but this institution cannot issue, ' +
          'rotate or co-sign again, ever.'
        );
      case AlarmKind.OFFICER_EVICTED:
        return (
          `An officer verification method was REMOVED from ${did} by ${signers}. Repeat this ` +
          'and the institution holds no key at all, after which rotation — the only ' +
          'remediation the 1-of-N model has — becomes impossible. If this was not authorised, ' +
          'the surviving officers have minutes, not hours: rotate every remaining slot now.'
        );
      case AlarmKind.CONTROLLER_CHANGED:
        return (
          `The controller set of ${did} changed, signed by ${signers}. A controller set is not ` +
          'repairable (S-1 §5.4): if this DID no longer controls itself, every future update ' +
          'needs the new controller to co-sign and this institution cannot get that back.'
        );
      case AlarmKind.OFFICER_ROTATED:
        return `An officer key of ${did} was rotated by ${signers}.`;
      case AlarmKind.OFFICER_ADDED:
        return `An officer verification method was added to ${did} by ${signers}.`;
      case AlarmKind.UPDATE_WITHOUT_KEY_CHANGE:
        return `${did} was updated by ${signers} with no change to its keys or controllers.`;
      case AlarmKind.REJECTED_ATTEMPT:
        return (
          `The chain REJECTED a DID-module message against ${did} signed by ${signers}. Nothing ` +
          'changed on chain. A rejected attempt we did not make is somebody testing what they ' +
          'can do with a key they hold.'
        );
      case AlarmKind.BROADCAST_NOT_ON_CHAIN:
        return (
          `This backend recorded a completed broadcast against ${did} that the chain watch has ` +
          'never observed. Either the write did not take effect, or the watcher is reading a ' +
          'different chain from the one we write to. Both make every other reading here unsafe.'
        );
      case AlarmKind.INTENT_UNRESOLVED:
        return (
          `A signing intent against ${did} produced neither a result nor a rejection. The ` +
          'process may have died between broadcast and log — check the chain for the versionId ' +
          'in the detail before assuming nothing happened.'
        );
      case AlarmKind.WATCH_GAP_UNRECOVERABLE:
        return (
          'The chain watch was down across blocks the node can no longer serve. Those heights ' +
          'cannot be examined. An eviction or deactivation in that window would be invisible ' +
          'to this system — do not read a quiet alarm list as an all-clear.'
        );
      case AlarmKind.WATCHER_STALLED:
        return (
          'The chain watch has stopped advancing. Detection latency is the control that makes ' +
          '1-of-N custody safe (#291); while this holds, there is effectively no alarm.'
        );
      case AlarmKind.AUDIT_CHAIN_TAMPERED:
        return (
          'The signing audit log does not verify against its own hash chain. Entries were ' +
          'altered or removed after they were written. Treat the log as evidence of tampering, ' +
          'not as a record of signing.'
        );
    }
  })();

  return input.attribution === AlarmAttribution.UNMATCHED ? `${body} ${UNMATCHED_SUFFIX}` : body;
}

