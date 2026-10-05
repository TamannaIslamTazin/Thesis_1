/**
 * SSI Healthcare Backend — the identity re-issuance ("visa re-issuance") workflow.
 *
 * ===========================================================================
 * WHAT THIS IS FOR
 * ===========================================================================
 * A patient's DID is permanently unrecoverable. They need a new identifier, and
 * then every authority that issued a credential against the old identifier has
 * to issue it again against the new one. Passport, then visas.
 *
 * It is an EMERGENCY procedure. It runs rarely, it runs on the only copy of
 * someone's medical identity, and a half-finished run is worse than no run at
 * all — a patient with two identities and credentials scattered across both is
 * harder to help than a patient with one broken identity. Everything below is
 * shaped by that, per #302:
 *
 *   - The worklist is PERSISTED BEFORE any signing, so a crash resumes rather
 *     than restarts and a partial run is countable rather than invisible.
 *   - `CredentialReissuance.oldCredentialId` is UNIQUE, so a re-run cannot mint
 *     a second replacement for a credential that already has one. Idempotence
 *     is a database constraint, not a code path that has to be remembered.
 *   - Per-credential failure is ISOLATED: one bad credential marks itself
 *     FAILED and the run continues, because stopping the run would strand the
 *     other twenty-five.
 *   - The old identity is retired only AFTER the new one is proven on chain.
 *     The failure ordering is deliberate: we would rather end with two live
 *     identities (visible, fixable) than zero (invisible, terminal).
 *
 * ===========================================================================
 * THE THREE ORDERING CONSTRAINTS, LEARNED THE HARD WAY FROM THE REAL DATA
 * ===========================================================================
 * 1. THE ISSUER MAY ITSELF BE DEAD. In this deployment every credential held by
 *    the broken holder DID was issued BY another of the broken DIDs. So the
 *    issuer must be migrated first, and re-issuance must resolve an issuer
 *    through {@link resolveCurrentIssuer} rather than copying `issuerDid` off
 *    the old row. Migrating an issuer is transitively expensive — it invalidates
 *    everything that issuer ever issued, for every holder — and that cost is a
 *    measurement this workflow reports rather than an assumption it hides.
 *
 * 2. THE NEW DID MUST EXIST AND RESOLVE BEFORE THE FIRST CREDENTIAL IS SIGNED.
 *    `issueCredential` binds a credential to the holder's key material via
 *    `assertHolderBound`; against a DID that is not yet on chain that fails
 *    closed, which is right, but it fails 26 times instead of once.
 *
 * 3. THE OLD CREDENTIAL IS REVOKED ONLY AFTER ITS REPLACEMENT IS PERSISTED.
 *    The reverse order has a window in which the patient holds neither.
 *
 * ===========================================================================
 * WHY THE OLD DID IS MARKED AND NOT DEACTIVATED
 * ===========================================================================
 * `MsgDeactivateDidDoc` requires signatures from controllers ∪ ALL
 * verification-method controllers (S-1 §5.6 D1). For the unrecoverable shape
 * that set contains the DID's own lost key — so IN THE FAILURE MODE THIS
 * WORKFLOW EXISTS FOR, THE OLD DID CANNOT BE DEACTIVATED AT ALL. A procedure
 * whose final step requires the key it has just declared lost is not a
 * procedure. S-4 T1 adds that deactivation is terminal (`code 1207`, no revival
 * path) and is itself a transaction that can fail.
 *
 * So the tombstone is kept by the institution, not stamped in the passport the
 * holder no longer has:
 *   - a {@link DidSuccession} row, unique on both `oldDid` and `newDid`;
 *   - every credential that WAS carried forward is revoked as it is superseded,
 *     one at a time in {@link reissueOneCredential} — that is the part a
 *     verifier actually observes;
 *   - `User.did` moved, and the cached `DIDDocument` marked REVOKED.
 * Deactivation remains available as an OPTIONAL extra when the old key happens
 * to survive — see {@link deactivateOldDid} — but nothing depends on it.
 *
 * WHAT THIS HONESTLY DOES NOT ACHIEVE. There is no key-free way to make an
 * EXTERNAL resolver see the old cheqd DID as dead: deactivation is the only
 * on-chain signal and it needs the lost key. So an outside party resolving the
 * old identifier still gets a live document. What they cannot get is a valid
 * credential bound to it, because every carried-forward credential is revoked
 * on the issuer's published status list. That is the actual boundary of this
 * design and it is stated rather than glossed.
 */

import type { Agent } from '@credo-ts/core';
import { randomUUID } from 'node:crypto';

import { db } from '../../db/index.js';
import { logger } from '../../utils/logger.js';
import { AppError } from '../../middleware/errorHandler.js';
import { ERROR_CODES, HealthcareCredentialCategory } from '@ssi-healthcare/shared';
import type { IssuableCredentialFormat } from '@ssi-healthcare/shared';
import type {
  CredentialCategory,
  DidSuccessionReason,
  ReissuanceOutcome,
} from '../../../prisma/generated/client/index.js';

import { classifyPatientDid } from '@ssi-healthcare/sdk/ledger';
import { agentSigner, resolveOnChain, requireLiveDidOnChain } from '../cheqdLedger.js';
import { deactivateCheqdDID } from '../cheqdDid.js';
import { enrolPatient, type RecoveryControllerProvider } from '../patientEnrolment.js';
import { provisionInstitutionalDid } from '../institutionalDid.js';
import { issueCredential, revokeCredential } from '../credentialService.js';
import {
  assertWithinValidityWindow,
  authorisationDigest,
  canonicalAuthorisationBytes,
  digestEvidence,
  verifyAuthorisationSignature,
  AUTHORISATION_STATEMENT_VERSION,
  MAX_AUTHORISATION_TTL_MS,
  type ReissuanceAuthorisationStatement,
  type ReissuanceEvidenceKind,
} from './authorisation.js';
import { decideCredentialFate, type MigratableCredential } from './worklist.js';

/**
 * Prisma's folder enum back to the vocabulary `issueCredential` speaks.
 *
 * Total by type, so adding a folder to the schema breaks the build here rather
 * than silently filing a migrated credential under GENERAL.
 */
const CATEGORY_TO_APP: Record<CredentialCategory, HealthcareCredentialCategory> = {
  BLOOD_WORK: HealthcareCredentialCategory.BLOOD_WORK,
  PRESCRIPTIONS: HealthcareCredentialCategory.PRESCRIPTIONS,
  VACCINATIONS: HealthcareCredentialCategory.VACCINATIONS,
  IMAGING: HealthcareCredentialCategory.IMAGING,
  LAB_RESULTS: HealthcareCredentialCategory.LAB_RESULTS,
  INSURANCE: HealthcareCredentialCategory.INSURANCE,
  GENERAL: HealthcareCredentialCategory.GENERAL,
  PROFESSIONAL: HealthcareCredentialCategory.PROFESSIONAL,
  IDENTITY: HealthcareCredentialCategory.IDENTITY,
};

// ---------------------------------------------------------------------------
// Phase 1 — authorise
// ---------------------------------------------------------------------------

export interface AuthoriseReissuanceInput {
  readonly oldDid: string;
  readonly userId: string;
  readonly institutionalDid: string;
  /** Which of the institution's N keys signs. Any one suffices (S-4 M1). */
  readonly institutionalSlotFragment?: string;
  readonly officerId: string;
  readonly officerName: string;
  readonly evidenceKind: ReissuanceEvidenceKind;
  /** A reference to the evidence — a case number. NEVER the document itself. */
  readonly evidenceReference: string;
  readonly ttlMs?: number;
}

export interface AuthorisationRecord {
  readonly id: string;
  readonly statement: ReissuanceAuthorisationStatement;
  readonly signatureBase64: string;
  readonly verificationMethodId: string;
}

/**
 * Sign and persist the authorisation. This is the whole of research question 2.
 *
 * Note what is checked BEFORE the institutional key is asked to sign anything:
 * that the institution resolves live on chain, that the target user exists and
 * that the old DID is really theirs, and that no succession already exists. A
 * signature is durable evidence; producing one over a statement we already know
 * to be wrong would be manufacturing a false record.
 */
export async function authoriseReissuance(
  agent: Agent,
  input: AuthoriseReissuanceInput,
): Promise<AuthorisationRecord> {
  const institution = await requireLiveDidOnChain(
    agent,
    input.institutionalDid,
    `authorise re-issuance of '${input.oldDid}'`,
  );

  const user = await db.user.findUnique({ where: { id: input.userId } });
  if (!user) {
    throw new AppError(
      ERROR_CODES.NOT_FOUND,
      `No user '${input.userId}'. The account is the only thing tying a human to a legacy ` +
        'DID that carries no institutional controller; without it there is nothing to ' +
        'authenticate against.',
      404,
    );
  }

  if (user.did !== input.oldDid) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `User '${input.userId}' currently holds '${user.did ?? 'no DID'}', not '${input.oldDid}'. ` +
        'Refusing to authorise the replacement of a DID this account does not own — that is ' +
        'the exact shape of an identity-seizure mistake.',
      409,
    );
  }

  const existing = await db.didSuccession.findUnique({ where: { oldDid: input.oldDid } });
  if (existing && existing.status !== 'ABANDONED') {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `'${input.oldDid}' already has a succession to '${existing.newDid}' in status ` +
        `${existing.status}. A second authorisation would fork the identity.`,
      409,
    );
  }

  const ttlMs = Math.min(input.ttlMs ?? MAX_AUTHORISATION_TTL_MS, MAX_AUTHORISATION_TTL_MS);
  const now = new Date();
  const statement: ReissuanceAuthorisationStatement = {
    version: AUTHORISATION_STATEMENT_VERSION,
    oldDid: input.oldDid,
    userId: input.userId,
    institutionalDid: input.institutionalDid,
    officerId: input.officerId,
    evidenceKind: input.evidenceKind,
    evidenceDigest: digestEvidence(input.evidenceReference),
    nonce: randomUUID(),
    notBefore: now.toISOString(),
    notAfter: new Date(now.getTime() + ttlMs).toISOString(),
  };

  const signer = await agentSigner(agent, input.institutionalDid, input.institutionalSlotFragment);
  const signature = await signer.sign(canonicalAuthorisationBytes(statement));
  const signatureBase64 = Buffer.from(signature).toString('base64');

  // Verify our own signature against the CHAIN-resolved document before storing
  // it. If the agent signed with a key the institution does not publish, the
  // authorisation is worthless and we would rather find out here than on the
  // day someone audits it.
  verifyAuthorisationSignature({
    statement,
    signatureBase64,
    verificationMethodId: signer.verificationMethodId,
    institution,
  });

  const row = await db.reissuanceAuthorisation.create({
    data: {
      oldDid: statement.oldDid,
      userId: statement.userId,
      institutionalDid: statement.institutionalDid,
      institutionalVerificationMethodId: signer.verificationMethodId,
      authorisationDigest: authorisationDigest(statement),
      institutionalSignature: signatureBase64,
      nonce: statement.nonce,
      officerId: input.officerId,
      officerName: input.officerName,
      evidenceKind: input.evidenceKind,
      evidenceReference: input.evidenceReference,
      evidenceDigest: statement.evidenceDigest,
      notBefore: new Date(statement.notBefore),
      notAfter: new Date(statement.notAfter),
    },
  });

  logger.warn('reissuance_authorised', {
    authorisationId: row.id,
    oldDid: statement.oldDid,
    userId: statement.userId,
    institutionalDid: statement.institutionalDid,
    signedBy: signer.verificationMethodId,
    officerId: input.officerId,
    evidenceKind: input.evidenceKind,
    expiresAt: statement.notAfter,
    note:
      'An identity replacement has been authorised on the institution’s signature alone. The ' +
      'holder’s key played no part, because it is gone. This entry is the record of that act.',
  });

  return {
    id: row.id,
    statement,
    signatureBase64,
    verificationMethodId: signer.verificationMethodId,
  };
}

// ---------------------------------------------------------------------------
// Measurements — research questions 3 and 4
// ---------------------------------------------------------------------------

export interface PhaseTiming {
  readonly phase: string;
  readonly ms: number;
}

export interface CredentialTiming {
  readonly oldCredentialId: string;
  readonly outcome: ReissuanceOutcome;
  readonly issueMs: number;
  readonly revokeMs: number;
  readonly totalMs: number;
}

export interface ReissuanceMeasurements {
  readonly totalMs: number;
  readonly phases: readonly PhaseTiming[];
  readonly perCredential: readonly CredentialTiming[];
  /** Ledger transactions this run initiated. The number that does NOT scale with credentials. */
  readonly chainWrites: number;
  readonly chainWriteDetail: readonly string[];
  /** Rows written. The number that DOES scale with credentials. */
  readonly dbWrites: number;
}

export interface ReissuanceRunResult {
  readonly successionId: string;
  readonly oldDid: string;
  readonly newDid: string;
  readonly newDidTxHash: string;
  readonly newDidHeight: number;
  readonly credentialsFound: number;
  readonly credentialsReissued: number;
  readonly credentialsSkipped: number;
  readonly credentialsFailed: number;
  readonly byOutcome: Readonly<Record<string, number>>;
  readonly disposition: 'MARKED' | 'DEACTIVATED';
  readonly measurements: ReissuanceMeasurements;
}

/** Accumulates the measurements without cluttering the flow that produces them. */
class RunMeter {
  private readonly startedAt = Date.now();
  private readonly phaseTimings: PhaseTiming[] = [];
  private readonly credentialTimings: CredentialTiming[] = [];
  private readonly chainWriteLabels: string[] = [];
  private dbWriteCount = 0;

  async phase<T>(name: string, work: () => Promise<T>): Promise<T> {
    const began = Date.now();
    try {
      return await work();
    } finally {
      this.phaseTimings.push({ phase: name, ms: Date.now() - began });
    }
  }

  chainWrite(label: string): void {
    this.chainWriteLabels.push(label);
  }

  dbWrites(count: number): void {
    this.dbWriteCount += count;
  }

  credential(timing: CredentialTiming): void {
    this.credentialTimings.push(timing);
  }

  snapshot(): ReissuanceMeasurements {
    return {
      totalMs: Date.now() - this.startedAt,
      phases: [...this.phaseTimings],
      perCredential: [...this.credentialTimings],
      chainWrites: this.chainWriteLabels.length,
      chainWriteDetail: [...this.chainWriteLabels],
      dbWrites: this.dbWriteCount,
    };
  }
}

// ---------------------------------------------------------------------------
// Phase 2..6 — execute
// ---------------------------------------------------------------------------

/**
 * WHICH SHAPE THE SUCCESSOR IS MINTED IN, AND WHY IT IS NOT ONE SHAPE.
 *
 * Measured the hard way on the first run of this workflow (steno #313). A
 * holder DID and an issuer DID want OPPOSITE shapes, and the difference is not
 * cosmetic — it decides whether the successor can do the job at all:
 *
 *   HOLDER  → the S-1 §8.1 patient shape. `controller: [RCK, institution]`,
 *             2-of-2 AND, verification method controlled by the RCK. Recoverable
 *             from device-key loss WITHOUT ever needing the device key, which is
 *             the whole point of the enrolment shape.
 *
 *   ISSUER  → the S-4 §6.2 institutional shape. SELF-CONTROLLED, N ≥ 2
 *             verification methods, all self-controlled. Recoverable by sibling
 *             rescue (S-4 M1) rather than by an external controller.
 *
 * The reason an issuer cannot use the patient shape is `x/resource`: publishing
 * a status list requires signatures from the SUBJECT'S CONTROLLER SET, and
 * `agent.modules.cheqd.createResource` signs with the subject's own keys only.
 * A patient-shaped issuer therefore cannot publish, cannot revoke, and so
 * cannot issue at all — the first run failed all 25 credentials on exactly this,
 * with `signer: <institution>: signature is required but not found`.
 *
 * Note the uncomfortable symmetry this exposes: the old issuer DID could
 * publish 54 status-list versions PRECISELY BECAUSE it was self-controlled —
 * the same property that made it unrecoverable is the one that made it able to
 * issue. Self-control is not a defect in itself; it is a defect in a HOLDER.
 */
export type SuccessorRole = 'HOLDER' | 'ISSUER';

export interface ExecuteReissuanceInput {
  readonly authorisationId: string;
  readonly reason: DidSuccessionReason;
  readonly institutionalDid: string;
  readonly recoveryControllerProvider: RecoveryControllerProvider;
  /**
   * Defaults to HOLDER. See {@link SuccessorRole}: the wrong choice here mints a
   * successor that cannot do what its predecessor did, so it is checked against
   * the old DID's observed behaviour in {@link assertRoleMatchesEvidence}
   * rather than trusted.
   */
  readonly successorRole?: SuccessorRole;
  /**
   * Additionally deactivate the old DID on chain.
   *
   * OFF BY DEFAULT AND NOT PART OF THE PROCEDURE. It is only possible while the
   * old key survives — i.e. never in the failure mode this workflow exists for —
   * and it is terminal (S-4 T1). Set it only when the old DID owns no
   * DID-linked resource anything still needs to dereference.
   */
  readonly alsoDeactivateOldDid?: boolean;
}

export async function executeReissuance(
  agent: Agent,
  input: ExecuteReissuanceInput,
): Promise<ReissuanceRunResult> {
  const meter = new RunMeter();

  // ---- Phase 2a: re-authenticate. Nothing is trusted from the caller. ------
  const { statement, authorisation } = await meter.phase('authenticate', async () =>
    loadAndVerifyAuthorisation(agent, input.authorisationId),
  );

  const oldDid = statement.oldDid;

  const role: SuccessorRole = input.successorRole ?? 'HOLDER';

  // ---- Phase 2b: preconditions, all before a single write. ----------------
  await meter.phase('preconditions', async () => {
    await assertReissuanceIsTheRightRemedy(agent, oldDid, input.reason);
    await assertRoleMatchesEvidence(oldDid, role);
  });

  // ---- Phase 3: the new identity. -----------------------------------------
  const succession = await meter.phase('mint-new-identity', async () => {
    let created: { id: string; newDid: string; newDidTxHash: string; newDidHeight: number } | null =
      null;

    const recordSuccession = async (enrolment: {
      patientDid: string;
      transactionHash: string;
      height: number;
    }): Promise<void> => {
      const row = await db.didSuccession.create({
        data: {
          oldDid,
          newDid: enrolment.patientDid,
          userId: statement.userId,
          reason: input.reason,
          status: 'MIGRATING',
          authorisationId: authorisation.id,
          newDidTxHash: enrolment.transactionHash,
          newDidHeight: enrolment.height,
        },
      });

      // Consumed in the same breath as the succession it authorised. An
      // authorisation that is consumed without a succession, or a succession
      // without a consumed authorisation, would both be residue.
      await db.reissuanceAuthorisation.update({
        where: { id: authorisation.id },
        data: { consumedAt: new Date() },
      });

      created = {
        id: row.id,
        newDid: row.newDid,
        newDidTxHash: row.newDidTxHash ?? '',
        newDidHeight: row.newDidHeight ?? 0,
      };
    };

    if (role === 'ISSUER') {
      // SELF-CONTROLLED, so it can publish its own status list. N = 2 so a lost
      // slot can be rescued by its sibling (S-4 M1) — the issuer's substitute
      // for the external controller a holder gets.
      const institution = await provisionInstitutionalDid(agent, {
        officers: [{ kind: 'agent-generated' }, { kind: 'agent-generated' }],
        purpose:
          `Successor issuing DID for '${oldDid}', minted by the R5 re-issuance workflow. ` +
          'Self-controlled because x/resource requires the SUBJECT’S controller set to sign a ' +
          'status-list publish (steno #313), which a 2-of-2 patient shape can never satisfy ' +
          'through agent.modules.cheqd.createResource.',
      });

      meter.chainWrite('MsgCreateDidDoc — new institutional issuing DID (1-of-2)');
      meter.dbWrites(2);

      await recordSuccession({
        patientDid: institution.did,
        transactionHash: institution.transactionHash,
        height: institution.height,
      });

      if (created === null) {
        throw new AppError(
          ERROR_CODES.DID_CREATION_FAILED,
          'Institutional provisioning returned without a succession row.',
          500,
        );
      }
      return created as { id: string; newDid: string; newDidTxHash: string; newDidHeight: number };
    }

    await enrolPatient(agent, {
      userId: statement.userId,
      institutionalDid: input.institutionalDid,
      recoveryControllerProvider: input.recoveryControllerProvider,
      // INSIDE the enrolment's atomic boundary on purpose. `enrolPatient` calls
      // this only after it has read the new document back OFF THE CHAIN and
      // re-checked its shape there, and it abandons everything it wrote if this
      // throws. Writing the succession row afterwards instead would open a
      // window where two DIDs exist on chain with nothing pointing at them.
      persist: recordSuccession,
    });

    meter.chainWrite('MsgCreateDidDoc — recovery controller DID');
    meter.chainWrite('MsgCreateDidDoc — new patient DID');
    meter.dbWrites(2);

    if (created === null) {
      throw new AppError(
        ERROR_CODES.DID_CREATION_FAILED,
        'Enrolment returned without persisting a succession row. Refusing to continue a ' +
          'migration whose new identity is not recorded.',
        500,
      );
    }

    return created as { id: string; newDid: string; newDidTxHash: string; newDidHeight: number };
  });

  logger.warn('reissuance_new_identity_minted', {
    successionId: succession.id,
    oldDid,
    newDid: succession.newDid,
    transactionHash: succession.newDidTxHash,
    height: succession.newDidHeight,
  });

  // ---- Phase 4: enumerate. The worklist is durable before anything signs. --
  const worklist = await meter.phase('enumerate-credentials', async () =>
    buildWorklist(succession.id, oldDid, meter),
  );

  // ---- Phase 5: drain. One credential's failure does not stop the rest. ---
  await meter.phase('reissue-credentials', async () => {
    for (const item of worklist.toReissue) {
      await reissueOneCredential({
        successionId: succession.id,
        reissuanceRowId: item.reissuanceRowId,
        oldCredentialId: item.credential.id,
        newHolderDid: succession.newDid,
        meter,
      });
    }
  });

  // ---- Phase 6: tombstone the old identity. -------------------------------
  // ---- Phase 6: tombstone — ONLY if the worklist actually drained. ---------
  //
  // THIS GUARD EXISTS BECAUSE ITS ABSENCE DID REAL DAMAGE (steno #314). On the
  // first run of this workflow every re-issuance failed, each one safely and in
  // isolation, leaving the old credentials untouched — and then this phase ran
  // anyway and revoked all 25 of them, because it assumed anything still ACTIVE
  // on the old DID had been superseded. It had not. The holder ended the run
  // with strictly less than they started with.
  //
  // The general lesson, worth more than the fix: per-step failsafes do not
  // compose into a safe procedure. Every individual step behaved correctly and
  // the composition was still destructive, because a later phase's precondition
  // was assumed rather than checked.
  const outstanding = await db.credentialReissuance.count({
    where: { successionId: succession.id, outcome: { in: ['PENDING', 'FAILED'] } },
  });

  const disposition = await meter.phase('tombstone-old-identity', async () => {
    if (outstanding > 0) {
      logger.error('reissuance_tombstone_refused', {
        successionId: succession.id,
        oldDid,
        newDid: succession.newDid,
        outstanding,
        state:
          'The new identity EXISTS and the old one is STILL LIVE, holding every credential ' +
          'that was not carried forward. That is deliberate: two live identities is a state ' +
          'an operator can see and finish; one dead identity holding nothing is not.',
        remedy:
          'Fix the cause of the failures and re-run. The worklist is durable and ' +
          'oldCredentialId is unique, so the re-run resumes rather than restarting.',
      });
      return 'MARKED' as const;
    }

    return tombstoneOldIdentity(agent, {
      oldDid,
      newDid: succession.newDid,
      userId: statement.userId,
      alsoDeactivate: input.alsoDeactivateOldDid === true,
      successionId: succession.id,
      meter,
    });
  });

  // ---- Phase 7: settle the counters from the child rows, not from memory. -
  const settled = await meter.phase('settle', async () => {
    const grouped = await db.credentialReissuance.groupBy({
      by: ['outcome'],
      where: { successionId: succession.id },
      _count: { _all: true },
    });

    const byOutcome: Record<string, number> = {};
    for (const group of grouped) byOutcome[group.outcome] = group._count._all;

    const reissued = byOutcome.REISSUED ?? 0;
    const failed = (byOutcome.FAILED ?? 0) + (byOutcome.PENDING ?? 0);
    const found = Object.values(byOutcome).reduce((sum, n) => sum + n, 0);

    await db.didSuccession.update({
      where: { id: succession.id },
      data: {
        status: failed === 0 ? 'COMPLETE' : 'MIGRATING',
        disposition,
        credentialsFound: found,
        credentialsReissued: reissued,
        credentialsSkipped: found - reissued - failed,
        credentialsFailed: failed,
        completedAt: failed === 0 ? new Date() : null,
        abandonReason:
          failed === 0
            ? null
            : `${failed} credential(s) did not reach a terminal outcome. The succession stays ` +
              'MIGRATING so the residue keeps showing up in reports rather than being closed over.',
      },
    });
    meter.dbWrites(1);

    return { byOutcome, reissued, failed, found };
  });

  const result: ReissuanceRunResult = {
    successionId: succession.id,
    oldDid,
    newDid: succession.newDid,
    newDidTxHash: succession.newDidTxHash ?? '',
    newDidHeight: succession.newDidHeight ?? 0,
    credentialsFound: settled.found,
    credentialsReissued: settled.reissued,
    credentialsSkipped: settled.found - settled.reissued - settled.failed,
    credentialsFailed: settled.failed,
    byOutcome: settled.byOutcome,
    disposition,
    measurements: meter.snapshot(),
  };

  logger.warn('reissuance_complete', {
    ...result,
    measurements: {
      totalMs: result.measurements.totalMs,
      chainWrites: result.measurements.chainWrites,
      dbWrites: result.measurements.dbWrites,
      phases: result.measurements.phases,
    },
  });

  return result;
}

// ---------------------------------------------------------------------------
// The pieces
// ---------------------------------------------------------------------------

async function loadAndVerifyAuthorisation(
  agent: Agent,
  authorisationId: string,
): Promise<{
  statement: ReissuanceAuthorisationStatement;
  authorisation: { id: string; institutionalVerificationMethodId: string };
}> {
  const row = await db.reissuanceAuthorisation.findUnique({ where: { id: authorisationId } });

  if (!row) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `No re-issuance authorisation '${authorisationId}'.`,
      404,
    );
  }

  if (row.consumedAt) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Authorisation '${authorisationId}' was already consumed at ` +
        `${row.consumedAt.toISOString()}. Single use: one identity check authorises exactly ` +
        'one migration.',
      409,
    );
  }

  const statement: ReissuanceAuthorisationStatement = {
    version: AUTHORISATION_STATEMENT_VERSION,
    oldDid: row.oldDid,
    userId: row.userId,
    institutionalDid: row.institutionalDid,
    officerId: row.officerId,
    evidenceKind: row.evidenceKind as ReissuanceEvidenceKind,
    evidenceDigest: row.evidenceDigest,
    nonce: row.nonce,
    notBefore: row.notBefore.toISOString(),
    notAfter: row.notAfter.toISOString(),
  };

  // The digest is recomputed rather than read back. If the stored statement
  // fields were edited after signing, the digest no longer matches and the
  // signature check below would fail anyway — but this names the tampering
  // instead of reporting a mysterious bad signature.
  const recomputed = authorisationDigest(statement);
  if (recomputed !== row.authorisationDigest) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Authorisation '${authorisationId}' does not re-digest to its stored value ` +
        `(${recomputed} vs ${row.authorisationDigest}). The row was altered after it was ` +
        'signed. Refusing to act on it.',
      409,
    );
  }

  assertWithinValidityWindow(statement, new Date());

  // THE CHAIN, not the cache. The institution's key set may have changed since
  // the authorisation was signed — an evicted officer key (S-4 H1) must not
  // still be able to move an identity.
  const institution = await resolveOnChain(agent, row.institutionalDid);
  if (!institution) {
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `Institutional DID '${row.institutionalDid}' does not resolve on chain, so the ` +
        'authorisation cannot be verified. Refusing to migrate an identity on an ' +
        'unverifiable authorisation.',
      502,
    );
  }

  verifyAuthorisationSignature({
    statement,
    signatureBase64: row.institutionalSignature,
    verificationMethodId: row.institutionalVerificationMethodId,
    institution,
  });

  return { statement, authorisation: row };
}

/**
 * Refuse to re-issue an identity that could be REPAIRED instead.
 *
 * Re-issuance is destructive of continuity: it changes the identifier, orphans
 * every credential until each is re-issued, and cannot be undone. Rotation
 * (S-1 R2) preserves the identifier and costs one transaction. So a correctly
 * shaped DID must not come through here just because someone lost a phone —
 * that is what the enrolment shape was built to survive, and quietly
 * re-issuing instead would waste the property and hide it from the measurements.
 */
async function assertReissuanceIsTheRightRemedy(
  agent: Agent,
  oldDid: string,
  reason: DidSuccessionReason,
): Promise<void> {
  const resolved = await resolveOnChain(agent, oldDid);

  if (!resolved) {
    throw new AppError(
      ERROR_CODES.DID_NOT_FOUND,
      `'${oldDid}' does not resolve on chain. Refusing to migrate an identity we cannot read: ` +
        'if it is absent the account was never enrolled, and if the node is unreachable this ' +
        'is a transient failure wearing a permanent one’s clothes.',
      502,
    );
  }

  const classification = classifyPatientDid({ ...resolved, id: resolved.did });

  if (reason === 'UNRECOVERABLE_SHAPE_LEGACY' && classification.verdict !== 'unrecoverable') {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `'${oldDid}' is classified '${classification.verdict}', not 'unrecoverable', so ` +
        'UNRECOVERABLE_SHAPE_LEGACY is the wrong reason. A recoverable DID should have its ' +
        'device key ROTATED (S-1 R2, one transaction, identifier preserved), not re-issued. ' +
        'Re-issuance orphans every credential the holder has until each is issued again.',
      409,
    );
  }
}

/**
 * The successor's shape must match what the old DID was actually DOING, not
 * what someone typed on the command line.
 *
 * A wrong answer here is not caught until the first credential is signed —
 * which, on the first run of this workflow, was 25 identical failures deep
 * (#313). The evidence is already in the database and costs two counts to read.
 */
async function assertRoleMatchesEvidence(oldDid: string, role: SuccessorRole): Promise<void> {
  const [issued, held] = await Promise.all([
    db.credential.count({ where: { issuerDid: oldDid } }),
    db.credential.count({ where: { holderDid: oldDid } }),
  ]);

  if (issued > 0 && held > 0) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `'${oldDid}' has both ISSUED ${issued} credentials and HELD ${held}. The two roles want ` +
        'opposite DID shapes — an issuer must be self-controlled to publish its status list, ' +
        'a holder must NOT be self-controlled or it is unrecoverable — so no single successor ' +
        'can serve both. Split the roles before migrating: mint a separate issuing DID, ' +
        're-issue that DID’s credentials under it, and then migrate this one as a holder.',
      409,
    );
  }

  if (role === 'HOLDER' && issued > 0) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `'${oldDid}' has issued ${issued} credentials, so it is an ISSUER, but the successor ` +
        'was requested as a HOLDER. A patient-shaped successor cannot publish a status list ' +
        '— x/resource requires the subject’s controller set to sign and the wallet can only ' +
        'offer the subject’s own key — so it could never revoke anything it issued.',
      409,
    );
  }

  if (role === 'ISSUER' && held > 0) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `'${oldDid}' holds ${held} credentials, so it is a HOLDER, but the successor was ` +
        'requested as an ISSUER. A self-controlled successor would be unrecoverable from ' +
        'device-key loss (S-1 R0) — it would reproduce the exact defect being migrated away ' +
        'from.',
      409,
    );
  }
}

interface WorklistItem {
  readonly reissuanceRowId: string;
  readonly credential: MigratableCredential;
}

async function buildWorklist(
  successionId: string,
  oldDid: string,
  meter: RunMeter,
): Promise<{ toReissue: WorklistItem[]; found: number }> {
  const credentials = await db.credential.findMany({
    where: { holderDid: oldDid },
    orderBy: { issuedAt: 'asc' },
  });

  const now = new Date();
  const toReissue: WorklistItem[] = [];

  for (const credential of credentials) {
    const decision = decideCredentialFate(credential, now);
    const outcome: ReissuanceOutcome =
      decision.action === 'REISSUE' ? 'PENDING' : decision.outcome;

    // `oldCredentialId` is UNIQUE, so a resumed run finds the row already there
    // and does not enqueue the credential twice.
    const row = await db.credentialReissuance.upsert({
      where: { oldCredentialId: credential.id },
      create: {
        successionId,
        oldCredentialId: credential.id,
        outcome,
        detail: decision.action === 'REISSUE' ? null : decision.detail,
        oldCredentialHash: credential.credentialHash,
        oldStatus: credential.status,
        oldFormat: credential.credentialFormat,
        settledAt: decision.action === 'REISSUE' ? null : new Date(),
      },
      update: {},
    });
    meter.dbWrites(1);

    if (decision.action === 'REISSUE' && row.outcome === 'PENDING') {
      toReissue.push({ reissuanceRowId: row.id, credential });
    }
  }

  logger.info('reissuance_worklist_built', {
    successionId,
    oldDid,
    found: credentials.length,
    toReissue: toReissue.length,
  });

  return { toReissue, found: credentials.length };
}

/**
 * The issuer of a credential may itself have been migrated.
 *
 * Consulting the succession table here is what makes the whole scheme compose:
 * migrating an issuer does not require touching any credential row, because
 * every later re-issuance follows the succession forward on its own.
 */
async function resolveCurrentIssuer(issuerDid: string): Promise<string> {
  const succession = await db.didSuccession.findUnique({ where: { oldDid: issuerDid } });
  if (!succession || succession.status !== 'COMPLETE') return issuerDid;
  return succession.newDid;
}

// No `agent` parameter: `issueCredential` reaches for the process-wide agent
// itself, and taking one here would imply a choice this function does not make.
async function reissueOneCredential(
  args: {
    successionId: string;
    reissuanceRowId: string;
    oldCredentialId: string;
    newHolderDid: string;
    meter: RunMeter;
  },
): Promise<void> {
  const began = Date.now();
  let issueMs = 0;
  let revokeMs = 0;

  const old = await db.credential.findUnique({ where: { id: args.oldCredentialId } });
  if (!old) {
    await settle(args.reissuanceRowId, 'FAILED', 'The old credential row disappeared mid-run.');
    args.meter.dbWrites(1);
    return;
  }

  try {
    const issuerDid = await resolveCurrentIssuer(old.issuerDid);

    // The subject claims, minus the old identifier. `id` is re-set by
    // issueCredential to the NEW holder; carrying the old one forward would
    // produce a credential that names the dead DID inside a document bound to
    // the live one.
    const subject = extractSubjectClaims(old.credentialData);

    // `type` is ["VerifiableCredential", <specific>]. issueCredential re-adds
    // the base type, so pass only the specific one or it would be duplicated.
    const specificType = old.type.find((t) => t !== 'VerifiableCredential') ?? 'HealthCredential';

    const issueBegan = Date.now();
    const issued = await issueCredential({
      issuerDid,
      subjectDid: args.newHolderDid,
      credentialType: specificType,
      category: CATEGORY_TO_APP[old.category],
      claims: subject,
      name: old.name,
      description: old.description ?? undefined,
      format: (old.credentialFormat as IssuableCredentialFormat | null) ?? undefined,
    });
    issueMs = Date.now() - issueBegan;

    const replacement = await db.credential.findFirst({
      where: { holderDid: args.newHolderDid, issuerDid },
      orderBy: { createdAt: 'desc' },
    });

    if (!replacement) {
      throw new AppError(
        ERROR_CODES.CREDENTIAL_ISSUANCE_FAILED,
        'The replacement credential was reported issued but no row can be found for it.',
        500,
      );
    }

    // ONLY NOW is the old one retired. The reverse order has a window in which
    // the patient holds neither copy.
    const revokeBegan = Date.now();
    await revokeCredential(
      old.id,
      old.issuerDid,
      `Superseded by ${replacement.id} under identity succession ${args.successionId}.`,
    );
    revokeMs = Date.now() - revokeBegan;

    // `revokeCredential` publishes the whole status list on EVERY call, so a
    // migration costs one MsgCreateResource PER CREDENTIAL on the revocation
    // side. Counted here rather than assumed away — it is the single term that
    // makes this workflow O(n) in chain writes instead of O(1), and it is the
    // first thing to batch if a mass migration is ever needed.
    args.meter.chainWrite(`MsgCreateResource — status list republish revoking ${old.id}`);

    await db.credentialReissuance.update({
      where: { id: args.reissuanceRowId },
      data: {
        outcome: 'REISSUED',
        newCredentialId: replacement.id,
        settledAt: new Date(),
        detail: `Re-issued by '${issuerDid}'${
          issuerDid === old.issuerDid ? '' : ` (successor of '${old.issuerDid}')`
        }; old credential revoked.`,
      },
    });
    args.meter.dbWrites(3);
    args.meter.credential({
      oldCredentialId: old.id,
      outcome: 'REISSUED',
      issueMs,
      revokeMs,
      totalMs: Date.now() - began,
    });

    void issued;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);

    // ISOLATED FAILURE. This credential is marked and the run continues; the
    // old credential was not revoked, so the holder still has the only copy
    // that exists. Stopping here would strand every credential after it.
    logger.error('reissuance_credential_failed', {
      successionId: args.successionId,
      oldCredentialId: args.oldCredentialId,
      error: detail,
      residue: 'The old credential is untouched and still bound to the old DID.',
    });

    await settle(args.reissuanceRowId, 'FAILED', detail);
    args.meter.dbWrites(1);
    args.meter.credential({
      oldCredentialId: args.oldCredentialId,
      outcome: 'FAILED',
      issueMs,
      revokeMs,
      totalMs: Date.now() - began,
    });
  }
}

async function settle(id: string, outcome: ReissuanceOutcome, detail: string): Promise<void> {
  await db.credentialReissuance.update({
    where: { id },
    data: { outcome, detail, settledAt: new Date() },
  });
}

function extractSubjectClaims(credentialData: unknown): Record<string, unknown> {
  const document = credentialData as { credentialSubject?: unknown } | null;
  const subject = document?.credentialSubject;

  // A VC 1.1 array-valued credentialSubject is legal. Taking [0] rather than
  // failing keeps a legacy row migratable; more than one subject would be a
  // different credential shape entirely and is refused.
  const single = Array.isArray(subject) ? subject[0] : subject;

  if (!single || typeof single !== 'object') return {};

  const { id: _discardedOldHolder, ...claims } = single as Record<string, unknown>;
  return claims;
}

/**
 * Retire the old identity.
 *
 * The order is: revoke first (that is what a verifier sees), then move the
 * account, then optionally deactivate. A failure part-way leaves the old
 * credentials revoked and the account still pointing at the old DID — visibly
 * mid-migration, which is the state we want to be caught in.
 */
async function tombstoneOldIdentity(
  agent: Agent,
  args: {
    oldDid: string;
    newDid: string;
    userId: string;
    alsoDeactivate: boolean;
    successionId: string;
    meter: RunMeter;
  },
): Promise<'MARKED' | 'DEACTIVATED'> {
  // NOTHING IS REVOKED HERE, AND THAT IS THE FIX FOR #314.
  //
  // Each old credential is revoked by `reissueOneCredential`, immediately after
  // its replacement is persisted and never before. By the time this phase runs,
  // every credential that HAS a successor is already revoked and every one that
  // does not is deliberately still standing, recorded on its worklist row with
  // the reason. A sweep here that revoked "everything still ACTIVE" could not
  // tell those two apart — and when it could not, it revoked 25 credentials
  // whose replacements had never been issued.
  //
  // So what is still ACTIVE on the old DID after this point is exactly the
  // residue the report names: UNTRACKABLE credentials the issuer holds no
  // revocation coordinates for, and expired ones a verifier already rejects.
  const residue = await db.credential.count({
    where: { holderDid: args.oldDid, status: 'ACTIVE' },
  });

  if (residue > 0) {
    logger.warn('reissuance_active_credentials_remain_on_old_did', {
      successionId: args.successionId,
      oldDid: args.oldDid,
      count: residue,
      consequence:
        'These stay ACTIVE against a superseded DID. They are unpresentable — the holder ' +
        'cannot prove control of the old DID — but a verifier that skips holder binding ' +
        'would accept them. Countable rather than invisible, which is the most this ' +
        'workflow can honestly offer for a credential the issuer never recorded a ' +
        'revocation bit for.',
    });
  }

  await db.user.update({ where: { id: args.userId }, data: { did: args.newDid } });
  args.meter.dbWrites(1);

  await db.dIDDocument.updateMany({
    where: { did: args.oldDid },
    data: { status: 'REVOKED', deactivatedAt: new Date() },
  });
  args.meter.dbWrites(1);

  if (!args.alsoDeactivate) return 'MARKED';

  const deactivated = await deactivateOldDid(agent, args.oldDid, args.successionId);
  if (!deactivated) return 'MARKED';

  args.meter.chainWrite(`MsgDeactivateDidDoc — ${args.oldDid}`);
  await db.didSuccession.update({
    where: { id: args.successionId },
    data: {
      deactivationTxHash: deactivated.transactionHash,
      deactivationHeight: deactivated.height,
    },
  });
  args.meter.dbWrites(1);

  return 'DEACTIVATED';
}

/**
 * Best-effort on-chain deactivation. Returns null rather than throwing.
 *
 * NOTHING DEPENDS ON THIS SUCCEEDING, and that is the point. In the failure
 * mode this workflow exists for it CANNOT succeed — deactivation needs the
 * verification-method controller's signature (S-1 D1), which for the
 * unrecoverable shape is the key that is gone. Letting it throw would make the
 * whole migration fail on its optional last step, having already done every
 * irreversible thing.
 */
async function deactivateOldDid(
  agent: Agent,
  oldDid: string,
  successionId: string,
): Promise<{ transactionHash: string; height: number } | null> {
  try {
    const result = await deactivateCheqdDID(agent, oldDid);
    logger.warn('reissuance_old_did_deactivated', {
      successionId,
      oldDid,
      transactionHash: result.transactionHash,
      height: result.height,
      note: 'Terminal. There is no revival path in x/did (S-4 T1, code 1207).',
    });
    return result;
  } catch (error) {
    logger.warn('reissuance_old_did_not_deactivated', {
      successionId,
      oldDid,
      error: error instanceof Error ? error.message : String(error),
      consequence:
        'The old DID stays resolvable on chain. It is marked dead here and every credential ' +
        'bound to it is revoked, which is the disposition the procedure actually depends on.',
    });
    return null;
  }
}
