/**
 * Mint the institutional DID for an onboarded L2 institution.
 *
 * ===========================================================================
 * THE SHAPE, AND WHY IT IS WHAT IT IS
 * ===========================================================================
 * `provisionInstitutionalDid` requires at least one slot this agent can sign
 * with, and `LEDGER_SIGNING_FRAGMENT` (#key-officer-1) says why: the SDK's
 * client-side guard demands the ledger-signing key be agent-held, so that slot
 * is ALWAYS `agent-generated` and never imported.
 *
 * So the institution would be 1-of-1 — agent-held, the backend holding the only
 * key — which is custody under a different name, and exactly what this project's
 * custody principles refuse. The fix is a SECOND slot from the institution's own
 * public key, supplied when its software claimed the enrolment. Then:
 *
 *   #key-officer-1  agent-generated   the ledger signing slot (required)
 *   #key-officer-2  imported          THE INSTITUTION'S OWN KEY
 *
 * and the document is a 2-of-N the institution actually controls.
 *
 * ===========================================================================
 * WHEN THERE IS NO INSTITUTION KEY
 * ===========================================================================
 * A software that cannot yet generate a key is still onboarded — 1-of-1,
 * agent-held, which #286 measured as repairable in place while the surviving key
 * lives. That is a RESIDUAL, not a silent default: the result carries
 * `institutionHoldsKey: false` so the caller can report it rather than implying
 * a custody property that is not there.
 *
 * ===========================================================================
 * READ THE DID BACK FROM THE CHAIN
 * ===========================================================================
 * A cached document is exactly what a failed write looks like. The mint is only
 * reported successful once the ledger answers with the document, which is the
 * discipline #295's tooling established.
 */
import { getAgent } from '../agent/index.js';
import { provisionInstitutionalDid } from './institutionalDid.js';
import { resolveOnChain } from './cheqdLedger.js';
import { logger } from '../utils/logger.js';

export interface MintInstitutionDidSpec {
  readonly institutionId: string;
  readonly institutionName: string;
  /** The officer's own words for why this exists. Recorded, never written to the ledger. */
  readonly purpose: string;
  /** The institution software's Ed25519 public key, multibase-encoded, if it has one. */
  readonly claimantPublicKey?: string | null;
}

export interface MintInstitutionDidResult {
  readonly did: string;
  /** How many verification methods the LEDGER reports, not what we intended. */
  readonly verificationMethodCount: number;
  /** False when the document is agent-held only — a residual, reported not hidden. */
  readonly institutionHoldsKey: boolean;
}

export async function mintInstitutionDid(
  spec: MintInstitutionDidSpec,
): Promise<MintInstitutionDidResult> {
  const agent = getAgent();

  const institutionHoldsKey =
    typeof spec.claimantPublicKey === 'string' && spec.claimantPublicKey.trim().length > 0;

  const officers = [
    // ALWAYS agent-held. The SDK guard requires it for the ledger signing slot.
    { kind: 'agent-generated' as const },
    ...(institutionHoldsKey
      ? [
          {
            kind: 'imported' as const,
            publicKeyMultibase: spec.claimantPublicKey!.trim(),
            // Required by the spec so the acknowledgement is explicit rather
            // than assumed: a foreign-held key IS cryptographically the whole
            // institution at this slot.
            acknowledgement:
              'I-ACCEPT-THAT-THIS-KEY-HOLDER-IS-CRYPTOGRAPHICALLY-THE-WHOLE-INSTITUTION' as const,
            custodian: `${spec.institutionName} (via issuer console onboarding)`,
          },
        ]
      : []),
  ];

  const result = await provisionInstitutionalDid(agent, {
    officers,
    purpose: spec.purpose,
  });

  // READ IT BACK. A cached document is what a failed write looks like.
  const onChain = await resolveOnChain(agent, result.did);
  const verificationMethodCount = onChain?.verificationMethod?.length ?? 0;

  if (verificationMethodCount !== officers.length) {
    throw new Error(
      `Institution DID ${result.did} was written but the ledger reports ` +
        `${verificationMethodCount} verification method(s), not the ${officers.length} requested. ` +
        'Refusing to record a document the chain does not agree with.',
    );
  }

  logger.info('l2_institution_did_minted', {
    institutionId: spec.institutionId,
    did: result.did,
    verificationMethodCount,
    institutionHoldsKey,
  });

  return { did: result.did, verificationMethodCount, institutionHoldsKey };
}
