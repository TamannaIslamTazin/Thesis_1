/**
 * Where symbols moved, batch by batch.
 *
 * This file is the record of the restructure as well as its instructions: each
 * rule stays here after it has been applied, so a later reader can see where a
 * symbol used to live, and so the whole set can be re-run against a branch that
 * was cut before the move.
 *
 * Rule shape:
 *   fromFile       absolute path of the file the symbols left (matches any
 *                  relative import that resolves to it, from any directory)
 *   fromSpecifier  or a bare specifier to match literally
 *   to             the new module specifier
 *   symbols        EXPORTED names to move; anything else in the same import
 *                  statement is left where it is
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sdkDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(sdkDir, '../..');

/** Trees the codemod scans. The HMS is a separate repo and is not rewritten. */
export const searchRoots = [
  path.join(repoRoot, 'packages/backend/src'),
  path.join(repoRoot, 'packages/backend/tests'),
  path.join(repoRoot, 'packages/mobile/src'),
  path.join(repoRoot, 'packages/sdk/src'),
];

/**
 * A rule is added by the SAME commit that moves the code it describes. Landing
 * one early means `--apply` repoints imports at a module that does not export
 * those symbols yet, breaking the tree for anyone who runs the tool between the
 * two commits.
 */
export const rules = [
  // Batch 1 — the did:cheqd vocabulary and the chain's signer-set rules.
  // `assertIsCheqdDid`, `assertRotationIsSurvivable` and the patient/institutional
  // shape assertions are deliberately absent: they throw the backend's AppError
  // and have not moved.
  {
    fromFile: path.join(repoRoot, 'packages/backend/src/services/cheqdDidShapes.ts'),
    to: '@ssi-healthcare/sdk/ledger',
    symbols: [
      'DID_V1_CONTEXT',
      'ED25519_2020_CONTEXT',
      'ED25519_VERIFICATION_KEY_2020',
      'ED25519_MULTICODEC_PREFIX',
      'ED25519_RAW_KEY_LENGTH',
      'VerificationMethodSlot',
      'CheqdDidDocumentShape',
      'VerificationMethodDelta',
      'SignerSetInputDocument',
      'isCheqdDid',
      'didPartOf',
      'fragmentOf',
      'uniqueSorted',
      'controllersOrSubject',
      'signerDidsForCreate',
      'signerDidsForUpdate',
      'verificationMethodDelta',
      'verificationMethodChanged',
    ],
  },
  // Batch 3 — key encoding. Credo's MultiBaseEncoder handles base58btc and
  // nothing else, so `sdk/ledger/multibase` replaces it outright; these two
  // were the only members of cheqdDidShapes blocked on it.
  {
    fromFile: path.join(repoRoot, 'packages/backend/src/services/cheqdDidShapes.ts'),
    to: '@ssi-healthcare/sdk/ledger',
    symbols: ['ed25519PublicKeyFromMultibase', 'assertEd25519Multibase'],
  },
  // Batch 4 — the shape refusals, unblocked by batch 2's SsiError. This empties
  // cheqdDidShapes.ts completely, so the file is retired to Backup/ in the same
  // commit rather than left behind as a re-export shim nobody would ever delete.
  {
    fromFile: path.join(repoRoot, 'packages/backend/src/services/cheqdDidShapes.ts'),
    to: '@ssi-healthcare/sdk/ledger',
    symbols: [
      'assertIsCheqdDid',
      'assertRotationIsSurvivable',
      'assertInstitutionalShape',
      'assertPatientRecoverableShape',
      'assertRecoveryControllerShape',
      'SHAPE_ASSERTION_DELIBERATELY_OMITTED',
      'classifyPatientDid',
      'PatientShapeExpectation',
      'PatientDidRecoverability',
    ],
  },
];
