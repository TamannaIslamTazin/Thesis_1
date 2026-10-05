/**
 * SSI Healthcare Backend — the authentication of an identity re-issuance.
 *
 * ===========================================================================
 * THE PROBLEM, STATED BEFORE THE SOLUTION
 * ===========================================================================
 * A re-issuance request CANNOT be authenticated by the holder's key, because
 * the missing key is the entire reason the request exists. Every other flow in
 * this system ultimately terminates in "the holder proved control of their
 * DID"; this one cannot, by construction, and no amount of protocol design
 * changes that.
 *
 * So authority has to come from somewhere else, and there is exactly one place
 * it can come from: the INSTITUTIONAL half of the 2-of-2 controller set that
 * S-1 §8.3 puts on every correctly enrolled patient DID. That is not a
 * convenience — it is the trust relationship enrolment exists to establish, and
 * re-issuance is the day it gets called upon.
 *
 * ===========================================================================
 * WHAT THIS MODULE ASSUMES. READ IT; DO NOT SKIP IT.
 * ===========================================================================
 * A1. THE INSTITUTION'S IDENTITY CHECK WAS SOUND. A dishonest officer can
 *     migrate any legacy patient onto a DID they control. There is no
 *     cryptographic control that prevents this and none can exist, because the
 *     only key that could object is the one that is gone. Per #302 the response
 *     is not to pretend otherwise: the act is made single-use, expiring,
 *     attributable to a named officer AND a named key, and hash-chained into
 *     the signing audit log, so its damage surface is small, visible and
 *     countable rather than prevented on paper.
 *
 * A2. THE ISSUER'S OWN RECORDS ARE INTACT. `User.did` is the record of the act
 *     that minted the old DID for this account, and it is the only thing tying
 *     a human to a legacy identifier that carries no institutional controller.
 *     It lives in the same Postgres this backend controls.
 *
 * A3. UNDER PHASE A THE RECOVERY CONTROLLER IS ALSO BACKEND-HELD (#298), so
 *     even for a correctly-shaped DID the "2-of-2" is one party holding both
 *     halves. This module's guarantees are about ATTRIBUTION and NON-REPUDIATION
 *     — which key authorised what, provably, forever — not about separation of
 *     powers, which arrives with Phase B.
 *
 * ===========================================================================
 * WHY THE SIGNATURE IS OVER A CANONICAL STATEMENT AND NOT OVER A ROW ID
 * ===========================================================================
 * The signature has to be checkable by someone who does not trust this backend
 * and cannot query its database — otherwise it is a log line, not evidence. So
 * it is an Ed25519 signature over a canonical serialisation of the WHOLE
 * authorisation, verifiable against the institutional DID document as resolved
 * FROM THE CHAIN. {@link verifyAuthorisationSignature} takes the resolved
 * document as an argument for exactly that reason: it never reaches for a
 * cached copy, and it is a pure function, so it is covered by `tests/fast`.
 *
 * Any ONE of the institution's N verification methods suffices (S-4 M1). That
 * is the same 1-of-N availability property #276 chose, applied here.
 */

import { createHash, createPublicKey, verify as verifyEd25519 } from 'node:crypto';

import { AppError } from '../../middleware/errorHandler.js';
import { ERROR_CODES } from '@ssi-healthcare/shared';
import { canonicalJson, sha256Hex } from '../custody/hashChain.js';

import { didPartOf, ed25519PublicKeyFromMultibase } from '@ssi-healthcare/sdk/ledger';

/** Bumping this invalidates every previously signed authorisation. It is meant to. */
export const AUTHORISATION_STATEMENT_VERSION = 'BDHT-REISSUANCE-AUTHORISATION-v1' as const;

/**
 * The longest an authorisation may stay usable.
 *
 * An authorisation that cannot expire is a standing permission to seize an
 * identity. Fifteen minutes is the window between an officer completing an
 * in-person check and an operator running the migration at the same desk; it is
 * deliberately too short to be carried out of the building.
 */
export const MAX_AUTHORISATION_TTL_MS = 15 * 60 * 1000;

export type ReissuanceEvidenceKind =
  | 'NATIONAL_ID_IN_PERSON'
  | 'BIRTH_CERTIFICATE_IN_PERSON'
  | 'PASSPORT_IN_PERSON'
  | 'VOUCHED_BY_ENROLLED_GUARDIAN'
  | 'OPERATOR_TEST_DATA';

/**
 * Everything the institution is putting its name to.
 *
 * The evidence itself is NEVER in here. A national ID number inside a signed,
 * archived statement is a worse liability than the problem the statement
 * documents, so only a reference and a digest travel.
 */
export interface ReissuanceAuthorisationStatement {
  readonly version: typeof AUTHORISATION_STATEMENT_VERSION;
  readonly oldDid: string;
  readonly userId: string;
  readonly institutionalDid: string;
  readonly officerId: string;
  readonly evidenceKind: ReissuanceEvidenceKind;
  readonly evidenceDigest: string;
  readonly nonce: string;
  readonly notBefore: string;
  readonly notAfter: string;
}

/**
 * The exact bytes that get signed.
 *
 * Reuses `canonicalJson` rather than inventing a second canonicalisation: the
 * signing audit log already hash-chains with it, and two canonicalisations in
 * one codebase is how a signature over "the same" object stops verifying.
 */
export function canonicalAuthorisationBytes(
  statement: ReissuanceAuthorisationStatement,
): Uint8Array {
  return new TextEncoder().encode(canonicalJson(statement));
}

export function authorisationDigest(statement: ReissuanceAuthorisationStatement): string {
  return sha256Hex(canonicalJson(statement));
}

export function digestEvidence(evidenceReference: string): string {
  return createHash('sha256').update(evidenceReference, 'utf8').digest('hex');
}

/**
 * Refuse a statement that is malformed before anything signs it.
 *
 * Fail closed at construction: a statement that names an empty officer or a TTL
 * of a week is not a signature problem, it is a governance problem, and it must
 * not become durable evidence of anything.
 */
export function assertStatementWellFormed(statement: ReissuanceAuthorisationStatement): void {
  if (statement.version !== AUTHORISATION_STATEMENT_VERSION) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Authorisation statement version is '${statement.version}', not ` +
        `'${AUTHORISATION_STATEMENT_VERSION}'. A statement of an unknown version cannot be ` +
        'checked against rules that did not exist when it was written.',
      400,
    );
  }

  for (const [field, value] of Object.entries({
    oldDid: statement.oldDid,
    userId: statement.userId,
    institutionalDid: statement.institutionalDid,
    officerId: statement.officerId,
    evidenceDigest: statement.evidenceDigest,
    nonce: statement.nonce,
  })) {
    if (typeof value !== 'string' || value.trim().length === 0) {
      throw new AppError(
        ERROR_CODES.VALIDATION_ERROR,
        `Authorisation statement field '${field}' is empty. Every field of this statement is ` +
          'load-bearing: it is the only account of who authorised the replacement of an ' +
          'identity that can no longer speak for itself.',
        400,
      );
    }
  }

  if (statement.oldDid === statement.institutionalDid) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      'The DID being replaced is the institution that is authorising the replacement. That is ' +
        'an institution vouching for its own succession, with nothing outside it to check.',
      400,
    );
  }

  const notBefore = Date.parse(statement.notBefore);
  const notAfter = Date.parse(statement.notAfter);

  if (Number.isNaN(notBefore) || Number.isNaN(notAfter)) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Authorisation validity window is not parseable ISO 8601: ` +
        `notBefore='${statement.notBefore}', notAfter='${statement.notAfter}'.`,
      400,
    );
  }

  if (notAfter <= notBefore) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      'Authorisation notAfter is not after notBefore, so it is valid for no instant at all.',
      400,
    );
  }

  if (notAfter - notBefore > MAX_AUTHORISATION_TTL_MS) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Authorisation is valid for ${Math.round((notAfter - notBefore) / 1000)}s, longer than ` +
        `the ${MAX_AUTHORISATION_TTL_MS / 1000}s ceiling. An authorisation that outlives the ` +
        'desk it was issued at is a standing permission to seize an identity.',
      400,
    );
  }
}

/**
 * Time is a gate, not a hint. Refuse rather than warn.
 */
export function assertWithinValidityWindow(
  statement: ReissuanceAuthorisationStatement,
  now: Date,
): void {
  const at = now.getTime();

  if (at < Date.parse(statement.notBefore)) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Authorisation for '${statement.oldDid}' is not yet valid (notBefore ` +
        `${statement.notBefore}, now ${now.toISOString()}).`,
      403,
    );
  }

  if (at > Date.parse(statement.notAfter)) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Authorisation for '${statement.oldDid}' EXPIRED at ${statement.notAfter} (now ` +
        `${now.toISOString()}). Re-run the in-person identity check and authorise again. ` +
        'Expiry is not a formality here: it is the only thing bounding how long a single ' +
        'identity check stays convertible into a new identity.',
      403,
    );
  }
}

/**
 * Extract the raw Ed25519 public key from a `publicKeyMultibase`.
 *
 * The multicodec prefix is VERIFIED, not skipped. `toMultibaseRaw` emits
 * `0xed 0x01` for Ed25519; a document that carried a different curve under an
 * `Ed25519VerificationKey2020` type would otherwise be truncated into 32 bytes
 * of something else, and `crypto.verify` would return false for a reason that
 * looks like a bad signature rather than a bad key.
 */
// Moved to `@ssi-healthcare/sdk/ledger` when DID CREATION also needed it (R5
// Phase B, then the SDK restructure): a device-supplied subject key must be
// validated before the document is assembled, and a low-level chain module
// cannot depend on this service. One implementation, reachable from the handset
// that has to make the same check before it broadcasts.
export { ed25519PublicKeyFromMultibase };

/** The shape {@link verifyAuthorisationSignature} needs. Deliberately not the Prisma row. */
export interface ResolvedInstitutionalDocument {
  readonly did: string;
  readonly deactivated: boolean;
  readonly verificationMethod: readonly {
    id: string;
    controller: string;
    publicKeyMultibase: string;
  }[];
}

/**
 * The whole of the authentication, as a pure function over a CHAIN-RESOLVED
 * document.
 *
 * Throws on every failure path. There is no boolean return, because a caller
 * that forgets to check a boolean gets a migration; a caller that forgets to
 * catch gets a stack trace.
 */
export function verifyAuthorisationSignature(args: {
  readonly statement: ReissuanceAuthorisationStatement;
  readonly signatureBase64: string;
  readonly verificationMethodId: string;
  readonly institution: ResolvedInstitutionalDocument;
}): void {
  const { statement, signatureBase64, verificationMethodId, institution } = args;

  assertStatementWellFormed(statement);

  if (institution.did !== statement.institutionalDid) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `The resolved document is '${institution.did}' but the statement names ` +
        `'${statement.institutionalDid}'. Verifying against the wrong document would prove ` +
        'that some institution authorised this, not that THIS one did.',
      400,
    );
  }

  // A deactivated institution is still authoritative over the DIDs it controls
  // (S-4 K1/K2) — but an institution that has destroyed its own identity is not
  // one whose fresh assertions should be honoured. Fail closed.
  if (institution.deactivated) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Institutional DID '${institution.did}' is DEACTIVATED. It retains authority over DIDs ` +
        'it already controls (S-4 K1/K2), but refusing new authorisations from a destroyed ' +
        'institution is the fail-closed reading, and deactivation is terminal (S-4 T1).',
      403,
    );
  }

  // Attribution is by ID PREFIX and never by the controller field (S-4 V2). A
  // verification method whose id sits under some other DID would be a signature
  // by that other DID, and the ledger would silently ignore it rather than
  // reject it.
  if (didPartOf(verificationMethodId) !== institution.did) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Verification method '${verificationMethodId}' is not under '${institution.did}'. ` +
        'Attribution is by id prefix (S-4 V2), so this would be a signature by a different ' +
        'DID wearing the institution’s name.',
      400,
    );
  }

  const method = institution.verificationMethod.find((vm) => vm.id === verificationMethodId);
  if (!method) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Verification method '${verificationMethodId}' is not in the on-chain document for ` +
        `'${institution.did}'. It holds [${institution.verificationMethod
          .map((vm) => vm.id)
          .join(', ')}]. A key that was evicted (S-4 H1) cannot retroactively authorise ` +
        'anything.',
      403,
    );
  }

  const publicKey = createPublicKey({
    key: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(ed25519PublicKeyFromMultibase(method.publicKeyMultibase)).toString(
        'base64url',
      ),
    },
    format: 'jwk',
  });

  let signature: Buffer;
  try {
    signature = Buffer.from(signatureBase64, 'base64');
  } catch {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      'Authorisation signature is not valid base64.',
      400,
    );
  }

  const ok = verifyEd25519(
    null,
    Buffer.from(canonicalAuthorisationBytes(statement)),
    publicKey,
    signature,
  );

  if (!ok) {
    throw new AppError(
      ERROR_CODES.VALIDATION_ERROR,
      `Authorisation for '${statement.oldDid}' does NOT verify against ` +
        `'${verificationMethodId}'. Either the statement was altered after signing or it was ` +
        'signed by a key the institution does not publish. Refusing to migrate an identity ' +
        'on an unverified authorisation.',
      403,
    );
  }
}
