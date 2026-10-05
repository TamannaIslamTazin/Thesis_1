/**
 * The two locker roles (#339: "one datastore, one keystore").
 *
 * ===========================================================================
 * ONE CODEBASE, ONE IMAGE, TWO DEPLOYMENTS
 * ===========================================================================
 * The owner asked for two containers and said the two are "the same". Both are
 * right, and this file is where they reconcile. The MECHANISM is identical —
 * DID challenge-response, opaque bytes, no decryption routine, erasure
 * receipts — so two codebases would be duplication with no benefit. The POLICY
 * genuinely differs, and the differences are not cosmetic:
 *
 *   - a keystore object is a ~200-byte KEK envelope; a datastore object is a
 *     health document that may be hundreds of megabytes
 *   - the keystore must therefore NEVER multipart, and the datastore always may
 *   - a keystore holds a fixed, tiny number of objects per subject; a datastore
 *     is unbounded and needs a quota or it will fill the disk
 *   - losing a keystore object destroys access to every datastore object, so
 *     its retained-generation count is a safety margin, not a preference
 *
 * A third role should therefore cost a policy object, not a service.
 *
 * ===========================================================================
 * WHY TWO CONTAINERS ANYWAY, STATED HONESTLY
 * ===========================================================================
 * The separation is NOT a confidentiality boundary. Neither store is readable
 * by its operator, so splitting them does not make anything more secret. What
 * it buys is AVAILABILITY and CORRELATION: an operator or attacker who
 * corrupts, loses or seizes one has not thereby got the other, and linking a
 * KEK envelope to the document set it opens requires compromising both.
 *
 * That only holds if the two deployments use DIFFERENT MinIO credentials and
 * DIFFERENT buckets. Point them at one credential pair and the separation is
 * theatre — see the compose file, which is where that is enforced.
 */

export type LockerRole = 'datastore' | 'keystore';

export interface LockerPolicy {
  readonly role: LockerRole;
  /** Largest single object accepted. */
  readonly maxObjectBytes: number;
  /**
   * Whether multipart upload is offered at all. The keystore refuses it: its
   * objects are two orders of magnitude below any sane part size, so a
   * multipart keystore write is a caller bug, and accepting it would mean
   * carrying interrupted-upload residue in the store that must never be the
   * reason a recovery fails.
   */
  readonly allowsMultipart: boolean;
  /** Total bytes one subject may hold. Mandatory: this disk is 85% full. */
  readonly quotaBytesPerSubject: number;
  /**
   * How many superseded generations of an object to retain.
   *
   * The keystore keeps several because a bad re-wrap is otherwise terminal: if
   * the wallet writes a KEK envelope sealed under a key it then loses, and
   * that write replaced the only good envelope, every document in the
   * datastore becomes unreachable. Retaining generations converts that from
   * unrecoverable to an inconvenience.
   */
  readonly retainedGenerations: number;
  /** How long an incomplete multipart upload may sit before the reaper aborts it. */
  readonly abandonedUploadTtlMs: number;
}

const ONE_HOUR_MS = 60 * 60 * 1000;

const DATASTORE_POLICY: LockerPolicy = {
  role: 'datastore',
  maxObjectBytes: 512 * 1024 * 1024,
  allowsMultipart: true,
  quotaBytesPerSubject: 2 * 1024 * 1024 * 1024,
  // Document versions are the user's own history; the wallet decides when to
  // supersede one. Two generations is a rollback margin, not an archive.
  retainedGenerations: 2,
  abandonedUploadTtlMs: 6 * ONE_HOUR_MS,
};

const KEYSTORE_POLICY: LockerPolicy = {
  role: 'keystore',
  // Generous by three orders of magnitude. A KEK envelope is ~200 bytes; this
  // is a sanity bound, not a budget, and anything approaching it is a bug.
  maxObjectBytes: 64 * 1024,
  allowsMultipart: false,
  quotaBytesPerSubject: 1 * 1024 * 1024,
  retainedGenerations: 8,
  abandonedUploadTtlMs: ONE_HOUR_MS,
};

export function policyForRole(role: string): LockerPolicy {
  if (role === 'datastore') return DATASTORE_POLICY;
  if (role === 'keystore') return KEYSTORE_POLICY;
  throw new Error(
    `LOCKER_ROLE must be exactly 'datastore' or 'keystore', got '${role}'. Refusing to ` +
      'start rather than guess: the roles differ in object size limits, multipart ' +
      'handling, quota and retained generations, and guessing wrong means either a ' +
      'keystore that accepts unbounded writes or a datastore that rejects real documents.',
  );
}
