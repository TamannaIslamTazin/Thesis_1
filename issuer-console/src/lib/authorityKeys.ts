/**
 * Which authority's keys this request should use.
 *
 * ===========================================================================
 * THE CONSOLE WAS SINGLE-TENANT, AND ONLY THE CRYPTO KNEW
 * ===========================================================================
 * Queue scoping was always correct — an officer sees only their own
 * institution's submissions. But the keys were not scoped at all: one
 * `ISSUER_CONTENT_KEY_X25519_SEED` and one `ISSUER_LOCKER_DID`, both the
 * ministry's. So a council officer could sign in, see the right queue, and then
 * fail to open a single document with
 *
 *   KeyEnvelopeError: The key envelope did not authenticate.
 *
 * That error is the SYSTEM WORKING. The holder's wallet seals each submission
 * to the public key of the authority its document type names, so only that
 * authority can open it — which is the property we want, and it means every
 * authority needs its own key rather than borrowing the ministry's.
 *
 * ===========================================================================
 * THE SUFFIX IS THE AUTHORITY, AND AN UNKNOWN ONE IS A REFUSAL
 * ===========================================================================
 * Variables are read as `NAME__SHORTNAME` (`..._SEED__BMDC`), falling back to
 * the unsuffixed name for the ministry, which is how the console was already
 * configured. An institution with no key configured is REFUSED, never silently
 * served the fallback: quietly handing a council the ministry's key would make
 * every decryption fail with a confusing error at best, and at worst let one
 * authority open another's documents if the keys were ever shared.
 */

/** Short names as they appear in the trust roots and in env var suffixes. */
const KNOWN_AUTHORITIES = ['MOHFW', 'BMDC', 'BNMC', 'PCB'] as const;

export type AuthorityShortName = (typeof KNOWN_AUTHORITIES)[number];

export class AuthorityKeyError extends Error {}

/**
 * Map an institution name to its short name.
 *
 * Matched on the name the backend reports for the officer's institution, since
 * that is what the console has in the session. A name it does not recognise is
 * an error rather than a default — the ministry is not a safe fallback for an
 * unknown authority.
 */
export function authorityShortName(institutionName: string | null | undefined): AuthorityShortName {
  const name = (institutionName ?? '').toLowerCase();
  if (name.includes('medical and dental')) return 'BMDC';
  if (name.includes('nursing')) return 'BNMC';
  if (name.includes('pharmacy council')) return 'PCB';
  if (name.includes('ministry')) return 'MOHFW';
  throw new AuthorityKeyError(
    `No console keys are configured for '${institutionName ?? 'unknown institution'}'. ` +
      'Add them rather than falling back to another authority, whose key cannot open these documents anyway.',
  );
}

/**
 * Read a per-authority env var.
 *
 * MOHFW keeps the unsuffixed names it was already deployed with, so this change
 * does not require re-configuring the one authority that already worked.
 */
export function authorityEnv(base: string, authority: AuthorityShortName): string | undefined {
  if (authority === 'MOHFW') return process.env[base] ?? process.env[`${base}__MOHFW`];
  return process.env[`${base}__${authority}`];
}

export function requireAuthorityEnv(base: string, authority: AuthorityShortName): string {
  const value = authorityEnv(base, authority);
  if (!value) {
    throw new AuthorityKeyError(
      `${base}__${authority} is not configured on this console instance. ` +
        `${authority} cannot open its own submissions without it.`,
    );
  }
  return value;
}
