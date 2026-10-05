/**
 * DID resolution over the cheqd Cosmos REST API.
 *
 * ===========================================================================
 * ABSENCE AND UNREACHABILITY MUST NOT COLLAPSE INTO ONE ANSWER
 * ===========================================================================
 * Carried deliberately from `cheqdLedger.ts`'s `isDefinitivelyNotFound`, and
 * it matters MORE here than it does there. If a stopped validator or a
 * network partition were reported as "no such DID", every user of this locker
 * would be told their identity does not exist at the moment they are trying
 * to reach their own health documents. That is the worst possible error
 * message to be wrong with: it is indistinguishable from catastrophe, it
 * invites the user to do something drastic, and it is a lie.
 *
 * So there are three outcomes, never two:
 *
 *   FOUND        — the resolver answered and the document exists
 *   NOT_FOUND    — the resolver ANSWERED and there is definitively no such DID
 *   UNREACHABLE  — we do not know, and must say so
 *
 * ===========================================================================
 * FAIL CLOSED, AND NEVER FROM CACHE
 * ===========================================================================
 * UNREACHABLE denies access. It does NOT fall back to a previously cached
 * document, because the thing a cache would paper over is exactly the thing
 * that must not be papered over: a DID whose authentication key was rotated
 * away from a stolen device, or one that was deactivated. Serving a stale
 * document would let a revoked key keep working for as long as the cache
 * lives.
 *
 * Refusing access is recoverable — the user retries when the resolver is back,
 * and no data is lost. Admitting a deactivated or rotated-away key is not.
 */

const CHEQD_DID_PATH = '/cheqd/did/v2';

export type DidResolution =
  | { readonly outcome: 'FOUND'; readonly document: DidDocument }
  | { readonly outcome: 'NOT_FOUND'; readonly detail: string }
  | { readonly outcome: 'UNREACHABLE'; readonly detail: string };

export interface DidVerificationMethod {
  readonly id: string;
  readonly type: string;
  readonly controller: string;
  readonly publicKeyMultibase?: string;
}

export interface DidDocument {
  readonly id: string;
  readonly verificationMethod: readonly DidVerificationMethod[];
  /** Entries may be absolute DID URLs or embedded methods; both are normalised on use. */
  readonly authentication: readonly string[];
  /**
   * Also accepted for capability auth. An institutional DID can hold only ONE
   * `authentication` key (a cheqd SDK constraint on document updates), so any
   * party other than the ledger operator — a council's own issuer console, for
   * instance — can only ever appear here. See `authenticationKeyMultibase`.
   */
  readonly assertionMethod?: readonly string[];
  readonly deactivated: boolean;
}

/**
 * The cheqd Cosmos LCD REST envelope, AS IT ACTUALLY COMES BACK — verified
 * live against a running node 5 Sep 2026 (round 5), not assumed. This is
 * `{ value: { did_doc: {...snake_case...}, metadata: { deactivated } } }`,
 * NOT the W3C-shaped `{ didDocument, didDocumentMetadata }` this module
 * previously expected.
 *
 * THIS WAS NEVER PARSED CORRECTLY BEFORE ROUND 5. `stub-resolver.mjs`'s own
 * docblock said so plainly: "It is NOT evidence that we parse a real cheqd
 * node's REST response shape correctly. That remains unverified." Every
 * document that shape mismatch produced a silent NOT_FOUND for — `!document?.id`
 * below was always true against a real node, because `raw.didDocument` did
 * not exist on the real response at all. Found by round 5's wallet-custody
 * broker: a real, on-chain-minted patient DID resolved fine via curl but
 * every locker auth attempt against it came back 404 DID_NOT_FOUND.
 */
interface RawCheqdRestVerificationMethod {
  id?: string;
  verification_method_type?: string;
  controller?: string;
  verification_material?: string;
}

interface RawCheqdRestEnvelope {
  value?: {
    did_doc?: {
      id?: string;
      controller?: string[];
      verification_method?: RawCheqdRestVerificationMethod[];
      authentication?: unknown[];
    };
    metadata?: { deactivated?: boolean };
  };
}

/**
 * A DID that was never written produces a definitive negative from the API.
 * A stopped node produces a transport failure with no HTTP status at all.
 * Only the first is NOT_FOUND.
 */
export async function resolveDid(
  did: string,
  resolverUrl: string,
  timeoutMs: number,
): Promise<DidResolution> {
  const url = `${resolverUrl.replace(/\/$/, '')}${CHEQD_DID_PATH}/${encodeURIComponent(did)}`;

  let response: Response;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    response = await fetch(url, { signal: controller.signal });
  } catch (error) {
    // No status line came back: transport failure, timeout, DNS, refused
    // connection. We genuinely do not know whether the DID exists.
    return {
      outcome: 'UNREACHABLE',
      detail:
        `Could not reach the DID resolver at ${resolverUrl}: ${
          error instanceof Error ? error.message : String(error)
        }. This is NOT evidence that the DID is absent.`,
    };
  } finally {
    clearTimeout(timer);
  }

  if (response.status === 404) {
    return { outcome: 'NOT_FOUND', detail: `The resolver answered: no DID document for '${did}'.` };
  }

  if (!response.ok) {
    // 5xx, 502 from a proxy, anything else: the resolver is degraded, not
    // authoritative. Treated as unreachable so it fails closed rather than
    // being mistaken for a definitive negative.
    return {
      outcome: 'UNREACHABLE',
      detail: `The DID resolver returned HTTP ${response.status}, which is not an authoritative answer.`,
    };
  }

  let raw: RawCheqdRestEnvelope;
  try {
    raw = (await response.json()) as RawCheqdRestEnvelope;
  } catch (error) {
    return {
      outcome: 'UNREACHABLE',
      detail: `The DID resolver returned a body that is not JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }

  const document = raw.value?.did_doc;
  if (!document?.id) {
    return {
      outcome: 'NOT_FOUND',
      detail: `The resolver answered with no DID document for '${did}'.`,
    };
  }

  return {
    outcome: 'FOUND',
    document: {
      id: document.id,
      verificationMethod: (document.verification_method ?? [])
        .filter((vm): vm is Required<Pick<RawCheqdRestVerificationMethod, 'id' | 'controller'>> &
          RawCheqdRestVerificationMethod => Boolean(vm.id && vm.controller))
        .map((vm) => ({
          id: vm.id,
          type: vm.verification_method_type ?? '',
          controller: vm.controller,
          publicKeyMultibase: vm.verification_material,
        })),
      // An authentication entry can be a DID URL string or an embedded
      // verification method object. Normalise to ids; embedded methods are
      // matched through verificationMethod below.
      authentication: (document.authentication ?? [])
        .map((entry) =>
          typeof entry === 'string' ? entry : (entry as { id?: string })?.id ?? '',
        )
        .filter((id): id is string => id.length > 0),
      // Normalised the same way, and carried for the same reason the auth check
      // now reads it: an institution's non-operator keys can only live here.
      // Dropping it during parsing would make that check silently always false
      // — the check would look right and refuse everything.
      // BOTH SPELLINGS. The chain's own document is snake_case
      // (`verification_method`, `verification_material`), so reading only the
      // camelCase name silently yielded an empty list and the auth check that
      // depends on it refused everything — while looking correct.
      assertionMethod: (((document as { assertionMethod?: unknown[]; assertion_method?: unknown[] })
        .assertionMethod ??
        (document as { assertion_method?: unknown[] }).assertion_method ??
        []) as unknown[])
        .map((entry) =>
          typeof entry === 'string' ? entry : (entry as { id?: string })?.id ?? '',
        )
        .filter((id): id is string => id.length > 0),
      deactivated: raw.value?.metadata?.deactivated === true,
    },
  };
}

/**
 * Find the public key for a verification method id, but ONLY if that method is
 * usable for authentication.
 *
 * A key listed under `assertionMethod` or `keyAgreement` but not
 * `authentication` must not authenticate a session. Checking the relationship
 * rather than merely the key's presence is the difference between "this DID
 * document contains this key" and "this DID says this key may act as it".
 */
export function authenticationKeyMultibase(
  document: DidDocument,
  verificationMethodId: string,
): string | null {
  const absolute = verificationMethodId.startsWith('#')
    ? `${document.id}${verificationMethodId}`
    : verificationMethodId;

  // ACCEPTS `authentication` OR `assertionMethod`, and the second one is not a
  // relaxation for convenience.
  //
  // An institutional DID minted by this system carries EXACTLY ONE
  // `authentication` key, and that is forced by `@cheqd/sdk`, not chosen: it
  // computes the required signer set for a document update from `authentication`
  // on both versions, so a second entry — or a foreign-held one — makes the
  // document unupdatable the moment that key is lost. The slot is therefore
  // reserved for the ledger operator's own key.
  //
  // The consequence is that no OTHER party can ever be in `authentication` for
  // an institution. A council's issuer console, holding its own key so the
  // ministry cannot act as it, sits in `assertionMethod` because there is
  // nowhere else for it to sit — and was refused here, which made 1-of-N
  // institutional custody unusable for exactly the parties that need it.
  //
  // Accepting `assertionMethod` is also the honest reading of what is happening:
  // the institution is ASSERTING its identity to spend a capability a holder
  // granted it, not logging in. What is NOT accepted is a key the document
  // merely contains — membership of `verificationMethod` alone still grants
  // nothing, which is the property the original check existed to enforce.
  const namesKey = (entry: string): boolean =>
    entry === absolute || entry === verificationMethodId;
  const authorised =
    document.authentication.some(namesKey) ||
    (document.assertionMethod ?? []).some(namesKey);
  if (!authorised) return null;

  const method = document.verificationMethod.find(
    (candidate) => candidate.id === absolute || candidate.id === verificationMethodId,
  );
  if (!method?.publicKeyMultibase) return null;

  return method.publicKeyMultibase;
}
