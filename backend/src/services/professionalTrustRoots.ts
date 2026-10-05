/**
 * SSI Healthcare Backend — which accrediting authorities THIS DEPLOYMENT pins.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS MODULE HAD TO EXIST BEFORE THE GUARD COULD EVER RETURN 200
 * ---------------------------------------------------------------------------
 * `requireProfessional` passed no root store, so it decided against the shipped
 * `PROFESSIONAL_TRUST_ROOTS` — three PLACEHOLDER DIDs that resolve to nothing
 * and whose keys nobody holds. No licence anyone can sign is issued by one of
 * them, so `issuerAccreditedAtIssuance` was false for every presentation that
 * could physically be made, and the guard's success path was unreachable in
 * every deployment. That is the correct failure direction, but it also meant
 * the end-to-end exchange could never be exercised (#263).
 *
 * ---------------------------------------------------------------------------
 * A SECOND COMPILED-IN TABLE SELECTED BY NETWORK — THE REMEDY #260 NAMED
 * ---------------------------------------------------------------------------
 * #260 made the store a function parameter with a safe default and warned that
 * the seam is one refactor away from being threaded out to a request-scoped
 * value, at which point the trust roots become attacker-influenced. It named
 * the answer for when a deployment genuinely needs an authority it controls:
 * "a second compiled-in table selected by network, not a parameter reaching the
 * HTTP layer." That is exactly this.
 *
 * Three properties make it defensible, and all three are load-bearing:
 *
 *   1. THE DID IS A LITERAL IN THIS FILE. It is not read from an environment
 *      variable, so no configuration change can nominate a different authority
 *      — only an edit, a review and a release, which is the whole argument for
 *      a pinned root store in the first place.
 *   2. IT ONLY EVER APPENDS. The shipped councils are returned unchanged and
 *      first; nothing here can weaken, shadow or remove a real trust root.
 *   3. TWO INDEPENDENT CONDITIONS GATE IT. The chain must be the development
 *      namespace (`bdhealthtestnet`) AND `NODE_ENV` must not be `production`.
 *      Our production chain is a different namespace (`bdhealth`), so a
 *      production deployment cannot reach this table even if someone sets
 *      NODE_ENV wrongly, and a NODE_ENV=production run on the test chain cannot
 *      reach it either. Either condition alone would be a single point of
 *      failure.
 *
 * A REASONABLE ENGINEER COULD DISAGREE. The alternative was to mint the three
 * council DIDs on the localnet at the placeholder UUIDs the shipped store
 * already names, leaving this file unnecessary. That was rejected: it makes the
 * SHIPPED placeholder roots resolve to keys sitting in a developer's wallet,
 * which is strictly the failure #260 refused, and it needs `createCheqdDID`
 * whose controller set is the open owner decision blocking R5 (#242).
 */

import {
  PROFESSIONAL_TRUST_ROOTS,
  type AccreditationAuthority,
  type TrustRootStore,
} from '@ssi-healthcare/shared';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

/**
 * The stand-in accrediting council on our development chain.
 *
 * One authority covering all three professions rather than three DIDs, for the
 * reason given in `tests/live/professionalAuthority.live.test.ts`: the
 * profession and scope narrowing that three separate councils would exercise is
 * pure logic already covered exhaustively in the fast tier, and minting more
 * permanent ledger identifiers buys nothing.
 *
 * The DID is the already-audited testnet issuer from steno #217, the same one
 * `tests/live/helpers/liveSdJwt.ts` signs with. The live tier keeps its own
 * copy of this shape deliberately — that one is a fixture proving the SHIPPED
 * store refuses a credential this one admits, and collapsing the two would
 * destroy the contrast that test exists to draw.
 */
const DEVELOPMENT_COUNCIL: AccreditationAuthority = Object.freeze({
  did: 'did:cheqd:bdhealthtestnet:fa3fc79f-9d49-43f5-9aa7-4f2df973bbb0',
  name: 'BDHealthTrust development accreditation authority (NOT A REAL COUNCIL)',
  shortName: 'DEV',
  professions: Object.freeze(['doctor', 'nurse', 'pharmacist']),
  maxScope: Object.freeze([
    'view-patient-record',
    'write-patient-record',
    'prescribe',
    'dispense',
    'administer-medication',
    'order-diagnostic',
  ]),
  authorisedFrom: '2026-01-01T00:00:00.000Z',
  placeholder: true,
}) as AccreditationAuthority;

/** The development namespace. Our production chain is `bdhealth`, not this. */
const DEVELOPMENT_NETWORK = 'bdhealthtestnet';

function developmentRootIsPermitted(): boolean {
  return config.nodeEnv !== 'production' && config.cheqdNetwork === DEVELOPMENT_NETWORK;
}

/**
 * The root store every authorization decision on this deployment is made
 * against.
 *
 * Computed once, at module load, from configuration that is itself loaded once.
 * Deliberately NOT a per-request lookup: a store that can change between two
 * requests is a store whose contents are a function of something other than the
 * release, which is the property this whole design exists to deny.
 */
export const DEPLOYMENT_TRUST_ROOTS: TrustRootStore = Object.freeze(
  developmentRootIsPermitted()
    ? [...PROFESSIONAL_TRUST_ROOTS, DEVELOPMENT_COUNCIL]
    : [...PROFESSIONAL_TRUST_ROOTS],
);

/** True when a non-council authority is pinned. A deployment check should refuse on this. */
export const DEVELOPMENT_AUTHORITY_IS_PINNED = developmentRootIsPermitted();

if (DEVELOPMENT_AUTHORITY_IS_PINNED) {
  // Once, at startup, naming the DID — an operator who sees this in a log that
  // is not a developer's terminal is looking at a misconfigured deployment.
  logger.warn('A DEVELOPMENT accreditation authority is pinned alongside the real councils', {
    did: DEVELOPMENT_COUNCIL.did,
    network: config.cheqdNetwork,
    nodeEnv: config.nodeEnv,
    consequence: 'Licences signed by this DID will be accepted as professional authority',
    remedy: 'This cannot happen on the bdhealth network or with NODE_ENV=production',
  });
}
