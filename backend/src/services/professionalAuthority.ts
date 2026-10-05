/**
 * SSI Healthcare Backend — the composition root for professional authority.
 *
 * THE DECISION IS NO LONGER HERE. It moved to
 * `@ssi-healthcare/sdk/verify` (steno #352) so that the backend, the hospital
 * HMS and the on-device wallet run ONE implementation rather than three that
 * drift. This file is what remains: the adapter that binds this deployment's
 * I/O — the cheqd ledger and winston — to that decision.
 *
 * THE EXPORTED SIGNATURE IS UNCHANGED. `requireProfessional` and the live
 * suite call `authoriseProfessional(options)` exactly as before and neither was
 * edited; the ports are supplied here, not by callers, because the choice of
 * where revocation is read from is a deployment decision and must not be
 * reachable from a request.
 *
 * WHY THE BINDING IS WORTH A FILE OF ITS OWN. `revocation` is mandatory in the
 * SDK precisely so that omitting it is a compile error rather than a silent
 * `notRevoked: true`. That guarantee is only as good as this file being the one
 * place that satisfies it — so the wiring is asserted directly by
 * `tests/fast/professionalAuthorityAdapter.test.ts`, which proves the port
 * reaches the real `checkStatusOnLedger` and the logger reaches real winston. A
 * port that were quietly bound to a stub would pass every test in the SDK.
 */

import {
  authoriseProfessional as decide,
  type AuthoriseProfessionalOptions,
  type ProfessionalAuthorisation,
} from '@ssi-healthcare/sdk/verify';
import { logger } from '../utils/logger.js';
import { checkStatusOnLedger } from './statusListService.js';

export type {
  AuthoriseProfessionalOptions,
  PresentedLicence,
  ProfessionalAuthorisation,
  ProfessionalAuthorityChecks,
  ProfessionalIdentity,
  ProfessionalRequirement,
  RevocationPort,
  RevocationStatus,
} from '@ssi-healthcare/sdk/verify';

/**
 * Revocation as THIS deployment reads it: from the chain, not from our own
 * database, so a third-party verifier gets the same answer we do.
 *
 * Named rather than inlined so there is one thing to point a test at, and so
 * that the day a second binding exists (a cached reader, say) the difference
 * between them is visible here instead of buried in a call site.
 */
const ledgerRevocation = { check: checkStatusOnLedger };

/**
 * Require a verified professional licence to satisfy `requirement`.
 *
 * @see {@link decide} for the decision itself, including why every check
 *   defaults to `false` and why an unreadable status list is a refusal.
 */
export async function authoriseProfessional(
  options: AuthoriseProfessionalOptions,
): Promise<ProfessionalAuthorisation> {
  return decide({ ...options, revocation: ledgerRevocation, log: logger });
}
