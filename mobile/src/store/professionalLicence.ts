/**
 * SSI Healthcare Mobile — which professional licences this wallet holds.
 *
 * A HOLDER IS SEVERAL GROUPS AT ONCE. Primarily a patient, and possibly also a
 * doctor, a nurse or a pharmacist. That is why verifier mode lives inside this
 * app rather than in a separate one: a pharmacist who is also a patient should
 * not carry two wallets, and asking them to is how a system designed for
 * institutions gets rebuilt by accident.
 *
 * ---------------------------------------------------------------------------
 * THE GROUP CHOSEN AT ONBOARDING IS NOT CONSULTED HERE, AND MUST NOT BE
 * ---------------------------------------------------------------------------
 * The self-declared group is a routing hint for the UI. It is not evidence of
 * anything and it never reaches an authorization decision — that is the whole
 * claim of R4. So this module reads CREDENTIALS, and there is deliberately no
 * parameter through which a profile field could arrive.
 *
 * Even so, what this module produces is still only a screen-routing decision.
 * A wallet cannot decide its own authority: it is working from a cached copy,
 * it cannot see a revocation published a minute ago, and a modified client can
 * say anything. `authoriseProfessional` decides, on a presentation verified
 * during the request. The asymmetry is intentional — showing verifier mode may
 * still end in a refusal; hiding it costs a menu item.
 *
 * ---------------------------------------------------------------------------
 * WHY THE LOGIC IS IN `shared` AND ONLY THE MAPPING IS HERE
 * ---------------------------------------------------------------------------
 * Same reason `credentialTransform.ts` was split out of the store: anything
 * that cannot be imported without React Native present is untestable in
 * practice, and every bug listed in that file's header survived for exactly
 * that reason. The predicate lives in `@ssi-healthcare/shared` and is covered
 * by `packages/backend/tests/fast/walletVerifierModeGate.test.ts`. What remains
 * here is the view-model mapping, which is the part that must stay small enough
 * to read.
 */

import {
  professionalLicencesHeld,
  walletOffersVerifierMode,
  type HeldCredential,
  type HeldProfessionalLicence,
} from '@ssi-healthcare/sdk';
import type { Credential } from '../types';

/**
 * Project the mobile view model onto the shape the shared predicate reads.
 *
 * `credential.type` on the view model is the SPECIFIC type only (the last entry
 * of the VC's type array), so the array is taken from the credential itself.
 * Reading the view model's single string here would work today and break the
 * moment a credential carries three types.
 */
function toHeldCredential(credential: Credential): HeldCredential {
  const vc = credential.verifiableCredential;
  const types = Array.isArray(vc?.type) ? vc.type : [credential.type];

  return {
    id: credential.id,
    type: types,
    credentialSubject: vc?.credentialSubject,
    ...(credential.issuer?.id ? { issuerDid: credential.issuer.id } : {}),
    // The wallet's own view. `status` is the only field carrying revocation;
    // deriving it from the expiry date alone displayed a revoked credential as
    // valid before `toMobileStatus` existed.
    locallyRevoked: credential.status === 'revoked',
  };
}

/** The licences this wallet holds, usable or not, for display. */
export function licencesInWallet(credentials: readonly Credential[]): HeldProfessionalLicence[] {
  return professionalLicencesHeld(credentials.map(toHeldCredential));
}

/**
 * Whether to show the verifier-mode entry point at all.
 *
 * False for a wallet holding no licence, and false for one whose only licence
 * has expired — presenting that is a guaranteed refusal, and an entry point
 * that appears for everyone and fails on tap is worse than no entry point. A
 * user who cannot tell "not for me" from "broken" reads it as broken.
 */
export function offersVerifierMode(credentials: readonly Credential[]): boolean {
  return walletOffersVerifierMode(credentials.map(toHeldCredential));
}
