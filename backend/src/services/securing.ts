/**
 * SSI Healthcare Backend - VC 2.0 Securing Mechanism Selection
 *
 * ONE PLACE THAT TURNS A CREDENTIAL INTO A SIGNED ARTIFACT, for both formats
 * and both issuance routes.
 *
 * ===========================================================================
 * WHY THIS EXISTS: TWO ROUTES ISSUE, AND THEY MUST NOT DRIFT
 * ===========================================================================
 * This system issues from two places — `routes/oid4vci.ts` (the OID4VCI
 * credential endpoint) and `services/credentialService.ts` (reached from
 * POST /api/credentials/accept-offer). A credential issued through either is
 * INDISTINGUISHABLE to a verifier, so any difference between them is a
 * difference the holder cannot see and did not choose.
 *
 * Those two paths have already drifted once, and the comments left behind at
 * each site record the repair: both must use VC 2.0, both must attach a status
 * entry, both must bind the holder, both must fail closed. Every one of those
 * is a rule that was restated in two places and therefore had to be fixed in
 * two places. Adding SD-JWT as a second securing mechanism would have made it
 * three rules in two places.
 *
 * So the securing step is extracted here rather than restated. Adding a third
 * format, or changing what SD-JWT issuance asserts before it returns, is now
 * ONE edit that both routes inherit — which is the only structural defence
 * against the drift, since nothing in the type system can notice that two
 * `signCredential` calls were supposed to agree.
 *
 * What this module deliberately does NOT do: decide the holder binding, the
 * status entry, or the credential's contents. Those arrive already settled.
 * Its single responsibility is the envelope.
 */

import {
  ClaimFormat,
  W3cV2Credential,
  type Agent,
} from '@credo-ts/core';
import {
  CREDENTIAL_FORMATS,
  buildDisclosureFrame,
  assertNothingDisclosableLeaked,
  type IssuableCredentialFormat,
  type VerifiableCredential,
} from '@ssi-healthcare/shared';
import {
  signSdJwtCredential,
  issuerSignedCredentialSubject,
  sdJwtVcToW3cJson,
} from './sdJwtVc.js';
import { signedCredentialToStoredJson, extractSerializedJwt } from './jwtVc.js';
import { logger } from '../utils/logger.js';

export interface SecureCredentialOptions {
  /** The credential to secure. Contents are already final. */
  credential: W3cV2Credential;
  /** Which securing mechanism to apply. */
  format: IssuableCredentialFormat;
  /** The issuer's verification method DID URL. */
  verificationMethod: string;
  /** The `cnf` binding, from the ONE resolver both routes share. */
  holder: { method: 'did'; didUrl: string };
  /**
   * The subject claims as they were handed to the credential, INCLUDING `id`.
   *
   * Needed separately from `credential` because the disclosure policy is
   * derived from the plain claim shape, and because
   * `assertNothingDisclosableLeaked` compares the signed payload against it.
   * Reading it back off `W3cV2Credential` would mean trusting Credo's in-memory
   * model to round-trip the shape unchanged, which is exactly the kind of
   * implicit dependency this codebase has been bitten by.
   */
  subjectClaims: Record<string, unknown>;
}

export interface SecuredCredential {
  /** The compact envelope — the ONLY thing carrying a signature under VC 2.0. */
  envelope: string;
  /** The credential as W3C JSON, fully disclosed, for storage. */
  json: VerifiableCredential;
  /** The format actually produced, for the `credentialFormat` column. */
  format: IssuableCredentialFormat;
}

/**
 * Secure a VC 2.0 credential with the requested mechanism.
 *
 * Throws rather than returning a partial result. Under VC 2.0 the credential
 * itself has no embedded proof, so a failure here does not yield a weaker
 * credential — it yields an UNVERIFIABLE one, and storing that would hand the
 * holder something that can never be presented.
 */
export async function secureV2Credential(
  agent: Agent,
  options: SecureCredentialOptions,
): Promise<SecuredCredential> {
  if (options.format === CREDENTIAL_FORMATS.SD_JWT_VC) {
    // WHAT CAN EVER BE DISCLOSED IS DECIDED HERE, ONCE, AND SIGNED IN.
    // Built from this credential's actual subject shape rather than a field
    // list, so a credential type that gains a field gets that field made
    // disclosable automatically instead of silently shipping it in cleartext
    // for the life of the credential.
    const disclosureFrame = buildDisclosureFrame(options.subjectClaims);

    const signed = await signSdJwtCredential(agent, {
      credential: options.credential,
      verificationMethod: options.verificationMethod,
      holder: options.holder,
      disclosureFrame,
    });

    // THE FRAME MUST BE PROVEN TO HAVE TAKEN EFFECT, NOT ASSUMED.
    // `@sd-jwt/core` ignores directives it does not understand without
    // erroring, so a frame bug surfaces as patient data in cleartext rather
    // than as an exception. Refuse to issue a credential that promises
    // selective disclosure it does not actually have.
    assertNothingDisclosableLeaked(options.subjectClaims, issuerSignedCredentialSubject(signed));

    const envelope = signed.encoded;
    // Store the FULLY DISCLOSED view: this row is the issuer's own record and
    // the holder's wallet copy, both of which are entitled to every claim.
    // Selection happens later, at presentation, and cannot happen at all if the
    // holder's own copy is already redacted.
    const json = sdJwtVcToW3cJson(envelope);
    if (!json) throw new Error('SD-JWT signing produced an undecodable credential');

    logger.info('Credential secured', {
      format: CREDENTIAL_FORMATS.SD_JWT_VC,
      disclosableClaimCount: Object.keys(options.subjectClaims).length - 1,
    });
    return { envelope, json, format: CREDENTIAL_FORMATS.SD_JWT_VC };
  }

  const signed = await agent.w3cV2Credentials.signCredential({
    format: ClaimFormat.JwtW3cVc,
    credential: options.credential,
    verificationMethod: options.verificationMethod,
    alg: 'EdDSA',
    holder: options.holder,
  });

  // `encoded` is a prototype getter: it survives property access but not
  // `JSON.stringify`. Read it before anything serializes the object.
  const json = signedCredentialToStoredJson(signed);
  const envelope = extractSerializedJwt(signed);
  if (!envelope) {
    throw new Error('VC 2.0 signing returned no compact JWT envelope');
  }

  logger.info('Credential secured', { format: CREDENTIAL_FORMATS.VC_JWT });
  return { envelope, json, format: CREDENTIAL_FORMATS.VC_JWT };
}
