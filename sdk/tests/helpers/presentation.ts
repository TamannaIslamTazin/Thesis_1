/**
 * Build `vc+sd-jwt` credentials and `vp+sd-jwt` presentations whose WIRE FORMAT
 * matches what Credo 0.6.3 emits.
 *
 * The shape is copied, field for field, from two places in this repository that
 * were measured against a live agent rather than read off a spec:
 *
 *   - `packages/backend/tests/live/helpers/liveSdJwt.ts` — `forgePresentation`
 *     shows the VP header (`{ typ: 'vp+sd-jwt', alg: 'EdDSA', kid }`) and that
 *     the payload is `JsonTransformer.toJSON(presentation)` with `nonce` and
 *     `aud` written on top.
 *   - `packages/backend/src/services/sdJwtVc.ts` — `envelopedCredentialToSdJwt`
 *     shows the enveloped form: `data:application/vc+sd-jwt,<compact>`.
 *
 * WHAT THIS DOES NOT PROVE. That Credo still emits exactly this. That belongs
 * to the live tier, which needs the chain. What it does prove is everything
 * about `verifySdJwtPresentation`'s own logic, against real signatures and real
 * digests, with no part of the module under test replaced by a stub.
 */
import { randomUUID } from 'node:crypto';
import { vendoredInstance, type TestIdentity } from './sdJwt';

/** The subject the leak tests use: one array whose last element is sensitive. */
export const SUBJECT = {
  patientName: 'Ahsan Rahman',
  hivStatus: 'negative',
  bloodType: 'O+',
  medications: ['Metformin 500mg', 'Lisinopril 10mg', 'Sertraline 50mg'],
};

export interface IssueOptions {
  issuer: TestIdentity;
  holder: TestIdentity;
  /** Defaults to a frame that makes every subject claim disclosable. */
  disclosureFrame?: unknown;
  /** VC 2.0 validity window. Defaults to a day either side of now. */
  validFrom?: string;
  validUntil?: string;
  /** Omit the `cnf` holder binding, to exercise the bearer-token refusal. */
  omitCnf?: boolean;
}

/** Issue a `vc+sd-jwt` W3C VC 2.0 credential bound to `holder`. */
export async function issueCredential(options: IssueOptions): Promise<string> {
  const { issuer, holder } = options;
  const payload: Record<string, unknown> = {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://schema.org'],
    id: `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', 'LabResultCredential'],
    issuer: issuer.did,
    validFrom: options.validFrom ?? new Date(Date.now() - 86_400_000).toISOString(),
    validUntil: options.validUntil ?? new Date(Date.now() + 86_400_000).toISOString(),
    credentialSubject: { id: holder.did, ...SUBJECT },
    iss: issuer.did,
    iat: Math.floor(Date.now() / 1000),
    ...(options.omitCnf ? {} : { cnf: { kid: holder.kid } }),
  };

  const frame =
    options.disclosureFrame === undefined
      ? {
          credentialSubject: {
            _sd: ['patientName', 'hivStatus', 'bloodType', 'medications'],
            medications: { _sd: [0, 1, 2] },
          },
        }
      : options.disclosureFrame;

  return vendoredInstance(issuer).issue(payload, frame as never, {
    header: { typ: 'vc+sd-jwt', alg: 'EdDSA', kid: issuer.kid },
  });
}

/** Apply a presentation frame, producing a credential carrying only what was chosen. */
export async function discloseCredential(
  holder: TestIdentity,
  compact: string,
  presentationFrame?: unknown,
): Promise<string> {
  return vendoredInstance(holder).present(compact, presentationFrame as never);
}

export interface PresentOptions {
  /** The party whose key signs the presentation. Not necessarily the holder. */
  signer: TestIdentity;
  /** The `holder` claim written into the presentation body. */
  holderDid?: string;
  credentials: string[];
  challenge: string;
  audience: string;
  /**
   * Override the JOSE `kid`, to exercise the relative-fragment form.
   *
   * A `kid` of `#key-1` is legitimate — the DID it belongs to comes from the
   * presentation's `holder` — and comparing it to an absolute `cnf.kid` as
   * plain strings would reject an honest presentation.
   */
  kid?: string;
}

/** Wrap disclosed credentials in a signed `vp+sd-jwt`. */
export async function signPresentation(options: PresentOptions): Promise<string> {
  const payload: Record<string, unknown> = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    holder: options.holderDid ?? options.signer.did,
    verifiableCredential: options.credentials.map((compact) => ({
      id: `data:application/vc+sd-jwt,${compact}`,
      type: ['EnvelopedVerifiableCredential'],
    })),
    nonce: options.challenge,
    aud: options.audience,
    iat: Math.floor(Date.now() / 1000),
  };

  // `undefined` frame, exactly as Credo's signPresentation does: the selective
  // disclosure was already applied to the credential, and the envelope has
  // nothing of its own to hide.
  return vendoredInstance(options.signer).issue(payload, undefined, {
    header: { typ: 'vp+sd-jwt', alg: 'EdDSA', kid: options.kid ?? options.signer.kid },
  });
}
