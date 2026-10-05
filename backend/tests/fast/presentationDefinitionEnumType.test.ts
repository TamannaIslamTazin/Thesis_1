/**
 * An input descriptor that accepts EITHER of two credential types must still
 * hand its claim requests to the disclosure sheet.
 *
 * Regression test for a defect measured on a handset 9 Sep 2026 during the
 * doctor login. `descriptorMatchesType` read only `filter.contains.const` —
 * one acceptable type. A verifier that accepts "a health card OR a
 * professional licence" must write `contains.enum`, because Presentation
 * Exchange treats two input descriptors as BOTH-required unless
 * submission_requirements say otherwise, so the either-or case cannot be
 * expressed with two descriptors.
 *
 * The failure pointed the wrong way and was completely silent. The enum
 * descriptor set `sawTypeConstraint` and then matched nothing, so it was
 * SKIPPED and its claim requests never reached the sheet. The holder saw a
 * request naming a credential and no claims, shared nothing — correct, the
 * sheet defaults to the minimum (#224) — and the HMS then refused the login
 * for six claims it had, as far as the wallet could tell, never asked for:
 *
 *   Licence claims are missing or malformed: profession Required;
 *   licenceNumber Required; register Required; ...
 *
 * with failedChecks: [] on the same request. The credential was genuine,
 * unrevoked and the holder's, and the login failed anyway.
 */
import { describe, expect, it } from 'vitest';
import { claimRequestsFromPresentationRequest } from '@ssi-healthcare/shared';

/** The shape the HMS actually sends (server/lib/ssi/oid4vpLogin.js). */
const eitherOrRequest = {
  presentation_definition: {
    id: 'req-1',
    input_descriptors: [
      {
        id: 'hospital-login-credential',
        constraints: {
          fields: [
            {
              path: ['$.type'],
              filter: {
                type: 'array',
                contains: { enum: ['ProfessionalLicenceCredential', 'HealthCardCredential'] },
              },
            },
            { path: ['$.credentialSubject.licenceNumber'], optional: true },
            { path: ['$.credentialSubject.profession'], optional: true },
          ],
        },
      },
    ],
  },
};

describe('presentation definition with an enum type constraint', () => {
  it('yields the claim requests for a type named in the enum', () => {
    const requests = claimRequestsFromPresentationRequest(
      eitherOrRequest,
      'ProfessionalLicenceCredential',
    );
    expect(requests.map((r) => r.path).sort()).toEqual(['licenceNumber', 'profession']);
    // `optional: true` in PE is `requirement: 'optional'` here — the polarity
    // is inverted between the two vocabularies, and a holder must be free to
    // withhold these and still sign in with a health card.
    expect(requests.every((r) => r.requirement === 'optional')).toBe(true);
  });

  it('yields them for the OTHER type in the same enum', () => {
    expect(
      claimRequestsFromPresentationRequest(eitherOrRequest, 'HealthCardCredential').map((r) => r.path),
    ).toContain('licenceNumber');
  });

  it('yields NOTHING for a type the enum does not name — the pairing that makes the above mean something', () => {
    // Without this, a matcher that returned true unconditionally would satisfy
    // both assertions above while handing every verifier's claim list to every
    // credential. The type constraint still has to constrain.
    expect(
      claimRequestsFromPresentationRequest(eitherOrRequest, 'VaccinationCredential'),
    ).toEqual([]);
  });

  it('still honours the single-type `const` form', () => {
    const constRequest = {
      presentation_definition: {
        id: 'req-2',
        input_descriptors: [
          {
            id: 'd',
            constraints: {
              fields: [
                { path: ['$.type'], filter: { type: 'array', contains: { const: 'HealthCardCredential' } } },
                { path: ['$.credentialSubject.verifiedAt'] },
              ],
            },
          },
        ],
      },
    };
    expect(
      claimRequestsFromPresentationRequest(constRequest, 'HealthCardCredential').map((r) => r.path),
    ).toEqual(['verifiedAt']);
    expect(claimRequestsFromPresentationRequest(constRequest, 'ProfessionalLicenceCredential')).toEqual([]);
  });

  it('$.type itself never becomes a requested CLAIM', () => {
    // It is a selector for which credential to present, not something the
    // holder chooses to disclose. Listing it on the sheet would offer a toggle
    // that cannot be turned off.
    expect(
      claimRequestsFromPresentationRequest(eitherOrRequest, 'ProfessionalLicenceCredential')
        .map((r) => r.path),
    ).not.toContain('type');
  });
});
