/**
 * What the PORT is obliged to be handed.
 *
 * The exchange itself is unchanged by the move and the live suite already
 * covers it end to end; this does not re-prove it. What is new is the seam:
 * `agent: Agent` became a two-method port, and everything the old code passed
 * to Credo directly now crosses an interface. Three of those values are
 * security properties, and a wiring mistake in the adapter would weaken each of
 * them silently while every test that only checks "a VP came back" still passed:
 *
 *   - the FRAME must carry only what the verifier marked required, expanded to
 *     leaves (naming a container discloses it EMPTY — measured, R4 Phase B)
 *   - the DOMAIN must be the audience the verifier named, never our own
 *   - the CHALLENGE must be the verifier's nonce, never a locally chosen one
 *
 * A recording fake stands in for the holder, so the assertions are about what
 * crossed the boundary rather than about what Credo did with it.
 */

import { describe, it, expect } from 'vitest';
import {
  signProfessionalPresentation,
  ProfessionalPresentationError,
  type ProfessionalLicenceHolder,
  type ProfessionalChallengeResponse,
} from '../../src/holder';

type PresentInput = Parameters<ProfessionalLicenceHolder['presentLicence']>[0];

const LICENCE_SUBJECT = {
  id: 'did:cheqd:testnet:holder',
  profession: 'pharmacist',
  licenceNumber: 'BD-PH-4471',
  practiceScope: ['dispense', 'counsel'],
  issuedBy: 'BD Pharmacy Council',
};

const CHALLENGE: ProfessionalChallengeResponse = {
  requestId: 'req-1',
  nonce: 'nonce-from-the-verifier',
  audience: 'did:cheqd:testnet:the-verifier',
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  definition: {
    id: 'pd-1',
    inputDescriptors: [
      {
        id: 'licence',
        constraints: {
          fields: [
            { path: ['$.credentialSubject.profession'] },
            { path: ['$.credentialSubject.practiceScope'] },
            { path: ['$.credentialSubject.licenceNumber'], optional: true },
          ],
        },
      },
    ],
  } as unknown as ProfessionalChallengeResponse['definition'],
};

function recordingHolder(overrides: Partial<ProfessionalLicenceHolder> = {}): {
  holder: ProfessionalLicenceHolder;
  calls: PresentInput[];
} {
  const calls: PresentInput[] = [];
  const holder: ProfessionalLicenceHolder = {
    readLicence: () => ({ credentialSubject: LICENCE_SUBJECT }),
    presentLicence: async (input) => {
      calls.push(input);
      return 'compact.vp.sd-jwt';
    },
    ...overrides,
  };
  return { holder, calls };
}

describe('the port receives the verifier\'s own binding values', () => {
  it('binds domain to the audience the verifier named', async () => {
    const { holder, calls } = recordingHolder();
    await signProfessionalPresentation(holder, {
      holderDid: 'did:cheqd:testnet:holder',
      licence: 'compact.vc.sd-jwt',
      challenge: CHALLENGE,
    });
    expect(calls[0]!.domain).toBe('did:cheqd:testnet:the-verifier');
  });

  it('binds challenge to the verifier\'s nonce', async () => {
    const { holder, calls } = recordingHolder();
    await signProfessionalPresentation(holder, {
      holderDid: 'did:cheqd:testnet:holder',
      licence: 'compact.vc.sd-jwt',
      challenge: CHALLENGE,
    });
    expect(calls[0]!.challenge).toBe('nonce-from-the-verifier');
  });

  it('passes the licence and holder DID through unaltered', async () => {
    const { holder, calls } = recordingHolder();
    await signProfessionalPresentation(holder, {
      holderDid: 'did:cheqd:testnet:holder',
      licence: 'compact.vc.sd-jwt',
      challenge: CHALLENGE,
    });
    expect(calls[0]!.compactLicence).toBe('compact.vc.sd-jwt');
    expect(calls[0]!.holderDid).toBe('did:cheqd:testnet:holder');
  });

  it('returns exactly what the port produced', async () => {
    const { holder } = recordingHolder();
    await expect(
      signProfessionalPresentation(holder, {
        holderDid: 'did:cheqd:testnet:holder',
        licence: 'compact.vc.sd-jwt',
        challenge: CHALLENGE,
      }),
    ).resolves.toBe('compact.vp.sd-jwt');
  });
});

describe('minimal disclosure survives the port', () => {
  const frameOf = async (volunteeredClaims?: readonly string[]) => {
    const { holder, calls } = recordingHolder();
    await signProfessionalPresentation(holder, {
      holderDid: 'did:cheqd:testnet:holder',
      licence: 'compact.vc.sd-jwt',
      challenge: CHALLENGE,
      ...(volunteeredClaims ? { volunteeredClaims } : {}),
    });
    return calls[0]!.frame as Record<string, unknown>;
  };

  it('discloses the required claims and NOT the optional one', async () => {
    const frame = await frameOf();
    const subject = frame.credentialSubject as Record<string, unknown> | undefined;
    expect(subject).toBeDefined();
    expect(subject!.profession).toBeTruthy();
    // licenceNumber was marked optional by the verifier, so it is not volunteered.
    expect(subject!.licenceNumber).toBeFalsy();
  });

  it('expands a container to its LEAVES, because naming it discloses it empty', async () => {
    const frame = await frameOf();
    const subject = frame.credentialSubject as Record<string, unknown>;
    // practiceScope has two members; a frame of `practiceScope: true` would
    // present an EMPTY array and be refused by the .min(1) schema (R4 Phase B).
    expect(subject.practiceScope).not.toBe(true);
    expect(subject.practiceScope).toEqual({ 0: true, 1: true });
  });

  /**
   * `volunteeredClaims` are SUBJECT-RELATIVE paths — 'licenceNumber', not
   * '$.credentialSubject.licenceNumber' and not 'credentialSubject.licenceNumber'.
   * They are matched against `enumerateDisclosableClaims(credentialSubject)`,
   * whose vocabulary is 'profession' / 'practiceScope[0]'. Asserted because the
   * failure mode of getting it wrong is SILENT: an unmatched path simply
   * discloses nothing, so a caller who volunteers a claim in the definition's
   * JSONPath spelling gets minimal disclosure and no complaint.
   */
  it('over-discloses only when a caller explicitly volunteers, by subject-relative path', async () => {
    const withVolunteered = await frameOf(['licenceNumber']);
    const subject = withVolunteered.credentialSubject as Record<string, unknown>;
    expect(subject.licenceNumber).toBe(true);
  });

  it('silently discloses nothing extra for a path spelled the definition\'s way', async () => {
    const wrongSpelling = await frameOf(['$.credentialSubject.licenceNumber']);
    const subject = wrongSpelling.credentialSubject as Record<string, unknown>;
    expect(subject.licenceNumber).toBeUndefined();
  });
});

describe('failing closed', () => {
  it('refuses, and never calls the signer, when the licence is unreadable', async () => {
    const { holder, calls } = recordingHolder({ readLicence: () => null });
    await expect(
      signProfessionalPresentation(holder, {
        holderDid: 'did:cheqd:testnet:holder',
        licence: 'not-a-credential',
        challenge: CHALLENGE,
      }),
    ).rejects.toBeInstanceOf(ProfessionalPresentationError);
    // The important half: nothing was signed on the way to failing.
    expect(calls).toHaveLength(0);
  });

  it('marks an unreadable licence as NOT retryable', async () => {
    const { holder } = recordingHolder({ readLicence: () => null });
    await signProfessionalPresentation(holder, {
      holderDid: 'did:cheqd:testnet:holder',
      licence: 'not-a-credential',
      challenge: CHALLENGE,
    }).catch((error: ProfessionalPresentationError) => {
      expect(error.code).toBe('LICENCE_UNREADABLE');
      expect(error.isRetryable).toBe(false);
    });
  });

  it('awaits an async readLicence, so a device-side store works too', async () => {
    const { holder, calls } = recordingHolder({
      readLicence: async () => ({ credentialSubject: LICENCE_SUBJECT }),
    });
    await signProfessionalPresentation(holder, {
      holderDid: 'did:cheqd:testnet:holder',
      licence: 'compact.vc.sd-jwt',
      challenge: CHALLENGE,
    });
    expect(calls).toHaveLength(1);
  });
});
