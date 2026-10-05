/**
 * A dispense append is only accepted if the pharmacy actually signed it.
 *
 * ===========================================================================
 * WHY THIS EXISTS
 * ===========================================================================
 * The append route is what makes the dispense ledger real: without it, a dispense
 * is recorded in one pharmacy's own database and the shared tally never learns it
 * happened — which is how the same prescription could be filled at two counters
 * with nothing to notice.
 *
 * The route is authorised by the SIGNATURE ALONE (owner's decision, ledger review
 * attack 2): the counter PC is not a signed-in user, it is an institution with a
 * key. So this verification is the whole control, and it must be tested in both
 * directions.
 *
 * ===========================================================================
 * EVERY REFUSAL IS PAIRED WITH A SUCCESS
 * ===========================================================================
 * The route's own refusals were verified live against the running server (an
 * unverified DID is refused; a verified DID with a bad signature is refused). But
 * a suite that only asserts refusals passes perfectly against a verifier that
 * refuses everything (#345, #347, #352). So the acceptance case is here, using a
 * key generated in this test and never leaving it.
 */
import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';

import {
  canonicalAppendMessage,
  verifyAppendSignature,
  type AppendPayload,
} from '../../src/services/dispenseAppend.js';

/** The same encoding the issuer and the pharmacy both produce. */
function multibaseFromRaw(raw: Uint8Array): string {
  return `z${base58.encode(new Uint8Array([0xed, 0x01, ...raw]))}`;
}

const PHARMACY = 'did:cheqd:bdhealthtestnet:405dea74-e236-4b29-8fac-dbaf28eafca1';
/** The citizen the dispense is about. Signed since A1; the wallet reads its tokens by this. */
const HOLDER = 'did:cheqd:bdhealthtestnet:f654bf75-b2f6-40ba-badb-d005e074c049';

function payload(overrides: Partial<AppendPayload> = {}): AppendPayload {
  return {
    prescriptionId: 'rx-1',
    quantity: 20,
    dispenseId: 'dispense-1',
    dispensedAt: '2026-09-24T12:00:00.000Z',
    pharmacyDid: PHARMACY,
    holderDid: HOLDER,
    ...overrides,
  };
}

/** Sign the way the pharmacy does, so the two implementations are checked against each other. */
function sign(p: AppendPayload, secretKey: Uint8Array): string {
  const message = new TextEncoder().encode(canonicalAppendMessage(p));
  return Buffer.from(ed25519.sign(message, secretKey)).toString('base64url');
}

describe('dispense append signature', () => {
  const secret = ed25519.utils.randomPrivateKey();
  const multibase = multibaseFromRaw(ed25519.getPublicKey(secret));

  // -- The acceptance case. Without it, "refuse everything" passes the rest. --

  it('ACCEPTS an append signed by a key on the signing DID', () => {
    const p = payload();
    expect(
      verifyAppendSignature({ payload: p, signature: sign(p, secret), publicKeyMultibase: [multibase] }),
    ).toBe(true);
  });

  it('accepts when the signing DID has several keys and the right one is among them', () => {
    // 1-of-N custody: any key on the institution is the institution (#276).
    const other = multibaseFromRaw(ed25519.getPublicKey(ed25519.utils.randomPrivateKey()));
    const p = payload();
    expect(
      verifyAppendSignature({
        payload: p,
        signature: sign(p, secret),
        publicKeyMultibase: [other, multibase],
      }),
    ).toBe(true);
  });

  // -- The refusals. --

  it('REFUSES a signature from a different key', () => {
    const stranger = ed25519.utils.randomPrivateKey();
    const p = payload();
    expect(
      verifyAppendSignature({ payload: p, signature: sign(p, stranger), publicKeyMultibase: [multibase] }),
    ).toBe(false);
  });

  it('REFUSES a valid signature over DIFFERENT content — the quantity cannot be edited', () => {
    // The attack this stops: intercept a genuine append and raise the quantity.
    const p = payload({ quantity: 20 });
    const signature = sign(p, secret);
    const tampered = payload({ quantity: 200 });
    expect(verifyAppendSignature({ payload: tampered, signature, publicKeyMultibase: [multibase] })).toBe(false);
  });

  it('REFUSES when the signing DID is swapped for another', () => {
    const p = payload();
    const signature = sign(p, secret);
    expect(
      verifyAppendSignature({
        payload: payload({ pharmacyDid: 'did:cheqd:bdhealthtestnet:other' }),
        signature,
        publicKeyMultibase: [multibase],
      }),
    ).toBe(false);
  });

  it('REFUSES a replayed signature on a different prescriptionId', () => {
    const p = payload();
    const signature = sign(p, secret);
    expect(
      verifyAppendSignature({ payload: payload({ prescriptionId: 'rx-2' }), signature, publicKeyMultibase: [multibase] }),
    ).toBe(false);
  });

  it('REFUSES malformed keys, wrong-length signatures and nonsense rather than throwing', () => {
    const p = payload();
    const good = sign(p, secret);
    // Each of these must be a clean `false`. A throw here would surface as a 500
    // and, worse, a permissive catch upstream could turn it into an accept.
    expect(verifyAppendSignature({ payload: p, signature: good, publicKeyMultibase: [] })).toBe(false);
    expect(verifyAppendSignature({ payload: p, signature: good, publicKeyMultibase: ['not-a-key'] })).toBe(false);
    expect(verifyAppendSignature({ payload: p, signature: good, publicKeyMultibase: ['z' + base58.encode(new Uint8Array(34))] })).toBe(false);
    expect(verifyAppendSignature({ payload: p, signature: 'AAAA', publicKeyMultibase: [multibase] })).toBe(false);
    expect(verifyAppendSignature({ payload: p, signature: '', publicKeyMultibase: [multibase] })).toBe(false);
  });

  it('the canonical message is a POSITIONAL ARRAY so two implementations cannot disagree on key order', () => {
    // An object would serialise by insertion order, so a signer and a verifier
    // that agree on the fields could still produce different bytes.
    const p = payload();
    expect(canonicalAppendMessage(p)).toBe(
      JSON.stringify(['rx-1', 20, 'dispense-1', '2026-09-24T12:00:00.000Z', PHARMACY, HOLDER]),
    );
  });

  it('the HOLDER is inside the signed bytes, so a pharmacy cannot attribute a dispense to someone else', () => {
    // The wallet reads its own tokens by holder. If the holder were carried but
    // not signed, a pharmacy could point a dispense at another citizen's wallet.
    const p = payload({ holderDid: HOLDER });
    const signedByHolderA = sign(p, secret);
    const forged = { ...p, holderDid: 'did:cheqd:bdhealthtestnet:someone-else' };
    expect(verifyAppendSignature({ payload: forged, signature: signedByHolderA, publicKeyMultibase: [multibase] })).toBe(false);
    // And the genuine one still verifies, so the refusal above is not a blanket no.
    expect(verifyAppendSignature({ payload: p, signature: signedByHolderA, publicKeyMultibase: [multibase] })).toBe(true);
  });
});
