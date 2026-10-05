/**
 * DID challenge-response login (AUTH-AND-KEYSTORE-API.md §1) — the parts with
 * no chain and no live Postgres: the canonical payload, the nonce
 * compare-and-swap (against an in-memory fake of `ChallengeStore`, exercising
 * the exact race the real Postgres-backed store closes with a guarded
 * `updateMany`), and signature verification against a hand-built document and
 * a locally generated Ed25519 key pair.
 *
 * `verifySignedDidLogin`'s on-chain resolution branch (via `resolveOnChain`)
 * needs a live cheqd localnet and is exercised, if at all, in `tests/live`
 * — not here. See the round report for what was and was not run.
 */
import { describe, it, expect, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { ed25519PublicKeyToMultibase } from '@ssi-healthcare/sdk/ledger';

// `didLoginAuth.ts` imports `db/index.ts`, which constructs a PrismaClient at
// MODULE LOAD TIME and throws immediately if DATABASE_URL is unset — it never
// needs to actually reach Postgres for the pure functions this file tests,
// but the module cannot even be imported without the string being present.
// Other fast tests in this suite avoid this only by accident: whichever of
// their imports happens to pull in `config/index.ts` first triggers that
// module's own `dotenv.config()`, populating the env var as a side effect
// before `db/index.ts` reads it. That is import-order-dependent and would
// break on a fresh checkout with no `.env` file. `vi.hoisted` runs before
// ES module imports are resolved — a plain top-of-file statement does NOT,
// because import statements hoist above it regardless of source order; that
// was tried first and confirmed to still throw. See the round report.
vi.hoisted(() => {
  process.env.DATABASE_URL ??= 'postgresql://fast-test:unused@localhost:5432/unused';
});

import {
  authPayload,
  consumeChallenge,
  type ChallengeStore,
  type StoredChallenge,
  verifySignatureAgainstDocument,
  type DidAuthDocument,
} from '../../src/services/didLoginAuth.js';

// ---------------------------------------------------------------------------
// An in-memory ChallengeStore, standing in for Postgres. `findDelayMs` opens
// the exact race window a real network round-trip would: without it, a
// single-threaded fake never actually interleaves two "concurrent" calls.
// ---------------------------------------------------------------------------
function createInMemoryChallengeStore(opts: { findDelayMs?: number } = {}): ChallengeStore {
  const rows = new Map<string, { did: string; audience: string; state: StoredChallenge['state']; expiresAt: Date }>();
  return {
    async create(args) {
      rows.set(args.nonce, { did: args.did, audience: args.audience, state: 'ISSUED', expiresAt: args.expiresAt });
    },
    async findByNonce(nonce) {
      if (opts.findDelayMs) await new Promise((resolve) => setTimeout(resolve, opts.findDelayMs));
      const row = rows.get(nonce);
      return row ? { ...row } : null;
    },
    async trySpend(nonce) {
      const row = rows.get(nonce);
      if (!row || row.state !== 'ISSUED') return false;
      row.state = 'SPENT';
      return true;
    },
    async markExpired(nonce) {
      const row = rows.get(nonce);
      if (row && row.state === 'ISSUED') row.state = 'EXPIRED';
    },
  };
}

describe('authPayload — canonical bytes, domain-separated', () => {
  it('is deterministic for the same inputs', () => {
    const a = authPayload({ audience: 'did:cheqd:x:aud', did: 'did:cheqd:x:subject', nonce: 'n1' });
    const b = authPayload({ audience: 'did:cheqd:x:aud', did: 'did:cheqd:x:subject', nonce: 'n1' });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it('changes if the audience changes — an accidental collision with another service is not enough to make two payloads equal on its own, but this is the property that at least makes them differ', () => {
    const a = authPayload({ audience: 'did:cheqd:x:aud-1', did: 'did:cheqd:x:subject', nonce: 'n1' });
    const b = authPayload({ audience: 'did:cheqd:x:aud-2', did: 'did:cheqd:x:subject', nonce: 'n1' });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('carries a domain tag distinct from the locker payload, byte for byte', () => {
    const payload = new TextDecoder().decode(
      authPayload({ audience: 'did:cheqd:x:aud', did: 'did:cheqd:x:subject', nonce: 'n1' }),
    );
    expect(payload.startsWith('bdhealthtrust/backend-auth/v1\n')).toBe(true);
    expect(payload).not.toContain('bdhealthtrust/locker-auth/v1');
  });
});

describe('consumeChallenge — single use by compare-and-swap', () => {
  const did = 'did:cheqd:bdhealthtestnet:subject';
  const audience = 'did:cheqd:bdhealthtestnet:aud';

  it('spends an unexpired challenge exactly once', async () => {
    const store = createInMemoryChallengeStore();
    await store.create({ nonce: 'n1', did, audience, expiresAt: new Date(Date.now() + 60_000) });

    const first = await consumeChallenge('n1', store);
    expect(first).toEqual({ ok: true, did, audience });

    const second = await consumeChallenge('n1', store);
    expect(second.ok).toBe(false);
  });

  it('refuses an unknown nonce', async () => {
    const store = createInMemoryChallengeStore();
    const result = await consumeChallenge('never-issued', store);
    expect(result).toEqual({ ok: false, reason: 'unknown challenge' });
  });

  it('refuses an expired challenge, even though it was never spent', async () => {
    const store = createInMemoryChallengeStore();
    await store.create({ nonce: 'n1', did, audience, expiresAt: new Date(Date.now() - 1) });
    const result = await consumeChallenge('n1', store);
    expect(result).toEqual({ ok: false, reason: 'challenge expired' });
  });

  it('two concurrent consumers of the same nonce: exactly one wins', async () => {
    // findDelayMs opens the window between "read state" and "write state" that
    // a real Postgres round-trip has. Verified by hand that this test goes red
    // when trySpend's `row.state !== 'ISSUED'` guard is removed (both calls
    // then report ok:true) — see the round report.
    const store = createInMemoryChallengeStore({ findDelayMs: 5 });
    await store.create({ nonce: 'n1', did, audience, expiresAt: new Date(Date.now() + 60_000) });

    const [a, b] = await Promise.all([consumeChallenge('n1', store), consumeChallenge('n1', store)]);
    const wins = [a, b].filter((outcome) => outcome.ok);
    expect(wins).toHaveLength(1);
  });
});

describe('verifySignatureAgainstDocument — the cryptographic check, no chain involved', () => {
  const did = 'did:cheqd:bdhealthtestnet:subject';
  const audience = 'did:cheqd:bdhealthtestnet:aud';
  const nonce = 'a-server-issued-nonce';

  function documentFor(publicKey: Uint8Array): DidAuthDocument {
    const vmId = `${did}#key-1`;
    return {
      authentication: [vmId],
      verificationMethod: [{ id: vmId, publicKeyMultibase: ed25519PublicKeyToMultibase(publicKey) }],
    };
  }

  it('accepts a signature made with the authentication key over the exact canonical payload', () => {
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const payload = authPayload({ audience, did, nonce });
    const signature = ed25519.sign(payload, privateKey);

    const outcome = verifySignatureAgainstDocument({
      document: documentFor(publicKey),
      did,
      audience,
      nonce,
      signatureBase64Url: Buffer.from(signature).toString('base64url'),
    });

    expect(outcome).toEqual({ ok: true, did });
  });

  it('refuses a signature made with a DIFFERENT key than the one in the document', () => {
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const otherPrivateKey = ed25519.utils.randomSecretKey();
    const payload = authPayload({ audience, did, nonce });
    const wrongSignature = ed25519.sign(payload, otherPrivateKey);

    const outcome = verifySignatureAgainstDocument({
      document: documentFor(publicKey),
      did,
      audience,
      nonce,
      signatureBase64Url: Buffer.from(wrongSignature).toString('base64url'),
    });

    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.httpStatus).toBe(401);
  });

  it('refuses a valid signature over a DIFFERENT nonce (replay across challenges)', () => {
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const signedElsewhere = ed25519.sign(authPayload({ audience, did, nonce: 'a-different-nonce' }), privateKey);

    const outcome = verifySignatureAgainstDocument({
      document: documentFor(publicKey),
      did,
      audience,
      nonce,
      signatureBase64Url: Buffer.from(signedElsewhere).toString('base64url'),
    });

    expect(outcome.ok).toBe(false);
  });

  it('refuses a valid signature bound to a DIFFERENT audience (replay across services)', () => {
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const signedForAnotherService = ed25519.sign(
      authPayload({ audience: 'did:cheqd:x:some-other-service', did, nonce }),
      privateKey,
    );

    const outcome = verifySignatureAgainstDocument({
      document: documentFor(publicKey),
      did,
      audience,
      nonce,
      signatureBase64Url: Buffer.from(signedForAnotherService).toString('base64url'),
    });

    expect(outcome.ok).toBe(false);
  });

  it('refuses a key that exists in the document but is not listed under authentication', () => {
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const vmId = `${did}#assertion-only`;
    const document: DidAuthDocument = {
      authentication: [], // the key below is NOT an authentication method
      verificationMethod: [{ id: vmId, publicKeyMultibase: ed25519PublicKeyToMultibase(publicKey) }],
    };
    const signature = ed25519.sign(authPayload({ audience, did, nonce }), privateKey);

    const outcome = verifySignatureAgainstDocument({
      document,
      did,
      audience,
      nonce,
      signatureBase64Url: Buffer.from(signature).toString('base64url'),
    });

    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.httpStatus).toBe(403);
  });

  it('refuses signature bytes that are not valid base64url without throwing', () => {
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);

    const outcome = verifySignatureAgainstDocument({
      document: documentFor(publicKey),
      did,
      audience,
      nonce,
      signatureBase64Url: '!!! not base64url !!!',
    });

    expect(outcome.ok).toBe(false);
  });
});
