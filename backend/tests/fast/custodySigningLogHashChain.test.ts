/**
 * R5 — THE SIGNING LOG'S TAMPER EVIDENCE, WITHOUT A DATABASE.
 *
 * The hash chain is the half of "append-only" that survives someone with DDL
 * rights dropping the triggers. Its whole value is that an alteration is
 * DETECTABLE, so the test that matters is not "we can append" — it is "we can
 * tell when someone changed something", including the alterations that leave
 * the row count intact and the ones that leave every stored hash intact.
 *
 * Deliberately fast-tier: this property must keep being checked on a laptop
 * with nothing running, because a check that only runs when the full stack is
 * up is a check that stops running exactly when the codebase gets rushed.
 */
import { describe, expect, it } from 'vitest';

import {
  canonicalJson,
  computeEntryHash,
  digestPayload,
  GENESIS_PREV_HASH,
  headDigest,
  verifyHashChain,
  type HashChainedFields,
  type VerifiableEntry,
} from '../../src/services/custody/hashChain.js';

function entry(seq: number, prevHash: string, overrides: Partial<HashChainedFields> = {}) {
  const fields: HashChainedFields = {
    seq,
    prevHash,
    kind: 'SIGNING_INTENT',
    correlationId: `corr-${seq}`,
    versionId: `ver-${seq}`,
    subjectDid: 'did:cheqd:bdhealthtestnet:institution',
    operation: 'retire-officer-slot',
    signedByVerificationMethodId: 'did:cheqd:bdhealthtestnet:institution#key-officer-1',
    payloadDigest: digestPayload({ removed: ['#key-officer-2'] }),
    actorSource: 'http',
    actorUserId: 'user-1',
    sourceIp: '10.0.0.7',
    userAgent: 'operator-console/1.0',
    requestId: `req-${seq}`,
    txHash: null,
    height: null,
    failureReason: null,
    occurredAt: `2026-08-22T09:0${seq}:00.000Z`,
    ...overrides,
  };
  return { ...fields, entryHash: computeEntryHash(fields) } satisfies VerifiableEntry;
}

function chainOf(length: number): VerifiableEntry[] {
  const entries: VerifiableEntry[] = [];
  let prev = GENESIS_PREV_HASH as string;
  for (let seq = 1; seq <= length; seq += 1) {
    const next = entry(seq, prev);
    entries.push(next);
    prev = next.entryHash;
  }
  return entries;
}

// ---------------------------------------------------------------------------

describe('an untouched log verifies', () => {
  it('accepts a well-formed chain and reports its head digest', () => {
    const entries = chainOf(5);
    const verdict = verifyHashChain(entries);

    expect(verdict.intact).toBe(true);
    expect(verdict.breaks).toEqual([]);
    expect(verdict.entriesChecked).toBe(5);
    expect(verdict.firstSeq).toBe(1);
    expect(verdict.lastSeq).toBe(5);
    // The single value that commits to the whole log — what an external anchor
    // would publish, if one existed. See the hashChain.ts header.
    expect(verdict.headDigest).toBe(headDigest(entries));
  });

  it('is insensitive to key ORDER in the payload and sensitive to key VALUES', () => {
    // Two structurally identical payloads assembled by different code paths
    // must digest the same, or every legitimate entry would read as tampered.
    expect(digestPayload({ a: 1, b: { c: 2, d: 3 } })).toBe(
      digestPayload({ b: { d: 3, c: 2 }, a: 1 }),
    );
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(digestPayload({ removed: ['#key-officer-2'] })).not.toBe(
      digestPayload({ removed: ['#key-officer-3'] }),
    );
  });
});

// ---------------------------------------------------------------------------

describe('tampering is detected, and the report names every break', () => {
  it('catches an edited field even when the row count is unchanged', () => {
    const entries = chainOf(4);
    // The forgery an insider would actually attempt: make the eviction look
    // like it was signed by a different officer.
    const forged = [...entries];
    forged[2] = {
      ...forged[2],
      signedByVerificationMethodId: 'did:cheqd:bdhealthtestnet:institution#key-officer-9',
    };

    const verdict = verifyHashChain(forged);
    expect(verdict.intact).toBe(false);
    expect(verdict.breaks.some((b) => b.seq === 3 && b.reason === 'entry-hash-mismatch')).toBe(true);
  });

  it('catches an edited field even when the entry hash is recomputed to match', () => {
    // A more careful forger recomputes the hash of the row they edited. That
    // repairs the row and breaks its successor's prevHash — which is the entire
    // reason the entries are CHAINED rather than individually hashed.
    const entries = chainOf(4);
    const rewritten = { ...entries[1], sourceIp: '203.0.113.9' };
    const forged = [...entries];
    forged[1] = { ...rewritten, entryHash: computeEntryHash(rewritten) };

    const verdict = verifyHashChain(forged);
    expect(verdict.intact).toBe(false);
    expect(verdict.breaks.some((b) => b.seq === 3 && b.reason === 'prev-hash-mismatch')).toBe(true);
  });

  it('catches a removed middle entry as both a gap and a link break', () => {
    const entries = chainOf(5);
    const verdict = verifyHashChain([...entries.slice(0, 2), ...entries.slice(3)]);

    expect(verdict.intact).toBe(false);
    expect(verdict.breaks.some((b) => b.seq === 4 && b.reason === 'sequence-gap')).toBe(true);
    expect(verdict.breaks.some((b) => b.seq === 4 && b.reason === 'prev-hash-mismatch')).toBe(true);
  });

  it('catches entries removed from the FRONT of the log', () => {
    // Truncating the head is the cheapest way to erase the beginning of an
    // incident. It leaves a perfectly self-consistent chain, so the only thing
    // that catches it is the genesis marker.
    const entries = chainOf(5);
    const verdict = verifyHashChain(entries.slice(2));

    expect(verdict.intact).toBe(false);
    expect(verdict.breaks[0]?.reason).toBe('wrong-genesis-prev-hash');
  });

  it('reports EVERY break, not just the first', () => {
    // A verifier that stops at the first break invites "fix that row, re-run,
    // declare it sound" while the rest of the damage is still there.
    const entries = chainOf(6);
    const forged = [...entries];
    forged[1] = { ...forged[1], operation: 'rotate-officer-slot' };
    forged[4] = { ...forged[4], sourceIp: '198.51.100.4' };

    const verdict = verifyHashChain(forged);
    const seqs = verdict.breaks.map((b) => b.seq);
    expect(seqs).toContain(2);
    expect(seqs).toContain(5);
  });

  it('moving a value between fields changes the hash', () => {
    // Field NAMES are hashed, not only values, so relabelling an IP as a user
    // agent (or vice versa) is not a free rewrite.
    const a = entry(1, GENESIS_PREV_HASH, { sourceIp: 'X', userAgent: null });
    const b = entry(1, GENESIS_PREV_HASH, { sourceIp: null, userAgent: 'X' });
    expect(a.entryHash).not.toBe(b.entryHash);
  });
});

// ---------------------------------------------------------------------------

describe('paged verification', () => {
  it('does not report a false break at a page boundary', () => {
    // `verifySigningLog` pages the log so an integrity check cannot run out of
    // memory on a long one. If paging produced a spurious break, the check
    // would cry wolf on every healthy log above the page size.
    const entries = chainOf(7);
    const first = verifyHashChain(entries.slice(0, 3));
    const second = verifyHashChain(entries.slice(3), entries[2]);

    expect(first.intact).toBe(true);
    expect(second.intact).toBe(true);
    expect(second.headDigest).toBe(headDigest(entries));
  });

  it('still catches a break that straddles a page boundary', () => {
    const entries = chainOf(7);
    const forged = [...entries];
    forged[3] = { ...forged[3], prevHash: 'not-the-previous-hash' };

    const second = verifyHashChain(forged.slice(3), forged[2]);
    expect(second.intact).toBe(false);
    expect(second.breaks.some((b) => b.reason === 'prev-hash-mismatch')).toBe(true);
  });
});
