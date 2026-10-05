import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  clearCachedKey,
  createOnceGuard,
  readCachedKey,
  releaseReducer,
  writeCachedKey,
  type ReleaseState,
} from './singleUseKey';
import type { RequestDetail } from './api';

const detail = (wrappedContentKey?: RequestDetail['wrappedContentKey']): RequestDetail => ({
  id: 'req-1',
  documentType: 'health-card',
  status: 'PENDING',
  holderDid: 'did:cheqd:bdhealthtestnet:holder',
  holder: { id: 'u1', firstName: 'A', lastName: 'B', email: 'a@b.com' },
  documents: [],
  createdAt: new Date().toISOString(),
  keyReleased: true,
  wrappedContentKey,
  lockerCapability: {
    claims: {
      iss: 'did:cheqd:bdhealthtestnet:holder',
      aud: 'did:cheqd:bdhealthtestnet:mohfw',
      obj: ['obj-1'],
      sub: 'req-1',
      jti: 'jti-1',
      nbf: 0,
      exp: 9999999999,
    },
    signature: 'c2ln',
    verificationMethodId: 'did:cheqd:bdhealthtestnet:holder#key-1',
  },
});

describe('createOnceGuard', () => {
  it('claims exactly once', () => {
    const guard = createOnceGuard();
    expect(guard.tryClaim()).toBe(true);
    expect(guard.tryClaim()).toBe(false);
    expect(guard.tryClaim()).toBe(false);
  });

  it('reset allows a fresh claim', () => {
    const guard = createOnceGuard();
    expect(guard.tryClaim()).toBe(true);
    guard.reset();
    expect(guard.tryClaim()).toBe(true);
  });
});

describe('releaseReducer', () => {
  it('idle -> START -> releasing', () => {
    const next = releaseReducer({ status: 'idle' }, { type: 'START' });
    expect(next.status).toBe('releasing');
  });

  it('releasing -> START is ignored (stays releasing)', () => {
    const releasing: ReleaseState = { status: 'releasing' };
    const next = releaseReducer(releasing, { type: 'START' });
    expect(next).toBe(releasing);
  });

  it('released -> START is ignored — the second call this whole module exists to prevent', () => {
    const released: ReleaseState = { status: 'released', detail: detail(), key: null };
    const next = releaseReducer(released, { type: 'START' });
    expect(next).toBe(released);
  });

  it('releasing -> SUCCESS with a key present carries the key through', () => {
    const wrappedContentKey = { version: 1 as const, wrappedToVerificationMethodId: 'did:x#key-1', ciphertext: 'abc' };
    const releasedDetail = detail(wrappedContentKey);
    const next = releaseReducer(
      { status: 'releasing' },
      { type: 'SUCCESS', detail: releasedDetail, key: wrappedContentKey },
    );
    expect(next).toEqual({ status: 'released', detail: releasedDetail, key: wrappedContentKey });
  });

  it('releasing -> SUCCESS with no key (already released earlier) surfaces key: null, not an error', () => {
    const next = releaseReducer(
      { status: 'releasing' },
      { type: 'SUCCESS', detail: detail(undefined), key: null },
    );
    expect(next.status).toBe('released');
    expect(next.status === 'released' && next.key).toBeNull();
  });

  it('idle -> SUCCESS is ignored (SUCCESS without a prior START cannot happen from the UI, and must not be trusted if it does)', () => {
    const idle: ReleaseState = { status: 'idle' };
    const next = releaseReducer(idle, { type: 'SUCCESS', detail: detail(), key: null });
    expect(next).toBe(idle);
  });

  it('releasing -> FAILURE surfaces the message', () => {
    const next = releaseReducer({ status: 'releasing' }, { type: 'FAILURE', message: 'network down' });
    expect(next).toEqual({ status: 'error', message: 'network down' });
  });
});

/**
 * The cache exists because the backend spends the key on first read (#384) and
 * will never issue it again, so losing the browser's copy makes the submitted
 * document permanently undecryptable. These assert the bounded-ness of that
 * trade, not just that storage round-trips: each refusal is paired with the
 * success it refuses against, per CLAUDE.md's failure pattern 2.
 */
describe('released-key cache', () => {
  const key = { version: 1 as const, wrappedToVerificationMethodId: 'did:x#key-1', ciphertext: 'abc' };

  // This package's vitest environment is 'node', so there is no DOM. Rather
  // than pull in jsdom for two Storage objects, stand up a minimal one: the
  // module reads `window.sessionStorage` at CALL time, so a global stub
  // exercises the real code path. Nothing here is mocked out of the module
  // itself — the functions under test are the shipped ones.
  function makeStorage(): Storage {
    const map = new Map<string, string>();
    return {
      get length() {
        return map.size;
      },
      clear: () => map.clear(),
      getItem: (k: string) => map.get(k) ?? null,
      key: (i: number) => [...map.keys()][i] ?? null,
      removeItem: (k: string) => void map.delete(k),
      setItem: (k: string, v: string) => void map.set(k, v),
    } as Storage;
  }

  const stubWindow = { sessionStorage: makeStorage(), localStorage: makeStorage() };
  const globalRef = globalThis as { window?: unknown };
  const hadWindow = 'window' in globalRef;
  const previousWindow = globalRef.window;

  beforeAll(() => {
    globalRef.window = stubWindow;
  });

  afterAll(() => {
    if (hadWindow) globalRef.window = previousWindow;
    else delete globalRef.window;
  });

  beforeEach(() => {
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  it('reads as absent when there is no window at all (server rendering)', () => {
    delete globalRef.window;
    try {
      expect(readCachedKey('req-1')).toBeNull();
      expect(() => writeCachedKey('req-1', key)).not.toThrow();
      expect(() => clearCachedKey('req-1')).not.toThrow();
    } finally {
      globalRef.window = stubWindow;
    }
  });

  it('a written key reads back, and a DIFFERENT request id does not see it', () => {
    writeCachedKey('req-1', key);
    expect(readCachedKey('req-1')).toEqual(key);
    // The pairing: without this, a cache that returned the same value for
    // every id would pass the assertion above.
    expect(readCachedKey('req-2')).toBeNull();
  });

  it('clearCachedKey erases it, and erases only the request it names', () => {
    writeCachedKey('req-1', key);
    writeCachedKey('req-2', key);
    clearCachedKey('req-1');
    expect(readCachedKey('req-1')).toBeNull();
    expect(readCachedKey('req-2')).toEqual(key);
  });

  it('it is in sessionStorage and NOT in localStorage — the copy must die with the tab', () => {
    writeCachedKey('req-1', key);
    expect(window.sessionStorage.length).toBe(1);
    expect(window.localStorage.length).toBe(0);
  });

  it('a corrupt entry reads as absent rather than throwing into the review', () => {
    window.sessionStorage.setItem('bdht.issuer-console.released-key.req-1', 'not json');
    expect(readCachedKey('req-1')).toBeNull();
  });

  it('a storage that throws degrades to no-cache instead of failing the release', () => {
    const original = window.sessionStorage.setItem;
    window.sessionStorage.setItem = () => {
      throw new Error('QuotaExceededError');
    };
    try {
      expect(() => writeCachedKey('req-1', key)).not.toThrow();
    } finally {
      window.sessionStorage.setItem = original;
    }
    expect(readCachedKey('req-1')).toBeNull();
  });
});
