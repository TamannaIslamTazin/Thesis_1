import { afterEach, describe, expect, it, vi } from 'vitest';
import { encryptLockerObject, bytesToBase64Url } from '@ssi-healthcare/shared';
import { decryptLockerObject, DocumentCryptoError, unwrapReleasedContentKey } from './documentCrypto';
import type { WrappedContentKey } from './api';

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

describe('decryptLockerObject (round 5 framing, @ssi-healthcare/shared)', () => {
  it('decrypts what shared\'s encryptLockerObject produced', () => {
    const objectId = 'health-card-nid-scan-1';
    const contentKey = randomBytes(32);
    const plaintext = new TextEncoder().encode('NID scan bytes standing in for a real document image.');

    const objectBytes = encryptLockerObject(objectId, contentKey, plaintext);
    const recovered = decryptLockerObject(objectId, contentKey, objectBytes);

    expect(new TextDecoder().decode(recovered)).toBe(new TextDecoder().decode(plaintext));
  });

  it('refuses when the content key is wrong', () => {
    const objectId = 'obj-1';
    const contentKey = randomBytes(32);
    const wrongKey = randomBytes(32);
    const objectBytes = encryptLockerObject(objectId, contentKey, new TextEncoder().encode('secret'));

    expect(() => decryptLockerObject(objectId, wrongKey, objectBytes)).toThrow(DocumentCryptoError);
  });

  it('refuses when the object id (AAD) does not match — a ciphertext relocated to a different object id fails the tag', () => {
    const contentKey = randomBytes(32);
    const objectBytes = encryptLockerObject('object-a', contentKey, new TextEncoder().encode('secret'));

    expect(() => decryptLockerObject('object-b', contentKey, objectBytes)).toThrow(DocumentCryptoError);
  });

  it('refuses a single flipped ciphertext byte', () => {
    const objectId = 'obj-1';
    const contentKey = randomBytes(32);
    const objectBytes = encryptLockerObject(objectId, contentKey, new TextEncoder().encode('secret'));
    const tampered = new Uint8Array(objectBytes);
    tampered[tampered.length - 1] ^= 0xff;

    expect(() => decryptLockerObject(objectId, contentKey, tampered)).toThrow(DocumentCryptoError);
  });
});

describe('unwrapReleasedContentKey — calls the server-side unwrap route, never opens the envelope itself', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns the plaintext content key the server route hands back', async () => {
    const key = randomBytes(32);
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ contentKeyBase64Url: bytesToBase64Url(key) }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const wrapped: WrappedContentKey = {
      version: 1,
      wrappedToVerificationMethodId: 'did:cheqd:bdhealthtestnet:mohfw#key-1',
      ephemeralPublicKey: 'e',
      nonce: 'n',
      salt: 's',
      ciphertext: 'c',
    };
    const result = await unwrapReleasedContentKey(wrapped, 'req-1');
    expect(Array.from(result)).toEqual(Array.from(key));
    expect(fetchMock).toHaveBeenCalledWith(
      '/console/content-key',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('surfaces the server\'s refusal as a DocumentCryptoError rather than returning garbage', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: false, json: async () => ({ error: 'wrong scheme' }) }),
    );
    const wrapped: WrappedContentKey = {
      version: 1,
      wrappedToVerificationMethodId: 'did:x#key-1',
      ciphertext: 'c',
    };
    await expect(unwrapReleasedContentKey(wrapped, 'req-1')).rejects.toThrow(DocumentCryptoError);
  });
});
