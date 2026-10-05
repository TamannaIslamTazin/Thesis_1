import { describe, expect, it, vi } from 'vitest';
import { resolveAuthorityIdentity } from './authorityIdentity';
import { ApiError } from './api';

vi.mock('./api', async () => {
  const actual = await vi.importActual<typeof import('./api')>('./api');
  return { ...actual, getMe: vi.fn() };
});

import { getMe } from './api';

describe('resolveAuthorityIdentity', () => {
  it('ADMIN: GET /api/authority/me returns the role directly, no message-parsing', async () => {
    vi.mocked(getMe).mockResolvedValueOnce({
      member: { id: '1', email: 'admin@mohfw.gov.bd', name: 'A', role: 'ADMIN' },
      institution: { id: 'l1-mohfw', did: 'did:cheqd:bdhealthtestnet:mohfw', name: 'MOHFW', type: 'MINISTRY' },
    });
    const identity = await resolveAuthorityIdentity('admin@mohfw.gov.bd');
    expect(identity).toEqual({
      member: true,
      role: 'ADMIN',
      self: expect.objectContaining({ email: 'admin@mohfw.gov.bd', role: 'ADMIN' }),
    });
  });

  it('OFFICER: GET /api/authority/me returns OFFICER directly', async () => {
    vi.mocked(getMe).mockResolvedValueOnce({
      member: { id: '2', email: 'officer@mohfw.gov.bd', name: 'O', role: 'OFFICER' },
      institution: { id: 'l1-mohfw', did: 'did:cheqd:bdhealthtestnet:mohfw', name: 'MOHFW', type: 'MINISTRY' },
    });
    const identity = await resolveAuthorityIdentity('officer@mohfw.gov.bd');
    expect(identity).toEqual({
      member: true,
      role: 'OFFICER',
      self: expect.objectContaining({ email: 'officer@mohfw.gov.bd', role: 'OFFICER' }),
    });
  });

  it('not a member: requireAuthorityMember refuses GET /me with 403', async () => {
    vi.mocked(getMe).mockRejectedValueOnce(
      new ApiError(403, 'AUTH_FORBIDDEN', 'Not an active staff member of an L1 issuing authority (ministry or professional council).'),
    );
    const identity = await resolveAuthorityIdentity('stranger@example.com');
    expect(identity).toEqual({ member: false });
  });

  it('a non-403 failure (e.g. network error) is not swallowed into either branch', async () => {
    vi.mocked(getMe).mockRejectedValueOnce(new Error('fetch failed'));
    await expect(resolveAuthorityIdentity('someone@example.com')).rejects.toThrow('fetch failed');
  });
});
