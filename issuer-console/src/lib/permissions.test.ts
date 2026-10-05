import { describe, expect, it } from 'vitest';
import { permissionsForRole } from './permissions';

describe('permissionsForRole', () => {
  it('OFFICER can review the queue but not manage the roster', () => {
    const p = permissionsForRole('OFFICER');
    expect(p.canReviewQueue).toBe(true);
    expect(p.canManageRoster).toBe(false);
  });

  it('ADMIN can review the queue and manage the roster', () => {
    const p = permissionsForRole('ADMIN');
    expect(p.canReviewQueue).toBe(true);
    expect(p.canManageRoster).toBe(true);
  });
});
