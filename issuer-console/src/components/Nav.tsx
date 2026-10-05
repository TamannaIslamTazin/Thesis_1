'use client';

import Link from 'next/link';
import { useAuth } from '@/lib/AuthContext';
import { permissionsForRole } from '@/lib/permissions';
import { Button } from '@/components/ui/button';

export function Nav() {
  const { status, user, identity, signOut } = useAuth();

  if (status !== 'signed-in' || !identity?.member) {
    return (
      <header className="border-b border-border px-4 py-3">
        <span className="text-sm font-medium text-foreground">BDHealthTrust — Issuer Console</span>
      </header>
    );
  }

  const permissions = permissionsForRole(identity.role);

  return (
    <header className="flex items-center justify-between border-b border-border px-4 py-3">
      <div className="flex items-center gap-6">
        <span className="text-sm font-medium text-foreground">BDHealthTrust — Issuer Console</span>
        {permissions.canReviewQueue && (
          <Link href="/queue" className="text-sm text-muted hover:text-foreground">
            Queue
          </Link>
        )}
        {permissions.canManageRoster && (
          <Link href="/roster" className="text-sm text-muted hover:text-foreground">
            Roster
          </Link>
        )}
        {permissions.canOnboardInstitution && (
          <Link href="/onboard" className="text-sm text-muted hover:text-foreground">
            Onboard institution
          </Link>
        )}
      </div>
      <div className="flex items-center gap-3">
        <span className="text-xs text-muted">
          {user?.email} · {identity.role}
        </span>
        <Button variant="outline" onClick={signOut}>
          Sign out
        </Button>
      </div>
    </header>
  );
}
