'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/AuthContext';
import { ApiError, bootstrapAuthority } from '@/lib/api';
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input, Label } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

/**
 * POST /api/authority/bootstrap — the one-time path to an institution's
 * first ADMIN (authorityMembers.ts). Only reachable while the target
 * institution's roster is empty; the server refuses with 409 otherwise and
 * this page shows that refusal rather than retrying anything.
 */
export default function BootstrapPage() {
  const { status, user, refreshIdentity } = useAuth();
  const router = useRouter();

  const [institutionId, setInstitutionId] = useState('');
  const [secret, setSecret] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (status === 'signed-out') {
    router.replace('/sign-in');
    return null;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await bootstrapAuthority(institutionId, secret);
      await refreshIdentity();
      router.replace('/queue');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Bootstrap failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-sm space-y-4">
      <p className="text-sm text-muted">
        {user?.email} is signed in but is not on any L1 authority roster. If your institution
        already has an ADMIN, ask them to add you via the roster screen instead of bootstrapping.
      </p>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Bootstrap an institution</CardTitle>
            <CardDescription>Only works while the institution has zero active members.</CardDescription>
          </div>
        </CardHeader>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <Label htmlFor="institutionId">Institution id</Label>
            <Input
              id="institutionId"
              required
              value={institutionId}
              onChange={(e) => setInstitutionId(e.target.value)}
              placeholder="l1-mohfw"
            />
          </div>
          <div>
            <Label htmlFor="secret">Bootstrap secret</Label>
            <Input
              id="secret"
              type="password"
              required
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
          </div>
          {error && <p className="text-sm text-danger">{error}</p>}
          <Button type="submit" disabled={busy} className="w-full">
            {busy ? 'Bootstrapping…' : 'Become the first ADMIN'}
          </Button>
        </form>
      </Card>
    </div>
  );
}
