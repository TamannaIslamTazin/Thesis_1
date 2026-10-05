'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/AuthContext';
import { permissionsForRole } from '@/lib/permissions';
import { ApiError, addMember, listMembers, updateMember, type AuthorityMember, type AuthorityRole } from '@/lib/api';
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input, Label } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

export default function RosterPage() {
  const { status, identity } = useAuth();
  const router = useRouter();

  const [members, setMembers] = useState<AuthorityMember[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState<AuthorityRole>('OFFICER');
  const [busy, setBusy] = useState(false);

  const canManage = identity?.member && permissionsForRole(identity.role).canManageRoster;

  useEffect(() => {
    if (status === 'signed-out') {
      router.replace('/sign-in');
      return;
    }
    if (status !== 'signed-in') return;
    if (!identity?.member) {
      router.replace('/bootstrap');
      return;
    }
    if (!canManage) return; // server will 403 an OFFICER; do not even try
    listMembers()
      .then((r) => setMembers(r.members))
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Could not load the roster.'));
  }, [status, identity, canManage, router]);

  if (identity?.member && !canManage) {
    return <p className="text-sm text-muted">Roster management requires the ADMIN role.</p>;
  }

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const created = await addMember({ email, name, role });
      setMembers((prev) => (prev ? [...prev, created] : [created]));
      setEmail('');
      setName('');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not add member.');
    } finally {
      setBusy(false);
    }
  }

  async function handleToggleActive(member: AuthorityMember) {
    setError(null);
    try {
      const updated = await updateMember(member.id, { isActive: !member.isActive });
      setMembers((prev) => prev?.map((m) => (m.id === updated.id ? updated : m)) ?? null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not update member.');
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-semibold">Roster</h1>
      {error && <p className="text-sm text-danger">{error}</p>}

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Add a member</CardTitle>
            <CardDescription>Only ADMIN can add or change roles.</CardDescription>
          </div>
        </CardHeader>
        <form onSubmit={handleAdd} className="grid gap-3 sm:grid-cols-3">
          <div>
            <Label htmlFor="member-email">Email</Label>
            <Input id="member-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="member-name">Name</Label>
            <Input id="member-name" required value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="member-role">Role</Label>
            <select
              id="member-role"
              className="w-full rounded-md border border-border bg-surface-raised px-3 py-2 text-sm"
              value={role}
              onChange={(e) => setRole(e.target.value as AuthorityRole)}
            >
              <option value="OFFICER">OFFICER</option>
              <option value="ADMIN">ADMIN</option>
            </select>
          </div>
          <div className="sm:col-span-3">
            <Button type="submit" disabled={busy}>
              Add
            </Button>
          </div>
        </form>
      </Card>

      <div className="space-y-2">
        {members?.map((m) => (
          <Card key={m.id} className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">{m.name} — {m.email}</p>
              <p className="text-xs text-muted">{m.role}</p>
            </div>
            <div className="flex items-center gap-3">
              <Badge tone={m.isActive ? 'ok' : 'danger'}>{m.isActive ? 'active' : 'inactive'}</Badge>
              <Button variant="outline" onClick={() => handleToggleActive(m)}>
                {m.isActive ? 'Deactivate' : 'Reactivate'}
              </Button>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
