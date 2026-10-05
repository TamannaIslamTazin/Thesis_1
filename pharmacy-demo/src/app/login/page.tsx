'use client';

import { useCallback, useState } from 'react';
import { useRouter } from 'next/navigation';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';

/**
 * One door for both roles. The account decides where you land: an owner goes to
 * the back office, a counter user goes to the till. The client never chooses its
 * own role — it only reads the one the server put in the session.
 */
export default function LoginPage() {
  const router = useRouter();
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const signIn = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });
      const body = (await res.json()) as { error?: string; role?: 'user' | 'admin' };
      if (!res.ok) {
        setError(body.error ?? 'Sign-in failed');
        return;
      }
      router.push(body.role === 'admin' ? '/admin' : '/dashboard');
      router.refresh();
    } finally {
      setBusy(false);
    }
  }, [credentials, router]);

  return (
    <main className="mx-auto max-w-sm px-6 py-16">
      <Card className="p-6">
        <h1 className="text-lg font-medium">Sign in</h1>
        <p className="mt-1 text-sm text-[var(--color-muted)]">Staff and owner accounts.</p>

        {error && <p className="mt-4 text-sm text-[var(--color-danger)]">{error}</p>}

        {/* A REAL FORM, so Enter submits natively. The previous markup was bare
            inputs with a button beside them, which meant Enter did nothing at all
            — the defect the owner reported. A handler would work too, but the
            form element is the browser's own mechanism and cannot drift. */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!busy) void signIn();
          }}
        >
          <label className="mt-4 block text-sm">
            Username
            <input
              className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-white px-3 py-2"
              value={credentials.username}
              onChange={(e) => setCredentials({ ...credentials, username: e.target.value })}
            />
          </label>
          <label className="mt-3 block text-sm">
            Password
            <input
              type="password"
              className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-white px-3 py-2"
              value={credentials.password}
              onChange={(e) => setCredentials({ ...credentials, password: e.target.value })}
            />
          </label>
          <Button type="submit" className="mt-4 w-full" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>
      </Card>
    </main>
  );
}
