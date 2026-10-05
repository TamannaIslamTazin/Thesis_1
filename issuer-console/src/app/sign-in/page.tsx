'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/AuthContext';
import { ApiError } from '@/lib/api';
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input, Label } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

export default function SignInPage() {
  const { requestCode, submitCode } = useAuth();
  const router = useRouter();

  const [email, setEmail] = useState('');
  const [pendingToken, setPendingToken] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleRequestCode(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const { pendingToken } = await requestCode(email);
      setPendingToken(pendingToken);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not request a login code.');
    } finally {
      setBusy(false);
    }
  }

  async function handleSubmitCode(e: React.FormEvent) {
    e.preventDefault();
    if (!pendingToken) return;
    setError(null);
    setBusy(true);
    try {
      await submitCode(pendingToken, code);
      router.replace('/');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Invalid or expired code.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-sm">
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Officer sign-in</CardTitle>
            <CardDescription>
              {pendingToken
                ? `Enter the code sent to ${email}.`
                : 'Sign in with the email your institution registered you under.'}
            </CardDescription>
          </div>
        </CardHeader>

        {!pendingToken ? (
          <form onSubmit={handleRequestCode} className="space-y-3">
            <div>
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="officer@authority.gov.bd"
              />
            </div>
            {error && <p className="text-sm text-danger">{error}</p>}
            <Button type="submit" disabled={busy} className="w-full">
              {busy ? 'Sending…' : 'Send code'}
            </Button>
          </form>
        ) : (
          <form onSubmit={handleSubmitCode} className="space-y-3">
            <div>
              <Label htmlFor="code">6-digit code</Label>
              <Input
                id="code"
                inputMode="numeric"
                maxLength={6}
                required
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="000000"
              />
            </div>
            {error && <p className="text-sm text-danger">{error}</p>}
            <Button type="submit" disabled={busy || code.length !== 6} className="w-full">
              {busy ? 'Verifying…' : 'Verify'}
            </Button>
            <Button type="button" variant="ghost" className="w-full" onClick={() => setPendingToken(null)}>
              Use a different email
            </Button>
          </form>
        )}
      </Card>
    </div>
  );
}
