'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/AuthContext';
import { ApiError, getQueue, type QueueEntry } from '@/lib/api';
import { Card, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

export default function QueuePage() {
  const { status, identity } = useAuth();
  const router = useRouter();

  const [requests, setRequests] = useState<QueueEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

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
    getQueue()
      .then((r) => setRequests(r.requests))
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Could not load the queue.'));
  }, [status, identity, router]);

  if (error) return <p className="text-sm text-danger">{error}</p>;
  if (!requests) return <p className="text-sm text-muted">Loading queue…</p>;

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Pending submissions</h1>
      {requests.length === 0 && <p className="text-sm text-muted">Nothing pending.</p>}
      <div className="space-y-3">
        {requests.map((r) => (
          <Link key={r.id} href={`/queue/${r.id}`}>
            <Card className="hover:border-primary/60">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>{r.documentType}</CardTitle>
                  <CardDescription>
                    {r.holder.firstName ?? r.holder.email ?? r.holderDid} · submitted{' '}
                    {new Date(r.createdAt).toLocaleString()}
                  </CardDescription>
                </div>
                <Badge tone={r.keyReleased ? 'warn' : 'default'}>
                  {r.keyReleased ? 'key released' : 'key unreleased'}
                </Badge>
              </div>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
