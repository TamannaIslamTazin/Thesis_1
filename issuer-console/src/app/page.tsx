'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/AuthContext';

export default function RootPage() {
  const { status, identity } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (status === 'loading') return;
    if (status === 'signed-out') {
      router.replace('/sign-in');
      return;
    }
    if (identity?.member) {
      router.replace('/queue');
    } else {
      router.replace('/bootstrap');
    }
  }, [status, identity, router]);

  return <p className="text-sm text-muted">Loading…</p>;
}
