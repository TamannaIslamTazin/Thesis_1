'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';

interface Session {
  username: string;
  role: 'user' | 'admin';
}

/**
 * The pharmacy's own navigation.
 *
 * It reads the session from the SERVER on mount rather than trusting anything in
 * the page, and it only renders the links the role can actually use — an owner
 * sees Counter and Back office, a counter user sees Counter only. The server
 * still enforces both; this is the map, not the lock.
 */
export function SiteHeader() {
  const router = useRouter();
  const pathname = usePathname();
  const [session, setSession] = useState<Session | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/auth/me')
      .then(async (res) => {
        if (cancelled) return;
        if (res.status === 401) {
          setSession(null);
          // The desk display at '/' is PUBLIC by design (#498): it shows one QR
          // and nothing else. Redirecting it to sign-in took the counter screen
          // off the counter, so a signed-out tablet could never present a code.
          if (pathname !== '/login' && pathname !== '/') router.replace('/login');
          return;
        }
        setSession((await res.json()) as Session);
      })
      .catch(() => {
        if (!cancelled) setSession(null);
      });
    return () => {
      cancelled = true;
    };
  }, [pathname, router]);

  const signOut = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    router.push('/login');
    router.refresh();
  };

  if (pathname === '/login' || pathname === '/') return null;

  return (
    <header className="border-b border-[var(--color-border)] bg-white">
      <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-3 text-sm">
        <div className="flex items-center gap-4">
          <span className="font-medium">Dhaka Community Pharmacy</span>
          <a className="underline" href="/">
            Counter
          </a>
          {session?.role === 'admin' && (
            <a className="underline" href="/admin">
              Back office
            </a>
          )}
        </div>
        <div className="flex items-center gap-3 text-[var(--color-muted)]">
          {session && (
            <span>
              {session.username} · {session.role === 'admin' ? 'Owner' : 'Counter'}
            </span>
          )}
          <button className="underline" onClick={signOut}>
            Sign out
          </button>
        </div>
      </div>
    </header>
  );
}
