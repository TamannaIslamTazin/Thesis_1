'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import QRCode from 'react-qr-code';

/**
 * THE DESK DISPLAY. This is the screen that faces the customer, and it is a
 * DIFFERENT SURFACE from the seller dashboard on purpose:
 *
 *   - It shows ONE thing at a time: a QR to scan, then the verdict.
 *   - It never shows a price, a token list or any other customer's data, because
 *     it is a public display that anyone at the counter can see.
 *   - It refreshes ITSELF. Nobody works this screen; it is left running.
 *
 * The token and the medicines appear on the DASHBOARD, which is staff-facing.
 * Splitting them is what lets this screen sit on a cheap tablet on the desk
 * without ever being a place patient data can leak.
 */
type Phase = 'starting' | 'waiting' | 'received' | 'rejected' | 'error';

const VERDICT_MS = 5_000;
const POLL_MS = 1_500;

interface CreatedRequest {
  requestId: string;
  qr: string;
}

export default function DeskDisplay() {
  const [phase, setPhase] = useState<Phase>('starting');
  const [qr, setQr] = useState<string | null>(null);
  const [verdict, setVerdict] = useState<string>('');
  const [token, setToken] = useState<number | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const reset = useRef<ReturnType<typeof setTimeout> | null>(null);

  const stopPolling = useCallback(() => {
    if (timer.current) {
      clearInterval(timer.current);
      timer.current = null;
    }
  }, []);

  const start = useCallback(async () => {
    stopPolling();
    setPhase('starting');
    setQr(null);
    setVerdict('');
    setToken(null);
    try {
      const res = await fetch('/api/request', { method: 'POST' });
      const body = (await res.json()) as { requestId?: string; qr?: string; error?: string };
      if (!res.ok || !body.requestId || !body.qr) {
        setPhase('error');
        setVerdict(body.error ?? 'Could not reach the backend');
        reset.current = setTimeout(() => void start(), VERDICT_MS);
        return;
      }
      setQr(body.qr);
      setPhase('waiting');

      timer.current = setInterval(async () => {
        const poll = await fetch(`/api/result/${encodeURIComponent(body.requestId!)}`);
        if (!poll.ok) return;
        const session = (await poll.json()) as { status: string };
        if (session.status === 'REQUESTED') return;

        stopPolling();
        if (session.status !== 'VERIFIED') {
          setPhase('rejected');
          setVerdict(session.status);
          reset.current = setTimeout(() => void start(), VERDICT_MS);
          return;
        }

        const dispensed = await fetch('/api/dispense', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requestId: body.requestId }),
        });
        const outcome = (await dispensed.json()) as { token?: number; error?: string };
        if (!dispensed.ok || typeof outcome.token !== 'number') {
          setPhase('rejected');
          setVerdict(outcome.error ?? 'Could not dispense');
        } else {
          setPhase('received');
          setToken(outcome.token);
        }
        // Either way the screen clears itself, so the next customer is never
        // waiting on a stale QR that has already been spent.
        reset.current = setTimeout(() => void start(), VERDICT_MS);
      }, POLL_MS);
    } catch (error) {
      setPhase('error');
      setVerdict(error instanceof Error ? error.message : String(error));
      reset.current = setTimeout(() => void start(), VERDICT_MS);
    }
  }, [stopPolling]);

  useEffect(() => {
    void start();
    return () => {
      stopPolling();
      if (reset.current) clearTimeout(reset.current);
    };
  }, [start, stopPolling]);

  return (
    <main className="flex min-h-[80vh] flex-col items-center justify-center px-6 py-10">
      <h1 className="text-xl font-medium">Scan to collect your medicine</h1>

      <div className="mt-8 flex h-[420px] w-[420px] items-center justify-center rounded-2xl border border-[var(--color-border)] bg-white">
        {phase === 'waiting' && qr && <QRCode value={qr} size={360} />}
        {phase === 'starting' && <p className="text-sm text-[var(--color-muted)]">Preparing…</p>}
        {phase === 'received' && (
          <div className="text-center">
            <p className="text-sm text-[var(--color-muted)]">Received</p>
            <p className="mt-2 text-7xl font-semibold tabular-nums">{token}</p>
            <p className="mt-2 text-sm text-[var(--color-muted)]">Token number</p>
          </div>
        )}
        {(phase === 'rejected' || phase === 'error') && (
          <div className="px-8 text-center">
            <p className="text-2xl font-semibold text-[var(--color-danger)]">Not accepted</p>
            <p className="mt-2 break-words text-sm text-[var(--color-muted)]">{verdict}</p>
          </div>
        )}
      </div>

      <p className="mt-6 text-sm text-[var(--color-muted)]">
        {phase === 'waiting'
          ? 'Wallet → Scan. This screen resets by itself.'
          : 'The next code appears automatically.'}
      </p>
    </main>
  );
}
