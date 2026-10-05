'use client';

import { useCallback, useEffect, useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';

/**
 * THE SELLER DASHBOARD. Staff-facing, and deliberately a different surface from
 * the desk display: this is where tokens, prices and stock live, so it is behind
 * a sign-in and never shown to a customer.
 *
 * ONE COLLAPSIBLE SECTION PER TOKEN. A busy counter accumulates tokens all day,
 * and a flat list buries today's newest under yesterday's — so the newest is
 * open by default and older ones collapse to their header.
 */
interface DispenseLine {
  medicineId: number;
  name: string;
  quantity: number;
  unitPrice: number;
  lineTotal: number;
  availability: number;
  storeArea: string;
}

interface Dispense {
  token: number;
  prescriptionId: string;
  total: number;
  createdAt: string;
  paid: boolean;
  paidAt: string | null;
  /** Set when the counter closed the token as not collected (A1). */
  abandonedAt?: string | null;
  abandonedReason?: string | null;
  /** The moment this token stops counting, derived from createdAt (A1 stage 4b). */
  expiresAt: string | null;
  /** True when the 24-hour window has passed and the token is still open. */
  expired: boolean;
  lines: DispenseLine[];
}

const POLL_MS = 3_000;

export default function DashboardPage() {
  const [dispenses, setDispenses] = useState<Dispense[]>([]);
  /** The pending confirmation. Nothing is settled until the operator confirms. */
  const [confirm, setConfirm] = useState<{ token: number; outcome: 'paid' | 'not-paid' } | null>(null);
  const [settling, setSettling] = useState<number | null>(null);
  /**
   * Tokens the counter recorded but could NOT tell the wallet about.
   *
   * This state exists because the two writes can disagree: the local record is
   * the desk's, the backend's is the patient's. If the local write succeeds and
   * the backend call fails, the desk must NOT show a settled token as finished —
   * the patient's wallet still holds it. Without this, the button disabled itself
   * on the local flag and left the operator with no way to retry.
   */
  const [walletPending, setWalletPending] = useState<Set<number>>(new Set());
  const [open, setOpen] = useState<Set<number>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [slipFor, setSlipFor] = useState<number | null>(null);

  const load = useCallback(async () => {
    const res = await fetch('/api/dispense/list');
    if (res.status === 401) {
      window.location.href = '/login';
      return;
    }
    const body = (await res.json()) as { dispenses?: Dispense[]; error?: string };
    if (!res.ok) {
      setError(body.error ?? 'Could not load the counter');
      return;
    }
    const list = body.dispenses ?? [];
    setDispenses(list);
    // Open the newest token so a new arrival is visible without a tap.
    setOpen((current) => (current.size === 0 && list[0] ? new Set([list[0].token]) : current));
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  const setQuantity = useCallback(
    async (token: number, medicineId: number, quantity: number) => {
      setError(null);
      const res = await fetch('/api/dispense/line', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, medicineId, quantity }),
      });
      const body = (await res.json()) as { error?: string };
      if (!res.ok) {
        setError(body.error ?? 'Could not change the quantity');
        return;
      }
      await load();
    },
    [load],
  );

  /**
   * Settle or close a token — after the operator has confirmed.
   *
   * The route writes the counter's own record AND tells the backend, because the
   * backend is what the patient's wallet reads. If the wallet could not be told,
   * the route says so and this surfaces it: the desk must not believe the patient
   * has been updated when they have not.
   */
  const settle = useCallback(
    async (token: number, outcome: 'paid' | 'not-paid') => {
      setError(null);
      setSettling(token);
      try {
        const res = await fetch('/api/dispense/settle', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, outcome }),
        });
        const body = (await res.json()) as {
          error?: string;
          walletNotified?: boolean;
          expired?: boolean;
        };
        if (!res.ok) {
          setError(body.error ?? 'Could not settle the token');
          // The local write may have succeeded. Remember it so the operator can
          // retry rather than being locked out by the disabled button.
          if (body.walletNotified === false) {
            setWalletPending((s) => new Set(s).add(token));
          }
          // The counter refused it as expired and wrote nothing. Close the
          // dialog so the next poll can show the token in its expired state.
          if (body.expired) setConfirm(null);
          return;
        }
        setWalletPending((s) => {
          const n = new Set(s);
          n.delete(token);
          return n;
        });
        setConfirm(null);
        await load();
      } finally {
        setSettling(null);
      }
    },
    [load],
  );

  return (
    <main className="mx-auto max-w-4xl px-6 py-10">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold">Counter</h1>
        <p className="mt-1 text-sm text-[var(--color-muted)]">
          Tokens raised by the desk. Prices and stock are live.
        </p>
      </header>

      {error && (
        <p className="mb-4 rounded-md border border-[var(--color-danger)] p-3 text-sm text-[var(--color-danger)]">
          {error}
        </p>
      )}

      {dispenses.length === 0 && (
        <Card className="p-6 text-sm text-[var(--color-muted)]">
          No tokens yet. They appear here the moment a prescription is accepted at the desk.
        </Card>
      )}

      <div className="space-y-3">
        {dispenses.map((d) => {
          const isOpen = open.has(d.token);
          const raised = new Date(d.createdAt).toLocaleString();
          const expiredAt = d.expiresAt ? new Date(d.expiresAt).toLocaleString() : null;
          return (
            <Card key={d.token} className="overflow-hidden">
              <button
                className="flex w-full items-center justify-between px-5 py-4 text-left"
                onClick={() =>
                  setOpen((current) => {
                    const next = new Set(current);
                    if (next.has(d.token)) next.delete(d.token);
                    else next.add(d.token);
                    return next;
                  })
                }
              >
                <span className="font-medium">Token number {d.token}</span>
                <span className="text-sm text-[var(--color-muted)]">
                  {d.paid
                    ? 'Paid'
                    : d.abandonedAt
                      ? 'Not collected'
                      : d.expired
                        ? 'Expired'
                        : `${d.total.toFixed(2)} due`}
                </span>
              </button>

              {isOpen && (
                <div className="border-t border-[var(--color-border)] px-5 py-4">
                  {/* THE PRE-EMPTIVE WARNING (A1 stage 4b). Shown before the
                      operator can reach the actions, because an expired token
                      cannot be settled at the backend and the counter refuses
                      it too; taking money here would record a payment the
                      patient’s wallet will never accept. */}
                  {d.expired && (
                    <div className="mb-4 rounded-md border border-[var(--color-danger)] p-3 text-sm">
                      <p className="font-medium text-[var(--color-danger)]">This token has expired.</p>
                      <p className="mt-1 text-[var(--color-muted)]">
                        {expiredAt
                          ? `It was raised on ${raised} and expired on ${expiredAt}.`
                          : `It was raised on ${raised}.`}{' '}
                        The 24-hour collection window has passed, so it cannot be paid or closed.
                        The patient’s wallet already shows it as not collected.
                      </p>
                    </div>
                  )}
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-[var(--color-muted)]">
                        <th className="pb-2 font-medium">Medicine</th>
                        <th className="pb-2 text-right font-medium">Price</th>
                        <th className="pb-2 text-right font-medium">Available</th>
                        <th className="pb-2 text-right font-medium">Qty</th>
                        <th className="pb-2 font-medium">Store</th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.lines.map((line) => (
                        <tr key={line.medicineId} className="border-t border-[var(--color-border)]">
                          <td className="py-2">{line.name}</td>
                          <td className="py-2 text-right tabular-nums">{line.unitPrice.toFixed(2)}</td>
                          <td className="py-2 text-right tabular-nums">{line.availability}</td>
                          <td className="py-2 text-right">
                            <input
                              type="number"
                              min={1}
                              className="w-20 rounded-md border border-[var(--color-border)] bg-white px-2 py-1 text-right tabular-nums"
                              defaultValue={line.quantity}
                              disabled={d.expired}
                              onBlur={(e) => {
                                const next = Number(e.target.value);
                                if (Number.isInteger(next) && next > 0 && next !== line.quantity) {
                                  void setQuantity(d.token, line.medicineId, next);
                                }
                              }}
                            />
                          </td>
                          <td className="py-2">{line.storeArea}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>

                  <div className="mt-4 flex flex-wrap items-center gap-3">
                    <Button variant="outline" onClick={() => setSlipFor(slipFor === d.token ? null : d.token)}>
                      {slipFor === d.token ? 'Hide slip' : 'Generate payment slip'}
                    </Button>
                    <Button
                      onClick={() => setConfirm({ token: d.token, outcome: 'paid' })}
                      disabled={
                        (d.paid && !walletPending.has(d.token)) || Boolean(d.abandonedAt) || d.expired
                      }
                    >
                      {walletPending.has(d.token)
                        ? 'Retry: tell the patient’s wallet'
                        : d.paid
                          ? 'Paid'
                          : d.abandonedAt
                            ? 'Not collected'
                            : d.expired
                              ? 'Expired'
                              : 'Mark paid'}
                    </Button>
                    {!d.paid && !d.abandonedAt && !d.expired && (
                      <Button
                        variant="outline"
                        onClick={() => setConfirm({ token: d.token, outcome: 'not-paid' })}
                      >
                        Not collected
                      </Button>
                    )}
                  </div>

                  {/* THE DOUBLE CONFIRM. Both outcomes are one-time and
                      irreversible, so both are confirmed. A single tap that
                      settles a payment cannot be undone, and the wallet acts on
                      what is recorded here. */}
                  {confirm?.token === d.token && (
                    <div className="mt-4 rounded-md border border-[var(--color-border)] p-4">
                      <p className="font-medium">
                        {confirm.outcome === 'paid'
                          ? `Confirm paid — token ${d.token}?`
                          : `Confirm not collected — token ${d.token}?`}
                      </p>
                      <p className="mt-1 text-xs text-[var(--color-muted)]">
                        {confirm.outcome === 'paid'
                          ? 'This records the medicine as dispensed and moves the patient’s balance.'
                          : 'This closes the token without moving the patient’s balance.'}
                      </p>
                      <div className="mt-3 flex gap-3">
                        <Button
                          onClick={() => void settle(d.token, confirm.outcome)}
                          disabled={settling === d.token}
                        >
                          {settling === d.token ? 'Recording…' : 'Confirm'}
                        </Button>
                        <Button variant="outline" onClick={() => setConfirm(null)}>
                          Cancel
                        </Button>
                      </div>
                    </div>
                  )}

                  {slipFor === d.token && (
                    <div className="mt-4 rounded-md border border-[var(--color-border)] p-4">
                      <p className="font-medium">Payment slip — Token {d.token}</p>
                      <p className="mt-1 text-xs text-[var(--color-muted)]">
                        {new Date(d.createdAt).toLocaleString()}
                      </p>
                      <table className="mt-3 w-full text-sm">
                        <tbody>
                          {d.lines.map((line) => (
                            <tr key={line.medicineId}>
                              <td className="py-1">
                                {line.name} × {line.quantity}
                              </td>
                              <td className="py-1 text-right tabular-nums">{line.lineTotal.toFixed(2)}</td>
                            </tr>
                          ))}
                          <tr className="border-t border-[var(--color-border)] font-medium">
                            <td className="pt-2">Total</td>
                            <td className="pt-2 text-right tabular-nums">{d.total.toFixed(2)}</td>
                          </tr>
                        </tbody>
                      </table>
                      <Button className="mt-3" variant="outline" onClick={() => window.print()}>
                        Print
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </main>
  );
}
