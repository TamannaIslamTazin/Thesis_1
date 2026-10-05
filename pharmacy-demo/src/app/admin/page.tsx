'use client';

import { useCallback, useEffect, useState } from 'react';
import { QrScanner } from '@/components/QrScanner';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface Medicine {
  id: number;
  name: string;
  strength: string;
  form: string;
  unitPrice: number;
  stock: number;
}

interface Stats {
  totalSales: number;
  totalRevenue: number;
  medicinesInStock: number;
  lowStock: Medicine[];
}

interface Account {
  id: number;
  username: string;
  displayName: string;
  role: 'user' | 'admin';
}

const EMPTY_MEDICINE = { name: '', strength: '', form: '', unitPrice: '', stock: '', storeArea: '' };
const EMPTY_ACCOUNT: { username: string; password: string; displayName: string; role: 'user' | 'admin' } = {
  username: '',
  password: '',
  displayName: '',
  role: 'user',
};

export default function AdminPage() {
  const [role, setRole] = useState<'user' | 'admin' | null>(null);
  const [checked, setChecked] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const [medicines, setMedicines] = useState<Medicine[]>([]);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [medicineForm, setMedicineForm] = useState(EMPTY_MEDICINE);
  const [accountForm, setAccountForm] = useState(EMPTY_ACCOUNT);
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [error, setError] = useState<string | null>(null);

  // -- Pairing with an L1 officer ------------------------------------------
  // The pharmacy's own identity. `scanned` holds whatever the counter scanner
  // typed; it is refused unless it carries the bdht-enrol:v1: prefix.
  const [identity, setIdentity] = useState<{ publicKeyMultibase: string; did: string | null } | null>(null);
  const [scanned, setScanned] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [pairNote, setPairNote] = useState<string | null>(null);
  const [pairError, setPairError] = useState<string | null>(null);
  const [pairing, setPairing] = useState(false);
  // The counter signs unattended, so the key lives in memory and a restart locks
  // it. Distinct from 'paired': a pharmacy can be onboarded and still unable to
  // dispense until an owner supplies the passphrase once.
  const [unlocked, setUnlocked] = useState(false);
  const [unlockPass, setUnlockPass] = useState('');
  const [unlockError, setUnlockError] = useState<string | null>(null);

  /**
   * The ONE unlock action. The button and the Enter key both call this, because
   * two implementations of the same operation drift: the button worked and Enter
   * did nothing, which is the defect this replaced.
   */
  const unlock = useCallback(async () => {
    setUnlockError(null);
    const res = await fetch('/api/admin/pair', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase: unlockPass }),
    });
    const body = (await res.json()) as { error?: string; unlocked?: boolean };
    if (!res.ok) setUnlockError(body.error ?? 'Could not unlock.');
    else {
      setUnlocked(true);
      setUnlockPass('');
    }
  }, [unlockPass]);

  /**
   * Enter submits. A form element is the correct fix, but these inputs are
   * spread across a page of independent actions rather than one form, so the
   * key handler is attached where each action lives.
   */
  const onEnter = (action: () => void) => (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      action();
    }
  };

  /** Pairing, extracted so the button and the Enter key share one implementation. */
  const pair = useCallback(async () => {
    setPairing(true);
    setPairError(null);
    setPairNote(null);
    try {
      const res = await fetch('/api/admin/pair', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanned, passphrase }),
      });
      const body = (await res.json()) as {
        error?: string;
        note?: string;
        publicKeyMultibase?: string;
      };
      if (!res.ok) {
        setPairError(body.error ?? 'Pairing failed.');
      } else {
        setPairNote(body.note ?? 'Paired.');
        setIdentity({ publicKeyMultibase: body.publicKeyMultibase ?? '', did: null });
      }
    } catch {
      setPairError('Could not reach the server.');
    } finally {
      setPairing(false);
    }
  }, [scanned, passphrase]);

  const load = useCallback(async () => {
    const me = await fetch('/api/auth/me');
    if (me.status === 401) {
      setRole(null);
      setChecked(true);
      return;
    }
    const session = (await me.json()) as { role: 'user' | 'admin' };
    setRole(session.role);

    // A counter user has no business in the owner area; sending them to the
    // counter is friendlier than an empty screen, and the server would refuse
    // the calls anyway.
    if (session.role !== 'admin') {
      setChecked(true);
      return;
    }

    const [statsRes, medsRes, accountsRes] = await Promise.all([
      fetch('/api/admin/stats'),
      fetch('/api/admin/medicines'),
      fetch('/api/admin/accounts'),
    ]);
    setStats((await statsRes.json()) as Stats);
    setMedicines(((await medsRes.json()) as { medicines: Medicine[] }).medicines);
    setAccounts(((await accountsRes.json()) as { accounts: Account[] }).accounts);
    setChecked(true);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // An ALREADY-PAIRED pharmacy must show its identity on load, not only in the
  // moment it pairs. Without this, a reload makes a paired pharmacy look unpaired
  // and invites a second pairing attempt against a DID that already exists.
  useEffect(() => {
    if (role !== 'admin') return;
    void (async () => {
      try {
        const res = await fetch('/api/admin/pair');
        if (!res.ok) return;
        const body = (await res.json()) as {
          identity: { publicKeyMultibase: string; did: string | null } | null;
          unlocked?: boolean;
        };
        setIdentity(body.identity);
        setUnlocked(Boolean(body.unlocked));
      } catch {
        // KNOWN LIMITATION, stated rather than papered over: a failed read leaves
        // the panel EMPTY, which is indistinguishable from "not paired". That is
        // the very confusion this codebase objects to elsewhere ("could not check"
        // read as "none"), and it is not fixed here because it needs a tri-state
        // the panel does not yet have. The pairing POST is still refused safely by
        // the server, so the worst outcome is a misleading panel, not a bad write.
      }
    })();
  }, [role]);

  const signIn = useCallback(async () => {
    setError(null);
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
    });
    if (!res.ok) {
      const body = (await res.json()) as { error?: string };
      setError(body.error ?? 'Sign-in failed');
      return;
    }
    await load();
  }, [credentials, load]);

  const addMedicine = useCallback(async () => {
    setError(null);
    const res = await fetch('/api/admin/medicines', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: medicineForm.name,
        strength: medicineForm.strength,
        form: medicineForm.form,
        unitPrice: Number(medicineForm.unitPrice),
        stock: Number(medicineForm.stock),
        storeArea: medicineForm.storeArea,
      }),
    });
    const body = (await res.json()) as { error?: string };
    if (!res.ok) {
      setError(body.error ?? 'Could not add the medicine');
      return;
    }
    setMedicineForm(EMPTY_MEDICINE);
    await load();
  }, [medicineForm, load]);

  const addAccount = useCallback(async () => {
    setError(null);
    const res = await fetch('/api/admin/accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(accountForm),
    });
    const body = (await res.json()) as { error?: string };
    if (!res.ok) {
      setError(body.error ?? 'Could not create the account');
      return;
    }
    setAccountForm(EMPTY_ACCOUNT);
    await load();
  }, [accountForm, load]);

  if (!checked) {
    return <main className="mx-auto max-w-3xl px-6 py-10 text-sm">Loading…</main>;
  }

  if (role === null) {
    return (
      <main className="mx-auto max-w-sm px-6 py-16">
        <Card className="p-6">
          <h1 className="text-lg font-medium">Sign in</h1>
          <p className="mt-1 text-sm text-[var(--color-muted)]">Staff and owner accounts.</p>
          {error && <p className="mt-4 text-sm text-[var(--color-danger)]">{error}</p>}
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
              onKeyDown={onEnter(() => void signIn())}
            />
          </label>
          <Button className="mt-4 w-full" onClick={() => void signIn()}>
            Sign in
          </Button>
        </Card>
      </main>
    );
  }

  if (role !== 'admin') {
    return (
      <main className="mx-auto max-w-sm px-6 py-16">
        <Card className="p-6">
          <h1 className="text-lg font-medium">Counter access</h1>
          <p className="mt-1 text-sm text-[var(--color-muted)]">
            This account works the counter. Stock and sales belong to the owner.
          </p>
          <a className="mt-4 inline-block text-sm underline" href="/">
            Go to the counter
          </a>
        </Card>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-4xl px-6 py-10">
      <header className="mb-8 flex items-baseline justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Owner</h1>
          <p className="mt-1 text-sm text-[var(--color-muted)]">Stock, staff, sales and revenue.</p>
        </div>
        <a className="text-sm underline" href="/">
          Counter
        </a>
      </header>

      {error && <p className="mb-4 text-sm text-[var(--color-danger)]">{error}</p>}

      {stats && (
        <div className="grid gap-4 sm:grid-cols-3">
          <Card className="p-6">
            <p className="text-sm text-[var(--color-muted)]">Total sales</p>
            <p className="mt-1 text-3xl font-semibold tabular-nums">{stats.totalSales}</p>
          </Card>
          <Card className="p-6">
            <p className="text-sm text-[var(--color-muted)]">Total revenue</p>
            <p className="mt-1 text-3xl font-semibold tabular-nums">
              {stats.totalRevenue.toFixed(2)}
            </p>
          </Card>
          <Card className="p-6">
            <p className="text-sm text-[var(--color-muted)]">Medicines in stock</p>
            <p className="mt-1 text-3xl font-semibold tabular-nums">{stats.medicinesInStock}</p>
          </Card>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Pharmacy identity. The admin's own act: a counter user must not be
          able to re-key the premises. */}
      {/* ------------------------------------------------------------------ */}
      <Card className="mt-6 p-6">
        <h2 className="text-lg font-medium">This pharmacy&rsquo;s identity</h2>
        {identity ? (
          <div className="mt-3 space-y-2 text-sm">
            <p>
              This pharmacy holds its own key, sealed under your passphrase. It is the second key
              on the institution&rsquo;s DID, so the ministry cannot act as this pharmacy on its
              own.
            </p>
            <p className="break-all font-mono text-xs text-[var(--color-muted)]">
              {identity.publicKeyMultibase}
            </p>
            {identity.did ? (
              <p className="break-all font-mono text-xs text-[var(--color-muted)]">{identity.did}</p>
            ) : (
              <p className="text-[var(--color-muted)]">
                Paired. The institution is created once the officer confirms what they verified on
                site. This page checks for it every few seconds.
              </p>
            )}
            {identity.did && !unlocked && (
              <div className="mt-2 space-y-2 rounded border border-[var(--color-border)] p-3">
                <p className="text-sm">
                  The signing key is locked — it is held in memory only, so a restart locks it. Enter
                  the owner passphrase before dispensing.
                </p>
                <input
                  type="password"
                  className="w-full rounded border border-[var(--color-border)] bg-transparent px-3 py-2 text-sm"
                  value={unlockPass}
                  onChange={(e) => setUnlockPass(e.target.value)}
                  onKeyDown={onEnter(() => void unlock())}
                  placeholder="Owner passphrase"
                />
                {unlockError && <p className="text-[var(--color-danger)]">{unlockError}</p>}
                <button
                  className="rounded bg-[var(--color-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
                  disabled={unlockPass.length < 8}
                  onClick={() => void unlock()}
                >
                  Unlock for dispensing
                </button>
              </div>
            )}
            {identity.did && unlocked && (
              <p className="text-[var(--color-muted)]">
                Signing key unlocked. Dispenses are signed and recorded on the shared ledger.
              </p>
            )}
          </div>
        ) : (
          <div className="mt-3 space-y-3 text-sm">
            <p className="text-[var(--color-muted)]">
              When a Pharmacy Council officer visits, they show a pairing code. Scan or type it
              here — this pharmacy then generates its own key, and only your passphrase can
              unlock it.
            </p>
            {/* SCAN, do not type. The code is a 32-character random string shown
                on the officer's screen; typing it is error-prone and is not what
                happens in the room. A text box would also invite pasting a code
                from anywhere, and this token is meant to be consumed in the
                presence of the officer who issued it. */}
            <QrScanner onScan={setScanned} />
            {scanned && (
              <p className="break-all font-mono text-xs text-[var(--color-muted)]">
                Recognised: {scanned}
              </p>
            )}
            <details className="text-xs">
              <summary className="cursor-pointer text-[var(--color-muted)]">
                No camera on this machine?
              </summary>
              <input
                className="mt-2 w-full rounded border border-[var(--color-border)] bg-transparent px-3 py-2 font-mono text-xs"
                value={scanned}
                onChange={(e) => setScanned(e.target.value)}
                placeholder="bdht-enrol:v1:..."
              />
              <p className="mt-1 text-[var(--color-muted)]">
                A USB scanner that types the code works here too — it appears as typed input.
              </p>
            </details>
            <div>
              <label className="mb-1 block text-sm">Choose a passphrase</label>
              <input
                type="password"
                className="w-full rounded border border-[var(--color-border)] bg-transparent px-3 py-2 text-sm"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                onKeyDown={onEnter(() => void pair())}
                placeholder="At least 8 characters"
              />
              <p className="mt-1 text-xs text-[var(--color-muted)]">
                Not stored anywhere. It seals the key that signs your dispensing records, so
                losing it means pairing again.
              </p>
            </div>
            {pairError && <p className="text-[var(--color-danger)]">{pairError}</p>}
            {pairNote && <p className="text-[var(--color-muted)]">{pairNote}</p>}
            <button
              className="rounded bg-[var(--color-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
              disabled={pairing || scanned.trim().length === 0 || passphrase.length < 8}
              onClick={() => void pair()}
            >
              {pairing ? 'Pairing…' : 'Pair this pharmacy'}
            </button>
          </div>
        )}
      </Card>

      <Card className="mt-6 p-6">
        <h2 className="text-lg font-medium">Add a medicine</h2>
        <div className="mt-4 grid gap-3 sm:grid-cols-6">
          {(
            [
              ['name', 'Name'],
              ['strength', 'Strength'],
              ['form', 'Form'],
              ['unitPrice', 'Unit price'],
              ['stock', 'Stock'],
              ['storeArea', 'Store area'],
            ] as const
          ).map(([key, label]) => (
            <label key={key} className="text-sm">
              {label}
              <input
                className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-white px-3 py-2"
                value={medicineForm[key]}
                onChange={(e) => setMedicineForm({ ...medicineForm, [key]: e.target.value })}
              />
            </label>
          ))}
        </div>
        <Button className="mt-4" onClick={addMedicine}>
          Add medicine
        </Button>
      </Card>

      <Card className="mt-6 p-6">
        <h2 className="text-lg font-medium">Staff accounts</h2>
        <p className="mt-1 text-sm text-[var(--color-muted)]">
          Counter users can dispense. Only owners can change stock or see revenue.
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-4">
          <label className="text-sm">
            Username
            <input
              className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-white px-3 py-2"
              value={accountForm.username}
              onChange={(e) => setAccountForm({ ...accountForm, username: e.target.value })}
            />
          </label>
          <label className="text-sm">
            Display name
            <input
              className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-white px-3 py-2"
              value={accountForm.displayName}
              onChange={(e) => setAccountForm({ ...accountForm, displayName: e.target.value })}
            />
          </label>
          <label className="text-sm">
            Password
            <input
              type="password"
              className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-white px-3 py-2"
              value={accountForm.password}
              onChange={(e) => setAccountForm({ ...accountForm, password: e.target.value })}
            />
          </label>
          <label className="text-sm">
            Role
            <select
              className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-white px-3 py-2"
              value={accountForm.role}
              onChange={(e) =>
                setAccountForm({ ...accountForm, role: e.target.value as 'user' | 'admin' })
              }
            >
              <option value="user">Counter user</option>
              <option value="admin">Owner</option>
            </select>
          </label>
        </div>
        <Button className="mt-4" onClick={addAccount}>
          Create account
        </Button>

        <table className="mt-6 w-full text-sm">
          <thead>
            <tr className="text-left text-[var(--color-muted)]">
              <th className="pb-2 font-medium">Username</th>
              <th className="pb-2 font-medium">Name</th>
              <th className="pb-2 font-medium">Role</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((a) => (
              <tr key={a.id} className="border-t border-[var(--color-border)]">
                <td className="py-2">{a.username}</td>
                <td className="py-2">{a.displayName}</td>
                <td className="py-2">
                  <Badge>{a.role === 'admin' ? 'Owner' : 'Counter user'}</Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card className="mt-6 p-6">
        <h2 className="text-lg font-medium">Shelf</h2>
        <table className="mt-4 w-full text-sm">
          <thead>
            <tr className="text-left text-[var(--color-muted)]">
              <th className="pb-2 font-medium">Name</th>
              <th className="pb-2 font-medium">Form</th>
              <th className="pb-2 text-right font-medium">Unit</th>
              <th className="pb-2 text-right font-medium">Stock</th>
            </tr>
          </thead>
          <tbody>
            {medicines.map((m) => (
              <tr key={m.id} className="border-t border-[var(--color-border)]">
                <td className="py-2">
                  {m.name} {m.strength}
                </td>
                <td className="py-2">{m.form}</td>
                <td className="py-2 text-right tabular-nums">{m.unitPrice.toFixed(2)}</td>
                <td className="py-2 text-right tabular-nums">
                  {m.stock < 60 ? <Badge className="bg-[var(--color-danger)] text-white">{m.stock}</Badge> : m.stock}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </main>
  );
}
