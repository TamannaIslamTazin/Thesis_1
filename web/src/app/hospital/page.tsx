'use client';

/**
 * Hospital Records — Connect and sync health data from hospitals
 * into your SSI wallet as verifiable credentials.
 */

import * as React from 'react';
import { useRouter } from 'next/navigation';
import {
  Building2,
  Plus,
  RefreshCw,
  Trash2,
  CheckCircle2,
  AlertCircle,
  FileText,
  Link2,
  ArrowLeft,
  Stethoscope,
  Pill,
  Calendar,
  Activity,
  Loader2,
  Info,
} from 'lucide-react';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { hospitalApi, HospitalConnection } from '@/lib/api';
import { cn } from '@/lib/utils';

type SyncStatus = 'idle' | 'syncing' | 'success' | 'error';

interface FormData {
  hospitalId: string;
  hospitalName: string;
  hospitalUrl: string;
  patientId: string;
  apiKey: string;
}

export default function HospitalPage() {
  const router = useRouter();
  const [connections, setConnections] = React.useState<HospitalConnection[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [showForm, setShowForm] = React.useState(false);
  const [syncStatuses, setSyncStatuses] = React.useState<Record<string, SyncStatus>>({});
  const [syncMessages, setSyncMessages] = React.useState<Record<string, string>>({});
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
  const [form, setForm] = React.useState<FormData>({
    hospitalId: '',
    hospitalName: '',
    hospitalUrl: process.env.NEXT_PUBLIC_DEFAULT_HOSPITAL_URL ?? '',
    patientId: '',
    apiKey: '',
  });

  const loadConnections = React.useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await hospitalApi.getConnections();
      setConnections(res.data ?? []);
    } catch {
      setError('Failed to load hospital connections');
    } finally {
      setIsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    loadConnections();
  }, [loadConnections]);

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await hospitalApi.connect({
        hospitalId: form.hospitalId,
        hospitalName: form.hospitalName,
        hospitalUrl: form.hospitalUrl,
        patientId: form.patientId,
        apiKey: form.apiKey || undefined,
      });
      setShowForm(false);
      setForm({ hospitalId: '', hospitalName: '', hospitalUrl: process.env.NEXT_PUBLIC_DEFAULT_HOSPITAL_URL ?? '', patientId: '', apiKey: '' });
      await loadConnections();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to connect to hospital';
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  const handleSync = async (conn: HospitalConnection) => {
    setSyncStatuses((p) => ({ ...p, [conn.id]: 'syncing' }));
    setSyncMessages((p) => ({ ...p, [conn.id]: '' }));
    try {
      const res = await hospitalApi.sync(conn.id);
      const result = res.data;
      setSyncStatuses((p) => ({ ...p, [conn.id]: 'success' }));
      setSyncMessages((p) => ({
        ...p,
        [conn.id]: `Imported ${result?.credentialsCreated ?? 0} health records as verifiable credentials`,
      }));
      await loadConnections();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Sync failed';
      setSyncStatuses((p) => ({ ...p, [conn.id]: 'error' }));
      setSyncMessages((p) => ({ ...p, [conn.id]: msg }));
    }
  };

  const handleRemove = async (id: string) => {
    if (!confirm('Remove this hospital connection? Your imported records will remain in your wallet.')) return;
    try {
      await hospitalApi.removeConnection(id);
      setConnections((p) => p.filter((c) => c.id !== id));
    } catch {
      setError('Failed to remove connection');
    }
  };

  return (
    <ProtectedRoute requireWallet>
      <div className="min-h-screen bg-background">
        {/* Header */}
        <div className="border-b border-border bg-card">
          <div className="max-w-4xl mx-auto px-4 py-4">
            <div className="flex items-center gap-3">
              <button
                onClick={() => router.back()}
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                <ArrowLeft className="w-5 h-5" />
              </button>
              <div className="flex items-center gap-2">
                <Building2 className="w-6 h-6 text-blue-500" />
                <div>
                  <h1 className="text-lg font-semibold text-foreground">Hospital Records</h1>
                  <p className="text-xs text-muted-foreground">Import your health data as private digital credentials</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-4xl mx-auto px-4 py-6 space-y-6">
          {/* Info Banner */}
          <div className="flex items-start gap-3 bg-blue-500/10 border border-blue-500/20 rounded-xl p-4">
            <Info className="w-5 h-5 text-blue-500 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-foreground">How it works</p>
              <p className="text-sm text-muted-foreground mt-0.5">
                Connect to a hospital and import your medical records — test results, prescriptions, appointments —
                into your private wallet. Only you control who can see them. Doctors you visit can request access,
                and you decide what to share.
              </p>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-center gap-2 bg-destructive/10 border border-destructive/20 rounded-xl p-4 text-sm text-destructive">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
          )}

          {/* Add Connection Button */}
          <div className="flex justify-between items-center">
            <h2 className="text-base font-semibold text-foreground">
              {connections.length === 0 ? 'No hospitals connected yet' : `${connections.length} hospital${connections.length > 1 ? 's' : ''} connected`}
            </h2>
            <button
              onClick={() => setShowForm((p) => !p)}
              className="flex items-center gap-2 bg-primary text-primary-foreground px-4 py-2 rounded-lg text-sm font-medium hover:opacity-90 transition-opacity"
            >
              <Plus className="w-4 h-4" />
              {showForm ? 'Cancel' : 'Add Hospital'}
            </button>
          </div>

          {/* Add Connection Form */}
          {showForm && (
            <form onSubmit={handleConnect} className="bg-card border border-border rounded-xl p-5 space-y-4">
              <h3 className="font-semibold text-foreground flex items-center gap-2">
                <Link2 className="w-4 h-4 text-blue-500" />
                Connect to a Hospital
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-foreground mb-1.5">Hospital ID</label>
                  <input
                    required
                    placeholder="e.g. city-general-hospital"
                    value={form.hospitalId}
                    onChange={(e) => setForm((p) => ({ ...p, hospitalId: e.target.value }))}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-foreground mb-1.5">Hospital Name</label>
                  <input
                    required
                    placeholder="e.g. City General Hospital"
                    value={form.hospitalName}
                    onChange={(e) => setForm((p) => ({ ...p, hospitalName: e.target.value }))}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-foreground mb-1.5">Hospital URL</label>
                  <input
                    required
                    placeholder="http://localhost:5000"
                    value={form.hospitalUrl}
                    onChange={(e) => setForm((p) => ({ ...p, hospitalUrl: e.target.value }))}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-foreground mb-1.5">Your Patient ID at this Hospital</label>
                  <input
                    required
                    placeholder="e.g. PAT001"
                    value={form.patientId}
                    onChange={(e) => setForm((p) => ({ ...p, patientId: e.target.value }))}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                </div>
                <div className="sm:col-span-2">
                  <label className="block text-sm font-medium text-foreground mb-1.5">
                    API Key <span className="text-muted-foreground font-normal">(if required by hospital)</span>
                  </label>
                  <input
                    type="password"
                    placeholder="Leave blank to use default"
                    value={form.apiKey}
                    onChange={(e) => setForm((p) => ({ ...p, apiKey: e.target.value }))}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={submitting}
                className="flex items-center gap-2 bg-primary text-primary-foreground px-5 py-2 rounded-lg text-sm font-medium hover:opacity-90 disabled:opacity-50 transition-opacity"
              >
                {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
                {submitting ? 'Connecting...' : 'Connect Hospital'}
              </button>
            </form>
          )}

          {/* Connections List */}
          {isLoading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="w-6 h-6 text-muted-foreground animate-spin" />
            </div>
          ) : (
            <div className="space-y-4">
              {connections.map((conn) => (
                <div key={conn.id} className="bg-card border border-border rounded-xl overflow-hidden">
                  {/* Connection Header */}
                  <div className="p-4 flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className="bg-blue-500/10 rounded-xl p-2.5 flex-shrink-0">
                        <Building2 className="w-5 h-5 text-blue-500" />
                      </div>
                      <div>
                        <h3 className="font-semibold text-foreground">{conn.hospitalName}</h3>
                        {conn.patientName && (
                          <p className="text-sm text-muted-foreground">{conn.patientName}</p>
                        )}
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-xs text-muted-foreground">Patient ID: {conn.patientId}</span>
                          <span className="text-xs text-muted-foreground">•</span>
                          <span className={cn(
                            'text-xs font-medium',
                            conn.isActive ? 'text-emerald-500' : 'text-muted-foreground'
                          )}>
                            {conn.isActive ? 'Active' : 'Inactive'}
                          </span>
                        </div>
                        {conn.lastSyncAt && (
                          <p className="text-xs text-muted-foreground mt-0.5">
                            Last synced: {new Date(conn.lastSyncAt).toLocaleDateString()}
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 flex-shrink-0">
                      <button
                        onClick={() => handleSync(conn)}
                        disabled={syncStatuses[conn.id] === 'syncing'}
                        className="flex items-center gap-1.5 bg-primary/10 text-primary px-3 py-1.5 rounded-lg text-xs font-medium hover:bg-primary/20 disabled:opacity-50 transition-colors"
                      >
                        {syncStatuses[conn.id] === 'syncing' ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <RefreshCw className="w-3.5 h-3.5" />
                        )}
                        {syncStatuses[conn.id] === 'syncing' ? 'Syncing...' : 'Sync Records'}
                      </button>
                      <button
                        onClick={() => handleRemove(conn.id)}
                        className="text-muted-foreground hover:text-destructive transition-colors p-1.5"
                        title="Remove connection"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Sync Status */}
                  {syncStatuses[conn.id] && syncStatuses[conn.id] !== 'idle' && (
                    <div className={cn(
                      'px-4 py-3 border-t border-border flex items-center gap-2 text-sm',
                      syncStatuses[conn.id] === 'success' && 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/5',
                      syncStatuses[conn.id] === 'error' && 'text-destructive bg-destructive/5',
                      syncStatuses[conn.id] === 'syncing' && 'text-muted-foreground',
                    )}>
                      {syncStatuses[conn.id] === 'success' && <CheckCircle2 className="w-4 h-4 flex-shrink-0" />}
                      {syncStatuses[conn.id] === 'error' && <AlertCircle className="w-4 h-4 flex-shrink-0" />}
                      {syncMessages[conn.id]}
                    </div>
                  )}

                  {/* Record Type Preview */}
                  <div className="px-4 pb-4 pt-2">
                    <p className="text-xs text-muted-foreground mb-2">Records that will be imported:</p>
                    <div className="flex flex-wrap gap-2">
                      {[
                        { icon: Activity, label: 'Vital Signs' },
                        { icon: Pill, label: 'Medications' },
                        { icon: Calendar, label: 'Appointments' },
                        { icon: FileText, label: 'Patient Profile' },
                        { icon: Stethoscope, label: 'Medical History' },
                      ].map(({ icon: Icon, label }) => (
                        <span key={label} className="flex items-center gap-1 bg-muted/50 text-muted-foreground px-2.5 py-1 rounded-full text-xs">
                          <Icon className="w-3 h-3" />
                          {label}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}

              {/* Empty State */}
              {connections.length === 0 && !showForm && (
                <div className="text-center py-16 bg-card border border-border rounded-xl">
                  <Building2 className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
                  <h3 className="font-semibold text-foreground mb-2">No hospital connections yet</h3>
                  <p className="text-sm text-muted-foreground max-w-sm mx-auto mb-6">
                    Connect to your hospital and your medical records will be securely imported
                    into your wallet. You control who can access them.
                  </p>
                  <button
                    onClick={() => setShowForm(true)}
                    className="flex items-center gap-2 bg-primary text-primary-foreground px-5 py-2.5 rounded-lg text-sm font-medium hover:opacity-90 transition-opacity mx-auto"
                  >
                    <Plus className="w-4 h-4" />
                    Connect Your First Hospital
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </ProtectedRoute>
  );
}
