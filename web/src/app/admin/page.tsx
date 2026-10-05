/**
 * SSI Healthcare Web - Admin Panel
 *
 * System administration: audit logs, emergency access history,
 * consent overview, and system configuration.
 * 
 * Protected: Requires authentication
 */

'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ScrollText,
  AlertTriangle,
  HandshakeIcon,
  Settings,
  Search,
  ChevronLeft,
  ChevronRight,
  Loader2,
} from "lucide-react";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { adminApi, type AuditLog } from "@/lib/api";

type TabId = 'audit' | 'emergency' | 'consents' | 'settings';

const TABS: { id: TabId; label: string; icon: React.ReactNode }[] = [
  { id: 'audit', label: 'Audit Log', icon: <ScrollText className="w-4 h-4" /> },
  { id: 'emergency', label: 'Emergency Access', icon: <AlertTriangle className="w-4 h-4" /> },
  { id: 'consents', label: 'Consents', icon: <HandshakeIcon className="w-4 h-4" /> },
  { id: 'settings', label: 'Settings', icon: <Settings className="w-4 h-4" /> },
];

const EVENT_TYPE_FILTERS = [
  { value: '', label: 'All Events' },
  { value: 'CONSENT', label: 'Consent' },
  { value: 'EMERGENCY', label: 'Emergency' },
  { value: 'CREDENTIAL', label: 'Credential' },
  { value: 'VERIFICATION', label: 'Verification' },
  { value: 'DID', label: 'DID' },
];

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState<TabId>('audit');
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [emergencyLogs, setEmergencyLogs] = useState<AuditLog[]>([]);
  const [consentLogs, setConsentLogs] = useState<AuditLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [page, setPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const pageSize = 20;

  const loadAuditLogs = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await adminApi.getAuditLogs({
        eventType: eventTypeFilter || undefined,
        page,
        limit: pageSize,
      });
      const data = res.data;
      if (data) {
        setLogs(data.events as AuditLog[]);
        setTotalCount(data.total ?? data.events.length);
      }
    } catch {
      setLogs([]);
    } finally {
      setIsLoading(false);
    }
  }, [eventTypeFilter, page]);

  const loadEmergencyLogs = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await adminApi.getEmergencyLogs({ page: 1, limit: 50 });
      if (res.data) setEmergencyLogs(res.data.events as AuditLog[]);
    } catch {
      setEmergencyLogs([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const loadConsentLogs = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await adminApi.getConsentLogs({ page: 1, limit: 50 });
      if (res.data) setConsentLogs(res.data.events as AuditLog[]);
    } catch {
      setConsentLogs([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'audit') loadAuditLogs();
    else if (activeTab === 'emergency') loadEmergencyLogs();
    else if (activeTab === 'consents') loadConsentLogs();
  }, [activeTab, loadAuditLogs, loadEmergencyLogs, loadConsentLogs]);

  // Filter locally by search query (actor/target DIDs or event type)
  const filteredLogs = searchQuery
    ? logs.filter(log =>
        (log.eventType ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (log.actorDid && log.actorDid.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (log.targetDid && log.targetDid.toLowerCase().includes(searchQuery.toLowerCase()))
      )
    : logs;

  const getStatusColor = (eventType: string | undefined | null): string => {
    if (!eventType) return 'success';
    if (eventType.includes('FAILED') || eventType.includes('DENIED') || eventType.includes('REVOKED')) return 'error';
    if (eventType.includes('EMERGENCY') || eventType.includes('WARNING')) return 'warning';
    return 'success';
  };

  return (
    <ProtectedRoute>
      <div className="p-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground">Admin Panel</h1>
          <p className="text-muted-foreground mt-1">
            System administration, audit logs, and monitoring
          </p>
        </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-card p-1 rounded-xl mb-6 border border-border w-fit">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
              activeTab === tab.id
                ? "bg-blue-600 text-foreground"
                : "text-muted-foreground hover:text-foreground hover:bg-muted"
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Audit Log Tab */}
      {activeTab === 'audit' && (
        <div className="bg-card rounded-xl border border-border overflow-hidden">
          <div className="px-6 py-4 border-b border-border flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">Audit Log</h2>
            <div className="flex gap-2">
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search events..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 pr-3 py-1.5 bg-muted border border-border rounded-lg text-sm text-foreground placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <select
                value={eventTypeFilter}
                onChange={(e) => { setEventTypeFilter(e.target.value); setPage(1); }}
                className="px-3 py-1.5 bg-muted border border-border rounded-lg text-sm text-foreground focus:outline-none focus:border-blue-500"
              >
                {EVENT_TYPE_FILTERS.map(f => (
                  <option key={f.value} value={f.value}>{f.label}</option>
                ))}
              </select>
            </div>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 text-blue-400 animate-spin" />
            </div>
          ) : (
            <>
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Timestamp</th>
                    <th className="text-left px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Event</th>
                    <th className="text-left px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Actor</th>
                    <th className="text-left px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Target</th>
                    <th className="text-left px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredLogs.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-center text-sm text-muted-foreground">
                        No audit events found
                      </td>
                    </tr>
                  ) : filteredLogs.map((row) => {
                    const status = getStatusColor(row.eventType);
                    return (
                      <tr key={row.id} className="hover:bg-muted/50 transition-colors">
                        <td className="px-6 py-3 text-sm text-muted-foreground font-mono">
                          {new Date(row.timestamp).toLocaleString()}
                        </td>
                        <td className="px-6 py-3">
                          <span className="text-sm font-medium text-foreground">{row.eventType}</span>
                        </td>
                        <td className="px-6 py-3 text-sm text-muted-foreground font-mono truncate max-w-[160px]">
                          {row.actorDid || 'system'}
                        </td>
                        <td className="px-6 py-3 text-sm text-muted-foreground font-mono truncate max-w-[160px]">
                          {row.targetDid || '—'}
                        </td>
                        <td className="px-6 py-3">
                          <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${
                            status === "success"
                              ? "text-emerald-400 bg-emerald-400/10"
                              : status === "warning"
                                ? "text-amber-400 bg-amber-400/10"
                                : "text-red-400 bg-red-400/10"
                          }`}>
                            {status}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>

              {/* Pagination */}
              <div className="px-6 py-3 border-t border-border flex items-center justify-between">
                <p className="text-sm text-muted-foreground">
                  Page {page} · {filteredLogs.length} events
                </p>
                <div className="flex gap-1">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="px-3 py-1 bg-muted text-muted-foreground rounded text-sm hover:text-foreground transition-colors flex items-center gap-1 disabled:opacity-50"
                  >
                    <ChevronLeft className="w-3 h-3" /> Previous
                  </button>
                  <span className="px-3 py-1 bg-blue-600 text-foreground rounded text-sm">{page}</span>
                  <button
                    onClick={() => setPage(p => p + 1)}
                    disabled={page * pageSize >= totalCount}
                    className="px-3 py-1 bg-muted text-muted-foreground rounded text-sm hover:text-foreground transition-colors flex items-center gap-1 disabled:opacity-50"
                  >
                    Next <ChevronRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* Placeholder for other tabs */}
      {activeTab === 'emergency' && (
        <div className="bg-card rounded-xl border border-border overflow-hidden">
          <div className="p-4 border-b border-border flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <h3 className="font-semibold text-foreground">Emergency Access Events</h3>
          </div>
          {isLoading ? (
            <div className="p-8 text-center"><Loader2 className="w-6 h-6 animate-spin mx-auto text-muted-foreground" /></div>
          ) : emergencyLogs.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">No emergency access events found.</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-muted/50">
                <tr>
                  <th className="text-left p-3 text-muted-foreground font-medium">Event</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Actor DID</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Target DID</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {emergencyLogs.map(log => (
                  <tr key={log.id} className="border-t border-border hover:bg-muted/30">
                    <td className="p-3 font-mono text-amber-600 text-xs">{log.eventType}</td>
                    <td className="p-3 font-mono text-xs text-muted-foreground truncate max-w-[200px]">{log.actorDid ?? '—'}</td>
                    <td className="p-3 font-mono text-xs text-muted-foreground truncate max-w-[200px]">{log.targetDid ?? '—'}</td>
                    <td className="p-3 text-xs text-muted-foreground whitespace-nowrap">{new Date(log.timestamp).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === 'consents' && (
        <div className="bg-card rounded-xl border border-border overflow-hidden">
          <div className="p-4 border-b border-border flex items-center gap-2">
            <HandshakeIcon className="w-5 h-5 text-blue-400" />
            <h3 className="font-semibold text-foreground">Consent Events</h3>
          </div>
          {isLoading ? (
            <div className="p-8 text-center"><Loader2 className="w-6 h-6 animate-spin mx-auto text-muted-foreground" /></div>
          ) : consentLogs.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">No consent events found.</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-muted/50">
                <tr>
                  <th className="text-left p-3 text-muted-foreground font-medium">Event</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Actor DID</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Resource</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {consentLogs.map(log => (
                  <tr key={log.id} className="border-t border-border hover:bg-muted/30">
                    <td className="p-3 font-mono text-blue-600 text-xs">{log.eventType}</td>
                    <td className="p-3 font-mono text-xs text-muted-foreground truncate max-w-[200px]">{log.actorDid ?? '—'}</td>
                    <td className="p-3 text-xs text-muted-foreground">{log.resourceType ?? '—'} {log.resourceId ? `#${log.resourceId.slice(0, 8)}` : ''}</td>
                    <td className="p-3 text-xs text-muted-foreground whitespace-nowrap">{new Date(log.timestamp).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === 'settings' && (
        <div className="bg-card rounded-xl border border-border p-8 text-center">
          <Settings className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-foreground mb-2">System Settings</h3>
          <p className="text-muted-foreground">Configuration managed via environment variables and backend config.</p>
        </div>
      )}
    </div>
    </ProtectedRoute>
  );
}
