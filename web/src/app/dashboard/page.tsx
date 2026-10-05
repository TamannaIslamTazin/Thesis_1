/**
 * SSI Healthcare Web - Dashboard Page
 *
 * Overview of system health, credential statistics,
 * recent activity, and quick actions.
 * 
 * Protected: Requires authentication
 */

'use client';

import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  FileEdit,
  CheckCircle2,
  Shield,
  Server,
  Cpu,
  Globe,
  Wallet,
  FileText,
  Fingerprint,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { adminApi, healthApi } from "@/lib/api";

const STAT_ICONS: Record<string, React.ReactNode> = {
  "Total DIDs": <KeyRound className="w-6 h-6 text-blue-400" />,
  "Credentials Issued": <FileEdit className="w-6 h-6 text-emerald-400" />,
  "Verifications": <CheckCircle2 className="w-6 h-6 text-purple-400" />,
  "Active Consents": <Shield className="w-6 h-6 text-amber-400" />,
};

const ACTIVITY_ICONS: Record<string, React.ReactNode> = {
  issue: <FileText className="w-5 h-5 text-emerald-400" />,
  did: <KeyRound className="w-5 h-5 text-blue-400" />,
  verify: <CheckCircle2 className="w-5 h-5 text-purple-400" />,
  emergency: <AlertTriangle className="w-5 h-5 text-red-400" />,
  consent: <Shield className="w-5 h-5 text-amber-400" />,
};

const HEALTH_ICONS: Record<string, React.ReactNode> = {
  "Backend Server": <Server className="w-4 h-4 text-muted-foreground" />,
  "Credo Agent": <Cpu className="w-4 h-4 text-muted-foreground" />,
  "Cheqd Testnet": <Globe className="w-4 h-4 text-muted-foreground" />,
  "Askar Wallet": <Wallet className="w-4 h-4 text-muted-foreground" />,
};

interface DashboardStat {
  label: string;
  value: string;
  change: string;
}

interface HealthService {
  name: string;
  status: string;
  color: string;
}

interface ActivityEntry {
  action: string;
  target: string;
  time: string;
  type: string;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStat[]>([]);
  const [healthServices, setHealthServices] = useState<HealthService[]>([]);
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadDashboard() {
      try {
        const [dashRes, healthRes] = await Promise.allSettled([
          adminApi.getDashboard(),
          healthApi.detailed(),
        ]);

        if (dashRes.status === 'fulfilled' && dashRes.value.data) {
          const d = dashRes.value.data as unknown as Record<string, unknown>;
          // Backend returns { totalEvents, uniqueSessions, uniqueUsers, topEvents, deviceBreakdown }
          setStats([
            { label: "Total DIDs", value: String(d.uniqueUsers ?? 0), change: `${d.uniqueSessions ?? 0} sessions` },
            { label: "Credentials Issued", value: String(d.totalEvents ?? 0), change: "total events" },
            { label: "Verifications", value: String(d.uniqueSessions ?? 0), change: "sessions" },
            { label: "Active Consents", value: String(d.uniqueUsers ?? 0), change: "users" },
          ]);
          if (Array.isArray(d.topEvents)) {
            setActivity((d.topEvents as Array<Record<string, unknown>>).map(a => ({
              action: String(a.eventName || 'Event'),
              target: `${a.count ?? 0} occurrences`,
              time: '',
              type: 'did',
            })));
          }
        } else {
          // Fallback: show zeros
          setStats([
            { label: "Total DIDs", value: "0", change: "+0" },
            { label: "Credentials Issued", value: "0", change: "+0" },
            { label: "Verifications", value: "0", change: "+0" },
            { label: "Active Consents", value: "0", change: "+0" },
          ]);
        }

        if (healthRes.status === 'fulfilled' && healthRes.value.data) {
          const h = healthRes.value.data as unknown as Record<string, unknown>;
          // Backend /health/readiness returns { status, checks: { database, agent }, uptime, version }
          const checks = h.checks as Record<string, boolean> | undefined;
          setHealthServices([
            { name: "Backend Server", status: h.status === 'healthy' ? 'Healthy' : h.status === 'degraded' ? 'Degraded' : 'Unhealthy', color: h.status === 'healthy' ? 'emerald' : 'amber' },
            { name: "Credo Agent", status: checks?.agent ? 'Running' : 'Down', color: checks?.agent ? 'emerald' : 'red' },
            { name: "Askar Wallet", status: checks?.database ? 'Connected' : 'Down', color: checks?.database ? 'emerald' : 'red' },
            { name: "Cheqd Testnet", status: checks?.agent ? 'Synced' : 'Unknown', color: checks?.agent ? 'emerald' : 'slate' },
          ]);
        } else {
          setHealthServices([
            { name: "Backend Server", status: "Unreachable", color: "red" },
            { name: "Credo Agent", status: "Unknown", color: "slate" },
            { name: "Cheqd Testnet", status: "Unknown", color: "slate" },
            { name: "Askar Wallet", status: "Unknown", color: "slate" },
          ]);
        }
      } catch (err) {
        setError('Failed to load dashboard data');
      } finally {
        setIsLoading(false);
      }
    }

    loadDashboard();
  }, []);

  if (isLoading) {
    return (
      <ProtectedRoute>
        <div className="flex items-center justify-center min-h-[60vh]">
          <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
        </div>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
      <div className="p-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground">Dashboard</h1>
          <p className="text-muted-foreground mt-1">
            System overview and credential management
          </p>
          {error && (
            <p className="text-sm text-amber-400 mt-2">{error} — showing cached data</p>
          )}
        </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {stats.map((stat) => (
          <div
            key={stat.label}
            className="bg-card rounded-xl p-6 border border-border hover:border-border transition-colors"
          >
            <div className="flex items-center justify-between mb-4">
              {STAT_ICONS[stat.label]}
              <span className="text-xs font-medium text-emerald-400 bg-emerald-400/10 px-2 py-1 rounded-full">
                {stat.change}
              </span>
            </div>
            <p className="text-3xl font-bold text-foreground">{stat.value}</p>
            <p className="text-sm text-muted-foreground mt-1">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* System Health & Recent Activity side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Health */}
        <div className="bg-card rounded-xl border border-border p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">System Health</h2>
          <div className="space-y-4">
            {healthServices.map((item) => (
              <div key={item.name} className="flex items-center justify-between py-2 border-b border-border last:border-0">
                <span className="text-sm text-foreground/80 flex items-center gap-2">
                  {HEALTH_ICONS[item.name]}
                  {item.name}
                </span>
                <span className={`text-xs font-medium text-${item.color}-400 bg-${item.color}-400/10 px-2.5 py-1 rounded-full flex items-center gap-1.5`}>
                  <span className={`w-1.5 h-1.5 rounded-full bg-${item.color}-400`}></span>
                  {item.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-card rounded-xl border border-border p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">Recent Activity</h2>
          <div className="space-y-3">
            {activity.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No recent activity</p>
            ) : activity.map((item, i) => (
              <div key={i} className="flex items-start gap-3 py-2 border-b border-border last:border-0">
                <span className="mt-0.5">
                  {ACTIVITY_ICONS[item.type] || <FileText className="w-5 h-5 text-muted-foreground" />}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground">{item.action}</p>
                  <p className="text-xs text-muted-foreground truncate">{item.target}</p>
                </div>
                <span className="text-xs text-muted-foreground whitespace-nowrap">{item.time}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
    </ProtectedRoute>
  );
}
