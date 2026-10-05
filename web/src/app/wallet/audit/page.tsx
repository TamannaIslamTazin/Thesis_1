/**
 * SSI Healthcare Web - Audit Trail Page (H6)
 *
 * Comprehensive audit history with:
 * - Timeline visualization
 * - Charts/statistics
 * - Filtering and search
 * - Export functionality
 *
 * Protected: Requires authentication
 */

'use client';

import * as React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Share2,
  CheckCircle2,
  XCircle,
  LogIn,
  FileText,
  Clock,
  Filter,
  Download,
  Search,
  ChevronRight,
  Calendar,
  TrendingUp,
  Activity,
  AlertCircle,
} from 'lucide-react';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useAuth } from '@/hooks/useAuth';
import { userApi } from '@/lib/api';
import { PremiumCard, CardContent, CardHeader, CardTitle } from '@/components/ui/premium-card';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumInput } from '@/components/ui/premium-input';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

// -- Types --

type ActivityType =
  | 'credential_issued'
  | 'credential_shared'
  | 'consent_granted'
  | 'consent_revoked'
  | 'verification_request'
  | 'login';

interface AuditEvent {
  id: string;
  type: ActivityType;
  title: string;
  description: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

interface ActivityTypeConfig {
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  bgColor: string;
  label: string;
  plainLanguage: string;
}

// -- Constants --

const ACTIVITY_CONFIG: Record<ActivityType, ActivityTypeConfig> = {
  credential_issued: {
    icon: FileText,
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-400/10',
    label: 'Credential Issued',
    plainLanguage: 'A new credential was added to your wallet',
  },
  credential_shared: {
    icon: Share2,
    color: 'text-blue-400',
    bgColor: 'bg-blue-400/10',
    label: 'Credential Shared',
    plainLanguage: 'You shared your credential with an organization',
  },
  consent_granted: {
    icon: CheckCircle2,
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-400/10',
    label: 'Consent Granted',
    plainLanguage: 'You allowed an app to access your data',
  },
  consent_revoked: {
    icon: XCircle,
    color: 'text-red-400',
    bgColor: 'bg-red-400/10',
    label: 'Consent Revoked',
    plainLanguage: 'You stopped sharing your data with an app',
  },
  verification_request: {
    icon: Shield,
    color: 'text-purple-400',
    bgColor: 'bg-purple-400/10',
    label: 'Verification',
    plainLanguage: 'Someone verified your credential',
  },
  login: {
    icon: LogIn,
    color: 'text-muted-foreground',
    bgColor: 'bg-muted/50',
    label: 'Login',
    plainLanguage: 'You signed in to an app',
  },
};

const FILTER_OPTIONS = [
  { value: 'all', label: 'All Activities' },
  { value: 'credential_issued', label: 'Credentials Issued' },
  { value: 'credential_shared', label: 'Credentials Shared' },
  { value: 'consent_granted', label: 'Consents Granted' },
  { value: 'consent_revoked', label: 'Consents Revoked' },
  { value: 'verification_request', label: 'Verifications' },
  { value: 'login', label: 'Logins' },
];

const TIME_RANGES = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: 'all', label: 'All time' },
];

// -- Helpers --

function formatDateTime(dateString: string): string {
  return new Date(dateString).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  });
}

function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function generateExportCSV(events: AuditEvent[]): string {
  const headers = ['Timestamp', 'Type', 'Title', 'Description'];
  const rows = events.map((e) => [
    formatDateTime(e.timestamp),
    ACTIVITY_CONFIG[e.type].label,
    e.title,
    e.description,
  ]);
  return [headers, ...rows].map((row) => row.map((cell) => `"${cell}"`).join(',')).join('\n');
}

// -- Statistics Card Component --

function StatCard({
  title,
  value,
  icon: Icon,
  trend,
}: {
  title: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  trend?: { value: number; positive: boolean };
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-card/50 rounded-xl border border-border p-4"
    >
      <div className="flex items-center justify-between mb-3">
        <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
          <Icon className="w-5 h-5 text-blue-400" />
        </div>
        {trend && (
          <div
            className={`flex items-center gap-1 text-xs ${
              trend.positive ? 'text-emerald-400' : 'text-red-400'
            }`}
          >
            <TrendingUp className={`w-3 h-3 ${!trend.positive && 'rotate-180'}`} />
            {trend.value}%
          </div>
        )}
      </div>
      <p className="text-2xl font-bold text-foreground">{value}</p>
      <p className="text-sm text-muted-foreground mt-1">{title}</p>
    </motion.div>
  );
}

// -- Audit Event Item Component --

function AuditEventItem({
  event,
  onClick,
}: {
  event: AuditEvent;
  onClick: () => void;
}) {
  const config = ACTIVITY_CONFIG[event.type];
  const Icon = config.icon;

  return (
    <motion.button
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      whileHover={{ x: 4 }}
      onClick={onClick}
      className="w-full flex items-center gap-4 p-4 rounded-xl bg-card/30 border border-border hover:border-border transition-colors text-left"
    >
      <div className={`w-10 h-10 rounded-lg ${config.bgColor} flex items-center justify-center flex-shrink-0`}>
        <Icon className={`w-5 h-5 ${config.color}`} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-foreground truncate">{event.title}</p>
        <p className="text-xs text-muted-foreground truncate">{event.description}</p>
      </div>
      <div className="flex items-center gap-3">
        <span className="text-xs text-muted-foreground">{formatRelativeTime(event.timestamp)}</span>
        <ChevronRight className="w-4 h-4 text-muted-foreground" />
      </div>
    </motion.button>
  );
}

// -- Event Detail Modal --

function EventDetailModal({
  event,
  onClose,
}: {
  event: AuditEvent | null;
  onClose: () => void;
}) {
  if (!event) return null;

  const config = ACTIVITY_CONFIG[event.type];
  const Icon = config.icon;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg bg-card rounded-2xl border border-border overflow-hidden"
      >
        {/* Header */}
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-xl ${config.bgColor} flex items-center justify-center`}>
              <Icon className={`w-6 h-6 ${config.color}`} />
            </div>
            <div>
              <Badge variant="outline" className={config.color}>
                {config.label}
              </Badge>
              <h2 className="text-lg font-semibold text-foreground mt-1">{event.title}</h2>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          {/* Plain Language */}
          <div className="p-4 rounded-xl bg-muted/50">
            <p className="text-sm text-muted-foreground mb-1">What happened</p>
            <p className="text-foreground">{config.plainLanguage}</p>
          </div>

          {/* Details */}
          <div>
            <p className="text-sm text-muted-foreground mb-1">Description</p>
            <p className="text-foreground">{event.description}</p>
          </div>

          <div>
            <p className="text-sm text-muted-foreground mb-1">When</p>
            <p className="text-foreground">{formatDateTime(event.timestamp)}</p>
          </div>

          {/* Metadata */}
          {event.metadata && Object.keys(event.metadata).length > 0 && (
            <div>
              <p className="text-sm text-muted-foreground mb-2">Additional Details</p>
              <div className="space-y-2">
                {Object.entries(event.metadata).map(([key, value]) => (
                  <div key={key} className="flex justify-between py-2 border-b border-border">
                    <span className="text-sm text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</span>
                    <span className="text-sm text-foreground">
                      {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-border">
          <PremiumButton variant="outline" onClick={onClose} className="w-full">
            Close
          </PremiumButton>
        </div>
      </motion.div>
    </motion.div>
  );
}

// -- Main Page Component --

export default function AuditTrailPage() {
  const { user } = useAuth();
  const [events, setEvents] = React.useState<AuditEvent[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [searchQuery, setSearchQuery] = React.useState('');
  const [filterType, setFilterType] = React.useState('all');
  const [timeRange, setTimeRange] = React.useState('30d');
  const [selectedEvent, setSelectedEvent] = React.useState<AuditEvent | null>(null);

  // Fetch audit events
  React.useEffect(() => {
    async function fetchEvents() {
      if (!user?.did) return;
      
      setIsLoading(true);
      setError(null);

      try {
        // FINDING-015: Use user-scoped audit endpoint, not admin-level
        const response = await userApi.getAuditLogs();
        const data = response.data;
        if (data && 'events' in data) {
          setEvents(data.events as unknown as AuditEvent[]);
        } else {
          setEvents((data || []) as unknown as AuditEvent[]);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load audit trail');
        setEvents([]);
      } finally {
        setIsLoading(false);
      }
    }

    fetchEvents();
  }, [user?.did]);

  // Filter events
  const filteredEvents = React.useMemo(() => {
    let result = [...events];

    // Filter by type
    if (filterType !== 'all') {
      result = result.filter((e) => e.type === filterType);
    }

    // Filter by time range
    if (timeRange !== 'all') {
      const days = parseInt(timeRange);
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - days);
      result = result.filter((e) => new Date(e.timestamp) >= cutoff);
    }

    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(
        (e) =>
          e.title.toLowerCase().includes(query) ||
          e.description.toLowerCase().includes(query)
      );
    }

    // Sort by timestamp (newest first)
    result.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    return result;
  }, [events, filterType, timeRange, searchQuery]);

  // Calculate statistics
  const stats = React.useMemo(() => {
    const now = new Date();
    const last30Days = events.filter(
      (e) => new Date(e.timestamp) >= new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
    );

    return {
      total: events.length,
      last30Days: last30Days.length,
      credentials: events.filter((e) => e.type.startsWith('credential_')).length,
      consents: events.filter((e) => e.type.startsWith('consent_')).length,
      verifications: events.filter((e) => e.type === 'verification_request').length,
    };
  }, [events]);

  // Export handler
  const handleExport = () => {
    const csv = generateExportCSV(filteredEvents);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ssi-audit-trail-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Group events by date
  const groupedEvents = React.useMemo(() => {
    const groups: Record<string, AuditEvent[]> = {};

    filteredEvents.forEach((event) => {
      const date = new Date(event.timestamp).toLocaleDateString('en-US', {
        month: 'long',
        day: 'numeric',
        year: 'numeric',
      });
      if (!groups[date]) groups[date] = [];
      groups[date].push(event);
    });

    return Object.entries(groups);
  }, [filteredEvents]);

  return (
    <ProtectedRoute requireWallet>
      <div className="min-h-screen p-6 lg:p-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground">Audit Trail</h1>
          <p className="text-muted-foreground mt-1">
            Complete history of your credential activities
          </p>
        </div>

        {/* Statistics */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard title="Total Activities" value={stats.total} icon={Activity} />
          <StatCard
            title="Last 30 Days"
            value={stats.last30Days}
            icon={Calendar}
            trend={{ value: 12, positive: true }}
          />
          <StatCard title="Credential Events" value={stats.credentials} icon={FileText} />
          <StatCard title="Verifications" value={stats.verifications} icon={Shield} />
        </div>

        {/* Filters */}
        <div className="flex flex-col lg:flex-row gap-4 mb-6">
          <div className="flex-1">
            <PremiumInput
              type="text"
              placeholder="Search activities..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full"
              leftIcon={<Search className="w-4 h-4" />}
            />
          </div>
          <div className="flex gap-4">
            <Select value={filterType} onValueChange={setFilterType}>
              <SelectTrigger className="w-[180px] bg-card border-border">
                <Filter className="w-4 h-4 mr-2" />
                <SelectValue placeholder="Filter by type" />
              </SelectTrigger>
              <SelectContent>
                {FILTER_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="w-[140px] bg-card border-border">
                <Clock className="w-4 h-4 mr-2" />
                <SelectValue placeholder="Time range" />
              </SelectTrigger>
              <SelectContent>
                {TIME_RANGES.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <PremiumButton variant="outline" onClick={handleExport}>
              <Download className="w-4 h-4 mr-2" />
              Export
            </PremiumButton>
          </div>
        </div>

        {/* Content */}
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full" />
          </div>
        ) : error ? (
          <PremiumCard>
            <CardContent className="py-12 text-center">
              <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
              <p className="text-red-400 mb-4">{error}</p>
              <PremiumButton variant="outline" onClick={() => window.location.reload()}>
                Retry
              </PremiumButton>
            </CardContent>
          </PremiumCard>
        ) : filteredEvents.length === 0 ? (
          <PremiumCard>
            <CardContent className="py-12 text-center">
              <Clock className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">No Activities Found</h3>
              <p className="text-muted-foreground">
                {searchQuery || filterType !== 'all'
                  ? 'Try adjusting your filters'
                  : 'Your audit trail will appear here once you start using credentials'}
              </p>
            </CardContent>
          </PremiumCard>
        ) : (
          <div className="space-y-6">
            {groupedEvents.map(([date, dateEvents]) => (
              <div key={date}>
                <h3 className="text-sm font-medium text-muted-foreground mb-3 px-1">{date}</h3>
                <div className="space-y-2">
                  {dateEvents.map((event) => (
                    <AuditEventItem
                      key={event.id}
                      event={event}
                      onClick={() => setSelectedEvent(event)}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Event Detail Modal */}
        <AnimatePresence>
          {selectedEvent && (
            <EventDetailModal
              event={selectedEvent}
              onClose={() => setSelectedEvent(null)}
            />
          )}
        </AnimatePresence>
      </div>
    </ProtectedRoute>
  );
}
