/**
 * SSI Healthcare - Consent Management Page
 *
 * Allows users to view and manage consent grants to third parties.
 * Key feature for user control over their data sharing.
 */

'use client';

import * as React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';
import {
  Shield,
  Building2,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ChevronRight,
  Eye,
  Trash2,
  RefreshCw,
  Calendar,
  FileText,
  Settings,
  History,
  Filter,
  Search,
  MoreVertical,
  Bell,
  BellOff,
} from 'lucide-react';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumCard, CardContent, CardHeader, CardTitle } from '@/components/ui/premium-card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose } from '@/components/ui/dialog';
import { cn } from '@/lib/utils';
import { useConsents } from '@/hooks/useConsents';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import type { Consent } from '@/lib/api';

// Consent type for the page (mapped from API type)
type PageConsent = Consent & {
  organization: {
    name: string;
    logo: null;
    did: string;
    verified: boolean;
  };
  description: string;
  sharedAttributes: string[];
  notifications: boolean;
};

function mapConsent(c: Consent): PageConsent {
  return {
    ...c,
    organization: {
      name: c.verifierName || 'Unknown Organization',
      logo: null,
      did: c.verifierDid,
      verified: true,
    },
    description: c.purpose,
    sharedAttributes: c.allowedFields.length > 0 ? c.allowedFields : c.scope,
    notifications: true,
  };
}

const statusConfig = {
  active: {
    icon: CheckCircle2,
    color: 'text-emerald-400',
    bg: 'bg-emerald-400/10',
    label: 'Active',
  },
  expired: {
    icon: Clock,
    color: 'text-amber-400',
    bg: 'bg-amber-400/10',
    label: 'Expired',
  },
  revoked: {
    icon: XCircle,
    color: 'text-red-400',
    bg: 'bg-red-400/10',
    label: 'Revoked',
  },
  pending: {
    icon: AlertTriangle,
    color: 'text-blue-400',
    bg: 'bg-blue-400/10',
    label: 'Pending',
  },
};

export default function ConsentsPage() {
  const { consents: rawConsents, stats, isLoading, error, revokeConsent } = useConsents();
  const consents = React.useMemo(() => rawConsents.map(mapConsent), [rawConsents]);
  const [filter, setFilter] = React.useState<'all' | 'active' | 'expired' | 'revoked'>('all');
  const [searchQuery, setSearchQuery] = React.useState('');
  const [selectedConsent, setSelectedConsent] = React.useState<PageConsent | null>(null);
  const [isRevokeDialogOpen, setIsRevokeDialogOpen] = React.useState(false);
  const [isDetailDialogOpen, setIsDetailDialogOpen] = React.useState(false);

  const filteredConsents = consents.filter((consent) => {
    const matchesFilter = filter === 'all' || consent.status === filter;
    const matchesSearch =
      consent.organization.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      consent.purpose.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const activeCount = stats?.active ?? consents.filter((c) => c.status === 'active').length;
  const expiredCount = stats?.expired ?? consents.filter((c) => c.status === 'expired').length;

  const handleRevoke = (consent: PageConsent) => {
    setSelectedConsent(consent);
    setIsRevokeDialogOpen(true);
  };

  const handleViewDetails = (consent: PageConsent) => {
    setSelectedConsent(consent);
    setIsDetailDialogOpen(true);
  };

  if (isLoading && consents.length === 0) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin mx-auto mb-4" />
          <p className="text-muted-foreground">Loading consents…</p>
        </div>
      </div>
    );
  }

  if (error && consents.length === 0) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center max-w-md">
          <AlertTriangle className="w-12 h-12 text-amber-400 mx-auto mb-4" />
          <p className="text-foreground font-medium mb-2">Unable to load consents</p>
          <p className="text-sm text-muted-foreground">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <ProtectedRoute>
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-background/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-4">
              <Link
                href="/wallet"
                className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
              >
                <Shield className="w-5 h-5" />
                <span className="font-semibold text-foreground">Wallet</span>
              </Link>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
              <span className="font-semibold text-foreground">Consents</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-2">
            Consent Management
          </h1>
          <p className="text-muted-foreground">
            Control who has access to your credentials and manage permissions.
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <StatsCard
            label="Active Consents"
            value={activeCount}
            icon={CheckCircle2}
            color="text-emerald-400"
          />
          <StatsCard
            label="Total Access"
            value={stats?.total ?? consents.reduce((sum, c) => sum + c.accessCount, 0)}
            icon={Eye}
            color="text-blue-400"
          />
          <StatsCard
            label="Organizations"
            value={consents.length}
            icon={Building2}
            color="text-purple-400"
          />
          <StatsCard
            label="Expired"
            value={expiredCount}
            icon={Clock}
            color="text-amber-400"
          />
        </div>

        {/* Filters and Search */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
          <Tabs value={filter} onValueChange={(v) => setFilter(v as typeof filter)}>
            <TabsList>
              <TabsTrigger value="all">All</TabsTrigger>
              <TabsTrigger value="active">Active</TabsTrigger>
              <TabsTrigger value="expired">Expired</TabsTrigger>
              <TabsTrigger value="revoked">Revoked</TabsTrigger>
            </TabsList>
          </Tabs>

          <div className="relative w-full sm:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search organizations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 pr-4 py-2 w-full bg-muted border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
          </div>
        </div>

        {/* Consent List */}
        <div className="space-y-4">
          <AnimatePresence>
            {filteredConsents.map((consent) => (
              <ConsentCard
                key={consent.id}
                consent={consent}
                onViewDetails={() => handleViewDetails(consent)}
                onRevoke={() => handleRevoke(consent)}
              />
            ))}
          </AnimatePresence>

          {filteredConsents.length === 0 && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-center py-12"
            >
              <Shield className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">
                {searchQuery ? 'No consents match your search' : 'No consents found'}
              </p>
            </motion.div>
          )}
        </div>
      </main>

      {/* Detail Dialog */}
      <Dialog open={isDetailDialogOpen} onOpenChange={setIsDetailDialogOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Consent Details</DialogTitle>
          </DialogHeader>
          
          {selectedConsent && (
            <div className="space-y-6">
              {/* Organization */}
              <div className="flex items-center gap-3 p-4 rounded-lg bg-muted/50">
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                  <Building2 className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-foreground">
                      {selectedConsent.organization.name}
                    </span>
                    {selectedConsent.organization.verified && (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {selectedConsent.organization.did}
                  </p>
                </div>
              </div>

              {/* Purpose */}
              <div>
                <h4 className="text-sm font-medium text-muted-foreground mb-1">Purpose</h4>
                <p className="text-foreground">{selectedConsent.purpose}</p>
                <p className="text-sm text-muted-foreground mt-1">
                  {selectedConsent.description}
                </p>
              </div>

              {/* Shared Attributes */}
              <div>
                <h4 className="text-sm font-medium text-muted-foreground mb-2">
                  Shared Attributes
                </h4>
                <div className="flex flex-wrap gap-2">
                  {selectedConsent.sharedAttributes.map((attr) => (
                    <Badge key={attr} variant="secondary">
                      {attr}
                    </Badge>
                  ))}
                </div>
              </div>

              {/* Timeline */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="text-sm font-medium text-muted-foreground mb-1">
                    Granted
                  </h4>
                  <p className="text-sm text-foreground">
                    {new Date(selectedConsent.grantedAt).toLocaleDateString()}
                  </p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-muted-foreground mb-1">
                    Expires
                  </h4>
                  <p className="text-sm text-foreground">
                    {selectedConsent.expiresAt
                      ? new Date(selectedConsent.expiresAt).toLocaleDateString()
                      : 'Never'}
                  </p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-muted-foreground mb-1">
                    Last Accessed
                  </h4>
                  <p className="text-sm text-foreground">
                    {selectedConsent.lastAccessedAt ? new Date(selectedConsent.lastAccessedAt).toLocaleDateString() : 'Never'}
                  </p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-muted-foreground mb-1">
                    Access Count
                  </h4>
                  <p className="text-sm text-foreground">
                    {selectedConsent.accessCount} times
                  </p>
                </div>
              </div>
            </div>
          )}

          <DialogFooter className="flex gap-2">
            {selectedConsent?.status === 'active' && (
              <PremiumButton
                variant="destructive"
                onClick={() => {
                  setIsDetailDialogOpen(false);
                  setTimeout(() => setIsRevokeDialogOpen(true), 200);
                }}
              >
                <XCircle className="w-4 h-4 mr-2" />
                Revoke Access
              </PremiumButton>
            )}
            <DialogClose>
              <PremiumButton variant="outline">Close</PremiumButton>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Revoke Dialog */}
      <Dialog open={isRevokeDialogOpen} onOpenChange={setIsRevokeDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke Consent?</DialogTitle>
            <DialogDescription>
              This will immediately revoke {selectedConsent?.organization.name}&apos;s
              access to your data. They will no longer be able to access the
              shared attributes.
            </DialogDescription>
          </DialogHeader>
          
          {selectedConsent && (
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20">
              <p className="text-sm text-red-400">
                <strong>Warning:</strong> This action cannot be undone. If you need
                to grant access again, you will need to create a new consent.
              </p>
            </div>
          )}

          <DialogFooter>
            <DialogClose>
              <PremiumButton variant="outline">Cancel</PremiumButton>
            </DialogClose>
            <PremiumButton
              variant="destructive"
              onClick={async () => {
                if (selectedConsent) {
                  try {
                    await revokeConsent(selectedConsent.id, 'User revoked via settings');
                  } catch {
                    // Error handled by hook
                  }
                }
                setIsRevokeDialogOpen(false);
              }}
            >
              <XCircle className="w-4 h-4 mr-2" />
              Revoke Access
            </PremiumButton>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
    </ProtectedRoute>
  );
}

function StatsCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
}) {
  return (
    <PremiumCard variant="elevated" className="p-4">
      <div className="flex items-center gap-3">
        <div className={cn('w-10 h-10 rounded-xl flex items-center justify-center', `${color}/10`)}>
          <Icon className={cn('w-5 h-5', color)} />
        </div>
        <div>
          <p className="text-2xl font-bold text-foreground">{value}</p>
          <p className="text-xs text-muted-foreground">{label}</p>
        </div>
      </div>
    </PremiumCard>
  );
}

function ConsentCard({
  consent,
  onViewDetails,
  onRevoke,
}: {
  consent: PageConsent;
  onViewDetails: () => void;
  onRevoke: () => void;
}) {
  const StatusIcon = statusConfig[consent.status].icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      layout
    >
      <PremiumCard variant="interactive" onClick={onViewDetails}>
        <CardContent className="p-4 sm:p-6">
          <div className="flex items-start gap-4">
            {/* Organization Icon */}
            <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center flex-shrink-0">
              <Building2 className="w-6 h-6 text-primary" />
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="font-semibold text-foreground">
                      {consent.organization.name}
                    </h3>
                    {consent.organization.verified && (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {consent.purpose}
                  </p>
                </div>

                {/* Status */}
                <div className="flex items-center gap-2">
                  <div
                    className={cn(
                      'flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium',
                      statusConfig[consent.status].bg,
                      statusConfig[consent.status].color
                    )}
                  >
                    <StatusIcon className="w-3.5 h-3.5" />
                    {statusConfig[consent.status].label}
                  </div>

                  <DropdownMenu>
                    <DropdownMenuTrigger
                      className="p-1.5 rounded hover:bg-muted transition-colors"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <MoreVertical className="w-4 h-4 text-muted-foreground" />
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={onViewDetails}>
                        <Eye className="w-4 h-4 mr-2" />
                        View Details
                      </DropdownMenuItem>
                      <DropdownMenuItem>
                        <History className="w-4 h-4 mr-2" />
                        Access History
                      </DropdownMenuItem>
                      <DropdownMenuItem>
                        {consent.notifications ? (
                          <>
                            <BellOff className="w-4 h-4 mr-2" />
                            Disable Notifications
                          </>
                        ) : (
                          <>
                            <Bell className="w-4 h-4 mr-2" />
                            Enable Notifications
                          </>
                        )}
                      </DropdownMenuItem>
                      {consent.status === 'active' && (
                        <>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            className="text-red-400"
                            onClick={(e) => {
                              e.stopPropagation();
                              onRevoke();
                            }}
                          >
                            <XCircle className="w-4 h-4 mr-2" />
                            Revoke Access
                          </DropdownMenuItem>
                        </>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>

              {/* Shared Attributes */}
              <div className="flex flex-wrap gap-1.5 mt-3">
                {consent.sharedAttributes.slice(0, 3).map((attr) => (
                  <Badge key={attr} variant="secondary" className="text-xs">
                    {attr}
                  </Badge>
                ))}
                {consent.sharedAttributes.length > 3 && (
                  <Badge variant="secondary" className="text-xs">
                    +{consent.sharedAttributes.length - 3} more
                  </Badge>
                )}
              </div>

              {/* Meta info */}
              <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Calendar className="w-3.5 h-3.5" />
                  Granted {new Date(consent.grantedAt).toLocaleDateString()}
                </span>
                <span className="flex items-center gap-1">
                  <Eye className="w-3.5 h-3.5" />
                  {consent.accessCount} accesses
                </span>
                {consent.expiresAt && (
                  <span className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    Expires {new Date(consent.expiresAt).toLocaleDateString()}
                  </span>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </PremiumCard>
    </motion.div>
  );
}
