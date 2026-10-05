/**
 * SSI Healthcare Web - Insurance Claims Page (H4)
 *
 * Submit and track insurance claims using verifiable credentials:
 * - Submit claims with attached credentials
 * - Track claim status
 * - View claim history
 * - Plain language explanations
 *
 * Protected: Requires authentication with wallet
 */

'use client';

import * as React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  FileText,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Plus,
  Search,
  ChevronRight,
  DollarSign,
  Calendar,
  Building2,
  Loader2,
  Upload,
  Eye,
} from 'lucide-react';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useAuth } from '@/hooks/useAuth';
import { claimsApi } from '@/lib/api';
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

type ClaimStatus = 'pending' | 'under_review' | 'approved' | 'denied' | 'paid';

interface InsuranceClaim {
  id: string;
  claimNumber?: string;
  type?: string;
  procedureCode?: string;
  amount: number;
  status: string;
  submittedAt: string;
  updatedAt: string;
  description?: string;
  providerName?: string;
  providerDid?: string;
  serviceDate?: string;
  credentialIds?: string[];
  statusHistory?: {
    status: string;
    timestamp: string;
    note?: string;
  }[];
}

// -- Constants --

const STATUS_CONFIG: Record<ClaimStatus, {
  color: string;
  bgColor: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  description: string;
}> = {
  pending: {
    color: 'text-muted-foreground',
    bgColor: 'bg-muted/50',
    icon: Clock,
    label: 'Pending',
    description: 'Your claim has been submitted and is waiting to be processed',
  },
  under_review: {
    color: 'text-amber-400',
    bgColor: 'bg-amber-400/10',
    icon: Eye,
    label: 'Under Review',
    description: 'An insurance representative is reviewing your claim',
  },
  approved: {
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-400/10',
    icon: CheckCircle2,
    label: 'Approved',
    description: 'Your claim has been approved for payment',
  },
  denied: {
    color: 'text-red-400',
    bgColor: 'bg-red-400/10',
    icon: XCircle,
    label: 'Denied',
    description: 'Your claim was not approved. You may appeal this decision.',
  },
  paid: {
    color: 'text-blue-400',
    bgColor: 'bg-blue-400/10',
    icon: DollarSign,
    label: 'Paid',
    description: 'Payment has been processed for this claim',
  },
};

const CLAIM_TYPES = [
  { value: 'medical', label: 'Medical Services' },
  { value: 'prescription', label: 'Prescription' },
  { value: 'dental', label: 'Dental' },
  { value: 'vision', label: 'Vision' },
  { value: 'mental_health', label: 'Mental Health' },
  { value: 'emergency', label: 'Emergency Services' },
];

// -- Helpers --

function formatCurrency(amount: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
  }).format(amount);
}

function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

// -- Claim Card Component --

function ClaimCard({
  claim,
  onClick,
}: {
  claim: InsuranceClaim;
  onClick: () => void;
}) {
  const normStatus = claim.status.toLowerCase().replace('submitted', 'pending') as keyof typeof STATUS_CONFIG;
  const status = STATUS_CONFIG[normStatus] ?? STATUS_CONFIG['pending'];
  const StatusIcon = status.icon;

  return (
    <motion.button
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -2 }}
      onClick={onClick}
      className="w-full p-4 rounded-xl bg-card/50 border border-border hover:border-border transition-all text-left"
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg ${status.bgColor} flex items-center justify-center`}>
            <StatusIcon className={`w-5 h-5 ${status.color}`} />
          </div>
          <div>
            <p className="text-sm font-medium text-foreground">{claim.claimNumber ?? claim.id.slice(0, 8)}</p>
            <p className="text-xs text-muted-foreground">{claim.type ?? claim.procedureCode}</p>
          </div>
        </div>
        <Badge variant="outline" className={status.color}>
          {status.label}
        </Badge>
      </div>
      
      <p className="text-sm text-foreground/80 mb-3 line-clamp-2">{claim.description}</p>
      
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{formatDate(claim.submittedAt)}</span>
        <span className="font-medium text-foreground">{formatCurrency(claim.amount)}</span>
      </div>
    </motion.button>
  );
}

// -- New Claim Modal --

function NewClaimModal({
  isOpen,
  onClose,
  onSubmit,
}: {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: {
    type: string;
    amount: number;
    description: string;
    providerName: string;
    serviceDate: string;
  }) => Promise<void>;
}) {
  const [type, setType] = React.useState('');
  const [amount, setAmount] = React.useState('');
  const [description, setDescription] = React.useState('');
  const [providerName, setProviderName] = React.useState('');
  const [serviceDate, setServiceDate] = React.useState('');
  const [isSubmitting, setIsSubmitting] = React.useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!type || !amount || !description || !providerName || !serviceDate) return;

    setIsSubmitting(true);
    try {
      await onSubmit({
        type,
        amount: parseFloat(amount),
        description,
        providerName,
        serviceDate,
      });
      onClose();
      // Reset form
      setType('');
      setAmount('');
      setDescription('');
      setProviderName('');
      setServiceDate('');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!isOpen) return null;

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
        <form onSubmit={handleSubmit}>
          <div className="p-6 border-b border-border">
            <h2 className="text-xl font-semibold text-foreground">Submit New Claim</h2>
            <p className="text-muted-foreground text-sm mt-1">
              Your verifiable credentials will be attached automatically
            </p>
          </div>

          <div className="p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-foreground/80 mb-2">
                Claim Type
              </label>
              <Select value={type} onValueChange={setType}>
                <SelectTrigger className="w-full bg-muted border-border">
                  <SelectValue placeholder="Select claim type" />
                </SelectTrigger>
                <SelectContent>
                  {CLAIM_TYPES.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground/80 mb-2">
                Amount
              </label>
              <PremiumInput
                type="number"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="0.00"
                leftIcon={<DollarSign className="w-4 h-4" />}
                min="0"
                step="0.01"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground/80 mb-2">
                Healthcare Provider
              </label>
              <PremiumInput
                type="text"
                value={providerName}
                onChange={(e) => setProviderName(e.target.value)}
                placeholder="e.g., City Hospital"
                leftIcon={<Building2 className="w-4 h-4" />}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground/80 mb-2">
                Service Date
              </label>
              <PremiumInput
                type="date"
                value={serviceDate}
                onChange={(e) => setServiceDate(e.target.value)}
                leftIcon={<Calendar className="w-4 h-4" />}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground/80 mb-2">
                Description
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Describe the services received..."
                rows={3}
                className="w-full px-4 py-3 bg-muted border border-border rounded-xl text-foreground placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors resize-none"
              />
            </div>

            <div className="p-3 rounded-xl bg-blue-500/10 border border-blue-500/30">
              <p className="text-sm text-blue-400 flex items-start gap-2">
                <Shield className="w-4 h-4 mt-0.5 flex-shrink-0" />
                Your insurance credential and relevant health records will be attached to verify your coverage.
              </p>
            </div>
          </div>

          <div className="p-6 border-t border-border flex gap-3">
            <PremiumButton
              type="button"
              variant="outline"
              onClick={onClose}
              className="flex-1"
            >
              Cancel
            </PremiumButton>
            <PremiumButton
              type="submit"
              disabled={!type || !amount || !description || !providerName || !serviceDate || isSubmitting}
              className="flex-1"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Submitting...
                </>
              ) : (
                <>
                  <Upload className="w-4 h-4 mr-2" />
                  Submit Claim
                </>
              )}
            </PremiumButton>
          </div>
        </form>
      </motion.div>
    </motion.div>
  );
}

// -- Claim Detail Modal --

function ClaimDetailModal({
  claim,
  onClose,
}: {
  claim: InsuranceClaim | null;
  onClose: () => void;
}) {
  if (!claim) return null;

  const normStatus = claim.status.toLowerCase().replace('submitted', 'pending') as keyof typeof STATUS_CONFIG;
  const status = STATUS_CONFIG[normStatus] ?? STATUS_CONFIG['pending'];
  const StatusIcon = status.icon;

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
        className="w-full max-w-lg bg-card rounded-2xl border border-border overflow-hidden max-h-[80vh] overflow-y-auto"
      >
        {/* Header */}
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-xl ${status.bgColor} flex items-center justify-center`}>
              <StatusIcon className={`w-6 h-6 ${status.color}`} />
            </div>
            <div>
              <Badge variant="outline" className={status.color}>
                {status.label}
              </Badge>
              <h2 className="text-lg font-semibold text-foreground mt-1">
                Claim {(claim as unknown as Record<string, string>).claimNumber ?? claim.id.slice(0, 8)}
              </h2>
            </div>
          </div>
        </div>

        {/* Status Explanation */}
        <div className="px-6 py-4 border-b border-border">
          <div className={`p-4 rounded-xl ${status.bgColor} border border-border`}>
            <p className={`text-sm ${status.color}`}>{status.description}</p>
          </div>
        </div>

        {/* Details */}
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm text-muted-foreground">Amount</p>
              <p className="text-xl font-semibold text-foreground">{formatCurrency(claim.amount)}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Type</p>
              <p className="text-foreground font-medium">{claim.type}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Provider</p>
              <p className="text-foreground font-medium">{claim.providerName ?? claim.providerDid?.slice(0, 20) ?? '—'}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Service Date</p>
              <p className="text-foreground font-medium">{claim.serviceDate ? formatDate(claim.serviceDate) : '—'}</p>
            </div>
          </div>

          <div>
            <p className="text-sm text-muted-foreground mb-1">Description</p>
            <p className="text-foreground">{claim.description}</p>
          </div>

          {/* Status Timeline */}
          <div>
            <p className="text-sm text-muted-foreground mb-3">Status History</p>
            <div className="space-y-3">
              {(claim.statusHistory ?? []).map((history, index) => {
                const normHistStatus = history.status.toLowerCase().replace('submitted', 'pending') as keyof typeof STATUS_CONFIG;
                const historyStatus = STATUS_CONFIG[normHistStatus] ?? STATUS_CONFIG['pending'];
                const HistoryIcon = historyStatus.icon;
                return (
                  <div key={index} className="flex items-start gap-3">
                    <div className={`w-8 h-8 rounded-lg ${historyStatus.bgColor} flex items-center justify-center flex-shrink-0`}>
                      <HistoryIcon className={`w-4 h-4 ${historyStatus.color}`} />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-foreground">{historyStatus.label}</p>
                      <p className="text-xs text-muted-foreground">{formatDate(history.timestamp)}</p>
                      {history.note && (
                        <p className="text-sm text-muted-foreground mt-1">{history.note}</p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
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

export default function InsurancePage() {
  const { user } = useAuth();
  const [claims, setClaims] = React.useState<InsuranceClaim[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [searchQuery, setSearchQuery] = React.useState('');
  const [statusFilter, setStatusFilter] = React.useState<string>('all');
  const [showNewClaim, setShowNewClaim] = React.useState(false);
  const [selectedClaim, setSelectedClaim] = React.useState<InsuranceClaim | null>(null);

  // Load claims
  React.useEffect(() => {
    async function loadClaims() {
      try {
        const response = await claimsApi.getClaims(
          statusFilter !== 'all' ? { status: statusFilter } : undefined
        );
        setClaims((response.data?.claims ?? []) as unknown as InsuranceClaim[]);
      } catch (err) {
        setError('Failed to load claims');
      } finally {
        setIsLoading(false);
      }
    }

    loadClaims();
  }, [statusFilter]);

  // Submit new claim
  const handleSubmitClaim = async (data: {
    type: string;
    amount: number;
    description: string;
    providerName: string;
    serviceDate: string;
  }) => {
    const result = await claimsApi.submitClaim({
      patientDid: user?.did || '',
      providerDid: '', // Will be resolved by backend
      insurerDid: '', // Will be resolved by backend
      procedureCode: data.type,
      diagnosisCode: data.type,
      amount: data.amount,
      description: data.description,
    });
    if (result.data) {
      setClaims((prev) => [result.data! as unknown as InsuranceClaim, ...prev]);
    } else {
      throw new Error('Failed to submit claim');
    }
  };

  // Filter claims
  const filteredClaims = React.useMemo(() => {
    let result = [...claims];

    if (statusFilter !== 'all') {
      const normFilter = statusFilter.toLowerCase();
      result = result.filter((c) => c.status.toLowerCase().replace('submitted', 'pending') === normFilter);
    }

    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      const r = result as unknown as Array<Record<string, string> & typeof result[number]>;
      result = r.filter(
        (c) =>
          (c.claimNumber ?? c.id ?? '').toLowerCase().includes(query) ||
          (c.description ?? '').toLowerCase().includes(query) ||
          (c.providerName ?? c.providerDid ?? '').toLowerCase().includes(query)
      ) as unknown as typeof result;
    }

    return result;
  }, [claims, statusFilter, searchQuery]);

  // Stats
  const stats = React.useMemo(() => {
    const total = claims.length;
    const normS = (c: InsuranceClaim) => c.status.toLowerCase().replace('submitted', 'pending');
    const pending = claims.filter((c) => normS(c) === 'pending' || normS(c) === 'under_review').length;
    const approved = claims.filter((c) => normS(c) === 'approved' || normS(c) === 'paid').length;
    const totalAmount = claims.reduce((sum, c) => sum + c.amount, 0);
    return { total, pending, approved, totalAmount };
  }, [claims]);

  return (
    <ProtectedRoute requireWallet>
      <div className="min-h-screen p-6 lg:p-8">
        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Insurance Claims</h1>
            <p className="text-muted-foreground mt-1">
              Submit and track your insurance claims with verified credentials
            </p>
          </div>
          <PremiumButton onClick={() => setShowNewClaim(true)}>
            <Plus className="w-4 h-4 mr-2" />
            New Claim
          </PremiumButton>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <div className="p-4 rounded-xl bg-card/50 border border-border">
            <p className="text-2xl font-bold text-foreground">{stats.total}</p>
            <p className="text-sm text-muted-foreground">Total Claims</p>
          </div>
          <div className="p-4 rounded-xl bg-card/50 border border-border">
            <p className="text-2xl font-bold text-amber-400">{stats.pending}</p>
            <p className="text-sm text-muted-foreground">Pending</p>
          </div>
          <div className="p-4 rounded-xl bg-card/50 border border-border">
            <p className="text-2xl font-bold text-emerald-400">{stats.approved}</p>
            <p className="text-sm text-muted-foreground">Approved</p>
          </div>
          <div className="p-4 rounded-xl bg-card/50 border border-border">
            <p className="text-2xl font-bold text-foreground">{formatCurrency(stats.totalAmount)}</p>
            <p className="text-sm text-muted-foreground">Total Claimed</p>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-col md:flex-row gap-4 mb-6">
          <div className="flex-1">
            <PremiumInput
              type="text"
              placeholder="Search claims..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              leftIcon={<Search className="w-4 h-4" />}
            />
          </div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[180px] bg-card border-border">
              <SelectValue placeholder="Filter by status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="under_review">Under Review</SelectItem>
              <SelectItem value="approved">Approved</SelectItem>
              <SelectItem value="denied">Denied</SelectItem>
              <SelectItem value="paid">Paid</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Claims List */}
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 text-muted-foreground animate-spin" />
          </div>
        ) : error ? (
          <PremiumCard>
            <CardContent className="py-12 text-center">
              <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
              <p className="text-red-400">{error}</p>
            </CardContent>
          </PremiumCard>
        ) : filteredClaims.length === 0 ? (
          <PremiumCard>
            <CardContent className="py-12 text-center">
              <FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">No Claims Found</h3>
              <p className="text-muted-foreground mb-4">
                {searchQuery || statusFilter !== 'all'
                  ? 'Try adjusting your filters'
                  : 'Submit your first claim to get started'}
              </p>
              {!searchQuery && statusFilter === 'all' && (
                <PremiumButton onClick={() => setShowNewClaim(true)}>
                  <Plus className="w-4 h-4 mr-2" />
                  Submit Claim
                </PremiumButton>
              )}
            </CardContent>
          </PremiumCard>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredClaims.map((claim) => (
              <ClaimCard
                key={claim.id}
                claim={claim}
                onClick={() => setSelectedClaim(claim)}
              />
            ))}
          </div>
        )}

        {/* Modals */}
        <AnimatePresence>
          {showNewClaim && (
            <NewClaimModal
              isOpen={showNewClaim}
              onClose={() => setShowNewClaim(false)}
              onSubmit={handleSubmitClaim}
            />
          )}
          {selectedClaim && (
            <ClaimDetailModal
              claim={selectedClaim}
              onClose={() => setSelectedClaim(null)}
            />
          )}
        </AnimatePresence>
      </div>
    </ProtectedRoute>
  );
}
