/**
 * SSI Healthcare Web - Pharmacy Verification Page (H3)
 *
 * Pharmacists verify prescription credentials from patients:
 * - Scan QR code or enter prescription ID
 * - Verify credential authenticity and validity
 * - Check if prescription is already filled
 * - Mark prescription as dispensed
 *
 * Protected: Requires authentication with pharmacy role
 */

'use client';

import * as React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useRouter } from 'next/navigation';
import {
  Pill,
  QrCode,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  User,
  Calendar,
  Search,
  RefreshCw,
  FileText,
  Shield,
  Loader2,
} from 'lucide-react';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useAuth } from '@/hooks/useAuth';
import { pharmacyApi } from '@/lib/api';
import { PremiumCard, CardContent, CardHeader, CardTitle } from '@/components/ui/premium-card';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumInput } from '@/components/ui/premium-input';
import { Badge } from '@/components/ui/badge';

// -- Types --

/**
 * Mirrors the backend union in packages/backend/src/routes/pharmacy.ts.
 * `invalid` is emitted whenever cryptographic verification fails.
 */
type PrescriptionStatus = 'valid' | 'expired' | 'filled' | 'revoked' | 'invalid';

interface PrescriptionVerification {
  id: string;
  prescriptionId: string;
  patientName: string;
  patientDid: string;
  medication: string;
  dosage: string;
  quantity: number;
  refillsRemaining: number;
  prescribedBy: string;
  prescribedDate: string;
  expirationDate: string;
  status: PrescriptionStatus;
  verified: boolean;
  verifiedAt?: string;
  dispensedAt?: string;
}

interface DispenseHistory {
  id: string;
  prescriptionId: string;
  patientName: string;
  medication: string;
  dispensedAt: string;
  dispensedBy: string;
  quantity: number;
}

// -- Constants --

interface StatusDescriptor {
  color: string;
  bgColor: string;
  borderColor: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  /**
   * Single source of truth for whether this status permits dispensing. The
   * badge, the dispense button and the blocked-reason panel all read this one
   * descriptor so they can never contradict each other on screen.
   */
  dispensable: boolean;
  blockedReason: string;
}

const STATUS_CONFIG: Record<PrescriptionStatus, StatusDescriptor> = {
  valid: {
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-400/10',
    borderColor: 'border-emerald-500/30',
    icon: CheckCircle2,
    label: 'Valid',
    dispensable: true,
    blockedReason: '',
  },
  expired: {
    color: 'text-amber-400',
    bgColor: 'bg-amber-400/10',
    borderColor: 'border-amber-500/30',
    icon: Clock,
    label: 'Expired',
    dispensable: false,
    blockedReason: 'This prescription has expired and cannot be filled.',
  },
  filled: {
    color: 'text-blue-400',
    bgColor: 'bg-blue-400/10',
    borderColor: 'border-blue-500/30',
    icon: CheckCircle2,
    label: 'Already Filled',
    dispensable: false,
    blockedReason: 'This prescription has already been filled and cannot be filled again.',
  },
  revoked: {
    color: 'text-red-400',
    bgColor: 'bg-red-400/10',
    borderColor: 'border-red-500/30',
    icon: XCircle,
    label: 'Revoked',
    dispensable: false,
    blockedReason: 'This prescription has been revoked and cannot be filled.',
  },
  invalid: {
    color: 'text-red-400',
    bgColor: 'bg-red-400/10',
    borderColor: 'border-red-500/30',
    icon: XCircle,
    label: 'Invalid - do not dispense',
    dispensable: false,
    blockedReason:
      'This prescription failed cryptographic verification. It must not be dispensed.',
  },
};

/**
 * Fallback for any status the backend sends that this build does not know
 * about. Defaulting to `valid` here would render a forged or unrecognised
 * prescription as safe to dispense, so an unknown status is always treated as
 * a hard stop.
 */
const UNKNOWN_STATUS: StatusDescriptor = {
  color: 'text-red-400',
  bgColor: 'bg-red-400/10',
  borderColor: 'border-red-500/30',
  icon: AlertTriangle,
  label: 'Unknown - do not dispense',
  dispensable: false,
  blockedReason:
    'This prescription has an unrecognised status and could not be validated. It must not be dispensed.',
};

function resolveStatus(status: string): StatusDescriptor {
  return (STATUS_CONFIG as Record<string, StatusDescriptor>)[status] ?? UNKNOWN_STATUS;
}

// -- Helpers --

function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function formatDateTime(dateString: string): string {
  return new Date(dateString).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  });
}

// -- Verification Result Component --

function VerificationResult({
  prescription,
  onDispense,
  isDispensing,
}: {
  prescription: PrescriptionVerification;
  onDispense: () => void;
  isDispensing: boolean;
}) {
  const status = resolveStatus(prescription.status);
  const StatusIcon = status.icon;
  const canDispense = status.dispensable && prescription.verified;
  const blockedReason = status.dispensable
    ? 'This prescription has not been cryptographically verified. It must not be dispensed.'
    : status.blockedReason;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className={`rounded-2xl border-2 ${status.borderColor} ${status.bgColor} overflow-hidden`}
    >
      {/* Status Header */}
      <div className="p-6 border-b border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-12 h-12 rounded-xl ${status.bgColor} flex items-center justify-center`}>
              <StatusIcon className={`w-6 h-6 ${status.color}`} />
            </div>
            <div>
              <Badge variant="outline" className={status.color}>
                {status.label}
              </Badge>
              <h3 className="text-lg font-semibold text-foreground mt-1">
                {prescription.medication}
              </h3>
            </div>
          </div>
          {prescription.verified && (
            <div className="flex items-center gap-2 text-emerald-400">
              <Shield className="w-5 h-5" />
              <span className="text-sm font-medium">Cryptographically Verified</span>
            </div>
          )}
        </div>
      </div>

      {/* Prescription Details */}
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-sm text-muted-foreground">Patient</p>
            <p className="text-foreground font-medium">{prescription.patientName}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Prescribed By</p>
            <p className="text-foreground font-medium">{prescription.prescribedBy}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Dosage</p>
            <p className="text-foreground font-medium">{prescription.dosage}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Quantity</p>
            <p className="text-foreground font-medium">{prescription.quantity} units</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Prescribed Date</p>
            <p className="text-foreground font-medium">{formatDate(prescription.prescribedDate)}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Expires</p>
            <p className="text-foreground font-medium">{formatDate(prescription.expirationDate)}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Refills Remaining</p>
            <p className="text-foreground font-medium">{prescription.refillsRemaining}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Prescription ID</p>
            <p className="text-foreground font-mono text-sm truncate">{prescription.prescriptionId}</p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="pt-4 border-t border-border">
          {canDispense ? (
            <PremiumButton
              onClick={onDispense}
              disabled={isDispensing}
              className="w-full bg-emerald-600 hover:bg-emerald-500"
            >
              {isDispensing ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Processing...
                </>
              ) : (
                <>
                  <Pill className="w-4 h-4 mr-2" />
                  Dispense Medication
                </>
              )}
            </PremiumButton>
          ) : (
            <div
              className={`text-center p-4 rounded-xl ${status.bgColor} border ${status.borderColor}`}
            >
              <p className={status.color}>{blockedReason}</p>
              {prescription.dispensedAt && (
                <p className={`${status.color} text-sm mt-1 opacity-80`}>
                  Dispensed on {formatDateTime(prescription.dispensedAt)}
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}

// -- Dispense History Item --

function HistoryItem({ item }: { item: DispenseHistory }) {
  return (
    <div className="flex items-center gap-4 p-4 rounded-xl bg-card/50 border border-border">
      <div className="w-10 h-10 rounded-lg bg-emerald-400/10 flex items-center justify-center flex-shrink-0">
        <Pill className="w-5 h-5 text-emerald-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-foreground">{item.medication}</p>
        <p className="text-xs text-muted-foreground">{item.patientName}</p>
      </div>
      <div className="text-right">
        <p className="text-xs text-muted-foreground">{formatDateTime(item.dispensedAt)}</p>
        <p className="text-xs text-muted-foreground">{item.quantity} units</p>
      </div>
    </div>
  );
}

// -- Main Page Component --

export default function PharmacyPage() {
  const { user } = useAuth();
  const router = useRouter();
  const [prescriptionId, setPrescriptionId] = React.useState('');
  const [isVerifying, setIsVerifying] = React.useState(false);
  const [isDispensing, setIsDispensing] = React.useState(false);
  const [verificationResult, setVerificationResult] = React.useState<PrescriptionVerification | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [history, setHistory] = React.useState<DispenseHistory[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = React.useState(true);

  // Load dispense history
  React.useEffect(() => {
    async function loadHistory() {
      try {
        const response = await pharmacyApi.getDispenseHistory();
        const rawHistory = response.data?.history ?? [];
        setHistory(rawHistory.map((r) => ({
          id: r.id,
          prescriptionId: r.prescriptionId,
          patientName: (r as unknown as Record<string, string>).patientName ?? r.patientDid,
          medication: r.medication,
          dispensedAt: r.dispensedAt,
          dispensedBy: (r as unknown as Record<string, string>).dispensedBy ?? r.pharmacyDid,
          quantity: r.quantity,
        })));
      } catch (err) {
        console.error('Failed to load history', err);
      } finally {
        setIsLoadingHistory(false);
      }
    }
    
    loadHistory();
  }, []);

  // Verify prescription
  const handleVerify = async () => {
    if (!prescriptionId.trim()) return;
    
    setIsVerifying(true);
    setError(null);
    setVerificationResult(null);

    try {
      const response = await pharmacyApi.verifyPrescription({
        prescriptionCredentialId: prescriptionId.trim(),
        patientDid: '', // Resolved by backend from credential
        pharmacyDid: user?.did || '',
      });
      
      if (response.data) {
        setVerificationResult(response.data as unknown as PrescriptionVerification);
      } else {
        setError(response.error?.message || 'Verification failed');
      }
    } catch (err) {
      setError('Failed to connect to verification service');
    } finally {
      setIsVerifying(false);
    }
  };

  // Dispense medication
  const handleDispense = async () => {
    if (!verificationResult) return;
    
    setIsDispensing(true);

    try {
      const response = await pharmacyApi.dispenseMedication({
        prescriptionId: verificationResult.prescriptionId,
        pharmacyDid: user?.did || '',
        medicationDetails: {
          quantity: verificationResult.quantity,
        },
      });
      
      if (response.data) {
        // Update local state
        setVerificationResult({
          ...verificationResult,
          status: 'filled',
          dispensedAt: new Date().toISOString(),
        });
        
        // Add to history
        setHistory(prev => [{
          id: (response.data as unknown as Record<string, string>).id || crypto.randomUUID(),
          prescriptionId: verificationResult.prescriptionId,
          patientName: verificationResult.patientName,
          medication: verificationResult.medication,
          dispensedAt: new Date().toISOString(),
          dispensedBy: user?.displayName || user?.email || 'Pharmacist',
          quantity: verificationResult.quantity,
        }, ...prev]);
      } else {
        setError(response.error?.message || 'Failed to dispense');
      }
    } catch (err) {
      setError('Failed to record dispense');
    } finally {
      setIsDispensing(false);
    }
  };

  // FINDING-011: Replace alert() stub with router navigation to the QR scanner page.
  // Camera-based scanning is handled by wallet/scan which uses the QRScanner component.
  const handleScanQR = () => {
    router.push('/wallet/scan?mode=prescription&returnTo=/pharmacy');
  };

  return (
    <ProtectedRoute requireWallet>
      <div className="min-h-screen p-6 lg:p-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground">Pharmacy Portal</h1>
          <p className="text-muted-foreground mt-1">
            Verify and dispense prescription credentials
          </p>
          {user?.did && (
            <p className="text-xs text-muted-foreground mt-2 font-mono">
              Pharmacy ID: {user.did.slice(0, 30)}...
            </p>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Verification Form */}
          <div className="lg:col-span-2 space-y-6">
            <PremiumCard>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-blue-400" />
                  Verify Prescription
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground mb-4">
                  Enter the prescription credential ID or scan the patient's QR code to verify authenticity.
                </p>

                <div className="flex gap-3 mb-4">
                  <div className="flex-1">
                    <PremiumInput
                      type="text"
                      placeholder="Enter prescription ID or credential URI..."
                      value={prescriptionId}
                      onChange={(e) => setPrescriptionId(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleVerify()}
                      leftIcon={<FileText className="w-4 h-4" />}
                    />
                  </div>
                  <PremiumButton
                    variant="outline"
                    onClick={handleScanQR}
                    className="flex-shrink-0"
                  >
                    <QrCode className="w-4 h-4" />
                  </PremiumButton>
                </div>

                <PremiumButton
                  onClick={handleVerify}
                  disabled={!prescriptionId.trim() || isVerifying}
                  className="w-full"
                >
                  {isVerifying ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Verifying...
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4 mr-2" />
                      Verify Prescription
                    </>
                  )}
                </PremiumButton>

                {/* Error */}
                {error && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mt-4 p-4 rounded-xl bg-red-500/10 border border-red-500/30"
                  >
                    <div className="flex items-center gap-2 text-red-400">
                      <AlertTriangle className="w-4 h-4" />
                      <p>{error}</p>
                    </div>
                  </motion.div>
                )}
              </CardContent>
            </PremiumCard>

            {/* Verification Result */}
            <AnimatePresence mode="wait">
              {verificationResult && (
                <VerificationResult
                  prescription={verificationResult}
                  onDispense={handleDispense}
                  isDispensing={isDispensing}
                />
              )}
            </AnimatePresence>

            {/* How It Works */}
            {!verificationResult && (
              <PremiumCard>
                <CardHeader>
                  <CardTitle>How It Works</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="p-4 rounded-xl bg-muted/50 border border-border">
                      <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center mb-3">
                        <QrCode className="w-5 h-5 text-blue-400" />
                      </div>
                      <h4 className="font-medium text-foreground mb-1">1. Scan or Enter</h4>
                      <p className="text-sm text-muted-foreground">
                        Scan the patient's QR code or enter their prescription ID
                      </p>
                    </div>
                    <div className="p-4 rounded-xl bg-muted/50 border border-border">
                      <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center mb-3">
                        <Shield className="w-5 h-5 text-purple-400" />
                      </div>
                      <h4 className="font-medium text-foreground mb-1">2. Verify</h4>
                      <p className="text-sm text-muted-foreground">
                        The system cryptographically verifies the credential's authenticity
                      </p>
                    </div>
                    <div className="p-4 rounded-xl bg-muted/50 border border-border">
                      <div className="w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center mb-3">
                        <Pill className="w-5 h-5 text-emerald-400" />
                      </div>
                      <h4 className="font-medium text-foreground mb-1">3. Dispense</h4>
                      <p className="text-sm text-muted-foreground">
                        If valid, dispense the medication and mark the prescription as filled
                      </p>
                    </div>
                  </div>
                </CardContent>
              </PremiumCard>
            )}
          </div>

          {/* Dispense History */}
          <div>
            <PremiumCard>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>Recent Dispenses</span>
                  <button 
                    onClick={() => window.location.reload()}
                    className="text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <RefreshCw className="w-4 h-4" />
                  </button>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {isLoadingHistory ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="w-6 h-6 text-muted-foreground animate-spin" />
                  </div>
                ) : history.length === 0 ? (
                  <div className="text-center py-8">
                    <Clock className="w-12 h-12 text-muted-foreground mx-auto mb-3" />
                    <p className="text-muted-foreground">No dispense history yet</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {history.slice(0, 10).map((item) => (
                      <HistoryItem key={item.id} item={item} />
                    ))}
                  </div>
                )}
              </CardContent>
            </PremiumCard>
          </div>
        </div>
      </div>
    </ProtectedRoute>
  );
}
