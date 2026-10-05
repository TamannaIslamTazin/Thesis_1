'use client';

/**
 * SSI Healthcare Web - Emergency Access Portal (H5)
 *
 * Break-glass emergency access for paramedics and healthcare providers.
 * Allows emergency personnel to request immediate access to patient data.
 *
 * Features:
 * - Emergency access request form
 * - Patient ID or QR scan to identify patient
 * - Immediate access to critical medical info
 * - Full audit trail and time-limited access
 */

import React, { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  Shield,
  Activity,
  FileText,
  Clock,
  User,
  CheckCircle,
  AlertCircle,
  Phone,
  Heart,
  Pill,
  Droplet,
  Search,
  QrCode,
  Eye,
  Lock,
  History,
  ChevronDown,
  XCircle,
} from 'lucide-react';
import { emergencyApi } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';

// -- Types --

interface EmergencyRequest {
  id: string;
  patientId: string;
  patientName?: string;
  requestedAt: string;
  expiresAt: string;
  status: 'pending' | 'granted' | 'expired' | 'denied';
  providerName: string;
  providerId: string;
  providerRole: string;
  location?: string;
  reason: string;
  accessedData: string[];
}

interface PatientEmergencyData {
  id: string;
  name: string;
  dob: string;
  bloodType: string;
  allergies: string[];
  conditions: string[];
  medications: {
    name: string;
    dosage: string;
    frequency: string;
  }[];
  emergencyContacts: {
    name: string;
    relationship: string;
    phone: string;
  }[];
  // NOTE: Do not reintroduce a `dnr` / code-status field here without a real
  // backend source. No such field exists in the Prisma schema, the backend
  // routes, @ssi-healthcare/shared or the SDK. Because getEmergencyData() is
  // cast straight onto this interface, an absent field reads as `false`, which
  // previously rendered a green "Full Code" for every patient regardless of
  // their actual directive. If code status is ever added it MUST be a
  // three-state value (on file / not on file / unknown) that defaults to
  // Unknown, and Unknown must never be styled as reassuring.
  organDonor: boolean;
  primaryPhysician?: {
    name: string;
    phone: string;
  };
  insuranceInfo?: {
    provider: string;
    policyNumber: string;
  };
  lastUpdated: string;
}

// -- Component: Emergency Access Form --

function EmergencyAccessForm({
  onRequestAccess,
  isLoading,
  onScanQr,
}: {
  onRequestAccess: (patientId: string, reason: string) => void;
  isLoading: boolean;
  onScanQr?: () => void;
}) {
  const [patientId, setPatientId] = useState('');
  const [reason, setReason] = useState('');
  const [searchMode, setSearchMode] = useState<'id' | 'qr'>('id');

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      if (patientId && reason) {
        onRequestAccess(patientId, reason);
      }
    },
    [patientId, reason, onRequestAccess]
  );

  return (
    <motion.form
      onSubmit={handleSubmit}
      className="bg-white rounded-xl border border-gray-200 p-6 shadow-sm"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center">
          <AlertTriangle className="w-5 h-5 text-red-600" />
        </div>
        <div>
          <h2 className="text-lg font-semibold text-gray-900">Emergency Access Request</h2>
          <p className="text-sm text-gray-500">For authorized emergency personnel only</p>
        </div>
      </div>

      {/* Search Mode Toggle */}
      <div className="flex gap-2 mb-4">
        <button
          type="button"
          onClick={() => setSearchMode('id')}
          className={`flex-1 flex items-center justify-center gap-2 py-2 px-4 rounded-lg text-sm font-medium transition-colors ${
            searchMode === 'id'
              ? 'bg-blue-100 text-blue-700 border border-blue-200'
              : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
          }`}
        >
          <Search className="w-4 h-4" />
          Patient ID
        </button>
        <button
          type="button"
          onClick={() => setSearchMode('qr')}
          className={`flex-1 flex items-center justify-center gap-2 py-2 px-4 rounded-lg text-sm font-medium transition-colors ${
            searchMode === 'qr'
              ? 'bg-blue-100 text-blue-700 border border-blue-200'
              : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
          }`}
        >
          <QrCode className="w-4 h-4" />
          Scan QR
        </button>
      </div>

      {searchMode === 'id' ? (
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Patient ID or SSI Identifier
          </label>
          <input
            type="text"
            value={patientId}
            onChange={(e) => setPatientId(e.target.value)}
            placeholder="Enter patient ID or DID..."
            className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent text-gray-900"
            required
          />
        </div>
      ) : (
        <div className="mb-4 p-8 border-2 border-dashed border-gray-300 rounded-lg text-center">
          <QrCode className="w-12 h-12 text-gray-400 mx-auto mb-3" />
          <p className="text-sm text-gray-600 mb-2">Point camera at patient's emergency QR code</p>
          <button
            type="button"
            onClick={onScanQr}
            className="text-sm text-blue-600 hover:text-blue-700 font-medium"
          >
            Open Camera
          </button>
        </div>
      )}

      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Emergency Reason <span className="text-red-500">*</span>
        </label>
        <select
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent text-gray-900"
          required
        >
          <option value="">Select reason for access...</option>
          <option value="ambulance_response">Ambulance Response</option>
          <option value="er_admission">Emergency Room Admission</option>
          <option value="trauma_care">Trauma Care</option>
          <option value="cardiac_emergency">Cardiac Emergency</option>
          <option value="respiratory_distress">Respiratory Distress</option>
          <option value="unconscious_patient">Unconscious Patient</option>
          <option value="other_emergency">Other Emergency Situation</option>
        </select>
      </div>

      <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-6">
        <div className="flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-amber-600 mt-0.5 flex-shrink-0" />
          <div className="text-sm text-amber-800">
            <p className="font-medium mb-1">Important Notice</p>
            <p>
              Emergency access is logged and audited. Only use this for genuine medical emergencies.
              Misuse may result in disciplinary action and legal consequences.
            </p>
          </div>
        </div>
      </div>

      <button
        type="submit"
        disabled={isLoading || !patientId || !reason}
        className="w-full bg-red-600 text-foreground py-3 px-6 rounded-lg font-semibold hover:bg-red-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
      >
        {isLoading ? (
          <>
            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            Requesting Access...
          </>
        ) : (
          <>
            <Shield className="w-5 h-5" />
            Request Emergency Access
          </>
        )}
      </button>
    </motion.form>
  );
}

// -- Component: Critical Info Card --

function CriticalInfoCard({
  icon: Icon,
  title,
  items,
  variant = 'default',
}: {
  icon: React.ElementType;
  title: string;
  items: string[];
  variant?: 'default' | 'warning' | 'danger';
}) {
  const bgColor =
    variant === 'danger'
      ? 'bg-red-50 border-red-200'
      : variant === 'warning'
        ? 'bg-amber-50 border-amber-200'
        : 'bg-gray-50 border-gray-200';

  const iconBg =
    variant === 'danger'
      ? 'bg-red-100'
      : variant === 'warning'
        ? 'bg-amber-100'
        : 'bg-blue-100';

  const iconColor =
    variant === 'danger'
      ? 'text-red-600'
      : variant === 'warning'
        ? 'text-amber-600'
        : 'text-blue-600';

  return (
    <div className={`rounded-lg border p-4 ${bgColor}`}>
      <div className="flex items-center gap-2 mb-3">
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${iconBg}`}>
          <Icon className={`w-4 h-4 ${iconColor}`} />
        </div>
        <h4 className="font-semibold text-gray-900">{title}</h4>
      </div>
      {items.length > 0 ? (
        <ul className="space-y-1.5">
          {items.map((item, idx) => (
            <li key={idx} className="text-sm text-gray-700 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-gray-400" />
              {item}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-gray-500 italic">None reported</p>
      )}
    </div>
  );
}

// -- Component: Emergency Data View --

function EmergencyDataView({
  data,
  accessExpiresAt,
  onClose,
}: {
  data: PatientEmergencyData;
  accessExpiresAt: string;
  onClose: () => void;
}) {
  const [expandedSection, setExpandedSection] = useState<string | null>('critical');

  const timeRemaining = () => {
    const now = new Date();
    const expires = new Date(accessExpiresAt);
    const diff = Math.max(0, expires.getTime() - now.getTime());
    const mins = Math.floor(diff / 60000);
    const secs = Math.floor((diff % 60000) / 1000);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <motion.div
      className="bg-white rounded-xl border-2 border-red-200 shadow-lg overflow-hidden"
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
    >
      {/* Emergency Header */}
      <div className="bg-red-600 text-foreground px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-6 h-6" />
            <div>
              <h2 className="text-lg font-bold">EMERGENCY ACCESS ACTIVE</h2>
              <p className="text-red-100 text-sm">Patient: {data.name}</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-red-100 text-xs">Time Remaining</p>
              <p className="text-xl font-mono font-bold">{timeRemaining()}</p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-red-700 rounded-lg transition-colors"
              aria-label="Close emergency access"
            >
              <XCircle className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>

      {/* Patient Basic Info */}
      <div className="bg-red-50 px-6 py-4 border-b border-red-200">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wide">Patient</p>
            <p className="font-semibold text-gray-900">{data.name}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wide">DOB</p>
            <p className="font-semibold text-gray-900">
              {new Date(data.dob).toLocaleDateString()}
            </p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wide">Blood Type</p>
            <p className="font-bold text-red-600 text-lg">{data.bloodType}</p>
          </div>
        </div>
      </div>

      {/* Critical Information */}
      <div className="p-6 space-y-4">
        {/* Allergies - Always Visible */}
        <CriticalInfoCard
          icon={AlertTriangle}
          title="ALLERGIES"
          items={data.allergies}
          variant="danger"
        />

        {/* Conditions */}
        <CriticalInfoCard
          icon={Activity}
          title="Medical Conditions"
          items={data.conditions}
          variant="warning"
        />

        {/* Medications */}
        <div className="rounded-lg border border-gray-200 p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-8 h-8 bg-purple-100 rounded-lg flex items-center justify-center">
              <Pill className="w-4 h-4 text-purple-600" />
            </div>
            <h4 className="font-semibold text-gray-900">Current Medications</h4>
          </div>
          <div className="space-y-2">
            {data.medications.map((med, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between text-sm py-2 border-b border-gray-100 last:border-0"
              >
                <span className="font-medium text-gray-900">{med.name}</span>
                <span className="text-gray-600">
                  {med.dosage} · {med.frequency}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Emergency Contacts */}
        <div className="rounded-lg border border-gray-200 p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center">
              <Phone className="w-4 h-4 text-green-600" />
            </div>
            <h4 className="font-semibold text-gray-900">Emergency Contacts</h4>
          </div>
          <div className="space-y-3">
            {data.emergencyContacts.map((contact, idx) => (
              <div key={idx} className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-gray-900">{contact.name}</p>
                  <p className="text-sm text-gray-500">{contact.relationship}</p>
                </div>
                <a
                  href={`tel:${contact.phone}`}
                  className="text-blue-600 hover:text-blue-700 font-medium text-sm flex items-center gap-1"
                >
                  <Phone className="w-4 h-4" />
                  {contact.phone}
                </a>
              </div>
            ))}
          </div>
        </div>

        {/* Additional Info */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {data.primaryPhysician && (
            <div className="rounded-lg border border-gray-200 p-4">
              <p className="text-sm text-gray-500 mb-1">Primary Physician</p>
              <p className="font-medium text-gray-900">{data.primaryPhysician.name}</p>
              <a
                href={`tel:${data.primaryPhysician.phone}`}
                className="text-sm text-blue-600 hover:text-blue-700"
              >
                {data.primaryPhysician.phone}
              </a>
            </div>
          )}
          {data.insuranceInfo && (
            <div className="rounded-lg border border-gray-200 p-4">
              <p className="text-sm text-gray-500 mb-1">Insurance</p>
              <p className="font-medium text-gray-900">{data.insuranceInfo.provider}</p>
              <p className="text-sm text-gray-600">Policy: {data.insuranceInfo.policyNumber}</p>
            </div>
          )}
        </div>

        {/* Organ Donor Status */}
        {data.organDonor && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-4 flex items-center gap-3">
            <Heart className="w-5 h-5 text-green-600" />
            <span className="text-green-800 font-medium">
              Patient is a registered organ donor
            </span>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="bg-gray-50 px-6 py-4 border-t border-gray-200">
        <div className="flex items-center justify-between text-sm">
          <div className="flex items-center gap-2 text-gray-500">
            <History className="w-4 h-4" />
            <span>Last updated: {new Date(data.lastUpdated).toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-2 text-gray-500">
            <Eye className="w-4 h-4" />
            <span>All access is logged and audited</span>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// -- Component: Provider Verification --

function ProviderVerification({
  onVerified,
  isLoading,
}: {
  onVerified: () => void;
  isLoading: boolean;
}) {
  const [providerId, setProviderId] = useState('');
  const [providerType, setProviderType] = useState('');

  return (
    <motion.div
      className="bg-white rounded-xl border border-gray-200 p-6 shadow-sm"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
          <Shield className="w-5 h-5 text-blue-600" />
        </div>
        <div>
          <h2 className="text-lg font-semibold text-gray-900">Provider Verification</h2>
          <p className="text-sm text-gray-500">Verify your credentials to access emergency data</p>
        </div>
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Provider ID / NPI</label>
          <input
            type="text"
            value={providerId}
            onChange={(e) => setProviderId(e.target.value)}
            placeholder="Enter your provider ID..."
            className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-gray-900"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Provider Type</label>
          <select
            value={providerType}
            onChange={(e) => setProviderType(e.target.value)}
            className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-gray-900"
          >
            <option value="">Select provider type...</option>
            <option value="paramedic">Paramedic / EMT</option>
            <option value="physician">Physician</option>
            <option value="nurse">Registered Nurse</option>
            <option value="er_staff">Emergency Room Staff</option>
            <option value="first_responder">First Responder</option>
          </select>
        </div>

        <button
          onClick={onVerified}
          disabled={isLoading || !providerId || !providerType}
          className="w-full bg-blue-600 text-foreground py-3 px-6 rounded-lg font-semibold hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
        >
          {isLoading ? (
            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          ) : (
            <>
              <CheckCircle className="w-5 h-5" />
              Verify Credentials
            </>
          )}
        </button>
      </div>
    </motion.div>
  );
}

// -- Main Page Component --

// FINDING-003: Emergency page must be behind auth. PHI should never be accessible
// to unauthenticated users — not even the request interface.
function EmergencyPageContent() {
  const { user } = useAuth();
  const router = useRouter();
  const [step, setStep] = useState<'verify' | 'request' | 'access'>('verify');
  const [isLoading, setIsLoading] = useState(false);
  const [emergencyData, setEmergencyData] = useState<PatientEmergencyData | null>(null);
  const [accessExpiresAt, setAccessExpiresAt] = useState<string>('');
  const [accessId, setAccessId] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  const handleProviderVerified = useCallback(async () => {
    if (!user?.did) return;
    setIsLoading(true);
    setError(null);
    try {
      // Provider is already authenticated; proceed to request step
      setStep('request');
    } catch {
      setStep('request');
    } finally {
      setIsLoading(false);
    }
  }, [user?.did]);

  const handleRequestAccess = useCallback(async (patientId: string, reason: string) => {
    if (!user?.did) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await emergencyApi.requestAccess({
        patientDid: patientId,
        reason,
        credentialIds: [], // Emergency access doesn't require specific credentials
      });

      if (res.data) {
        setAccessId((res.data as unknown as Record<string, string>).id || '');
        setAccessExpiresAt(
          (res.data as unknown as Record<string, string>).expiresAt ||
          new Date(Date.now() + 15 * 60 * 1000).toISOString()
        );
      }

      // Now fetch the patient's emergency data
      const dataRes = await emergencyApi.getEmergencyData(patientId);
      if (dataRes.data) {
        setEmergencyData(dataRes.data as unknown as PatientEmergencyData);
        setStep('access');
      } else {
        setError('Access granted but patient data unavailable.');
      }
    } catch {
      setError('Failed to activate emergency access. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }, [user]);

  const handleCloseAccess = useCallback(async () => {
    if (accessId) {
      try {
        await emergencyApi.revokeAccess(accessId);
      } catch {
        // Log but don't block — deactivation is best-effort
      }
    }
    setEmergencyData(null);
    setAccessId('');
    setStep('request');
  }, [accessId]);

  return (
    <div className="min-h-screen bg-gradient-to-b from-red-50 to-gray-100">
      <div className="max-w-4xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-red-100 rounded-full mb-4">
            <AlertTriangle className="w-8 h-8 text-red-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Emergency Medical Access</h1>
          <p className="text-gray-600 max-w-md mx-auto">
            Authorized healthcare providers can access critical patient information during medical
            emergencies.
          </p>
        </div>

        {/* Step Indicator */}
        <div className="flex items-center justify-center gap-4 mb-8">
          {['Provider Verification', 'Request Access', 'View Data'].map((label, idx) => {
            const stepNum = idx + 1;
            const currentStep = step === 'verify' ? 1 : step === 'request' ? 2 : 3;
            const isActive = stepNum === currentStep;
            const isComplete = stepNum < currentStep;

            return (
              <React.Fragment key={label}>
                <div className="flex items-center gap-2">
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                      isComplete
                        ? 'bg-green-500 text-foreground'
                        : isActive
                          ? 'bg-red-600 text-foreground'
                          : 'bg-gray-200 text-gray-500'
                    }`}
                  >
                    {isComplete ? <CheckCircle className="w-5 h-5" /> : stepNum}
                  </div>
                  <span
                    className={`text-sm font-medium ${
                      isActive ? 'text-gray-900' : 'text-gray-500'
                    }`}
                  >
                    {label}
                  </span>
                </div>
                {idx < 2 && <ChevronDown className="w-4 h-4 text-gray-300 rotate-[-90deg]" />}
              </React.Fragment>
            );
          })}
        </div>

        {/* Main Content */}
        {error && (
          <div className="mb-4 p-4 bg-red-100 border border-red-200 rounded-lg text-red-800 text-sm">
            {error}
          </div>
        )}
        <AnimatePresence mode="wait">
          {step === 'verify' && (
            <ProviderVerification onVerified={handleProviderVerified} isLoading={isLoading} />
          )}
          {step === 'request' && (
            <EmergencyAccessForm onRequestAccess={handleRequestAccess} isLoading={isLoading} onScanQr={() => router.push('/wallet/scan?mode=emergency&returnTo=/emergency')} />
          )}
          {step === 'access' && emergencyData && (
            <EmergencyDataView
              data={emergencyData}
              accessExpiresAt={accessExpiresAt}
              onClose={handleCloseAccess}
            />
          )}
        </AnimatePresence>

        {/* Security Notice */}
        <div className="mt-8 bg-gray-900 text-foreground rounded-xl p-6">
          <div className="flex items-start gap-4">
            <Lock className="w-6 h-6 text-gray-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-semibold mb-2">Security & Audit Notice</h3>
              <ul className="text-sm text-gray-300 space-y-1">
                <li>• All emergency access requests are logged with timestamp, provider ID, and location</li>
                <li>• Patient is notified of emergency access within 24 hours</li>
                <li>• Access is time-limited (15 minutes) and auto-expires</li>
                <li>• Unauthorized access is a HIPAA violation and subject to legal action</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function EmergencyAccessPage() {
  return (
    <ProtectedRoute>
      <EmergencyPageContent />
    </ProtectedRoute>
  );
}
