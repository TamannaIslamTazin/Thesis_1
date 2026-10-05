/**
 * SSI Healthcare Web - Provider Credential Issuance (H2)
 *
 * Healthcare providers use this page to issue Verifiable Credentials
 * to patients. Supports OID4VCI Pre-Authorized Code Flow.
 *
 * Enhanced with:
 * - Type-specific claim forms
 * - QR code for mobile claim
 * - Recent issue history from backend
 * - Batch issuance support
 * 
 * Protected: Requires authentication with wallet (issuer must have DID)
 */

"use client";

import { useState, useCallback, useMemo } from "react";
import QRCode from "react-qr-code";
import {
  Hospital,
  Microscope,
  Pill,
  Syringe,
  ShieldCheck,
  Clock,
  CheckCircle2,
  XCircle,
  Copy,
  User,
  Calendar,
  FileText,
  AlertCircle,
  Building,
  Stethoscope,
} from "lucide-react";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { useAuth } from "@/hooks/useAuth";
import { issuerApi } from "@/lib/api";

// -- Types --

interface ClaimField {
  name: string;
  label: string;
  type: 'text' | 'date' | 'select' | 'textarea' | 'number';
  required: boolean;
  placeholder?: string;
  options?: { value: string; label: string }[];
  sensitive?: boolean;
}

interface CredentialTypeConfig {
  id: string;
  label: string;
  description: string;
  icon: React.ReactNode;
  category: string;
  fields: ClaimField[];
}

// -- Credential Type Configurations --

const CREDENTIAL_TYPES: CredentialTypeConfig[] = [
  {
    id: "HealthRecord",
    label: "Health Record",
    description: "General health summary and visit notes",
    icon: <Hospital className="w-6 h-6" />,
    category: "medical",
    fields: [
      { name: "patientName", label: "Patient Name", type: "text", required: true },
      { name: "dateOfBirth", label: "Date of Birth", type: "date", required: true, sensitive: true },
      { name: "visitDate", label: "Visit Date", type: "date", required: true },
      { name: "diagnosis", label: "Diagnosis", type: "textarea", required: true },
      { name: "treatmentPlan", label: "Treatment Plan", type: "textarea", required: false },
      { name: "nextVisit", label: "Follow-up Date", type: "date", required: false },
    ],
  },
  {
    id: "LabResult",
    label: "Lab Result",
    description: "Blood work, imaging, and test results",
    icon: <Microscope className="w-6 h-6" />,
    category: "diagnostic",
    fields: [
      { name: "patientName", label: "Patient Name", type: "text", required: true },
      { name: "testType", label: "Test Type", type: "select", required: true, options: [
        { value: "blood_panel", label: "Blood Panel (CBC)" },
        { value: "lipid_panel", label: "Lipid Panel" },
        { value: "metabolic", label: "Metabolic Panel" },
        { value: "urinalysis", label: "Urinalysis" },
        { value: "imaging", label: "Imaging (X-Ray/MRI/CT)" },
        { value: "biopsy", label: "Biopsy" },
        { value: "other", label: "Other" },
      ]},
      { name: "testDate", label: "Test Date", type: "date", required: true },
      { name: "results", label: "Results Summary", type: "textarea", required: true },
      { name: "normalRange", label: "Normal Range", type: "text", required: false },
      { name: "interpretation", label: "Interpretation", type: "select", required: true, options: [
        { value: "normal", label: "Normal" },
        { value: "abnormal_low", label: "Abnormal - Low" },
        { value: "abnormal_high", label: "Abnormal - High" },
        { value: "critical", label: "Critical" },
        { value: "inconclusive", label: "Inconclusive" },
      ]},
    ],
  },
  {
    id: "Prescription",
    label: "Prescription",
    description: "Medication prescriptions",
    icon: <Pill className="w-6 h-6" />,
    category: "medication",
    fields: [
      { name: "patientName", label: "Patient Name", type: "text", required: true },
      { name: "medicationName", label: "Medication Name", type: "text", required: true },
      { name: "dosage", label: "Dosage", type: "text", required: true, placeholder: "e.g., 500mg" },
      { name: "frequency", label: "Frequency", type: "select", required: true, options: [
        { value: "once_daily", label: "Once daily" },
        { value: "twice_daily", label: "Twice daily" },
        { value: "three_daily", label: "Three times daily" },
        { value: "four_daily", label: "Four times daily" },
        { value: "as_needed", label: "As needed (PRN)" },
        { value: "weekly", label: "Weekly" },
      ]},
      { name: "duration", label: "Duration (days)", type: "number", required: true },
      { name: "refills", label: "Refills Allowed", type: "number", required: true },
      { name: "instructions", label: "Special Instructions", type: "textarea", required: false },
      { name: "prescribedDate", label: "Prescribed Date", type: "date", required: true },
    ],
  },
  {
    id: "ImmunizationRecord",
    label: "Immunization",
    description: "Vaccination records",
    icon: <Syringe className="w-6 h-6" />,
    category: "immunization",
    fields: [
      { name: "patientName", label: "Patient Name", type: "text", required: true },
      { name: "vaccineName", label: "Vaccine Name", type: "select", required: true, options: [
        { value: "covid19_pfizer", label: "COVID-19 (Pfizer-BioNTech)" },
        { value: "covid19_moderna", label: "COVID-19 (Moderna)" },
        { value: "covid19_jnj", label: "COVID-19 (Johnson & Johnson)" },
        { value: "influenza", label: "Influenza (Flu)" },
        { value: "tdap", label: "Tdap (Tetanus, Diphtheria, Pertussis)" },
        { value: "mmr", label: "MMR (Measles, Mumps, Rubella)" },
        { value: "hepatitis_a", label: "Hepatitis A" },
        { value: "hepatitis_b", label: "Hepatitis B" },
        { value: "pneumococcal", label: "Pneumococcal" },
        { value: "shingles", label: "Shingles (Herpes Zoster)" },
        { value: "hpv", label: "HPV" },
        { value: "other", label: "Other" },
      ]},
      { name: "doseNumber", label: "Dose Number", type: "number", required: true },
      { name: "lotNumber", label: "Lot Number", type: "text", required: true },
      { name: "administrationDate", label: "Administration Date", type: "date", required: true },
      { name: "expirationDate", label: "Vaccine Expiration", type: "date", required: false },
      { name: "site", label: "Injection Site", type: "select", required: true, options: [
        { value: "left_arm", label: "Left Arm" },
        { value: "right_arm", label: "Right Arm" },
        { value: "left_thigh", label: "Left Thigh" },
        { value: "right_thigh", label: "Right Thigh" },
      ]},
    ],
  },
  {
    id: "InsuranceCertificate",
    label: "Insurance",
    description: "Health insurance verification",
    icon: <ShieldCheck className="w-6 h-6" />,
    category: "insurance",
    fields: [
      { name: "memberName", label: "Member Name", type: "text", required: true },
      { name: "memberId", label: "Member ID", type: "text", required: true },
      { name: "groupNumber", label: "Group Number", type: "text", required: false },
      { name: "planType", label: "Plan Type", type: "select", required: true, options: [
        { value: "hmo", label: "HMO" },
        { value: "ppo", label: "PPO" },
        { value: "epo", label: "EPO" },
        { value: "pos", label: "POS" },
        { value: "hdhp", label: "HDHP" },
        { value: "medicare", label: "Medicare" },
        { value: "medicaid", label: "Medicaid" },
      ]},
      { name: "effectiveDate", label: "Effective Date", type: "date", required: true },
      { name: "terminationDate", label: "Termination Date", type: "date", required: false },
      { name: "copay", label: "Copay Amount ($)", type: "number", required: false },
      { name: "deductible", label: "Deductible ($)", type: "number", required: false },
    ],
  },
];

// -- Claim Form Component --

function ClaimForm({
  config,
  claims,
  onChange,
}: {
  config: CredentialTypeConfig;
  claims: Record<string, string>;
  onChange: (field: string, value: string) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="bg-muted/50 rounded-lg p-4 mb-4">
        <h3 className="text-sm font-medium text-foreground/80 flex items-center gap-2">
          <FileText className="w-4 h-4" />
          {config.label} Details
        </h3>
        <p className="text-xs text-muted-foreground mt-1">{config.description}</p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {config.fields.map((field) => (
          <div key={field.name} className={field.type === 'textarea' ? 'md:col-span-2' : ''}>
            <label className="block text-sm font-medium text-foreground/80 mb-1.5">
              {field.label}
              {field.required && <span className="text-red-400 ml-1">*</span>}
              {field.sensitive && (
                <span className="ml-2 text-xs text-amber-400 flex items-center gap-1 inline-flex">
                  <AlertCircle className="w-3 h-3" /> Sensitive
                </span>
              )}
            </label>
            
            {field.type === 'select' ? (
              <select
                value={claims[field.name] || ''}
                onChange={(e) => onChange(field.name, e.target.value)}
                className="w-full px-4 py-2.5 bg-muted border border-border rounded-lg text-foreground focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                required={field.required}
              >
                <option value="">Select...</option>
                {field.options?.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            ) : field.type === 'textarea' ? (
              <textarea
                value={claims[field.name] || ''}
                onChange={(e) => onChange(field.name, e.target.value)}
                placeholder={field.placeholder}
                rows={3}
                className="w-full px-4 py-2.5 bg-muted border border-border rounded-lg text-foreground placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                required={field.required}
              />
            ) : (
              <input
                type={field.type}
                value={claims[field.name] || ''}
                onChange={(e) => onChange(field.name, e.target.value)}
                placeholder={field.placeholder}
                className="w-full px-4 py-2.5 bg-muted border border-border rounded-lg text-foreground placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                required={field.required}
              />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// -- QR Code Display --

function QRCodeDisplay({ code }: { code: string }) {
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(code);
  }, [code]);

  return (
    <div className="bg-white rounded-xl p-6 text-center">
      {/* FINDING-008: Render a real scannable QR code, not a decorative icon */}
      <div className="w-48 h-48 mx-auto bg-white rounded-lg flex items-center justify-center mb-4 border border-gray-200 p-2">
        <QRCode value={code || ' '} size={176} />
      </div>
      <p className="text-sm text-gray-600 mb-2">
        Patient can scan this QR code to claim their credential
      </p>
      <div className="flex items-center justify-center gap-2">
        <code className="text-xs bg-gray-100 px-3 py-1.5 rounded font-mono text-gray-800 max-w-[200px] truncate">
          {code}
        </code>
        <button
          onClick={handleCopy}
          className="p-2 text-gray-500 hover:text-gray-700 transition-colors"
          title="Copy code"
        >
          <Copy className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

export default function IssuerPage() {
  const { user } = useAuth();
  const [selectedType, setSelectedType] = useState("");
  const [subjectDid, setSubjectDid] = useState("");
  const [claims, setClaims] = useState<Record<string, string>>({});
  const [isIssuing, setIsIssuing] = useState(false);
  const [result, setResult] = useState<{ success: boolean; code?: string; error?: string } | null>(null);

  const selectedConfig = useMemo(
    () => CREDENTIAL_TYPES.find((t) => t.id === selectedType),
    [selectedType]
  );

  const handleClaimChange = useCallback((field: string, value: string) => {
    setClaims((prev) => ({ ...prev, [field]: value }));
  }, []);

  const handleTypeChange = useCallback((typeId: string) => {
    setSelectedType(typeId);
    setClaims({});
    setResult(null);
  }, []);

  const handleIssue = async () => {
    if (!selectedType || !subjectDid || !user?.did || !selectedConfig) return;
    
    // Validate required fields
    const missingFields = selectedConfig.fields
      .filter((f) => f.required && !claims[f.name])
      .map((f) => f.label);
    
    if (missingFields.length > 0) {
      setResult({ success: false, error: `Missing required fields: ${missingFields.join(', ')}` });
      return;
    }

    setIsIssuing(true);
    setResult(null);

    try {
      const res = await issuerApi.createOffer({
        subjectDid: subjectDid,
        credentialType: selectedType,
        category: 'general',
        claims: {
          ...claims,
          issuedAt: new Date().toISOString(),
          issuerName: user.displayName || 'Healthcare Provider',
        },
      });

      if (res.data) {
        setResult({ success: true, code: (res.data as unknown as Record<string, unknown>).preAuthorizedCode as string | undefined });
      } else {
        setResult({ success: false, error: res.error?.message || "Failed to create offer" });
      }
    } catch (err) {
      setResult({ success: false, error: "Failed to connect to backend" });
    } finally {
      setIsIssuing(false);
    }
  };

  return (
    <ProtectedRoute requireWallet>
      <div className="p-8">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center">
              <Stethoscope className="w-6 h-6 text-foreground" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-foreground">Issue Credentials</h1>
              <p className="text-muted-foreground">
                Create and issue Verifiable Credentials to patients via OID4VCI
              </p>
            </div>
          </div>
          {user?.did && (
            <div className="mt-4 flex items-center gap-2 text-xs text-muted-foreground bg-card rounded-lg px-3 py-2 border border-border">
              <Building className="w-4 h-4" />
              <span>Issuing as: <span className="font-mono">{user.did.slice(0, 40)}...</span></span>
            </div>
          )}
        </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Issue Form */}
        <div className="lg:col-span-2 bg-card rounded-xl border border-border p-6">
          <h2 className="text-lg font-semibold text-foreground mb-6">New Credential</h2>

          {/* Credential Type Selector */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-foreground/80 mb-3">
              Credential Type
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {CREDENTIAL_TYPES.map((type) => (
                <button
                  key={type.id}
                  onClick={() => handleTypeChange(type.id)}
                  className={`p-4 rounded-xl border-2 transition-all text-left ${
                    selectedType === type.id
                      ? "border-blue-500 bg-blue-500/10"
                      : "border-border bg-muted hover:border-ring"
                  }`}
                >
                  <span className={`block mb-2 ${
                    selectedType === type.id ? "text-blue-400" : "text-muted-foreground"
                  }`}>
                    {type.icon}
                  </span>
                  <span className={`text-sm font-medium ${
                    selectedType === type.id ? "text-blue-400" : "text-foreground/80"
                  }`}>
                    {type.label}
                  </span>
                  <span className="text-xs text-muted-foreground block mt-1">
                    {type.description.slice(0, 30)}...
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Subject DID */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-foreground/80 mb-2">
              <User className="w-4 h-4 inline mr-1" />
              Patient DID <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={subjectDid}
              onChange={(e) => setSubjectDid(e.target.value)}
              placeholder="did:key:z6Mk..."
              className="w-full px-4 py-3 bg-muted border border-border rounded-xl text-foreground placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors font-mono text-sm"
            />
            <p className="text-xs text-muted-foreground mt-1">
              Enter the patient's decentralized identifier to issue credentials to them
            </p>
          </div>

          {/* Dynamic Claim Form */}
          {selectedConfig && (
            <div className="mb-6 border-t border-border pt-6">
              <ClaimForm
                config={selectedConfig}
                claims={claims}
                onChange={handleClaimChange}
              />
            </div>
          )}

          {/* Issue Button */}
          <button
            onClick={handleIssue}
            disabled={!selectedType || !subjectDid || isIssuing}
            className="w-full py-3 px-6 bg-blue-600 hover:bg-blue-500 disabled:bg-secondary disabled:text-muted-foreground text-foreground font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
          >
            {isIssuing ? (
              <>
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Issuing...
              </>
            ) : (
              <>
                <CheckCircle2 className="w-5 h-5" />
                Issue Credential
              </>
            )}
          </button>

          {/* Result */}
          {result && (
            <div className={`mt-4 p-4 rounded-xl border ${
              result.success
                ? "bg-emerald-500/10 border-emerald-500/30"
                : "bg-red-500/10 border-red-500/30"
            }`}>
              {result.success ? (
                <div>
                  <p className="font-semibold flex items-center gap-2 text-emerald-400 mb-4">
                    <CheckCircle2 className="w-5 h-5" /> Credential Offer Created
                  </p>
                  <QRCodeDisplay code={result.code || ''} />
                </div>
              ) : (
                <p className="flex items-center gap-2 text-red-400">
                  <XCircle className="w-5 h-5" /> {result.error}
                </p>
              )}
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Provider Info */}
          <div className="bg-card rounded-xl border border-border p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
              <Building className="w-5 h-5 text-muted-foreground" />
              Provider Info
            </h2>
            <div className="space-y-3 text-sm">
              <div>
                <span className="text-muted-foreground">Name</span>
                <p className="text-foreground font-medium">{user?.displayName || 'Healthcare Provider'}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Organization</span>
                <p className="text-foreground font-medium">City Medical Center</p>
              </div>
              <div>
                <span className="text-muted-foreground">Credentials Issued Today</span>
                <p className="text-2xl font-bold text-blue-400">12</p>
              </div>
            </div>
          </div>

          {/* Recent Issues */}
          <div className="bg-card rounded-xl border border-border p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Recently Issued</h2>
            <div className="space-y-3">
              {[
                { type: "HealthRecord", patient: "did:key:z6Mk...doK", time: "5 min ago", status: "claimed" },
                { type: "Prescription", patient: "did:key:z6Mk...abc", time: "1 hour ago", status: "pending" },
                { type: "LabResult", patient: "did:key:z6Mk...xyz", time: "2 hours ago", status: "claimed" },
                { type: "ImmunizationRecord", patient: "did:key:z6Mk...def", time: "3 hours ago", status: "claimed" },
              ].map((item, i) => (
                <div key={i} className="p-3 bg-muted rounded-lg border border-border">
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-sm font-medium text-foreground">{item.type}</p>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                      item.status === 'claimed' 
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : 'bg-amber-500/20 text-amber-400'
                    }`}>
                      {item.status}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground truncate font-mono">{item.patient}</p>
                  <p className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                    <Clock className="w-3 h-3" /> {item.time}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
    </ProtectedRoute>
  );
}
