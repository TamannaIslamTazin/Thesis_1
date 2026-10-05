/**
 * SSI Healthcare Web - Verifier Portal
 *
 * Doctors and insurance companies verify patient credentials
 * via OID4VP presentation requests.
 * 
 * Protected: Requires authentication with wallet (verifier must have DID)
 */

"use client";

import React, { useState } from "react";
import {
  CheckCircle2,
  XCircle,
  Clock,
  Send,
} from "lucide-react";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { useAuth } from "@/hooks/useAuth";
import { verifierApi } from "@/lib/api";
import QRCode from "react-qr-code";

export default function VerifierPage() {
  const { user } = useAuth();
  const [holderDid, setHolderDid] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<string[]>(["HealthRecord"]);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{
    verified: boolean;
    requestUrl?: string;
    requestQrData?: string;
    errors: string[];
  } | null>(null);
  const [history, setHistory] = useState<Array<{
    id: string;
    holderDid?: string;
    credentialType?: string;
    status: string;
    createdAt: string;
  }>>([]);

  // Load verification history
  React.useEffect(() => {
    async function loadHistory() {
      try {
        const res = await verifierApi.getVerificationHistory({ limit: 10 });
        if (res.data) {
          const presentations = (res.data as unknown as { presentations: Array<{
            id: string;
            holderDid?: string;
            credentialIds?: string[];
            requestedTypes?: string[];
            status: string;
            createdAt: string;
          }> }).presentations || [];
          setHistory(presentations.map(v => ({
            id: v.id,
            holderDid: v.holderDid,
            credentialType: v.requestedTypes?.[0] ?? v.credentialIds?.[0] ?? 'Unknown',
            status: v.status,
            createdAt: v.createdAt,
          })));
        }
      } catch {
        // History loading is non-critical
      }
    }
    loadHistory();
  }, [verifyResult]); // Reload after new verification

  const toggleType = (type: string) => {
    setSelectedTypes(prev =>
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    );
  };

  const handleCreateRequest = async () => {
    if (!holderDid || !user?.did || selectedTypes.length === 0) return;
    setVerifying(true);
    setVerifyResult(null);

    try {
      const res = await verifierApi.createPresentationRequest({
        // FINDING-009: Pass holderDid so the backend knows which wallet to direct the request to.
        holderDid,
        definition: {
          id: `verify-${Date.now()}`,
          name: 'Health Record Verification',
          purpose: 'Health Record Verification',
          inputDescriptors: selectedTypes.map((type, i) => ({
            id: `desc_${i}`,
            name: type,
            purpose: `Verify ${type}`,
            constraints: {
              fields: [{
                path: ['$.type'],
                filter: { type: 'array' },
              }],
            },
          })),
        },
      });

      if (res.data) {
        const qrData = res.data.requestByReference ?? res.data.requestUri ?? '';
        setVerifyResult({ verified: true, requestUrl: qrData, requestQrData: qrData, errors: [] });
      } else {
        setVerifyResult({ verified: false, errors: [res.error?.message || "Failed"] });
      }
    } catch (err) {
      setVerifyResult({ verified: false, errors: ["Failed to connect to backend"] });
    } finally {
      setVerifying(false);
    }
  };

  return (
    <ProtectedRoute requireWallet>
      <div className="p-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground">Verify Credentials</h1>
          <p className="text-muted-foreground mt-1">
            Request and verify patient credentials via OID4VP
          </p>
          {user?.did && (
            <p className="text-xs text-muted-foreground mt-2 font-mono">
              Verifying as: {user.did.slice(0, 30)}...
            </p>
          )}
        </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Verification Form */}
        <div className="bg-card rounded-xl border border-border p-6">
          <h2 className="text-lg font-semibold text-foreground mb-6">
            Create Verification Request
          </h2>

          <div className="mb-6">
            <label className="block text-sm font-medium text-foreground/80 mb-2">
              Patient / Holder DID
            </label>
            <input
              type="text"
              value={holderDid}
              onChange={(e) => setHolderDid(e.target.value)}
              placeholder="did:key:z6Mk..."
              className="w-full px-4 py-3 bg-muted border border-border rounded-xl text-foreground placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
            />
          </div>

          <div className="mb-6">
            <label className="block text-sm font-medium text-foreground/80 mb-3">
              Requested Credentials
            </label>
            <div className="space-y-2">
              {[
                { type: "HealthRecord", label: "Health Record", checked: true },
                { type: "LabResult", label: "Lab Results", checked: false },
                { type: "ImmunizationRecord", label: "Immunization Record", checked: false },
                { type: "Prescription", label: "Prescription", checked: false },
              ].map((item) => (
                <label key={item.type} className="flex items-center gap-3 p-3 bg-muted rounded-lg border border-border cursor-pointer hover:border-ring transition-colors">
                  <input
                    type="checkbox"
                    checked={selectedTypes.includes(item.type)}
                    onChange={() => toggleType(item.type)}
                    className="w-4 h-4 rounded border-slate-600 text-blue-500 focus:ring-blue-500"
                  />
                  <span className="text-sm text-foreground/80">{item.label}</span>
                </label>
              ))}
            </div>
          </div>

          <button
            onClick={handleCreateRequest}
            disabled={!holderDid || verifying}
            className="w-full py-3 px-6 bg-purple-600 hover:bg-purple-500 disabled:bg-secondary disabled:text-muted-foreground text-foreground font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
          >
            {verifying ? (
              "Creating Request..."
            ) : (
              <>
                <Send className="w-4 h-4" /> Request Presentation
              </>
            )}
          </button>

          {verifyResult && (
            <div className={`mt-4 p-4 rounded-xl border ${
              verifyResult.verified
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                : "bg-red-500/10 border-red-500/30 text-red-400"
            }`}>
              {verifyResult.verified ? (
                <div>
                  <p className="font-semibold flex items-center gap-2 mb-3">
                    <CheckCircle2 className="w-4 h-4" /> Presentation Request Created
                  </p>
                  {verifyResult.requestQrData ? (
                    <div className="flex flex-col items-center gap-3 mt-2">
                      <p className="text-sm text-emerald-300">Ask the patient to scan this QR code with their SSI wallet:</p>
                      <div className="bg-white p-3 rounded-lg">
                        <QRCode value={verifyResult.requestQrData} size={180} />
                      </div>
                      <p className="text-xs text-muted-foreground break-all max-w-xs text-center opacity-60">{verifyResult.requestQrData.slice(0, 80)}…</p>
                    </div>
                  ) : (
                    <p className="text-sm mt-1">Request sent to holder&apos;s DID.</p>
                  )}
                </div>
              ) : (
                <div>
                  <p className="font-semibold flex items-center gap-2">
                    <XCircle className="w-4 h-4" /> Request Failed
                  </p>
                  {verifyResult.errors.map((err, i) => (
                    <p key={i} className="text-sm mt-1">{err}</p>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Verification History */}
        <div className="bg-card rounded-xl border border-border p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">
            Verification History
          </h2>
          <div className="space-y-3">
            {history.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No verification history yet</p>
            ) : history.map((item) => (
              <div key={item.id} className="p-4 bg-muted rounded-lg border border-border">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-foreground">{item.credentialType || 'Credential'}</span>
                  <span className={`text-xs font-medium px-2 py-1 rounded-full flex items-center gap-1 ${
                    item.status === "verified"
                      ? "text-emerald-400 bg-emerald-400/10"
                      : "text-red-400 bg-red-400/10"
                  }`}>
                    {item.status === "verified" ? (
                      <><CheckCircle2 className="w-3 h-3" /> Verified</>
                    ) : (
                      <><XCircle className="w-3 h-3" /> {item.status}</>
                    )}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground truncate">{item.holderDid || 'Unknown'}</p>
                <p className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                  <Clock className="w-3 h-3" /> {new Date(item.createdAt).toLocaleString()}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
    </ProtectedRoute>
  );
}
