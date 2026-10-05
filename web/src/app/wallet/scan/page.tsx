/**
 * SSI Healthcare - QR Scan Page
 *
 * Mode-aware QR scan page for the holder wallet.
 * - receive mode: scans OID4VCI offer → resolves offer → accepts
 * - share mode:   scans OID4VP request → resolves request → user selects credentials → submits
 *
 * Supports two credential-offer flows:
 *   1. Internal: offer created by the SSI backend (pre-auth code in our DB)
 *   2. External: offer created by a hospital / external issuer (direct OID4VCI exchange)
 */

'use client';

import * as React from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ArrowLeft,
  QrCode,
  FileText,
  Shield,
  CheckCircle2,
  Building2,
  Calendar,
  Fingerprint,
  Loader2,
} from 'lucide-react';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumCard, CardContent, CardHeader, CardTitle } from '@/components/ui/premium-card';
import { Badge } from '@/components/ui/badge';
import { QRScanner, ManualQRInput } from '@/components/wallet/qr-scanner';
import { cn } from '@/lib/utils';
import { credentialApi, presentationApi, userApi, type Credential } from '@/lib/api';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import {
  parseCredentialOfferUri,
  // `resolveExternalOffer` and `receiveExternalCredential` are no longer called
  // from this page: third-party issuer import is disabled (OpenDiscussion §P4).
  // Both still exist in that module and both throw, so nothing can reach the
  // dead `/api/credentials/store-external` route by any path.
  EXTERNAL_ISSUER_UNSUPPORTED_MESSAGE,
  type ParsedCredentialOffer,
} from '@/lib/api/oid4vciClient';

type FlowType = 'credential-offer' | 'presentation-request' | null;
type FlowStep = 'scan' | 'review' | 'authorize' | 'success';

interface ResolvedOffer {
  offerId: string;
  credentialType: string;
  issuerDid: string;
  issuerName: string;
  previewData: Record<string, unknown>;
  pinRequired: boolean;
  expiresAt: string;
  /** True when this offer is from an external issuer (hospital etc.) */
  isExternal?: boolean;
  /** The full parsed offer for external flows */
  parsedOffer?: ParsedCredentialOffer;
}

interface ResolvedRequest {
  id: string;
  definition: Record<string, unknown>;
  verifierDid: string;
  nonce: string;
  createdAt: number;
  expiresAt: number;
  status: string;
}

/** Extract identifiers from OID4VCI / OID4VP QR codes. */
function parseQRForIds(data: string):
  | { type: 'credential-offer'; preAuthorizedCode: string; parsedOffer: ParsedCredentialOffer }
  | { type: 'presentation-request'; requestId: string }
  | null {
  try {
    if (data.startsWith('openid-credential-offer://') || data.includes('credential_offer')) {
      const offer = parseCredentialOfferUri(data);
      if (offer) {
        return { type: 'credential-offer', preAuthorizedCode: offer.preAuthorizedCode, parsedOffer: offer };
      }
    }

    if (data.startsWith('openid4vp://')) {
      const normalized = data.replace('openid4vp://', 'https://placeholder/');
      const url = new URL(normalized);

      const requestUri = url.searchParams.get('request_uri');
      if (requestUri) {
        const match = requestUri.match(/authorization-request\/([a-f0-9-]{36})/);
        if (match?.[1]) return { type: 'presentation-request', requestId: match[1] };
      }

      const requestParam = url.searchParams.get('request');
      if (requestParam) {
        const req = JSON.parse(decodeURIComponent(requestParam));
        const requestId = req?.presentation_definition?.id as string | undefined;
        if (requestId) return { type: 'presentation-request', requestId };
      }
    }
  } catch {
    // Not a recognized URI
  }
  return null;
}

// FINDING-006: wallet/scan requires authentication
function ScanPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const mode = searchParams.get('mode') as 'receive' | 'share' | null;

  const [step, setStep] = React.useState<FlowStep>('scan');
  const [flowType, setFlowType] = React.useState<FlowType>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [isResolving, setIsResolving] = React.useState(false);

  // Credential offer state
  const [resolvedOffer, setResolvedOffer] = React.useState<ResolvedOffer | null>(null);

  // Presentation request state
  const [resolvedRequest, setResolvedRequest] = React.useState<ResolvedRequest | null>(null);
  const [userCredentials, setUserCredentials] = React.useState<Credential[]>([]);
  const [selectedCredentialIds, setSelectedCredentialIds] = React.useState<string[]>([]);

  const handleScan = async (data: string) => {
    setError(null);
    setIsResolving(true);

    const parsed = parseQRForIds(data);
    if (!parsed) {
      setError('Unrecognized QR code format. Please scan a valid credential offer or verification request.');
      setIsResolving(false);
      return;
    }

    try {
      if (parsed.type === 'credential-offer') {
        const { parsedOffer } = parsed;

        if (!parsedOffer.isInternal) {
          // THIRD-PARTY ISSUER IMPORT IS DISABLED — refused here, at scan time,
          // BEFORE the review screen exists and before any network call to the
          // issuer. See OpenDiscussion §P4 and steno #193.
          //
          // This branch used to call `resolveExternalOffer`, render a review
          // card, and let the user press Accept — which ran the full OID4VCI
          // exchange against the issuer and only then POSTed to
          // `/api/credentials/store-external`, a route the backend does not
          // have. The user reached a 404 having already spent a single-use
          // pre-authorized code. Refusing at scan means the user cannot click
          // into that; `receiveExternalCredential` and `resolveExternalOffer`
          // also throw now, so a future caller cannot reopen the path silently.
          //
          // Restore this branch together with the backend route. The parked
          // implementation is in `@/lib/api/oid4vciClient`.
          setError(EXTERNAL_ISSUER_UNSUPPORTED_MESSAGE);
          return; // `finally` below clears isResolving
        }

        // Internal SSI backend offer — look it up in our DB
        const res = await credentialApi.resolveOffer(parsedOffer.preAuthorizedCode);
        if (!res.data) throw new Error('Invalid response from server');
        setResolvedOffer(res.data);
        setFlowType('credential-offer');
      } else {
        const [reqRes, credsRes] = await Promise.all([
          presentationApi.getRequest(parsed.requestId),
          userApi.getCredentials(),
        ]);

        if (!reqRes.data) throw new Error('Verification request not found');
        setResolvedRequest(reqRes.data);

        const allCreds = credsRes.data?.credentials ?? [];
        const requestedTypes = ((reqRes.data.definition as { types?: string[] }).types ?? []);
        const matching =
          requestedTypes.length > 0
            ? allCreds.filter((c) => c.type.some((t) => requestedTypes.includes(t)))
            : allCreds;

        setUserCredentials(matching);
        setSelectedCredentialIds(matching.map((c) => c.id));
        setFlowType('presentation-request');
      }
      setStep('review');
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to resolve QR code. Please try again.';
      setError(msg);
    } finally {
      setIsResolving(false);
    }
  };

  const handleAccept = async () => {
    setStep('authorize');
    setError(null);

    try {
      if (flowType === 'credential-offer' && resolvedOffer) {
        // Defence in depth, not dead weight. `handleScan` no longer sets
        // `isExternal`, so this should be unreachable — but "should be
        // unreachable" is exactly the assumption that produced the bugs this
        // codebase keeps finding. If a future change starts setting it again
        // before the backend route exists, this fails loudly with the same
        // message the user would have seen at scan time, instead of falling
        // through to `acceptOffer` and looking up an external pre-authorized
        // code in our own database — which would 404 with a misleading
        // "offer not found".
        if (resolvedOffer.isExternal) {
          throw new Error(EXTERNAL_ISSUER_UNSUPPORTED_MESSAGE);
        }
        // Internal SSI backend offer
        await credentialApi.acceptOffer(resolvedOffer.offerId);
      } else if (flowType === 'presentation-request' && resolvedRequest) {
        await presentationApi.submitByIds(resolvedRequest.id, selectedCredentialIds);
      }
      setStep('success');
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Action failed. Please try again.';
      setError(msg);
      setStep('scan');
    }
  };

  const handleDone = () => {
    router.push('/wallet');
  };

  const toggleCredential = (id: string) => {
    setSelectedCredentialIds((prev) =>
      prev.includes(id) ? prev.filter((k) => k !== id) : [...prev, id]
    );
  };

  const modeTitle =
    mode === 'share'
      ? 'Share Credentials'
      : mode === 'receive'
        ? 'Receive Credential'
        : 'Scan QR Code';

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-background/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-2xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            <button
              onClick={() => router.back()}
              className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              <span className="hidden sm:inline">Back</span>
            </button>
            <h1 className="font-semibold text-foreground">
              {step === 'scan' && modeTitle}
              {step === 'review' && (flowType === 'credential-offer' ? 'Credential Offer' : 'Verification Request')}
              {step === 'authorize' && 'Authorizing…'}
              {step === 'success' && 'Success'}
            </h1>
            <div className="w-16" />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-2xl mx-auto px-4 sm:px-6 py-8">
        <AnimatePresence mode="wait">
          {/* Scan Step */}
          {step === 'scan' && (
            <motion.div
              key="scan"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              {mode && (
                <p className="text-sm text-muted-foreground mb-4 text-center">
                  {mode === 'receive'
                    ? 'Scan a credential offer QR code from your healthcare provider'
                    : 'Scan a verification request QR code to share your credentials'}
                </p>
              )}

              {isResolving ? (
                <div className="flex flex-col items-center justify-center py-16 gap-4">
                  <Loader2 className="w-10 h-10 text-primary animate-spin" />
                  <p className="text-muted-foreground">Resolving QR code…</p>
                </div>
              ) : (
                <>
                  <QRScanner onScan={handleScan} />

                  {error && (
                    <div className="mt-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400">
                      {error}
                    </div>
                  )}

                  <div className="mt-8">
                    <ManualQRInput onSubmit={handleScan} />
                  </div>
                </>
              )}
            </motion.div>
          )}

          {/* Review Step — Credential Offer */}
          {step === 'review' && flowType === 'credential-offer' && resolvedOffer && (
            <motion.div
              key="review-offer"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <PremiumCard variant="premium">
                <CardHeader>
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center">
                      <FileText className="w-6 h-6 text-emerald-500" />
                    </div>
                    <div>
                      <CardTitle>New Credential Offer</CardTitle>
                      <p className="text-sm text-muted-foreground">
                        Review and accept to add to your wallet
                      </p>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="space-y-6">
                  {/* Issuer */}
                  <div className="p-4 rounded-lg bg-muted/50">
                    <div className="flex items-center gap-3">
                      <Building2 className="w-5 h-5 text-muted-foreground" />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-foreground">
                            {resolvedOffer.issuerName || resolvedOffer.issuerDid}
                          </span>
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        </div>
                        <p className="text-xs text-muted-foreground font-mono">
                          {resolvedOffer.issuerDid}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Credential type */}
                  <div>
                    <h3 className="font-semibold text-foreground mb-2">
                      {resolvedOffer.credentialType}
                    </h3>
                    {resolvedOffer.pinRequired && (
                      <Badge variant="secondary">PIN required</Badge>
                    )}
                  </div>

                  {/* Preview data */}
                  {resolvedOffer.previewData && Object.keys(resolvedOffer.previewData).length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium text-muted-foreground mb-2">
                        This credential will include:
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {Object.keys(resolvedOffer.previewData).map((key) => (
                          <Badge key={key} variant="secondary">
                            {key.replace(/([A-Z])/g, ' $1').trim()}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Expiry */}
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Calendar className="w-4 h-4" />
                    <span>Offer expires {new Date(resolvedOffer.expiresAt).toLocaleString()}</span>
                  </div>

                  {/* Actions */}
                  <div className="flex gap-3 pt-4">
                    <PremiumButton
                      variant="outline"
                      onClick={() => setStep('scan')}
                      className="flex-1"
                    >
                      Cancel
                    </PremiumButton>
                    <PremiumButton
                      variant="premium"
                      onClick={handleAccept}
                      className="flex-1"
                    >
                      Accept Credential
                    </PremiumButton>
                  </div>
                </CardContent>
              </PremiumCard>
            </motion.div>
          )}

          {/* Review Step — Presentation Request */}
          {step === 'review' && flowType === 'presentation-request' && resolvedRequest && (
            <motion.div
              key="review-request"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <PremiumCard variant="premium">
                <CardHeader>
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-12 h-12 rounded-xl bg-blue-500/10 flex items-center justify-center">
                      <Shield className="w-6 h-6 text-blue-500" />
                    </div>
                    <div>
                      <CardTitle>Verification Request</CardTitle>
                      <p className="text-sm text-muted-foreground">
                        Select which credentials to share
                      </p>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="space-y-6">
                  {/* Verifier */}
                  <div className="p-4 rounded-lg bg-muted/50">
                    <div className="flex items-center gap-3">
                      <Building2 className="w-5 h-5 text-muted-foreground" />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-foreground">
                            {(resolvedRequest.definition as { verifierName?: string }).verifierName || 'Verifier'}
                          </span>
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        </div>
                        <p className="text-xs text-muted-foreground font-mono">
                          {resolvedRequest.verifierDid}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Purpose */}
                  <div>
                    <h3 className="font-semibold text-foreground mb-1">
                      {(resolvedRequest.definition as { purpose?: string }).purpose || 'Credential Verification'}
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      Requested types:{' '}
                      {((resolvedRequest.definition as { types?: string[] }).types ?? []).join(', ') || 'Any credential'}
                    </p>
                  </div>

                  {/* Your matching credentials */}
                  <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-3">
                      {userCredentials.length > 0
                        ? 'Select credentials to share:'
                        : 'No matching credentials in your wallet'}
                    </h4>
                    {userCredentials.length > 0 ? (
                      <div className="space-y-2">
                        {userCredentials.map((cred) => (
                          <label
                            key={cred.id}
                            className={cn(
                              'flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-colors',
                              selectedCredentialIds.includes(cred.id)
                                ? 'border-primary bg-primary/5'
                                : 'border-border hover:border-muted-foreground/50'
                            )}
                          >
                            <input
                              type="checkbox"
                              checked={selectedCredentialIds.includes(cred.id)}
                              onChange={() => toggleCredential(cred.id)}
                              className="sr-only"
                            />
                            <div
                              className={cn(
                                'w-5 h-5 rounded border-2 flex items-center justify-center flex-shrink-0 transition-colors',
                                selectedCredentialIds.includes(cred.id)
                                  ? 'bg-primary border-primary'
                                  : 'border-muted-foreground/50'
                              )}
                            >
                              {selectedCredentialIds.includes(cred.id) && (
                                <CheckCircle2 className="w-3 h-3 text-primary-foreground" />
                              )}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-sm font-medium text-foreground">
                                  {cred.name || cred.type.at(-1) || 'Credential'}
                                </span>
                                <Badge variant="secondary" className="text-xs">
                                  {cred.category}
                                </Badge>
                              </div>
                              <p className="text-xs text-muted-foreground mt-0.5">
                                Issued {new Date(cred.issuedAt).toLocaleDateString()}
                              </p>
                            </div>
                          </label>
                        ))}
                      </div>
                    ) : (
                      <div className="p-4 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-sm text-yellow-400">
                        You don&apos;t have the requested credentials in your wallet. Contact your healthcare provider to obtain them.
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex gap-3 pt-4">
                    <PremiumButton
                      variant="outline"
                      onClick={() => setStep('scan')}
                      className="flex-1"
                    >
                      Decline
                    </PremiumButton>
                    <PremiumButton
                      variant="premium"
                      onClick={handleAccept}
                      className="flex-1"
                      disabled={selectedCredentialIds.length === 0}
                    >
                      Share ({selectedCredentialIds.length})
                    </PremiumButton>
                  </div>
                </CardContent>
              </PremiumCard>
            </motion.div>
          )}

          {/* Authorize Step */}
          {step === 'authorize' && (
            <motion.div
              key="authorize"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="flex flex-col items-center justify-center py-16"
            >
              <motion.div
                animate={{ scale: [1, 1.1, 1] }}
                transition={{ repeat: Infinity, duration: 1.5 }}
                className="w-24 h-24 rounded-full bg-primary/10 flex items-center justify-center mb-6"
              >
                <Fingerprint className="w-12 h-12 text-primary" />
              </motion.div>
              <h2 className="text-xl font-semibold text-foreground mb-2">Processing…</h2>
              <p className="text-muted-foreground text-center">
                Securely completing your request
              </p>
            </motion.div>
          )}

          {/* Success Step */}
          {step === 'success' && (
            <motion.div
              key="success"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="flex flex-col items-center justify-center py-16"
            >
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: 'spring', stiffness: 300, damping: 20 }}
                className="w-20 h-20 rounded-full bg-emerald-500/20 flex items-center justify-center mb-6"
              >
                <CheckCircle2 className="w-10 h-10 text-emerald-500" />
              </motion.div>
              <h2 className="text-xl font-semibold text-foreground mb-2">
                {flowType === 'credential-offer' ? 'Credential Received!' : 'Credentials Shared!'}
              </h2>
              <p className="text-muted-foreground text-center mb-8">
                {flowType === 'credential-offer'
                  ? 'The credential has been added to your wallet.'
                  : 'Your credentials have been shared securely.'}
              </p>
              <PremiumButton variant="premium" onClick={handleDone}>
                Return to Wallet
              </PremiumButton>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

export default function ScanPage() {
  return (
    <ProtectedRoute requireWallet>
      <ScanPageContent />
    </ProtectedRoute>
  );
}
