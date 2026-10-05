'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import {
  ArrowLeft,
  FileText,
  Calendar,
  Building2,
  CheckCircle2,
  XCircle,
  QrCode,
  Loader2,
  Inbox,
} from 'lucide-react';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumCard, CardContent } from '@/components/ui/premium-card';
import { Badge } from '@/components/ui/badge';
import { credentialApi, type CredentialOffer } from '@/lib/api';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';

// FINDING-006: wallet/request requires authentication
function WalletRequestPageContent() {
  const router = useRouter();
  const [offers, setOffers] = React.useState<CredentialOffer[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [actionStates, setActionStates] = React.useState<Record<string, 'idle' | 'loading' | 'done'>>({});

  React.useEffect(() => {
    loadOffers();
  }, []);

  const loadOffers = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await credentialApi.getOffers();
      setOffers(result.data ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load offers');
    } finally {
      setIsLoading(false);
    }
  };

  const handleAccept = async (offerId: string) => {
    setActionStates((prev) => ({ ...prev, [offerId]: 'loading' }));
    try {
      await credentialApi.acceptOffer(offerId);
      setActionStates((prev) => ({ ...prev, [offerId]: 'done' }));
      setTimeout(() => {
        setOffers((prev) => prev.filter((o) => o.id !== offerId));
      }, 1500);
    } catch {
      setActionStates((prev) => ({ ...prev, [offerId]: 'idle' }));
    }
  };

  const handleReject = async (offerId: string) => {
    setActionStates((prev) => ({ ...prev, [offerId]: 'loading' }));
    try {
      await credentialApi.rejectOffer(offerId);
      setOffers((prev) => prev.filter((o) => o.id !== offerId));
    } catch (err) {
      // FINDING-029: Surface rejection errors to the user instead of silently swallowing them
      setActionStates((prev) => ({ ...prev, [offerId]: 'idle' }));
      toast.error(err instanceof Error ? err.message : 'Failed to reject offer. Please try again.');
    }
  };

        const pendingOffers = offers.filter((o) => o.status === 'PENDING');

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-background/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-2xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            <button
              onClick={() => router.push('/wallet')}
              className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              <span className="hidden sm:inline">Back</span>
            </button>
            <h1 className="font-semibold text-foreground">Pending Offers</h1>
            <div className="w-16" />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-2xl mx-auto px-4 sm:px-6 py-8">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-16 gap-4">
            <Loader2 className="w-8 h-8 text-primary animate-spin" />
            <p className="text-muted-foreground">Loading offers…</p>
          </div>
        ) : error ? (
          <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400 text-center">
            {error}
            <button onClick={loadOffers} className="block mx-auto mt-2 underline text-red-300">
              Try again
            </button>
          </div>
        ) : pendingOffers.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-4 text-center">
            <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center">
              <Inbox className="w-8 h-8 text-muted-foreground" />
            </div>
            <h2 className="text-xl font-semibold text-foreground">No Pending Offers</h2>
            <p className="text-muted-foreground max-w-xs">
              You have no pending credential offers. Scan a QR code from your healthcare provider to receive credentials.
            </p>
            <PremiumButton
              variant="premium"
              onClick={() => router.push('/wallet/scan?mode=receive')}
              className="mt-2"
            >
              <QrCode className="w-4 h-4 mr-2" />
              Scan QR Code
            </PremiumButton>
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              {pendingOffers.length} pending credential {pendingOffers.length === 1 ? 'offer' : 'offers'} awaiting your response.
            </p>

            {pendingOffers.map((offer, i) => {
              const state = actionStates[offer.id] ?? 'idle';
              const isDone = state === 'done';
              const isLoading = state === 'loading';

              return (
                <motion.div
                  key={offer.id}
                  initial={{ opacity: 0, y: 16 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.06 }}
                >
                  <PremiumCard variant="default">
                    <CardContent className="p-5">
                      {isDone ? (
                        <div className="flex items-center gap-3 text-emerald-400">
                          <CheckCircle2 className="w-5 h-5" />
                          <span>Credential accepted and added to your wallet!</span>
                        </div>
                      ) : (
                        <>
                          {/* Header row */}
                          <div className="flex items-start gap-3 mb-4">
                            <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                              <FileText className="w-5 h-5 text-primary" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <h3 className="font-semibold text-foreground truncate">
                                {offer.credentialType}
                              </h3>
                              <Badge variant="secondary" className="mt-1 text-xs">
                                {offer.status}
                              </Badge>
                            </div>
                          </div>

                          {/* Issuer */}
                          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                            <Building2 className="w-4 h-4 flex-shrink-0" />
                            <span className="truncate font-mono text-xs">
                              {offer.issuerName || offer.issuerDid}
                            </span>
                          </div>

                          {/* Expiry */}
                          {offer.expiresAt && (
                            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                              <Calendar className="w-4 h-4 flex-shrink-0" />
                              <span>
                                Expires {new Date(offer.expiresAt).toLocaleDateString()}
                              </span>
                            </div>
                          )}

                          {/* Actions */}
                          <div className="flex gap-2">
                            <PremiumButton
                              variant="outline"
                              size="sm"
                              onClick={() => handleReject(offer.id)}
                              disabled={isLoading}
                              className="flex-1 text-red-400 border-red-500/30 hover:bg-red-500/10"
                            >
                              <XCircle className="w-4 h-4 mr-1" />
                              Decline
                            </PremiumButton>
                            <PremiumButton
                              variant="premium"
                              size="sm"
                              onClick={() => handleAccept(offer.id)}
                              disabled={isLoading}
                              className="flex-1"
                            >
                              {isLoading ? (
                                <Loader2 className="w-4 h-4 animate-spin" />
                              ) : (
                                <>
                                  <CheckCircle2 className="w-4 h-4 mr-1" />
                                  Accept
                                </>
                              )}
                            </PremiumButton>
                          </div>
                        </>
                      )}
                    </CardContent>
                  </PremiumCard>
                </motion.div>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
}

export default function WalletRequestPage() {
  return (
    <ProtectedRoute requireWallet>
      <WalletRequestPageContent />
    </ProtectedRoute>
  );
}
