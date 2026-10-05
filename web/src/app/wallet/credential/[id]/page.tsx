/**
 * SSI Healthcare - Credential Detail Page
 *
 * Displays full credential information with selective disclosure controls.
 * Allows users to share specific attributes without revealing all data.
 */

'use client';

import * as React from 'react';
import { useParams, useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ArrowLeft,
  Shield,
  Share2,
  Download,
  Trash2,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Eye,
  EyeOff,
  Copy,
  QrCode,
  MoreVertical,
  Building2,
  Calendar,
  FileText,
  Lock,
  Unlock,
  ChevronDown,
  ChevronUp,
  Fingerprint,
  Loader2,
} from 'lucide-react';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumCard, CardContent } from '@/components/ui/premium-card';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose } from '@/components/ui/dialog';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';
import { credentialCategories, type CredentialCategory } from '@/lib/design-system';
import { useCredentials } from '@/hooks/useCredentials';
import { verifierApi, credentialApi, type Credential } from '@/lib/api';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';

/**
 * Derive the displayable attributes of a credential.
 *
 * These come from the VC's `credentialSubject` — the issuer's claims about the
 * holder. The previous version iterated the whole `credentialData` column,
 * which rendered `@context`, `type`, `issuer` and `proof` as if they were
 * medical attributes.
 *
 * `id` is excluded because it is the subject's DID, shown elsewhere, and it is
 * never a disclosable claim.
 */
function deriveAttributes(cred: Credential) {
  const sensitiveKeys = new Set(['dateOfBirth', 'patientId', 'ssn', 'healthcareProvider', 'mrn']);
  return Object.entries(cred.credential.credentialSubject)
    .filter(([key, value]) => key !== 'id' && value !== undefined && value !== null)
    .map(([key, value]) => ({
      key,
      label: key.replace(/([A-Z])/g, ' $1').replace(/^./, (s) => s.toUpperCase()),
      value: typeof value === 'object' ? JSON.stringify(value) : String(value),
      sensitive: sensitiveKeys.has(key),
    }));
}

function mapApiStatus(status: Credential['status']): 'valid' | 'expired' | 'revoked' | 'pending' {
  switch (status) {
    case 'ACTIVE': return 'valid';
    case 'EXPIRED': return 'expired';
    case 'REVOKED': case 'SUSPENDED': return 'revoked';
    case 'PENDING': return 'pending';
    default: return 'valid';
  }
}

const statusConfig = {
  valid: {
    icon: CheckCircle2,
    color: 'text-emerald-400',
    bg: 'bg-emerald-400/10',
    label: 'Valid',
  },
  expired: {
    icon: Clock,
    color: 'text-amber-400',
    bg: 'bg-amber-400/10',
    label: 'Expired',
  },
  revoked: {
    icon: AlertTriangle,
    color: 'text-red-400',
    bg: 'bg-red-400/10',
    label: 'Revoked',
  },
  pending: {
    icon: Clock,
    color: 'text-blue-400',
    bg: 'bg-blue-400/10',
    label: 'Pending',
  },
};

// FINDING-006: wallet/credential/[id] requires authentication
function CredentialDetailPageContent() {
  const params = useParams();
  const router = useRouter();
  const { getCredential, deleteCredential } = useCredentials();
  const [credential, setCredential] = React.useState<Credential | null>(null);
  const [isLoading, setIsLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [showSensitive, setShowSensitive] = React.useState<Record<string, boolean>>({});
  const [selectedAttributes, setSelectedAttributes] = React.useState<string[]>([]);
  const [isShareDialogOpen, setIsShareDialogOpen] = React.useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = React.useState(false);
  const [shareStep, setShareStep] = React.useState<'select' | 'confirm' | 'biometric' | 'success'>('select');
  const [expandedSections, setExpandedSections] = React.useState({
    attributes: true,
    proofs: false,
    history: false,
  });

  React.useEffect(() => {
    const id = params.id as string;
    if (!id) return;
    setIsLoading(true);
    getCredential(id)
      .then((cred) => {
        if (cred) setCredential(cred);
        else setLoadError('Credential not found');
      })
      .catch(() => setLoadError('Failed to load credential'))
      .finally(() => setIsLoading(false));
  }, [params.id, getCredential]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (loadError || !credential) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center gap-4">
        <AlertTriangle className="w-12 h-12 text-red-400" />
        <p className="text-muted-foreground">{loadError || 'Credential not found'}</p>
        <PremiumButton variant="outline" onClick={() => router.push('/wallet')}>
          Back to Wallet
        </PremiumButton>
      </div>
    );
  }

  const displayStatus = mapApiStatus(credential.status);
  const categoryKey = credential.category.toLowerCase() as CredentialCategory;
  const categoryData = credentialCategories[categoryKey] || credentialCategories.general;
  const StatusIcon = statusConfig[displayStatus].icon;
  const attributes = deriveAttributes(credential);

  const toggleSensitive = (key: string) => {
    setShowSensitive((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const toggleAttribute = (key: string) => {
    setSelectedAttributes((prev) =>
      prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]
    );
  };

  const toggleSection = (section: keyof typeof expandedSections) => {
    setExpandedSections((prev) => ({ ...prev, [section]: !prev[section] }));
  };

  const handleShare = () => {
    setShareStep('select');
    setIsShareDialogOpen(true);
  };

  const handleShareConfirm = async () => {
    setShareStep('biometric');
    try {
      // FINDING-013: Use the holder presentation endpoint, not verifierApi.
      // verifierApi.createPresentationRequest is a *verifier* call — the holder
      // submits credentials via credentialApi (which calls the holder's own endpoint).
      await credentialApi.shareCredential(credential.id, {
        selectedAttributes,
        recipientDid: undefined, // set by user flow if needed
      });
      setShareStep('success');
    } catch (err) {
      // FINDING-026: Replace alert() with non-blocking toast notification
      console.error('Credential share failed:', err);
      setShareStep('select');
      toast.error(err instanceof Error ? err.message : 'Failed to share credential. Please try again.');
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(text);
      } else {
        const el = document.createElement('textarea');
        el.value = text;
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);
      }
      toast.success('Copied to clipboard');
    } catch {
      toast.error('Failed to copy to clipboard');
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-background/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-4xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            <button
              onClick={() => router.back()}
              className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              <span className="hidden sm:inline">Back to Wallet</span>
            </button>

            <div className="flex items-center gap-2">
              <PremiumButton variant="outline" size="sm" onClick={handleShare}>
                <Share2 className="w-4 h-4 mr-2" />
                Share
              </PremiumButton>
              
              <DropdownMenu>
                <DropdownMenuTrigger className="p-2 rounded-lg hover:bg-muted transition-colors">
                  <MoreVertical className="w-5 h-5 text-muted-foreground" />
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem>
                    <QrCode className="w-4 h-4 mr-2" />
                    Show QR Code
                  </DropdownMenuItem>
                  <DropdownMenuItem>
                    <Download className="w-4 h-4 mr-2" />
                    Export
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    className="text-red-400"
                    onClick={() => setIsDeleteDialogOpen(true)}
                  >
                    <Trash2 className="w-4 h-4 mr-2" />
                    Delete
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-4 sm:px-6 py-8">
        {/* Credential Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <PremiumCard variant="premium" className="overflow-hidden">
            {/* Category banner */}
            <div
              className="h-2"
              style={{ backgroundColor: categoryData.color }}
            />
            
            <CardContent className="p-6">
              <div className="flex items-start gap-4">
                {/* Icon */}
                <div
                  className="w-16 h-16 rounded-2xl flex items-center justify-center flex-shrink-0"
                  style={{ backgroundColor: `${categoryData.color}20` }}
                >
                  <FileText
                    className="w-8 h-8"
                    style={{ color: categoryData.color }}
                  />
                </div>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <h1 className="text-2xl font-bold text-foreground mb-1">
                        {credential.name}
                      </h1>
                      <p className="text-muted-foreground">
                        {credential.type.join(', ')}
                      </p>
                    </div>
                    
                    {/* Status badge */}
                    <div
                      className={cn(
                        'flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium',
                        statusConfig[displayStatus].bg,
                        statusConfig[displayStatus].color
                      )}
                    >
                      <StatusIcon className="w-4 h-4" />
                      {statusConfig[displayStatus].label}
                    </div>
                  </div>

                  {/* Issuer */}
                  <div className="mt-4 flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                    <Building2 className="w-5 h-5 text-muted-foreground" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-foreground">
                          {credential.issuerDid.split(':').slice(0, 3).join(':')}
                        </span>
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      </div>
                      <p className="text-xs text-muted-foreground truncate">
                        {credential.issuerDid}
                      </p>
                    </div>
                    <button
                      onClick={() => copyToClipboard(credential.issuerDid)}
                      className="p-1.5 rounded hover:bg-muted transition-colors"
                    >
                      <Copy className="w-4 h-4 text-muted-foreground" />
                    </button>
                  </div>

                  {/* Dates */}
                  <div className="mt-4 grid grid-cols-2 gap-4">
                    <div className="flex items-center gap-2 text-sm">
                      <Calendar className="w-4 h-4 text-muted-foreground" />
                      <span className="text-muted-foreground">Issued:</span>
                      <span className="text-foreground">
                        {new Date(credential.issuedAt).toLocaleDateString()}
                      </span>
                    </div>
                    {credential.expiresAt && (
                      <div className="flex items-center gap-2 text-sm">
                        <Clock className="w-4 h-4 text-muted-foreground" />
                        <span className="text-muted-foreground">Expires:</span>
                        <span className={cn(
                          'font-medium',
                          new Date(credential.expiresAt) < new Date()
                            ? 'text-amber-400'
                            : 'text-foreground'
                        )}>
                          {new Date(credential.expiresAt).toLocaleDateString()}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </PremiumCard>
        </motion.div>

        {/* Attributes Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mb-6"
        >
          <PremiumCard variant="elevated">
            <button
              onClick={() => toggleSection('attributes')}
              className="w-full flex items-center justify-between p-4 text-left"
            >
              <div className="flex items-center gap-3">
                <FileText className="w-5 h-5 text-primary" />
                <span className="font-semibold text-foreground">Credential Attributes</span>
                <Badge variant="secondary">{attributes.length}</Badge>
              </div>
              {expandedSections.attributes ? (
                <ChevronUp className="w-5 h-5 text-muted-foreground" />
              ) : (
                <ChevronDown className="w-5 h-5 text-muted-foreground" />
              )}
            </button>
            
            <AnimatePresence>
              {expandedSections.attributes && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden"
                >
                  <div className="px-4 pb-4 space-y-2">
                    {attributes.map((attr) => (
                      <div
                        key={attr.key}
                        className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          {attr.sensitive ? (
                            <Lock className="w-4 h-4 text-amber-400" />
                          ) : (
                            <Unlock className="w-4 h-4 text-muted-foreground" />
                          )}
                          <div>
                            <p className="text-sm text-muted-foreground">
                              {attr.label}
                            </p>
                            <p className="font-medium text-foreground">
                              {attr.sensitive && !showSensitive[attr.key]
                                ? '••••••••'
                                : attr.value}
                            </p>
                          </div>
                        </div>
                        
                        <div className="flex items-center gap-2">
                          {attr.sensitive && (
                            <button
                              onClick={() => toggleSensitive(attr.key)}
                              className="p-1.5 rounded hover:bg-muted transition-colors"
                            >
                              {showSensitive[attr.key] ? (
                                <EyeOff className="w-4 h-4 text-muted-foreground" />
                              ) : (
                                <Eye className="w-4 h-4 text-muted-foreground" />
                              )}
                            </button>
                          )}
                          <button
                            onClick={() => copyToClipboard(attr.value)}
                            className="p-1.5 rounded hover:bg-muted transition-colors"
                          >
                            <Copy className="w-4 h-4 text-muted-foreground" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </PremiumCard>
        </motion.div>

        {/* Proofs Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mb-6"
        >
          <PremiumCard variant="elevated">
            <button
              onClick={() => toggleSection('proofs')}
              className="w-full flex items-center justify-between p-4 text-left"
            >
              <div className="flex items-center gap-3">
                <Shield className="w-5 h-5 text-emerald-400" />
                <span className="font-semibold text-foreground">Cryptographic Proofs</span>
                <Badge variant="secondary" className="bg-emerald-400/10 text-emerald-400">
                  Verified
                </Badge>
              </div>
              {expandedSections.proofs ? (
                <ChevronUp className="w-5 h-5 text-muted-foreground" />
              ) : (
                <ChevronDown className="w-5 h-5 text-muted-foreground" />
              )}
            </button>
            
            <AnimatePresence>
              {expandedSections.proofs && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden"
                >
                  <div className="px-4 pb-4">
                    <div className="p-3 rounded-lg bg-muted/30">
                      <div className="flex items-center gap-2 mb-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <span className="font-mono text-sm text-foreground">
                          {/* Read the real proof, across both data models.
                              VC 2.0 secures a credential with an ENVELOPING
                              proof — the compact JWT in `credentialJwt` — and
                              has no `proof` member at all, so reading only
                              `proof.type` labelled every VC 2.0 credential
                              "Unsigned" despite it being perfectly signed.
                              VC 1.1 credentials still embed JwtProof2020. */}
                          {credential.credential.proof?.type
                            ?? (credential.credentialJwt ? 'JWT (enveloping proof)' : 'Unsigned')}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Created: {new Date(credential.issuedAt).toLocaleString()}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Hash: {credential.credentialHash.slice(0, 32)}…
                      </p>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </PremiumCard>
        </motion.div>
      </main>

      {/* Share Dialog with Selective Disclosure */}
      <Dialog open={isShareDialogOpen} onOpenChange={setIsShareDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {shareStep === 'select' && 'Select Attributes to Share'}
              {shareStep === 'confirm' && 'Confirm Sharing'}
              {shareStep === 'biometric' && 'Verify Your Identity'}
              {shareStep === 'success' && 'Shared Successfully'}
            </DialogTitle>
            <DialogDescription>
              {shareStep === 'select' &&
                'Choose which information to include in your presentation.'}
              {shareStep === 'confirm' &&
                'Review the data you are about to share.'}
              {shareStep === 'biometric' &&
                'Use biometrics to authorize this sharing.'}
              {shareStep === 'success' &&
                'Your credential has been shared securely.'}
            </DialogDescription>
          </DialogHeader>

          <AnimatePresence mode="wait">
            {shareStep === 'select' && (
              <motion.div
                key="select"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-2 max-h-64 overflow-y-auto"
              >
                {attributes.map((attr) => (
                  <label
                    key={attr.key}
                    className={cn(
                      'flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-colors',
                      selectedAttributes.includes(attr.key)
                        ? 'border-primary bg-primary/5'
                        : 'border-border hover:border-muted-foreground/50'
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={selectedAttributes.includes(attr.key)}
                      onChange={() => toggleAttribute(attr.key)}
                      className="sr-only"
                    />
                    <div className={cn(
                      'w-5 h-5 rounded border-2 flex items-center justify-center transition-colors',
                      selectedAttributes.includes(attr.key)
                        ? 'bg-primary border-primary'
                        : 'border-muted-foreground/50'
                    )}>
                      {selectedAttributes.includes(attr.key) && (
                        <CheckCircle2 className="w-3 h-3 text-primary-foreground" />
                      )}
                    </div>
                    <div className="flex-1">
                      <p className="text-sm font-medium text-foreground">
                        {attr.label}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {attr.sensitive ? '(Sensitive)' : attr.value}
                      </p>
                    </div>
                  </label>
                ))}
              </motion.div>
            )}

            {shareStep === 'confirm' && (
              <motion.div
                key="confirm"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-4"
              >
                <div className="p-4 rounded-lg bg-muted/50">
                  <p className="text-sm text-muted-foreground mb-2">
                    You are sharing {selectedAttributes.length} attributes:
                  </p>
                  <ul className="space-y-1">
                    {selectedAttributes.map((key) => {
                      const attr = attributes.find((a) => a.key === key);
                      return attr ? (
                        <li key={key} className="text-sm text-foreground flex items-center gap-2">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          {attr.label}
                        </li>
                      ) : null;
                    })}
                  </ul>
                </div>
              </motion.div>
            )}

            {shareStep === 'biometric' && (
              <motion.div
                key="biometric"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="flex flex-col items-center py-8"
              >
                <motion.div
                  animate={{ scale: [1, 1.1, 1] }}
                  transition={{ repeat: Infinity, duration: 1.5 }}
                  className="w-20 h-20 rounded-full bg-primary/10 flex items-center justify-center mb-4"
                >
                  <Fingerprint className="w-10 h-10 text-primary" />
                </motion.div>
                <p className="text-muted-foreground">Verifying...</p>
              </motion.div>
            )}

            {shareStep === 'success' && (
              <motion.div
                key="success"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="flex flex-col items-center py-8"
              >
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 300, damping: 20 }}
                  className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center mb-4"
                >
                  <CheckCircle2 className="w-8 h-8 text-emerald-500" />
                </motion.div>
                <p className="font-medium text-foreground">Credential Shared</p>
                <p className="text-sm text-muted-foreground">
                  {selectedAttributes.length} attributes were shared securely.
                </p>
              </motion.div>
            )}
          </AnimatePresence>

          <DialogFooter>
            {shareStep === 'select' && (
              <>
                <DialogClose>
                  <PremiumButton variant="outline">Cancel</PremiumButton>
                </DialogClose>
                <PremiumButton
                  variant="premium"
                  disabled={selectedAttributes.length === 0}
                  onClick={() => setShareStep('confirm')}
                >
                  Continue ({selectedAttributes.length})
                </PremiumButton>
              </>
            )}
            {shareStep === 'confirm' && (
              <>
                <PremiumButton variant="outline" onClick={() => setShareStep('select')}>
                  Back
                </PremiumButton>
                <PremiumButton variant="premium" onClick={handleShareConfirm}>
                  <Fingerprint className="w-4 h-4 mr-2" />
                  Authorize
                </PremiumButton>
              </>
            )}
            {shareStep === 'success' && (
              <PremiumButton
                variant="premium"
                onClick={() => setIsShareDialogOpen(false)}
                className="w-full"
              >
                Done
              </PremiumButton>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Credential?</DialogTitle>
            <DialogDescription>
              This will permanently remove this credential from your wallet.
              This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose>
              <PremiumButton variant="outline">Cancel</PremiumButton>
            </DialogClose>
            <PremiumButton
              variant="destructive"
              onClick={async () => {
                try {
                  await deleteCredential(credential.id);
                  setIsDeleteDialogOpen(false);
                  router.push('/wallet');
                } catch (err) {
                  toast.error(err instanceof Error ? err.message : 'Failed to delete credential');
                }
              }}
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Delete
            </PremiumButton>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default function CredentialDetailPage() {
  return (
    <ProtectedRoute requireWallet>
      <CredentialDetailPageContent />
    </ProtectedRoute>
  );
}
