/**
 * SSI Healthcare - Wallet Setup Wizard
 *
 * Guides users through frictionless wallet creation with progressive disclosure.
 * Abstracts complexity of DID/key generation behind familiar UX patterns.
 */

'use client';

import * as React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import {
  CheckCircle2,
  Shield,
  Fingerprint,
  Key,
  Wallet,
  ArrowRight,
  Loader2,
  ChevronLeft,
  Sparkles,
  Cloud,
  Smartphone,
} from 'lucide-react';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumCard, PremiumCardContent } from '@/components/ui/premium-card';
import { useAuth } from '@/hooks/useAuth';
import { authApi } from '@/lib/api';

type WizardStep = 'welcome' | 'security' | 'backup' | 'complete';

interface WalletSetupWizardProps {
  onComplete: () => void;
  userEmail?: string;
  userName?: string;
}

const stepConfig = {
  welcome: {
    icon: Wallet,
    title: 'Your Healthcare Wallet',
    subtitle: 'Securely manage your medical credentials',
  },
  security: {
    icon: Shield,
    title: 'Enhanced Security',
    subtitle: 'Protect your identity with biometrics',
  },
  backup: {
    icon: Key,
    title: 'Recovery Setup',
    subtitle: 'Never lose access to your credentials',
  },
  complete: {
    icon: CheckCircle2,
    title: 'All Set!',
    subtitle: 'Your wallet is ready to use',
  },
};

const wizardSteps: WizardStep[] = ['welcome', 'security', 'backup', 'complete'];

export function WalletSetupWizard({
  onComplete,
  userEmail,
  userName,
}: WalletSetupWizardProps) {
  const { setupWallet } = useAuth();
  const [currentStep, setCurrentStep] = React.useState<WizardStep>('welcome');
  const [isProcessing, setIsProcessing] = React.useState(false);
  const [biometricEnabled, setBiometricEnabled] = React.useState(false);
  const [recoveryMethod, setRecoveryMethod] = React.useState<'cloud' | 'device' | null>(null);
  const [walletDid, setWalletDid] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  
  const currentStepIndex = wizardSteps.indexOf(currentStep);
  const progress = ((currentStepIndex + 1) / wizardSteps.length) * 100;

  const handleNext = async () => {
    if (currentStep === 'complete') {
      onComplete();
      return;
    }
    
    setIsProcessing(true);
    setError(null);
    
    try {
      if (currentStep === 'welcome') {
        // Create the wallet via real API
        const result = await setupWallet();
        setWalletDid(result.did);
      } else if (currentStep === 'security' && biometricEnabled) {
        // Register a passkey for biometric auth
        try {
          const optionsRes = await authApi.getPasskeyRegistrationOptions();
          if (optionsRes.data) {
            const credential = await navigator.credentials.create({
              publicKey: {
                challenge: Uint8Array.from(atob(optionsRes.data.challenge), c => c.charCodeAt(0)),
                rp: optionsRes.data.rp,
                user: {
                  id: Uint8Array.from(atob(optionsRes.data.user.id), c => c.charCodeAt(0)),
                  name: optionsRes.data.user.name,
                  displayName: optionsRes.data.user.displayName,
                },
                pubKeyCredParams: optionsRes.data.pubKeyCredParams.map(p => ({
                  ...p,
                  type: p.type as 'public-key',
                })),
                timeout: optionsRes.data.timeout ?? 60000,
                authenticatorSelection: optionsRes.data.authenticatorSelection as AuthenticatorSelectionCriteria | undefined,
              },
            });
            if (credential) {
              await authApi.verifyPasskeyRegistration(credential);
            }
          }
        } catch {
          // Passkey registration is optional — user can skip
        }
      }
      
      const nextIndex = currentStepIndex + 1;
      if (nextIndex < wizardSteps.length) {
        setCurrentStep(wizardSteps[nextIndex]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleBack = () => {
    const prevIndex = currentStepIndex - 1;
    if (prevIndex >= 0) {
      setCurrentStep(wizardSteps[prevIndex]);
    }
  };

  const config = stepConfig[currentStep];
  const StepIcon = config.icon;

  return (
    <div className="w-full max-w-md mx-auto">
      {/* Progress bar */}
      <div className="mb-8">
        <div className="h-1 w-full bg-muted rounded-full overflow-hidden">
          <motion.div
            className="h-full bg-gradient-to-r from-primary to-primary/80"
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
          />
        </div>
        <div className="flex justify-between mt-2">
          {wizardSteps.map((step, index) => (
            <div
              key={step}
              className={cn(
                'w-3 h-3 rounded-full transition-colors duration-300',
                index <= currentStepIndex ? 'bg-primary' : 'bg-muted'
              )}
            />
          ))}
        </div>
      </div>

      {/* Step content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={currentStep}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -20 }}
          transition={{ duration: 0.3 }}
        >
          <PremiumCard variant="premium" className="p-8">
            <PremiumCardContent className="flex flex-col items-center text-center p-0">
              {/* Icon */}
              <motion.div
                className="w-20 h-20 rounded-2xl bg-primary/10 flex items-center justify-center mb-6"
                initial={{ scale: 0.8 }}
                animate={{ scale: 1 }}
                transition={{ type: 'spring', stiffness: 300, damping: 20 }}
              >
                <StepIcon className="w-10 h-10 text-primary" />
              </motion.div>

              {/* Title */}
              <h2 className="text-2xl font-bold text-foreground mb-2">
                {config.title}
              </h2>
              <p className="text-muted-foreground mb-8">
                {config.subtitle}
              </p>

              {/* Step-specific content */}
              {currentStep === 'welcome' && (
                <WelcomeStep userName={userName} />
              )}
              {currentStep === 'security' && (
                <SecurityStep
                  biometricEnabled={biometricEnabled}
                  onBiometricToggle={setBiometricEnabled}
                />
              )}
              {currentStep === 'backup' && (
                <BackupStep
                  recoveryMethod={recoveryMethod}
                  onRecoveryMethodSelect={setRecoveryMethod}
                />
              )}
              {currentStep === 'complete' && (
                <CompleteStep userEmail={userEmail} walletDid={walletDid} />
              )}
              
              {error && (
                <div className="w-full text-sm text-destructive bg-destructive/10 rounded-lg p-3 mt-4">
                  {error}
                </div>
              )}

              {/* Navigation */}
              <div className="flex items-center gap-4 w-full mt-8">
                {currentStepIndex > 0 && currentStep !== 'complete' && (
                  <PremiumButton
                    variant="outline"
                    onClick={handleBack}
                    disabled={isProcessing}
                    className="flex-1"
                  >
                    <ChevronLeft className="w-4 h-4 mr-2" />
                    Back
                  </PremiumButton>
                )}
                <PremiumButton
                  variant="premium"
                  onClick={handleNext}
                  disabled={isProcessing || (currentStep === 'backup' && !recoveryMethod)}
                  isLoading={isProcessing}
                  className={cn(
                    'flex-1',
                    currentStepIndex === 0 && 'w-full'
                  )}
                >
                  {currentStep === 'complete' ? (
                    <>
                      <Sparkles className="w-4 h-4 mr-2" />
                      Open Wallet
                    </>
                  ) : (
                    <>
                      Continue
                      <ArrowRight className="w-4 h-4 ml-2" />
                    </>
                  )}
                </PremiumButton>
              </div>
            </PremiumCardContent>
          </PremiumCard>
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

function WelcomeStep({ userName }: { userName?: string }) {
  const features = [
    { icon: Shield, text: 'Bank-grade security' },
    { icon: Fingerprint, text: 'Biometric protection' },
    { icon: Key, text: 'You own your data' },
  ];

  return (
    <div className="w-full space-y-4">
      {userName && (
        <p className="text-lg text-foreground">
          Welcome, <span className="font-semibold">{userName}</span>
        </p>
      )}
      <div className="space-y-3">
        {features.map((feature, index) => {
          const Icon = feature.icon;
          return (
            <motion.div
              key={feature.text}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="flex items-center gap-3 p-3 rounded-xl bg-muted/50"
            >
              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                <Icon className="w-5 h-5 text-primary" />
              </div>
              <span className="text-foreground">{feature.text}</span>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}

function SecurityStep({
  biometricEnabled,
  onBiometricToggle,
}: {
  biometricEnabled: boolean;
  onBiometricToggle: (enabled: boolean) => void;
}) {
  return (
    <div className="w-full space-y-4">
      <p className="text-sm text-muted-foreground">
        Enable biometric authentication for quick and secure access to your credentials.
      </p>
      
      <button
        onClick={() => onBiometricToggle(!biometricEnabled)}
        className={cn(
          'w-full flex items-center justify-between p-4 rounded-xl border-2 transition-all',
          biometricEnabled
            ? 'border-primary bg-primary/5'
            : 'border-muted hover:border-muted-foreground/50'
        )}
      >
        <div className="flex items-center gap-3">
          <div className={cn(
            'w-12 h-12 rounded-xl flex items-center justify-center',
            biometricEnabled ? 'bg-primary/20' : 'bg-muted'
          )}>
            <Fingerprint className={cn(
              'w-6 h-6',
              biometricEnabled ? 'text-primary' : 'text-muted-foreground'
            )} />
          </div>
          <div className="text-left">
            <p className="font-medium text-foreground">Biometric Login</p>
            <p className="text-sm text-muted-foreground">
              Face ID or fingerprint
            </p>
          </div>
        </div>
        <div className={cn(
          'w-6 h-6 rounded-full border-2 flex items-center justify-center transition-colors',
          biometricEnabled
            ? 'bg-primary border-primary'
            : 'border-muted-foreground/50'
        )}>
          {biometricEnabled && (
            <CheckCircle2 className="w-4 h-4 text-primary-foreground" />
          )}
        </div>
      </button>
      
      {!biometricEnabled && (
        <p className="text-xs text-muted-foreground text-center">
          You can enable this later in settings
        </p>
      )}
    </div>
  );
}

function BackupStep({
  recoveryMethod,
  onRecoveryMethodSelect,
}: {
  recoveryMethod: 'cloud' | 'device' | null;
  onRecoveryMethodSelect: (method: 'cloud' | 'device') => void;
}) {
  const options = [
    {
      id: 'cloud' as const,
      title: 'Cloud Backup',
      description: 'Encrypted backup to a secure cloud vault',
      icon: <Cloud className="w-6 h-6 text-primary" />,
      recommended: true,
    },
    {
      id: 'device' as const,
      title: 'Device Only',
      description: 'Keys stored securely on this device',
      icon: <Smartphone className="w-6 h-6 text-muted-foreground" />,
      recommended: false,
    },
  ];

  return (
    <div className="w-full space-y-4">
      <p className="text-sm text-muted-foreground">
        Choose how to back up your wallet. This ensures you can recover your credentials if needed.
      </p>
      
      <div className="space-y-3">
        {options.map((option) => (
          <button
            key={option.id}
            onClick={() => onRecoveryMethodSelect(option.id)}
            className={cn(
              'w-full flex items-start gap-3 p-4 rounded-xl border-2 transition-all text-left',
              recoveryMethod === option.id
                ? 'border-primary bg-primary/5'
                : 'border-muted hover:border-muted-foreground/50'
            )}
          >
            <span className="text-2xl">{option.icon}</span>
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <p className="font-medium text-foreground">{option.title}</p>
                {option.recommended && (
                  <span className="text-xs bg-primary/20 text-primary px-2 py-0.5 rounded-full">
                    Recommended
                  </span>
                )}
              </div>
              <p className="text-sm text-muted-foreground mt-0.5">
                {option.description}
              </p>
            </div>
            <div className={cn(
              'w-5 h-5 rounded-full border-2 flex items-center justify-center flex-shrink-0 mt-0.5',
              recoveryMethod === option.id
                ? 'bg-primary border-primary'
                : 'border-muted-foreground/50'
            )}>
              {recoveryMethod === option.id && (
                <div className="w-2 h-2 rounded-full bg-primary-foreground" />
              )}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function CompleteStep({ userEmail, walletDid }: { userEmail?: string; walletDid?: string | null }) {
  return (
    <div className="w-full space-y-6">
      <motion.div
        initial={{ scale: 0 }}
        animate={{ scale: 1 }}
        transition={{ type: 'spring', stiffness: 300, damping: 20, delay: 0.2 }}
        className="w-16 h-16 mx-auto rounded-full bg-emerald-500/20 flex items-center justify-center"
      >
        <CheckCircle2 className="w-8 h-8 text-emerald-500" />
      </motion.div>
      
      <div className="space-y-2 text-center">
        <p className="text-foreground">
          Your wallet has been created successfully!
        </p>
        {walletDid && (
          <p className="text-xs text-muted-foreground font-mono break-all px-4">
            {walletDid}
          </p>
        )}
        {userEmail && (
          <p className="text-sm text-muted-foreground">
            Linked to <span className="font-medium">{userEmail}</span>
          </p>
        )}
      </div>
      
      <div className="grid grid-cols-3 gap-4 py-4">
        {['Credentials', 'Consents', 'Contacts'].map((item, index) => (
          <motion.div
            key={item}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 + index * 0.1 }}
            className="text-center"
          >
            <div className="text-2xl font-bold text-foreground">0</div>
            <div className="text-xs text-muted-foreground">{item}</div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
