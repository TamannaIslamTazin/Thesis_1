/**
 * SSI Healthcare - Authentication Page
 *
 * SSI-native authentication using Passkey/WebAuthn, DID Wallet, or Magic Link.
 * Creates embedded wallet automatically for new users after authentication.
 */

'use client';

import * as React from 'react';
import { Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';
import {
  Shield,
  ArrowLeft,
  Mail,
  CheckCircle2,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import { PremiumCard, CardContent, CardHeader, CardTitle } from '@/components/ui/premium-card';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumInput } from '@/components/ui/premium-input';
import {
  AuthMethodGroup,
  AuthDivider,
} from '@/components/auth/social-login-button';
import type { AuthMethod } from '@/components/auth/social-login-button';
import { WalletSetupWizard } from '@/components/auth/wallet-setup-wizard';
import { cn } from '@/lib/utils';
import { useForm, FieldError } from '@/hooks/useForm';
import { magicLinkSchema, verifyCodeSchema } from '@/lib/validations';
import { authApi } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';

type AuthStep = 'initial' | 'email' | 'verify' | 'setup-wallet';

function AuthPageContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const isSignup = searchParams.get('signup') === 'true';
  const { refreshUser } = useAuth();
  
  const [step, setStep] = React.useState<AuthStep>('initial');
  const [loadingMethod, setLoadingMethod] = React.useState<AuthMethod | null>(null);
  const [emailForVerification, setEmailForVerification] = React.useState('');
  const [pendingToken, setPendingToken] = React.useState('');
  const [authError, setAuthError] = React.useState<string | null>(null);

  // Handle SSI auth method selection
  const handleAuthMethod = React.useCallback(async (method: AuthMethod) => {
    setLoadingMethod(method);
    setAuthError(null);

    try {
      switch (method) {
        case 'passkey': {
          // Start passkey authentication via WebAuthn
          const optionsRes = await authApi.getPasskeyAuthenticationOptions();
          if (!optionsRes.data) throw new Error('Failed to get passkey options');

          // Call WebAuthn API
          const credential = await navigator.credentials.get({
            publicKey: {
              challenge: Uint8Array.from(atob(optionsRes.data.challenge), c => c.charCodeAt(0)),
              timeout: optionsRes.data.timeout ?? 60000,
              rpId: optionsRes.data.rpId ?? window.location.hostname,
              allowCredentials: (optionsRes.data.allowCredentials ?? []).map(c => ({
                id: Uint8Array.from(atob(c.id), ch => ch.charCodeAt(0)),
                type: c.type as 'public-key',
                transports: c.transports as AuthenticatorTransport[] | undefined,
              })),
              userVerification: (optionsRes.data.userVerification ?? 'preferred') as UserVerificationRequirement,
            },
          });

          if (!credential) throw new Error('Passkey authentication cancelled');

          // Verify with backend
          const authRes = await authApi.verifyPasskeyAuthentication(credential);
          if (!authRes.data) throw new Error('Passkey verification failed');

          router.push('/wallet');
          return;
        }

        case 'did_wallet': {
          // DID wallet authentication — redirect to wallet connect flow
          // For now, trigger the magic link flow with DID hint
          setStep('email');
          return;
        }

        case 'magic_link': {
          setStep('email');
          return;
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Authentication failed';
      // Don't show error for user-initiated cancellations
      if (!message.includes('cancelled') && !message.includes('AbortError')) {
        setAuthError(message);
      }
    } finally {
      setLoadingMethod(null);
    }
  }, [router]);

  // Email form — sends magic link via real API
  const emailForm = useForm({
    schema: magicLinkSchema,
    defaultValues: { email: '' },
    validateOnBlur: true,
    validateOnChange: false,
    onSubmit: async (data) => {
      setEmailForVerification(data.email);
      
      try {
        const result = await authApi.sendMagicLink(data.email);
        if (result.data?.pendingToken) {
          setPendingToken(result.data.pendingToken);
        }
        setStep('verify');
      } catch (error) {
        throw new Error(
          error instanceof Error ? error.message : 'Failed to send login code'
        );
      }
    },
  });

  // Verification form — verifies code via real API
  const verifyForm = useForm({
    schema: verifyCodeSchema,
    defaultValues: { email: emailForVerification, code: '' },
    validateOnBlur: true,
    validateOnChange: true,
    onSubmit: async (data) => {
      try {
        const response = await authApi.verifyCode(pendingToken, data.code);
        
        // Sync auth context so wallet page doesn't see isAuthenticated: false
        await refreshUser();
        
        // Use `needsWalletSetup` from the response (reliable) — fallback to !walletSetup
        const needsSetup = response.data?.needsWalletSetup ?? !response.data?.user?.walletSetup;
        if (needsSetup) {
          setStep('setup-wallet');
        } else {
          router.push('/wallet');
        }
      } catch (error) {
        throw new Error(
          error instanceof Error ? error.message : 'Invalid verification code'
        );
      }
    },
  });

  // Update email in verify form when it changes
  React.useEffect(() => {
    if (emailForVerification) {
      verifyForm.setValue('email', emailForVerification);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- verifyForm.setValue is stable (useCallback)
  }, [emailForVerification]);

  const handleResendCode = React.useCallback(async () => {
    if (!emailForVerification) return;
    try {
      const result = await authApi.sendMagicLink(emailForVerification);
      if (result.data?.pendingToken) {
        setPendingToken(result.data.pendingToken);
      }
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Failed to resend code. Please try again.');
    }
  }, [emailForVerification]);

  const handleWalletSetupComplete = React.useCallback(() => {
    router.push('/wallet');
  }, [router]);

  return (
    <div className="min-h-screen bg-background flex">
      {/* Left side - branding */}
      <div className="hidden lg:flex lg:w-1/2 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/20 via-background to-purple-500/10" />
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/3 right-1/3 w-64 h-64 bg-purple-500/10 rounded-full blur-3xl" />
        
        <div className="relative z-10 flex flex-col justify-center p-12">
          <Link href="/" className="flex items-center gap-3 mb-12">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center">
              <Shield className="w-6 h-6 text-primary-foreground" />
            </div>
            <span className="text-2xl font-bold text-foreground">
              SSI Health
            </span>
          </Link>
          
          <h1 className="text-4xl font-bold text-foreground mb-4">
            {isSignup ? 'Create your wallet' : 'Welcome back'}
          </h1>
          <p className="text-lg text-muted-foreground max-w-md">
            {isSignup
              ? 'Take control of your healthcare credentials with a secure, self-sovereign identity wallet.'
              : 'Access your credentials and manage your healthcare identity securely.'}
          </p>
          
          {isSignup && (
            <div className="mt-12 space-y-4">
              {[
                'No passwords to remember',
                'Bank-grade security with passkeys',
                'You own your data — fully self-sovereign',
              ].map((item, index) => (
                <motion.div
                  key={item}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.2 + index * 0.1 }}
                  className="flex items-center gap-3 text-muted-foreground"
                >
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <span>{item}</span>
                </motion.div>
              ))}
            </div>
          )}
        </div>
      </div>
      
      {/* Right side - auth forms */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-6">
        <div className="w-full max-w-md">
          <AnimatePresence mode="wait">
            {step === 'initial' && (
              <motion.div
                key="initial"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
              >
                {/* Mobile logo */}
                <div className="lg:hidden mb-8 text-center">
                  <Link href="/" className="inline-flex items-center gap-2">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center">
                      <Shield className="w-5 h-5 text-primary-foreground" />
                    </div>
                    <span className="text-xl font-bold text-foreground">
                      SSI Health
                    </span>
                  </Link>
                </div>
                
                <PremiumCard variant="premium">
                  <CardHeader className="text-center pb-2">
                    <CardTitle className="text-2xl">
                      {isSignup ? 'Create your account' : 'Sign in'}
                    </CardTitle>
                    <p className="text-muted-foreground mt-2">
                      {isSignup
                        ? 'Get started with your self-sovereign health wallet'
                        : 'Access your healthcare wallet'}
                    </p>
                  </CardHeader>
                  <CardContent className="pt-6">
                    {authError && (
                      <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 rounded-lg p-3 mb-4">
                        <AlertCircle className="w-4 h-4 shrink-0" />
                        {authError}
                      </div>
                    )}
                    
                    <AuthMethodGroup
                      onSelect={handleAuthMethod}
                      loadingMethod={loadingMethod}
                      methods={['passkey', 'magic_link']}
                    />
                    
                    <AuthDivider text="or use email" />
                    
                    <PremiumButton
                      variant="outline"
                      fullWidth
                      onClick={() => setStep('email')}
                      disabled={!!loadingMethod}
                    >
                      <Mail className="w-5 h-5 mr-2" />
                      Continue with Email
                    </PremiumButton>
                    
                    <p className="text-center text-sm text-muted-foreground mt-6">
                      {isSignup ? (
                        <>
                          Already have an account?{' '}
                          <Link href="/auth" className="text-primary hover:underline">
                            Sign in
                          </Link>
                        </>
                      ) : (
                        <>
                          New to SSI Health?{' '}
                          <Link href="/auth?signup=true" className="text-primary hover:underline">
                            Create an account
                          </Link>
                        </>
                      )}
                    </p>
                  </CardContent>
                </PremiumCard>
              </motion.div>
            )}
            
            {step === 'email' && (
              <motion.div
                key="email"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
              >
                <button
                  onClick={() => {
                    emailForm.reset();
                    setStep('initial');
                  }}
                  className="flex items-center gap-2 text-muted-foreground hover:text-foreground mb-6 transition-colors"
                >
                  <ArrowLeft className="w-4 h-4" />
                  Back
                </button>
                
                <PremiumCard variant="premium">
                  <CardHeader className="text-center pb-2">
                    <CardTitle className="text-2xl">
                      Enter your email
                    </CardTitle>
                    <p className="text-muted-foreground mt-2">
                      We&apos;ll send you a magic link to sign in securely
                    </p>
                  </CardHeader>
                  <CardContent className="pt-6">
                    <form onSubmit={emailForm.handleSubmit}>
                      <div className="space-y-1">
                        <PremiumInput
                          type="email"
                          placeholder="you@example.com"
                          name="email"
                          value={(emailForm.values.email as string) || ''}
                          onChange={(e) => emailForm.setValue('email', e.target.value)}
                          onBlur={() => {
                            emailForm.setTouched('email', true);
                            emailForm.validateField('email');
                          }}
                          aria-invalid={!!emailForm.getFieldError('email')}
                          className={cn(
                            emailForm.getFieldError('email') && 'border-destructive focus:ring-destructive/20'
                          )}
                          autoFocus
                        />
                        <FieldError 
                          name="email" 
                          error={emailForm.getFieldError('email')} 
                        />
                      </div>
                      
                      {emailForm.errors._form && (
                        <div className="flex items-center gap-2 text-sm text-destructive mt-2">
                          <AlertCircle className="w-4 h-4" />
                          {emailForm.errors._form}
                        </div>
                      )}
                      
                      <PremiumButton
                        variant="premium"
                        fullWidth
                        type="submit"
                        isLoading={emailForm.isSubmitting}
                        className="mt-4"
                      >
                        Send Magic Link
                      </PremiumButton>
                    </form>
                  </CardContent>
                </PremiumCard>
              </motion.div>
            )}
            
            {step === 'verify' && (
              <motion.div
                key="verify"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
              >
                <button
                  onClick={() => {
                    verifyForm.reset();
                    setStep('email');
                  }}
                  className="flex items-center gap-2 text-muted-foreground hover:text-foreground mb-6 transition-colors"
                >
                  <ArrowLeft className="w-4 h-4" />
                  Back
                </button>
                
                <PremiumCard variant="premium">
                  <CardHeader className="text-center pb-2">
                    <div className="w-16 h-16 mx-auto rounded-full bg-primary/10 flex items-center justify-center mb-4">
                      <Mail className="w-8 h-8 text-primary" />
                    </div>
                    <CardTitle className="text-2xl">
                      Check your email
                    </CardTitle>
                    <p className="text-muted-foreground mt-2">
                      We sent a 6-digit code to{' '}
                      <span className="font-medium text-foreground">{emailForVerification}</span>
                    </p>
                  </CardHeader>
                  <CardContent className="pt-6">
                    <form onSubmit={verifyForm.handleSubmit}>
                      <div className="space-y-1">
                        <PremiumInput
                          type="text"
                          placeholder="000000"
                          value={verifyForm.values.code || ''}
                          onChange={(e) => {
                            const value = e.target.value.replace(/\D/g, '').slice(0, 6);
                            verifyForm.setValue('code', value);
                          }}
                          onBlur={() => verifyForm.setTouched('code', true)}
                          maxLength={6}
                          className={cn(
                            "text-center text-2xl tracking-[0.5em] font-mono",
                            verifyForm.getFieldError('code') && 'border-destructive focus:ring-destructive/20'
                          )}
                          autoFocus
                        />
                        <FieldError 
                          name="code" 
                          error={verifyForm.getFieldError('code')} 
                        />
                      </div>
                      
                      {verifyForm.errors._form && (
                        <div className="flex items-center gap-2 text-sm text-destructive mt-2">
                          <AlertCircle className="w-4 h-4" />
                          {verifyForm.errors._form}
                        </div>
                      )}
                      
                      <PremiumButton
                        variant="premium"
                        fullWidth
                        type="submit"
                        isLoading={verifyForm.isSubmitting}
                        disabled={(verifyForm.values.code || '').length !== 6}
                        className="mt-4"
                      >
                        Verify
                      </PremiumButton>
                    </form>
                    
                    <p className="text-center text-sm text-muted-foreground mt-6">
                      Did not receive the code?{' '}
                      <button 
                        onClick={handleResendCode}
                        className="text-primary hover:underline"
                      >
                        Resend
                      </button>
                    </p>
                  </CardContent>
                </PremiumCard>
              </motion.div>
            )}
            
            {step === 'setup-wallet' && (
              <motion.div
                key="setup-wallet"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
              >
                <WalletSetupWizard
                  onComplete={handleWalletSetupComplete}
                  userEmail={emailForVerification || undefined}
                />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

function AuthPageLoading() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <Loader2 className="w-8 h-8 animate-spin text-primary" />
    </div>
  );
}

export default function AuthPage() {
  return (
    <Suspense fallback={<AuthPageLoading />}>
      <AuthPageContent />
    </Suspense>
  );
}
