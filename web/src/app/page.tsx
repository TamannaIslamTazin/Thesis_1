/**
 * SSI Healthcare - Premium Landing Page
 *
 * Modern, neuromorphic landing page showcasing SSI as
 * the frictionless alternative to traditional identity.
 */

'use client';

import * as React from 'react';
import { motion, useScroll, useTransform } from 'framer-motion';
import Link from 'next/link';
import {
  Shield,
  Fingerprint,
  Zap,
  Lock,
  Users,
  ArrowRight,
  CheckCircle2,
  Globe,
  Key,
  Smartphone,
  Building2,
  Heart,
  ChevronRight,
} from 'lucide-react';
import { PremiumButton } from '@/components/ui/premium-button';
import { PremiumCard, CardContent } from '@/components/ui/premium-card';
import { cn } from '@/lib/utils';

export default function LandingPage() {
  const { scrollYProgress } = useScroll();
  const opacity = useTransform(scrollYProgress, [0, 0.3], [1, 0]);
  const scale = useTransform(scrollYProgress, [0, 0.3], [1, 0.95]);

  return (
    <div className="min-h-screen bg-background">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/80 backdrop-blur-xl border-b border-border">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link href="/" className="flex items-center gap-2">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center">
                <Shield className="w-5 h-5 text-primary-foreground" />
              </div>
              <span className="text-xl font-bold text-foreground">
                SSI Health
              </span>
            </Link>
            
            <div className="hidden md:flex items-center gap-8">
              <Link href="#features" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Features
              </Link>
              <Link href="#how-it-works" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                How It Works
              </Link>
              <Link href="/developers" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Developers
              </Link>
              <Link href="/auth" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Sign In
              </Link>
              <PremiumButton variant="premium" size="sm" asChild>
                <Link href="/auth?signup=true">
                  Get Started
                </Link>
              </PremiumButton>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <motion.section
        style={{ opacity, scale }}
        className="relative pt-32 pb-20 px-6 overflow-hidden"
      >
        {/* Background gradient */}
        <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent" />
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-purple-500/10 rounded-full blur-3xl" />
        
        <div className="relative max-w-5xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-medium mb-8">
              <Zap className="w-4 h-4" />
              Introducing Frictionless SSI
            </div>
            
            <h1 className="text-5xl md:text-7xl font-bold text-foreground mb-6 leading-tight">
              Your Identity,{' '}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary to-purple-400">
                Your Control
              </span>
            </h1>
            
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto mb-10">
              The future of healthcare credentials. Secure, private, and instantly verifiable. 
              No more passwords. No more waiting. Just you.
            </p>
            
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <PremiumButton variant="premium" size="lg" asChild>
                <Link href="/auth?signup=true">
                  Create Your Wallet
                  <ArrowRight className="w-5 h-5 ml-2" />
                </Link>
              </PremiumButton>
              <PremiumButton variant="outline" size="lg" asChild>
                <Link href="#how-it-works">
                  See How It Works
                </Link>
              </PremiumButton>
            </div>
          </motion.div>
          
          {/* Trust indicators */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="mt-16 flex flex-wrap items-center justify-center gap-8 text-muted-foreground"
          >
            <div className="flex items-center gap-2">
              <Lock className="w-5 h-5" />
              <span className="text-sm">End-to-end encrypted</span>
            </div>
            <div className="flex items-center gap-2">
              <Globe className="w-5 h-5" />
              <span className="text-sm">W3C Standards compliant</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5" />
              <span className="text-sm">HIPAA ready</span>
            </div>
          </motion.div>
        </div>
      </motion.section>

      {/* Features Section */}
      <section id="features" className="py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-foreground mb-4">
              Why Self-Sovereign Identity?
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Take control of your healthcare data with cryptographically secured credentials 
              that only you can access and share.
            </p>
          </motion.div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.1 }}
              >
                <PremiumCard variant="interactive" className="h-full">
                  <CardContent className="p-6">
                    <div className={cn(
                      'w-14 h-14 rounded-2xl flex items-center justify-center mb-5',
                      feature.bgColor
                    )}>
                      <feature.icon className={cn('w-7 h-7', feature.iconColor)} />
                    </div>
                    <h3 className="text-xl font-semibold text-foreground mb-2">
                      {feature.title}
                    </h3>
                    <p className="text-muted-foreground">
                      {feature.description}
                    </p>
                  </CardContent>
                </PremiumCard>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="py-24 px-6 bg-muted/30">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-foreground mb-4">
              How It Works
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Get started in minutes. No technical knowledge required.
            </p>
          </motion.div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {steps.map((step, index) => (
              <motion.div
                key={step.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.15 }}
                className="relative"
              >
                {/* Connector line */}
                {index < steps.length - 1 && (
                  <div className="hidden md:block absolute top-12 left-1/2 w-full h-0.5 bg-gradient-to-r from-primary/50 to-transparent" />
                )}
                
                <div className="relative flex flex-col items-center text-center">
                  <div className="w-24 h-24 rounded-3xl bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center mb-6 border border-primary/20">
                    <step.icon className="w-10 h-10 text-primary" />
                  </div>
                  <div className="absolute top-0 right-1/3 w-8 h-8 rounded-full bg-background border-2 border-primary flex items-center justify-center text-sm font-bold text-primary">
                    {index + 1}
                  </div>
                  <h3 className="text-xl font-semibold text-foreground mb-2">
                    {step.title}
                  </h3>
                  <p className="text-muted-foreground">
                    {step.description}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Use Cases Section */}
      <section className="py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-foreground mb-4">
              For Everyone
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Whether you are a patient, provider, or developer, SSI Health has you covered.
            </p>
          </motion.div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {useCases.map((useCase, index) => (
              <motion.div
                key={useCase.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.1 }}
              >
                <PremiumCard variant="premium" className="h-full">
                  <CardContent className="p-8">
                    <useCase.icon className="w-12 h-12 text-primary mb-6" />
                    <h3 className="text-2xl font-bold text-foreground mb-3">
                      {useCase.title}
                    </h3>
                    <p className="text-muted-foreground mb-6">
                      {useCase.description}
                    </p>
                    <ul className="space-y-3">
                      {useCase.benefits.map((benefit, i) => (
                        <li key={i} className="flex items-start gap-3 text-sm">
                          <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                          <span className="text-foreground">{benefit}</span>
                        </li>
                      ))}
                    </ul>
                    <PremiumButton
                      variant="ghost"
                      className="mt-6 -ml-3"
                      asChild
                    >
                      <Link href={useCase.link}>
                        Learn more
                        <ChevronRight className="w-4 h-4 ml-1" />
                      </Link>
                    </PremiumButton>
                  </CardContent>
                </PremiumCard>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 px-6">
        <div className="max-w-4xl mx-auto">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
          >
            <PremiumCard variant="premium" className="overflow-hidden">
              <CardContent className="relative p-12 text-center">
                <div className="absolute inset-0 bg-gradient-to-r from-primary/10 via-purple-500/10 to-primary/10" />
                <div className="absolute top-0 left-1/4 w-32 h-32 bg-primary/20 rounded-full blur-3xl" />
                <div className="absolute bottom-0 right-1/4 w-24 h-24 bg-purple-500/20 rounded-full blur-3xl" />
                
                <div className="relative">
                  <h2 className="text-4xl font-bold text-foreground mb-4">
                    Ready to take control?
                  </h2>
                  <p className="text-lg text-muted-foreground mb-8 max-w-xl mx-auto">
                    Join thousands of users who have already made the switch to 
                    self-sovereign identity. It takes less than 2 minutes.
                  </p>
                  <PremiumButton variant="premium" size="lg" asChild>
                    <Link href="/auth?signup=true">
                      Create Your Free Wallet
                      <ArrowRight className="w-5 h-5 ml-2" />
                    </Link>
                  </PremiumButton>
                </div>
              </CardContent>
            </PremiumCard>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-12 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-primary/80 flex items-center justify-center">
                <Shield className="w-4 h-4 text-primary-foreground" />
              </div>
              <span className="font-semibold text-foreground">SSI Health</span>
            </div>
            
            <div className="flex items-center gap-6 text-sm text-muted-foreground">
              <Link href="/privacy" className="hover:text-foreground transition-colors">
                Privacy
              </Link>
              <Link href="/terms" className="hover:text-foreground transition-colors">
                Terms
              </Link>
              <Link href="/docs" className="hover:text-foreground transition-colors">
                Documentation
              </Link>
              <Link href="https://github.com" className="hover:text-foreground transition-colors">
                GitHub
              </Link>
            </div>
            
            <p className="text-sm text-muted-foreground">
              A research project for frictionless SSI
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

const features = [
  {
    icon: Fingerprint,
    title: 'Biometric Security',
    description: 'Use Face ID or fingerprint to access your credentials. No passwords to remember or reset.',
    bgColor: 'bg-blue-500/10',
    iconColor: 'text-blue-400',
  },
  {
    icon: Lock,
    title: 'Zero-Knowledge Proofs',
    description: 'Prove you are over 18 without revealing your birthdate. Share only what is necessary.',
    bgColor: 'bg-purple-500/10',
    iconColor: 'text-purple-400',
  },
  {
    icon: Key,
    title: 'Self-Custody',
    description: 'Your keys, your data. No central authority can access or revoke your credentials.',
    bgColor: 'bg-emerald-500/10',
    iconColor: 'text-emerald-400',
  },
  {
    icon: Zap,
    title: 'Instant Verification',
    description: 'Share credentials in seconds. Verifiers get cryptographic proof immediately.',
    bgColor: 'bg-amber-500/10',
    iconColor: 'text-amber-400',
  },
  {
    icon: Shield,
    title: 'HIPAA Compliant',
    description: 'Built from the ground up for healthcare compliance and patient privacy.',
    bgColor: 'bg-red-500/10',
    iconColor: 'text-red-400',
  },
  {
    icon: Globe,
    title: 'Interoperable',
    description: 'W3C DID and Verifiable Credentials standards. Works across systems and borders.',
    bgColor: 'bg-cyan-500/10',
    iconColor: 'text-cyan-400',
  },
];

const steps = [
  {
    icon: Users,
    title: 'Sign Up',
    description: 'Create your wallet with a passkey or magic link. We generate a secure DID for you automatically.',
  },
  {
    icon: Heart,
    title: 'Receive Credentials',
    description: 'Your healthcare provider issues verifiable credentials directly to your wallet.',
  },
  {
    icon: CheckCircle2,
    title: 'Share Securely',
    description: 'Choose exactly what to share with one tap. Biometric confirmation keeps you in control.',
  },
];

const useCases = [
  {
    icon: Smartphone,
    title: 'Patients',
    description: 'Manage all your healthcare credentials in one secure place.',
    benefits: [
      'Instant access to vaccination records',
      'Share prescriptions with any pharmacy',
      'Emergency contacts for critical situations',
      'Control who sees your medical history',
    ],
    link: '/auth?signup=true',
  },
  {
    icon: Building2,
    title: 'Healthcare Providers',
    description: 'Issue and verify credentials with confidence.',
    benefits: [
      'Reduce administrative overhead by 80%',
      'Instant credential verification',
      'Tamper-proof audit trails',
      'Comply with regulations automatically',
    ],
    link: '/issuer',
  },
  {
    icon: Key,
    title: 'Developers',
    description: 'Integrate SSI into your applications easily.',
    benefits: [
      'SSI-native developer experience',
      'React hooks and components',
      'Comprehensive documentation',
      'Open source SDK',
    ],
    link: '#developers',
  },
];
