/**
 * SSI Healthcare Mobile - Onboarding Screen
 *
 * Progressive onboarding flow following the Frictionless SSI
 * proposal's progressive decentralization model:
 *   Step 1: Welcome & value proposition
 *   Step 2: Sign in (email/social login via Web3Auth)
 *   Step 3: Identity created (DID generated in background)
 *
 * REFACTORED to use:
 * - Design tokens from theme system
 * - useCallback for event handlers
 * - Proper TypeScript types
 * - Accessibility attributes
 */

import React, { useState, useCallback, useMemo } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Dimensions,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, fontSizes, fontWeights, borderRadius, lineHeights, lineHeightFor} from '../theme';
import { withOpacity } from '../theme/colors';
import { Button } from '../components/common';

// -- Constants --

const { width } = Dimensions.get('window');

// -- Types --

interface OnboardingStep {
  id: string;
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  subtitle: string;
  description: string;
  color: string;
}

interface OnboardingScreenProps {
  onComplete: () => void;
}

// -- Step Data --

const ONBOARDING_STEPS: OnboardingStep[] = [
  {
    id: 'welcome',
    icon: 'shield-checkmark',
    title: 'Your Health,\nYour Identity',
    subtitle: 'Take control of your medical records',
    description:
      'SSI Healthcare gives you a secure digital wallet for all your health credentials. No more paper records or lost documents.',
    color: colors.brand.primary,
  },
  {
    id: 'signin',
    icon: 'finger-print',
    title: 'Sign In\nSecurely',
    subtitle: 'No passwords to remember',
    description:
      'Use your email, Google, or Apple account to sign in. Your cryptographic keys are generated automatically and protected by Multi-Party Computation.',
    color: colors.ui.purple,
  },
  {
    id: 'complete',
    icon: 'sparkles',
    title: 'Identity\nCreated!',
    subtitle: 'Your DID is ready',
    description:
      'Your Decentralized Identifier (DID) has been created. You can now receive, store, and share verifiable health credentials with full privacy control.',
    color: colors.semantic.success,
  },
];

// -- Step Indicator Component --

interface StepIndicatorProps {
  totalSteps: number;
  currentStep: number;
  activeColor: string;
}

const StepIndicator = React.memo<StepIndicatorProps>(({ totalSteps, currentStep, activeColor }) => (
  <View
    style={styles.indicators}
    accessibilityRole="progressbar"
    accessibilityValue={{ now: currentStep + 1, min: 1, max: totalSteps }}
  >
    {Array.from({ length: totalSteps }).map((_, index) => (
      <View
        key={index}
        style={[
          styles.indicator,
          index === currentStep && { backgroundColor: activeColor, width: 24 },
        ]}
      />
    ))}
  </View>
));

StepIndicator.displayName = 'StepIndicator';

// -- Step Content Component --

interface StepContentProps {
  step: OnboardingStep;
}

const StepContent = React.memo<StepContentProps>(({ step }) => (
  <View style={styles.content} accessibilityRole="none">
    <View style={[styles.iconContainer, { backgroundColor: withOpacity(step.color, 0.08) }]}>
      <Ionicons name={step.icon} size={80} color={step.color} />
    </View>

    <Text
      style={styles.title}
      accessibilityRole="header"
    >
      {step.title}
    </Text>
    <Text style={[styles.subtitle, { color: step.color }]}>
      {step.subtitle}
    </Text>
    <Text style={styles.description}>
      {step.description}
    </Text>
  </View>
));

StepContent.displayName = 'StepContent';

// -- Screen Component --

export default function OnboardingScreen({ onComplete }: OnboardingScreenProps) {
  const [currentStep, setCurrentStep] = useState(0);

  const step = useMemo(() => ONBOARDING_STEPS[currentStep], [currentStep]);
  const isLast = currentStep === ONBOARDING_STEPS.length - 1;
  const isFirst = currentStep === 0;

  const handleNext = useCallback(() => {
    if (isLast) {
      onComplete();
    } else {
      setCurrentStep((prev) => prev + 1);
    }
  }, [isLast, onComplete]);

  const handleBack = useCallback(() => {
    setCurrentStep((prev) => Math.max(0, prev - 1));
  }, []);

  const handleSkip = useCallback(() => {
    onComplete();
  }, [onComplete]);

  return (
    <View style={styles.container} accessibilityLabel="Onboarding screen">
      {/* Skip button */}
      <TouchableOpacity
        style={styles.skipButton}
        onPress={handleSkip}
        activeOpacity={0.7}
        accessibilityRole="button"
        accessibilityLabel="Skip onboarding"
        accessibilityHint="Skips the introduction and goes directly to the app"
      >
        <Text style={styles.skipText}>Skip</Text>
      </TouchableOpacity>

      {/* Content */}
      <StepContent step={step} />

      {/* Bottom */}
      <View style={styles.bottom}>
        {/* Step indicators */}
        <StepIndicator
          totalSteps={ONBOARDING_STEPS.length}
          currentStep={currentStep}
          activeColor={step.color}
        />

        {/* Action buttons */}
        <View style={styles.buttons}>
          {!isFirst && (
            <TouchableOpacity
              style={styles.backButton}
              onPress={handleBack}
              activeOpacity={0.7}
              accessibilityRole="button"
              accessibilityLabel="Go back"
              accessibilityHint="Returns to previous step"
            >
              <Ionicons name="arrow-back" size={20} color={colors.text.secondary} />
            </TouchableOpacity>
          )}

          <Button
            label={isLast ? 'Get Started' : 'Continue'}
            onPress={handleNext}
            variant="primary"
            size="large"
            icon={isLast ? 'checkmark' : 'arrow-forward'}
            iconPosition="right"
            style={[styles.nextButton, { backgroundColor: step.color }]}
            accessibilityHint={isLast ? 'Completes onboarding and enters the app' : 'Continues to next step'}
          />
        </View>
      </View>
    </View>
  );
}

// -- Styles --

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background.primary,
    paddingTop: 60,
    paddingHorizontal: spacing.xl,
    paddingBottom: spacing.xxl,
  },
  skipButton: {
    alignSelf: 'flex-end',
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
  },
  skipText: {
    color: colors.text.disabled,
    fontSize: fontSizes.md,
    fontWeight: fontWeights.medium,
  },
  content: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    gap: spacing.md,
  },
  iconContainer: {
    width: 160,
    height: 160,
    borderRadius: borderRadius.xxl,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: spacing.md,
  },
  title: {
    color: colors.text.primary,
    fontSize: 34,
    fontWeight: fontWeights.extrabold,
    textAlign: 'center',
    lineHeight: 42,
  },
  subtitle: {
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.semibold,
    textAlign: 'center',
  },
  description: {
    color: colors.text.secondary,
    fontSize: fontSizes.md,
    textAlign: 'center',
    lineHeight: lineHeightFor(fontSizes.md, lineHeights.relaxed),
    paddingHorizontal: spacing.sm,
    marginTop: spacing.sm,
  },
  bottom: {
    gap: spacing.xl,
  },
  indicators: {
    flexDirection: 'row',
    justifyContent: 'center',
    gap: spacing.sm,
  },
  indicator: {
    width: 8,
    height: 8,
    borderRadius: borderRadius.full,
    backgroundColor: colors.surface.tertiary,
  },
  buttons: {
    flexDirection: 'row',
    gap: spacing.md,
  },
  backButton: {
    width: 56,
    height: 56,
    borderRadius: borderRadius.lg,
    backgroundColor: colors.surface.secondary,
    justifyContent: 'center',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: colors.border.default,
  },
  nextButton: {
    flex: 1,
    height: 56,
  },
});
