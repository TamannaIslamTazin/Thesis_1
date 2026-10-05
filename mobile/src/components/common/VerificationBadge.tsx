/**
 * SSI Healthcare Mobile - Verification Badge Component
 *
 * Shows credential verification status.
 */

import React from 'react';
import { View, Text, StyleSheet, ViewStyle } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../../theme';
import type { CredentialStatus } from '../../types';

interface VerificationBadgeProps {
  status: CredentialStatus;
  issuer?: string;
  issuedDate?: string;
  compact?: boolean;
  style?: ViewStyle;
}

const STATUS_CONFIG: Record<CredentialStatus, {
  icon: keyof typeof Ionicons.glyphMap;
  color: string;
  bgColor: string;
  borderColor: string;
  label: string;
}> = {
  valid: {
    icon: 'shield-checkmark',
    color: colors.semantic.success,
    bgColor: colors.semantic.successLight,
    borderColor: colors.semantic.successBorder,
    label: 'Verified',
  },
  expired: {
    icon: 'time',
    color: colors.semantic.warning,
    bgColor: colors.semantic.warningLight,
    borderColor: colors.semantic.warningBorder,
    label: 'Expired',
  },
  revoked: {
    icon: 'close-circle',
    color: colors.semantic.error,
    bgColor: colors.semantic.errorLight,
    borderColor: colors.semantic.errorBorder,
    label: 'Revoked',
  },
  pending: {
    icon: 'hourglass',
    color: colors.semantic.info,
    bgColor: colors.semantic.infoLight,
    borderColor: colors.semantic.infoBorder,
    label: 'Pending',
  },
};

export function VerificationBadge({
  status,
  issuer,
  issuedDate,
  compact = false,
  style,
}: VerificationBadgeProps) {
  const config = STATUS_CONFIG[status];

  if (compact) {
    return (
      <View
        style={[
          styles.compactContainer,
          { backgroundColor: config.bgColor, borderColor: config.borderColor },
          style,
        ]}
        accessibilityLabel={`Credential status: ${config.label}`}
        accessibilityRole="text"
      >
        <Ionicons name={config.icon} size={16} color={config.color} />
        <Text style={[styles.compactLabel, { color: config.color }]}>
          {config.label}
        </Text>
      </View>
    );
  }

  return (
    <View
      style={[
        styles.container,
        { backgroundColor: config.bgColor, borderColor: config.borderColor },
        style,
      ]}
      accessibilityLabel={`Credential status: ${config.label}${issuer ? `, issued by ${issuer}` : ''}`}
      accessibilityRole="text"
    >
      <Ionicons name={config.icon} size={48} color={config.color} />
      <View style={styles.info}>
        <Text style={[styles.statusLabel, { color: config.color }]}>
          {config.label} Credential
        </Text>
        {issuer && (
          <Text style={styles.issuer}>Issued by {issuer}</Text>
        )}
        {issuedDate && (
          <Text style={styles.date}>{issuedDate}</Text>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: spacing.cardPaddingLarge,
    borderRadius: borderRadius.card,
    borderWidth: 1,
    gap: spacing.lg,
  },
  info: {
    flex: 1,
  },
  statusLabel: {
    fontSize: fontSizes['2xl'],
    fontWeight: fontWeights.bold,
  },
  issuer: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.normal,
    color: colors.text.secondary,
    marginTop: spacing.xs,
  },
  date: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.normal,
    color: colors.text.tertiary,
    marginTop: spacing.xxs,
  },

  // Compact variant
  compactContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: spacing.xs,
    paddingHorizontal: spacing.md,
    borderRadius: borderRadius.badge,
    borderWidth: 1,
    gap: spacing.xs,
  },
  compactLabel: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
  },
});

export default VerificationBadge;
