/**
 * SSI Healthcare Mobile - Expiration Badge Component
 *
 * Displays credential expiration status with visual indicators:
 * - Expired: Red with warning
 * - Expiring soon (within 30 days): Amber warning
 * - Valid: Green or no badge (optional)
 */

import React, { useMemo } from 'react';
import { View, Text, StyleSheet, ViewStyle } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import type { ComponentProps } from 'react';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../../theme';

type IoniconsName = ComponentProps<typeof Ionicons>['name'];

interface ExpirationBadgeProps {
  /** ISO date string or Date object for expiration */
  expirationDate?: string | Date | null;
  /** Show badge even when valid (default: false) */
  showWhenValid?: boolean;
  /** Custom style */
  style?: ViewStyle;
  /** Compact mode for list items */
  compact?: boolean;
}

type ExpirationStatus = 'valid' | 'expiring' | 'expired' | 'no-expiration';

const EXPIRING_THRESHOLD_DAYS = 30;

export const ExpirationBadge = React.memo(function ExpirationBadge({
  expirationDate,
  showWhenValid = false,
  style,
  compact = false,
}: ExpirationBadgeProps) {
  const { status, daysRemaining, message } = useMemo(() => {
    if (!expirationDate) {
      return { 
        status: 'no-expiration' as ExpirationStatus, 
        daysRemaining: null,
        message: 'No expiration',
      };
    }

    const expDate = new Date(expirationDate);
    const now = new Date();
    const diffTime = expDate.getTime() - now.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays < 0) {
      const expiredDays = Math.abs(diffDays);
      return {
        status: 'expired' as ExpirationStatus,
        daysRemaining: diffDays,
        message: expiredDays === 1 
          ? 'Expired yesterday' 
          : `Expired ${expiredDays} days ago`,
      };
    }

    if (diffDays === 0) {
      return {
        status: 'expiring' as ExpirationStatus,
        daysRemaining: 0,
        message: 'Expires today',
      };
    }

    if (diffDays <= EXPIRING_THRESHOLD_DAYS) {
      return {
        status: 'expiring' as ExpirationStatus,
        daysRemaining: diffDays,
        message: diffDays === 1 
          ? 'Expires tomorrow' 
          : `Expires in ${diffDays} days`,
      };
    }

    return {
      status: 'valid' as ExpirationStatus,
      daysRemaining: diffDays,
      message: 'Valid',
    };
  }, [expirationDate]);

  // Don't render if valid and not showing valid state
  if (status === 'valid' && !showWhenValid) {
    return null;
  }

  if (status === 'no-expiration' && !showWhenValid) {
    return null;
  }

  const config = STATUS_CONFIG[status];

  if (compact) {
    return (
      <View style={[styles.compactContainer, { backgroundColor: config.bgColor }, style]}>
        <Ionicons name={config.icon} size={12} color={config.color} />
        <Text style={[styles.compactText, { color: config.color }]} numberOfLines={1}>
          {message}
        </Text>
      </View>
    );
  }

  return (
    <View style={[styles.container, { backgroundColor: config.bgColor }, style]}>
      <View style={styles.iconContainer}>
        <Ionicons name={config.icon} size={20} color={config.color} />
      </View>
      <View style={styles.textContainer}>
        <Text style={[styles.title, { color: config.color }]}>
          {config.title}
        </Text>
        <Text style={styles.message}>{message}</Text>
      </View>
    </View>
  );
});

const STATUS_CONFIG: Record<ExpirationStatus, {
  title: string;
  icon: IoniconsName;
  color: string;
  bgColor: string;
}> = {
  expired: {
    title: 'Expired',
    icon: 'alert-circle',
    color: colors.semantic.error,
    bgColor: colors.semantic.error + '15',
  },
  expiring: {
    title: 'Expiring Soon',
    icon: 'warning',
    color: colors.semantic.warning,
    bgColor: colors.semantic.warning + '15',
  },
  valid: {
    title: 'Valid',
    icon: 'checkmark-circle',
    color: colors.semantic.success,
    bgColor: colors.semantic.success + '15',
  },
  'no-expiration': {
    title: 'No Expiration',
    icon: 'infinite',
    color: colors.text.secondary,
    bgColor: colors.surface.secondary,
  },
};

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: spacing.md,
    borderRadius: borderRadius.card,
    gap: spacing.sm,
  },
  iconContainer: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: colors.background.primary,
    alignItems: 'center',
    justifyContent: 'center',
  },
  textContainer: {
    flex: 1,
  },
  title: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.semibold,
  },
  message: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.normal,
    color: colors.text.secondary,
    marginTop: 2,
  },
  compactContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.xxs,
    borderRadius: borderRadius.full,
    gap: spacing.xxs,
  },
  compactText: {
    fontSize: fontSizes.xs,
    fontWeight: fontWeights.medium,
  },
});

export default ExpirationBadge;
