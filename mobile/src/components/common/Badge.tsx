/**
 * SSI Healthcare Mobile - Badge Component
 *
 * Reusable badge/tag for status indicators.
 */

import React from 'react';
import { View, Text, StyleSheet, ViewStyle } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../../theme';

export type BadgeVariant = 'default' | 'success' | 'warning' | 'error' | 'info' | 'neutral';
export type BadgeSize = 'small' | 'medium';

interface BadgeProps {
  label: string;
  variant?: BadgeVariant;
  size?: BadgeSize;
  icon?: keyof typeof Ionicons.glyphMap;
  style?: ViewStyle;
}

const VARIANT_COLORS: Record<BadgeVariant, { bg: string; border: string; text: string }> = {
  default: {
    bg: colors.brand.primaryMuted,
    border: colors.brand.primaryBorder,
    text: colors.brand.primaryLight,
  },
  success: {
    bg: colors.semantic.successLight,
    border: colors.semantic.successBorder,
    text: colors.semantic.success,
  },
  warning: {
    bg: colors.semantic.warningLight,
    border: colors.semantic.warningBorder,
    text: colors.semantic.warning,
  },
  error: {
    bg: colors.semantic.errorLight,
    border: colors.semantic.errorBorder,
    text: colors.semantic.error,
  },
  info: {
    bg: colors.semantic.infoLight,
    border: colors.semantic.infoBorder,
    text: colors.semantic.info,
  },
  neutral: {
    bg: colors.surface.elevated,
    border: colors.border.default,
    text: colors.text.secondary,
  },
};

export function Badge({ label, variant = 'default', size = 'medium', icon, style }: BadgeProps) {
  const colorScheme = VARIANT_COLORS[variant];
  const iconSize = size === 'small' ? 12 : 14;

  return (
    <View
      style={[
        styles.base,
        styles[`size_${size}`],
        {
          backgroundColor: colorScheme.bg,
          borderColor: colorScheme.border,
        },
        style,
      ]}
      accessibilityRole="text"
    >
      {icon && (
        <Ionicons
          name={icon}
          size={iconSize}
          color={colorScheme.text}
          style={styles.icon}
        />
      )}
      <Text
        style={[
          styles.label,
          styles[`labelSize_${size}`],
          { color: colorScheme.text },
        ]}
      >
        {label}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  base: {
    flexDirection: 'row',
    alignItems: 'center',
    borderRadius: borderRadius.badge,
    borderWidth: 1,
  },
  size_small: {
    paddingVertical: spacing.xxs,
    paddingHorizontal: spacing.sm,
  },
  size_medium: {
    paddingVertical: spacing.xs,
    paddingHorizontal: spacing.md,
  },
  label: {
    fontWeight: fontWeights.semibold,
  },
  labelSize_small: {
    fontSize: fontSizes.xs,
  },
  labelSize_medium: {
    fontSize: fontSizes.sm,
  },
  icon: {
    marginRight: spacing.xs,
  },
});

export default Badge;
