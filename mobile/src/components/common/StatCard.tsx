/**
 * SSI Healthcare Mobile - Stat Card Component
 *
 * Displays a statistic with label and optional icon.
 */

import React from 'react';
import { View, Text, StyleSheet, ViewStyle, StyleProp } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../../theme';

interface StatCardProps {
  label: string;
  value: string | number;
  icon?: keyof typeof Ionicons.glyphMap;
  iconColor?: string;
  trend?: {
    value: number;
    direction: 'up' | 'down' | 'neutral';
  };
  style?: StyleProp<ViewStyle>;
}

export function StatCard({
  label,
  value,
  icon,
  iconColor = colors.brand.primary,
  trend,
  style,
}: StatCardProps) {
  return (
    <View style={[styles.container, style]} accessibilityRole="text">
      <View style={styles.header}>
        {icon && (
          <View style={[styles.iconContainer, { backgroundColor: `${iconColor}20` }]}>
            <Ionicons name={icon} size={20} color={iconColor} />
          </View>
        )}
        {trend && (
          <View style={styles.trend}>
            <Ionicons
              name={trend.direction === 'up' ? 'arrow-up' : trend.direction === 'down' ? 'arrow-down' : 'remove'}
              size={12}
              color={trend.direction === 'up' ? colors.semantic.success : trend.direction === 'down' ? colors.semantic.error : colors.text.tertiary}
            />
            <Text
              style={[
                styles.trendValue,
                {
                  color: trend.direction === 'up' ? colors.semantic.success : trend.direction === 'down' ? colors.semantic.error : colors.text.tertiary,
                },
              ]}
            >
              {Math.abs(trend.value)}%
            </Text>
          </View>
        )}
      </View>
      <Text style={styles.value}>{value}</Text>
      <Text style={styles.label}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    backgroundColor: colors.surface.card,
    borderRadius: borderRadius.card,
    padding: spacing.cardPadding,
    borderWidth: 1,
    borderColor: colors.border.default,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: spacing.md,
  },
  iconContainer: {
    width: 40,
    height: 40,
    borderRadius: borderRadius.md,
    justifyContent: 'center',
    alignItems: 'center',
  },
  trend: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xxs,
  },
  trendValue: {
    fontSize: fontSizes.xs,
    fontWeight: fontWeights.semibold,
  },
  value: {
    fontSize: fontSizes['4xl'],
    fontWeight: fontWeights.bold,
    color: colors.text.primary,
    marginBottom: spacing.xs,
  },
  label: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.medium,
    color: colors.text.secondary,
  },
});

export default StatCard;
