/**
 * SSI Healthcare Mobile - Confirmation Sheet
 *
 * A reusable confirmation sheet for destructive actions.
 * Provides clear context about what will happen.
 *
 * Replaces Alert.alert for:
 * - Sign out
 * - Delete all data
 * - Revoke consent
 * - Any destructive action
 */

import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { BottomSheet } from './BottomSheet';
import { colors } from '../../theme/colors';
import { spacing } from '../../theme/spacing';
import { borderRadius } from '../../theme/borderRadius';
import { typography } from '../../theme/typography';

type ConfirmationVariant = 'default' | 'destructive' | 'warning';

interface ConfirmationSheetProps {
  /** Whether the sheet is visible */
  visible: boolean;
  /** Callback when sheet is closed */
  onClose: () => void;
  /** Callback when user confirms */
  onConfirm: () => void;
  /** Title text */
  title: string;
  /** Description/explanation */
  description: string;
  /** Confirm button text */
  confirmText?: string;
  /** Cancel button text */
  cancelText?: string;
  /** Visual variant */
  variant?: ConfirmationVariant;
  /** Optional icon name */
  icon?: keyof typeof Ionicons.glyphMap;
  /** Additional info items */
  infoItems?: Array<{ label: string; value: string }>;
}

const variantConfig: Record<ConfirmationVariant, {
  iconColor: string;
  buttonColor: string;
  iconBgColor: string;
}> = {
  default: {
    iconColor: colors.brand.primary,
    buttonColor: colors.brand.primary,
    iconBgColor: colors.brand.primaryMuted,
  },
  destructive: {
    iconColor: colors.semantic.error,
    buttonColor: colors.semantic.error,
    iconBgColor: colors.semantic.errorLight,
  },
  warning: {
    iconColor: colors.semantic.warning,
    buttonColor: colors.semantic.warning,
    iconBgColor: colors.semantic.warningLight,
  },
};

export function ConfirmationSheet({
  visible,
  onClose,
  onConfirm,
  title,
  description,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  variant = 'default',
  icon = 'alert-circle-outline',
  infoItems,
}: ConfirmationSheetProps) {
  const config = variantConfig[variant];

  const handleConfirm = () => {
    onConfirm();
    onClose();
  };

  return (
    <BottomSheet
      visible={visible}
      onClose={onClose}
      // 0.7, not 0.45. The consent template sheet lists every included field
      // now, and 0.45 clipped them with no way to reach the rest.
      snapPoint={0.7}
      testID="confirmation-sheet"
    >
      {/* Icon */}
      <View style={styles.iconContainer}>
        <View style={[styles.iconBadge, { backgroundColor: config.iconBgColor }]}>
          <Ionicons name={icon} size={32} color={config.iconColor} />
        </View>
      </View>

      {/* Title & Description */}
      <Text style={styles.title}>{title}</Text>
      <Text style={styles.description}>{description}</Text>

      {/* Optional info items */}
      {infoItems && infoItems.length > 0 && (
        <View style={styles.infoContainer}>
          {infoItems.map((item, index) => (
            <View key={index} style={styles.infoRow}>
              <Text style={styles.infoLabel}>{item.label}</Text>
              <Text style={styles.infoValue}>{item.value}</Text>
            </View>
          ))}
        </View>
      )}

      {/* Actions */}
      <View style={styles.actions}>
        <TouchableOpacity
          style={styles.cancelButton}
          onPress={onClose}
          activeOpacity={0.7}
          accessibilityRole="button"
          accessibilityLabel={cancelText}
        >
          <Text style={styles.cancelButtonText}>{cancelText}</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.confirmButton, { backgroundColor: config.buttonColor }]}
          onPress={handleConfirm}
          activeOpacity={0.7}
          accessibilityRole="button"
          accessibilityLabel={confirmText}
        >
          <Text style={styles.confirmButtonText}>{confirmText}</Text>
        </TouchableOpacity>
      </View>
    </BottomSheet>
  );
}

const styles = StyleSheet.create({
  iconContainer: {
    alignItems: 'center',
    marginBottom: spacing.lg,
  },
  iconBadge: {
    width: 64,
    height: 64,
    borderRadius: borderRadius.full,
    alignItems: 'center',
    justifyContent: 'center',
  },
  title: {
    ...typography.headingMd,
    color: colors.text.primary,
    textAlign: 'center',
    marginBottom: spacing.sm,
  },
  description: {
    ...typography.bodyMedium,
    color: colors.text.secondary,
    textAlign: 'center',
    marginBottom: spacing.lg,
    lineHeight: 22,
  },
  infoContainer: {
    backgroundColor: colors.background.secondary,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginBottom: spacing.lg,
  },
  infoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: spacing.xs,
  },
  infoLabel: {
    ...typography.bodySmall,
    color: colors.text.tertiary,
  },
  infoValue: {
    ...typography.bodySmall,
    color: colors.text.primary,
  },
  actions: {
    flexDirection: 'row',
    gap: spacing.md,
    marginTop: spacing.md,
  },
  cancelButton: {
    flex: 1,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    backgroundColor: colors.surface.elevated,
    alignItems: 'center',
    justifyContent: 'center',
  },
  cancelButtonText: {
    ...typography.labelMedium,
    color: colors.text.primary,
  },
  confirmButton: {
    flex: 1,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    alignItems: 'center',
    justifyContent: 'center',
  },
  confirmButtonText: {
    ...typography.labelMedium,
    color: colors.text.primary,
  },
});

export default ConfirmationSheet;
