/**
 * SSI Healthcare Mobile - Info Sheet
 *
 * A sheet for displaying information, success messages, or errors.
 * Provides better UX than Alert.alert for non-blocking information.
 *
 * Replaces Alert.alert for:
 * - Success messages
 * - Error messages
 * - Information displays
 * - Coming soon messages
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

type InfoVariant = 'success' | 'error' | 'info' | 'warning';

interface InfoSheetProps {
  /** Whether the sheet is visible */
  visible: boolean;
  /** Callback when sheet is closed */
  onClose: () => void;
  /** Title text */
  title: string;
  /** Description/message */
  description: string;
  /** Visual variant */
  variant?: InfoVariant;
  /** Dismiss button text */
  dismissText?: string;
  /** Optional action button */
  action?: {
    label: string;
    onPress: () => void;
  };
  /** Auto-dismiss after ms (0 = no auto-dismiss) */
  autoDismissMs?: number;
}

const variantConfig: Record<InfoVariant, {
  icon: keyof typeof Ionicons.glyphMap;
  iconColor: string;
  iconBgColor: string;
}> = {
  success: {
    icon: 'checkmark-circle',
    iconColor: colors.semantic.success,
    iconBgColor: colors.semantic.successLight,
  },
  error: {
    icon: 'close-circle',
    iconColor: colors.semantic.error,
    iconBgColor: colors.semantic.errorLight,
  },
  info: {
    icon: 'information-circle',
    iconColor: colors.semantic.info,
    iconBgColor: colors.semantic.infoLight,
  },
  warning: {
    icon: 'warning',
    iconColor: colors.semantic.warning,
    iconBgColor: colors.semantic.warningLight,
  },
};

export function InfoSheet({
  visible,
  onClose,
  title,
  description,
  variant = 'info',
  dismissText = 'Got it',
  action,
  autoDismissMs = 0,
}: InfoSheetProps) {
  const config = variantConfig[variant];

  // Auto-dismiss
  React.useEffect(() => {
    if (visible && autoDismissMs > 0) {
      const timer = setTimeout(onClose, autoDismissMs);
      return () => clearTimeout(timer);
    }
  }, [visible, autoDismissMs, onClose]);

  return (
    <BottomSheet
      visible={visible}
      onClose={onClose}
      snapPoint={0.35}
      testID="info-sheet"
    >
      {/* Icon */}
      <View style={styles.iconContainer}>
        <View style={[styles.iconBadge, { backgroundColor: config.iconBgColor }]}>
          <Ionicons name={config.icon} size={32} color={config.iconColor} />
        </View>
      </View>

      {/* Title & Description */}
      <Text style={styles.title}>{title}</Text>
      <Text style={styles.description}>{description}</Text>

      {/* Actions */}
      <View style={[styles.actions, action && styles.actionsWithAction]}>
        {action && (
          <TouchableOpacity
            style={styles.actionButton}
            onPress={() => {
              action.onPress();
              onClose();
            }}
            activeOpacity={0.7}
            accessibilityRole="button"
            accessibilityLabel={action.label}
          >
            <Text style={styles.actionButtonText}>{action.label}</Text>
          </TouchableOpacity>
        )}

        <TouchableOpacity
          style={[styles.dismissButton, !action && styles.dismissButtonFull]}
          onPress={onClose}
          activeOpacity={0.7}
          accessibilityRole="button"
          accessibilityLabel={dismissText}
        >
          <Text style={styles.dismissButtonText}>{dismissText}</Text>
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
  actions: {
    flexDirection: 'row',
    gap: spacing.md,
    marginTop: spacing.md,
  },
  actionsWithAction: {
    // When action button is present
  },
  actionButton: {
    flex: 1,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    backgroundColor: colors.brand.primary,
    alignItems: 'center',
    justifyContent: 'center',
  },
  actionButtonText: {
    ...typography.labelMedium,
    color: colors.text.primary,
  },
  dismissButton: {
    flex: 1,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    backgroundColor: colors.surface.elevated,
    alignItems: 'center',
    justifyContent: 'center',
  },
  dismissButtonFull: {
    flex: 1,
  },
  dismissButtonText: {
    ...typography.labelMedium,
    color: colors.text.primary,
  },
});

export default InfoSheet;
