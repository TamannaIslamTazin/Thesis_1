/**
 * SSI Healthcare Mobile - Button Component
 *
 * Reusable button with multiple variants and sizes.
 */

import React, { useCallback } from 'react';
import {
  TouchableOpacity,
  Text,
  StyleSheet,
  ViewStyle,
  TextStyle,
  ActivityIndicator,
  View,
  StyleProp,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../../theme';

type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
type ButtonSize = 'small' | 'medium' | 'large';

interface ButtonProps {
  label: string;
  onPress: () => void;
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: keyof typeof Ionicons.glyphMap;
  iconPosition?: 'left' | 'right';
  disabled?: boolean;
  loading?: boolean;
  fullWidth?: boolean;
  style?: StyleProp<ViewStyle>;
  textStyle?: TextStyle;
  accessibilityLabel?: string;
  accessibilityHint?: string;
}

export function Button({
  label,
  onPress,
  variant = 'primary',
  size = 'medium',
  icon,
  iconPosition = 'left',
  disabled = false,
  loading = false,
  fullWidth = false,
  style,
  textStyle,
  accessibilityLabel,
  accessibilityHint,
}: ButtonProps) {
  const handlePress = useCallback(() => {
    if (!disabled && !loading) {
      onPress();
    }
  }, [disabled, loading, onPress]);

  const buttonStyle = [
    styles.base,
    styles[`variant_${variant}`],
    styles[`size_${size}`],
    fullWidth && styles.fullWidth,
    (disabled || loading) && styles.disabled,
    style,
  ];

  const labelStyle = [
    styles.label,
    styles[`labelVariant_${variant}`],
    styles[`labelSize_${size}`],
    (disabled || loading) && styles.labelDisabled,
    textStyle,
  ];

  const iconSize = size === 'small' ? 16 : size === 'medium' ? 20 : 24;
  const iconColor = getIconColor(variant, disabled || loading);

  return (
    <TouchableOpacity
      style={buttonStyle}
      onPress={handlePress}
      disabled={disabled || loading}
      activeOpacity={0.7}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel || label}
      accessibilityHint={accessibilityHint}
      accessibilityState={{ disabled: disabled || loading }}
    >
      {loading ? (
        <ActivityIndicator size="small" color={iconColor} />
      ) : (
        <View style={styles.content}>
          {icon && iconPosition === 'left' && (
            <Ionicons name={icon} size={iconSize} color={iconColor} style={styles.iconLeft} />
          )}
          <Text style={labelStyle}>{label}</Text>
          {icon && iconPosition === 'right' && (
            <Ionicons name={icon} size={iconSize} color={iconColor} style={styles.iconRight} />
          )}
        </View>
      )}
    </TouchableOpacity>
  );
}

function getIconColor(variant: ButtonVariant, isDisabled: boolean): string {
  if (isDisabled) return colors.text.disabled;
  
  switch (variant) {
    case 'primary':
      return colors.text.primary;
    case 'secondary':
    case 'outline':
    case 'ghost':
      return colors.brand.primary;
    case 'danger':
      return colors.text.primary;
    default:
      return colors.text.primary;
  }
}

const styles = StyleSheet.create({
  base: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    borderRadius: borderRadius.button,
  },
  content: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
  },

  // Variants
  variant_primary: {
    backgroundColor: colors.brand.primary,
  },
  variant_secondary: {
    backgroundColor: colors.brand.primarySubtle,
    borderWidth: 1,
    borderColor: colors.brand.primaryBorder,
  },
  variant_outline: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: colors.border.default,
  },
  variant_ghost: {
    backgroundColor: 'transparent',
  },
  variant_danger: {
    backgroundColor: colors.semantic.error,
  },

  // Sizes
  size_small: {
    paddingVertical: spacing.sm,
    paddingHorizontal: spacing.md,
    minHeight: 36,
  },
  size_medium: {
    paddingVertical: spacing.md,
    paddingHorizontal: spacing.lg,
    minHeight: 44,
  },
  size_large: {
    paddingVertical: spacing.lg,
    paddingHorizontal: spacing.xl,
    minHeight: 52,
  },

  // States
  disabled: {
    opacity: 0.5,
  },
  fullWidth: {
    width: '100%',
  },

  // Label
  label: {
    textAlign: 'center',
  },
  labelVariant_primary: {
    // WHITE ON THE BRAND FILL, not the body text colour. `text.primary` is a
    // near-black meant for text on a light surface, so on a saturated blue it
    // read as black-on-blue: legible enough to ship and wrong enough to look
    // unfinished, which is exactly how it looked on a handset.
    color: colors.base.white,
  },
  labelVariant_secondary: {
    color: colors.brand.primary,
  },
  labelVariant_outline: {
    color: colors.text.primary,
  },
  labelVariant_ghost: {
    color: colors.brand.primary,
  },
  labelVariant_danger: {
    color: colors.text.primary,
  },
  labelSize_small: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
  },
  labelSize_medium: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.bold,
  },
  labelSize_large: {
    fontSize: fontSizes.xl,
    fontWeight: fontWeights.bold,
  },
  labelDisabled: {
    color: colors.text.disabled,
  },

  // Icons
  iconLeft: {
    marginRight: spacing.sm,
  },
  iconRight: {
    marginLeft: spacing.sm,
  },
});

export default Button;
