/**
 * SSI Healthcare Mobile - Card Component
 *
 * Reusable card container with consistent styling.
 */

import React from 'react';
import { View, StyleSheet, ViewStyle, StyleProp, Pressable } from 'react-native';
import { colors, spacing, borderRadius, shadows } from '../../theme';

interface CardProps {
  children: React.ReactNode;
  variant?: 'default' | 'elevated' | 'outlined' | 'success' | 'warning' | 'error';
  onPress?: () => void;
  disabled?: boolean;
  style?: StyleProp<ViewStyle>;
  accessibilityLabel?: string;
  accessibilityHint?: string;
}

export function Card({
  children,
  variant = 'default',
  onPress,
  disabled = false,
  style,
  accessibilityLabel,
  accessibilityHint,
}: CardProps) {
  const cardStyle = [
    styles.base,
    styles[`variant_${variant}`],
    disabled && styles.disabled,
    style,
  ];

  if (onPress) {
    return (
      <Pressable
        style={({ pressed }) => [
          cardStyle,
          pressed && !disabled && styles.pressed,
        ]}
        onPress={disabled ? undefined : onPress}
        accessibilityRole="button"
        accessibilityLabel={accessibilityLabel}
        accessibilityHint={accessibilityHint}
        accessibilityState={{ disabled }}
      >
        {children}
      </Pressable>
    );
  }

  return (
    <View style={cardStyle} accessibilityLabel={accessibilityLabel}>
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  base: {
    borderRadius: borderRadius.card,
    padding: spacing.cardPadding,
    borderWidth: 1,
  },

  // Variants
  // A CARD IS DEFINED BY ITS SURFACE, NOT BY A LINE AROUND IT.
  //
  // The default sat on the page as a 1px rectangle with no depth, so on a
  // near-white background a card holding a whole form read as an outline drawn
  // around the screen rather than as a raised surface. A soft shadow and a
  // near-invisible border give the same separation without the boxed-in look,
  // and it costs nothing because the shadow token already existed and was
  // being used only by the elevated variant.
  variant_default: {
    backgroundColor: colors.surface.card,
    borderColor: colors.border.subtle,
    ...shadows.card,
  },
  variant_elevated: {
    backgroundColor: colors.surface.card,
    borderColor: colors.border.default,
    ...shadows.card,
  },
  variant_outlined: {
    backgroundColor: 'transparent',
    borderColor: colors.border.default,
  },
  variant_success: {
    backgroundColor: colors.semantic.successLight,
    borderColor: colors.semantic.successBorder,
  },
  variant_warning: {
    backgroundColor: colors.semantic.warningLight,
    borderColor: colors.semantic.warningBorder,
  },
  variant_error: {
    backgroundColor: colors.semantic.errorLight,
    borderColor: colors.semantic.errorBorder,
  },

  // States
  disabled: {
    opacity: 0.5,
  },
  pressed: {
    opacity: 0.8,
    transform: [{ scale: 0.98 }],
  },
});

export default Card;
