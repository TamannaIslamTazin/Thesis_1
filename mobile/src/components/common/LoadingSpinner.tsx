/**
 * SSI Healthcare Mobile - Loading Spinner Component
 *
 * Reusable loading indicator with consistent styling.
 */

import React from 'react';
import { View, ActivityIndicator, Text, StyleSheet, ViewStyle } from 'react-native';
import { colors, spacing, fontSizes, fontWeights } from '../../theme';

interface LoadingSpinnerProps {
  size?: 'small' | 'large';
  color?: string;
  message?: string;
  fullScreen?: boolean;
  style?: ViewStyle;
}

export function LoadingSpinner({
  size = 'large',
  color = colors.brand.primary,
  message,
  fullScreen = false,
  style,
}: LoadingSpinnerProps) {
  const content = (
    <View style={[styles.container, fullScreen && styles.fullScreen, style]}>
      <ActivityIndicator
        size={size}
        color={color}
        accessibilityLabel="Loading"
        accessibilityRole="progressbar"
      />
      {message && (
        <Text style={styles.message} accessibilityLiveRegion="polite">
          {message}
        </Text>
      )}
    </View>
  );

  return content;
}

const styles = StyleSheet.create({
  container: {
    justifyContent: 'center',
    alignItems: 'center',
    padding: spacing.xl,
  },
  fullScreen: {
    flex: 1,
    backgroundColor: colors.background.primary,
  },
  message: {
    marginTop: spacing.md,
    color: colors.text.secondary,
    fontSize: fontSizes.base,
    fontWeight: fontWeights.medium,
    textAlign: 'center',
  },
});

export default LoadingSpinner;
