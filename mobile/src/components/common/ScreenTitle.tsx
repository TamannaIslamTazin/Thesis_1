/**
 * The screen's name, rendered inline at the top of its content.
 *
 * Replaces the navigator header on the tab screens. A fixed header bar cost
 * roughly a fifth of the viewport on every screen and repeated a name the tab
 * label already carries; rendered inline the title scrolls away once the user
 * has read it.
 *
 * Screens using this must take the top safe-area inset themselves, because the
 * header they are replacing was the only thing supplying the status-bar gap.
 */
import React from 'react';
import { Text, StyleSheet } from 'react-native';

import { colors, fontSizes, fontWeights, spacing } from '../../theme';

interface ScreenTitleProps {
  children: string;
}

export function ScreenTitle({ children }: ScreenTitleProps) {
  return (
    <Text style={styles.title} accessibilityRole="header">
      {children}
    </Text>
  );
}

const styles = StyleSheet.create({
  title: {
    color: colors.text.primary,
    fontSize: fontSizes.xxl,
    fontWeight: fontWeights.bold,
    marginBottom: spacing.lg,
  },
});
