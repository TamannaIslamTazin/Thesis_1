/**
 * SSI Healthcare Mobile - Design Tokens: Typography
 *
 * Font sizes, weights, and line heights for consistent text styling.
 */

import { TextStyle } from 'react-native';

export const fontSizes = {
  xxs: 10,
  xs: 11,
  sm: 12,
  md: 13,
  base: 14,
  lg: 15,
  xl: 16,
  '2xl': 18,
  xxl: 20,
  '3xl': 20,
  '4xl': 24,
  '5xl': 28,
  '6xl': 32,
} as const;

export const fontWeights = {
  normal: '400' as const,
  medium: '500' as const,
  semibold: '600' as const,
  bold: '700' as const,
  extrabold: '800' as const,
};

/**
 * RATIOS, not pixels.
 *
 * React Native's `lineHeight` is in density-independent PIXELS. Passing one of
 * these straight to it sets a line height of 1.1-1.8px, which draws every line
 * of a wrapped paragraph on top of the one before: the "overlapping text" seen
 * on the onboarding carousel, the emergency break-glass banner and the audit
 * trail. Seven sites did this and none multiplied. Use `lineHeightFor`.
 */
export const lineHeights = {
  tight: 1.1,
  snug: 1.2,
  normal: 1.4,
  relaxed: 1.6,
  loose: 1.8,
} as const;

/** Absolute line height in px for a font size and one of the ratios above. */
export function lineHeightFor(fontSize: number, ratio: number): number {
  return Math.round(fontSize * ratio);
}

// -- Preset Text Styles --
export const textStyles: Record<string, TextStyle> = {
  // Headlines
  h1: {
    fontSize: fontSizes['5xl'],
    fontWeight: fontWeights.bold,
    lineHeight: fontSizes['5xl'] * lineHeights.tight,
  },
  h2: {
    fontSize: fontSizes['4xl'],
    fontWeight: fontWeights.bold,
    lineHeight: fontSizes['4xl'] * lineHeights.tight,
  },
  h3: {
    fontSize: fontSizes['2xl'],
    fontWeight: fontWeights.bold,
    lineHeight: fontSizes['2xl'] * lineHeights.snug,
  },
  h4: {
    fontSize: fontSizes.xl,
    fontWeight: fontWeights.bold,
    lineHeight: fontSizes.xl * lineHeights.snug,
  },

  // Body
  bodyLarge: {
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.normal,
    lineHeight: fontSizes.lg * lineHeights.normal,
  },
  body: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.normal,
    lineHeight: fontSizes.base * lineHeights.normal,
  },
  bodySmall: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.normal,
    lineHeight: fontSizes.md * lineHeights.normal,
  },

  // UI Elements
  button: {
    fontSize: fontSizes.xl,
    fontWeight: fontWeights.bold,
    lineHeight: fontSizes.xl * lineHeights.snug,
  },
  buttonSmall: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.semibold,
    lineHeight: fontSizes.base * lineHeights.snug,
  },
  label: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.medium,
    lineHeight: fontSizes.sm * lineHeights.normal,
  },
  caption: {
    fontSize: fontSizes.xs,
    fontWeight: fontWeights.normal,
    lineHeight: fontSizes.xs * lineHeights.normal,
  },

  // Tab Bar
  tabLabel: {
    fontSize: fontSizes.xs,
    fontWeight: fontWeights.semibold,
    lineHeight: fontSizes.xs * lineHeights.tight,
  },
};

export type FontSizeKey = keyof typeof fontSizes;
export type FontWeightKey = keyof typeof fontWeights;
export type TextStyleKey = keyof typeof textStyles;

// Named typography styles for component usage
export const typography = {
  // Headings
  headingLg: {
    fontSize: fontSizes['3xl'],
    fontWeight: fontWeights.bold,
    lineHeight: fontSizes['3xl'] * lineHeights.tight,
  } as TextStyle,
  headingMd: {
    fontSize: fontSizes['2xl'],
    fontWeight: fontWeights.semibold,
    lineHeight: fontSizes['2xl'] * lineHeights.snug,
  } as TextStyle,
  headingSm: {
    fontSize: fontSizes.xl,
    fontWeight: fontWeights.semibold,
    lineHeight: fontSizes.xl * lineHeights.snug,
  } as TextStyle,
  
  // Body text
  bodyLarge: textStyles.bodyLarge,
  bodyMedium: textStyles.body,
  bodySmall: textStyles.bodySmall,
  
  // Labels
  labelLarge: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.medium,
    lineHeight: fontSizes.base * lineHeights.snug,
  } as TextStyle,
  labelMedium: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.medium,
    lineHeight: fontSizes.md * lineHeights.snug,
  } as TextStyle,
  labelSmall: textStyles.label,
  
  // Caption
  caption: textStyles.caption,
  
  // Mono (for DIDs, hashes, etc.)
  mono: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.normal,
    fontFamily: 'monospace',
    lineHeight: fontSizes.sm * lineHeights.normal,
  } as TextStyle,
} as const;

export default {
  fontSizes,
  fontWeights,
  lineHeights,
  textStyles,
  typography,
};
