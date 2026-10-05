/**
 * SSI Healthcare Mobile - Theme System
 *
 * Central export for all design tokens.
 */

export { colors, opacity, withOpacity, withOpacityToken } from './colors';
export type { ColorKeys, BackgroundColor, TextColor, SemanticColor, BrandColor, OpacityLevel } from './colors';

export { spacing, gap } from './spacing';
export type { SpacingKey } from './spacing';

export { fontSizes, fontWeights, lineHeights, lineHeightFor, textStyles, typography } from './typography';
export type { FontSizeKey, FontWeightKey, TextStyleKey } from './typography';

export { borderRadius } from './borderRadius';
export type { BorderRadiusKey } from './borderRadius';

export { shadows, getShadowStyle } from './shadows';
export type { Shadow, ShadowKey } from './shadows';

// Convenience re-export of all theme values
import { colors, opacity } from './colors';
import { spacing } from './spacing';
import { fontSizes, fontWeights, lineHeights, textStyles, typography } from './typography';
import { borderRadius } from './borderRadius';
import { shadows } from './shadows';

export const theme = {
  colors,
  opacity,
  spacing,
  fontSizes,
  fontWeights,
  lineHeights,
  textStyles,
  typography,
  borderRadius,
  shadows,
} as const;

export default theme;
