/**
 * SSI Healthcare Mobile - Design Tokens: Spacing
 *
 * Consistent spacing scale based on 4px base unit.
 */

export const spacing = {
  // -- Base Scale --
  none: 0,
  xxs: 2,
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  xxl: 24,
  xxxl: 32,
  huge: 40,
  massive: 48,
  giant: 64,

  // -- Component-Specific --
  screenPadding: 16,
  cardPadding: 16,
  cardPaddingLarge: 20,
  sectionGap: 24,
  itemGap: 12,
  buttonPadding: 16,
  inputPadding: 14,
  
  // -- Tab Bar --
  tabBarHeight: 65,
  tabBarPaddingTop: 8,
  tabBarPaddingBottom: 8,
} as const;

export type SpacingKey = keyof typeof spacing;

// Helper to create consistent gap values
export function gap(multiplier: number = 1): number {
  return spacing.sm * multiplier;
}

export default spacing;
