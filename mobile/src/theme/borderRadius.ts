/**
 * SSI Healthcare Mobile - Design Tokens: Border Radius
 *
 * Consistent corner radius values.
 */

export const borderRadius = {
  none: 0,
  xs: 4,
  sm: 8,
  md: 10,
  lg: 12,
  xl: 14,
  '2xl': 16,
  xxl: 18,
  '3xl': 20,
  full: 9999,

  // -- Component-Specific --
  card: 16,
  button: 14,
  input: 12,
  badge: 12,
  avatar: 9999, // Circular
  tag: 8,
} as const;

export type BorderRadiusKey = keyof typeof borderRadius;

export default borderRadius;
