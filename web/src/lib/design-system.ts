/**
 * SSI Healthcare Design System
 *
 * Neuromorphic design tokens and utilities for building
 * premium, accessible UI components with consistent styling.
 */

/** Color palette based on Tailwind Slate with blue accents */
export const colors = {
  // Base colors
  background: {
    DEFAULT: '#020617', // slate-950
    surface: '#0f172a', // slate-900
    elevated: '#1e293b', // slate-800
    overlay: 'rgba(2, 6, 23, 0.8)',
  },
  
  // Text colors
  text: {
    primary: '#f1f5f9', // slate-100
    secondary: '#94a3b8', // slate-400
    muted: '#64748b', // slate-500
    disabled: '#475569', // slate-600
  },
  
  // Border colors
  border: {
    DEFAULT: '#1e293b', // slate-800
    subtle: '#334155', // slate-700
    focus: '#3b82f6', // blue-500
  },
  
  // Accent colors
  accent: {
    primary: '#3b82f6', // blue-500
    primaryHover: '#2563eb', // blue-600
    primaryLight: 'rgba(59, 130, 246, 0.1)',
    secondary: '#8b5cf6', // violet-500
    secondaryLight: 'rgba(139, 92, 246, 0.1)',
  },
  
  // Status colors
  status: {
    success: '#10b981', // emerald-500
    successLight: 'rgba(16, 185, 129, 0.1)',
    warning: '#f59e0b', // amber-500
    warningLight: 'rgba(245, 158, 11, 0.1)',
    error: '#ef4444', // red-500
    errorLight: 'rgba(239, 68, 68, 0.1)',
    info: '#3b82f6', // blue-500
    infoLight: 'rgba(59, 130, 246, 0.1)',
  },
  
  // Healthcare credential folder colors
  credentialFolders: {
    bloodWork: '#dc2626', // red-600
    prescriptions: '#16a34a', // green-600
    vaccinations: '#2563eb', // blue-600
    imaging: '#9333ea', // purple-600
    labResults: '#ca8a04', // yellow-600
    insurance: '#0891b2', // cyan-600
    general: '#6b7280', // gray-500
  },
} as const;

/** Spacing scale (in pixels) */
export const spacing = {
  0: '0',
  1: '4px',
  2: '8px',
  3: '12px',
  4: '16px',
  5: '20px',
  6: '24px',
  8: '32px',
  10: '40px',
  12: '48px',
  16: '64px',
  20: '80px',
  24: '96px',
} as const;

/** Border radius scale */
export const radii = {
  none: '0',
  sm: '6px',
  md: '8px',
  DEFAULT: '12px',
  lg: '16px',
  xl: '20px',
  '2xl': '24px',
  full: '9999px',
} as const;

/** Shadow definitions for neuromorphic design */
export const shadows = {
  // Raised elements (buttons, cards)
  raised: `
    6px 6px 12px rgba(0, 0, 0, 0.5),
    -2px -2px 8px rgba(255, 255, 255, 0.02)
  `,
  
  // Pressed/active state
  pressed: `
    inset 4px 4px 8px rgba(0, 0, 0, 0.5),
    inset -2px -2px 6px rgba(255, 255, 255, 0.02)
  `,
  
  // Subtle elevation
  flat: `
    3px 3px 6px rgba(0, 0, 0, 0.5),
    -1px -1px 4px rgba(255, 255, 255, 0.02)
  `,
  
  // Glow effects for interactive elements
  glow: '0 0 20px rgba(59, 130, 246, 0.2), 0 0 40px rgba(59, 130, 246, 0.2)',
  glowSubtle: '0 0 15px rgba(59, 130, 246, 0.15)',
  glowSuccess: '0 0 15px rgba(16, 185, 129, 0.2)',
  glowError: '0 0 15px rgba(239, 68, 68, 0.2)',
  
  // Card hover state
  cardHover: `
    0 12px 24px rgba(0, 0, 0, 0.3),
    0 0 20px rgba(59, 130, 246, 0.15)
  `,
  
  // Modal/dialog shadow
  modal: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
} as const;

/** Typography scale */
export const typography = {
  fontFamily: {
    sans: 'var(--font-sans), system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    mono: 'var(--font-mono), ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace',
  },
  
  fontSize: {
    xs: ['12px', { lineHeight: '16px' }],
    sm: ['14px', { lineHeight: '20px' }],
    base: ['16px', { lineHeight: '24px' }],
    lg: ['18px', { lineHeight: '28px' }],
    xl: ['20px', { lineHeight: '28px' }],
    '2xl': ['24px', { lineHeight: '32px' }],
    '3xl': ['30px', { lineHeight: '36px' }],
    '4xl': ['36px', { lineHeight: '40px' }],
    '5xl': ['48px', { lineHeight: '48px' }],
  },
  
  fontWeight: {
    normal: '400',
    medium: '500',
    semibold: '600',
    bold: '700',
  },
} as const;

/** Animation timing functions */
export const transitions = {
  // Standard easing
  easeOut: 'cubic-bezier(0, 0, 0.2, 1)',
  easeIn: 'cubic-bezier(0.4, 0, 1, 1)',
  easeInOut: 'cubic-bezier(0.4, 0, 0.2, 1)',
  
  // Spring-like motion
  spring: 'cubic-bezier(0.34, 1.56, 0.64, 1)',
  
  // Smooth deceleration
  smooth: 'cubic-bezier(0.25, 0.1, 0.25, 1)',
} as const;

/** Animation durations */
export const durations = {
  instant: '50ms',
  fast: '100ms',
  normal: '200ms',
  slow: '300ms',
  slower: '500ms',
} as const;

/** Z-index scale for layering */
export const zIndex = {
  base: 0,
  dropdown: 100,
  sticky: 200,
  fixed: 300,
  modalBackdrop: 400,
  modal: 500,
  popover: 600,
  tooltip: 700,
  toast: 800,
} as const;

/** Breakpoints for responsive design */
export const breakpoints = {
  sm: '640px',
  md: '768px',
  lg: '1024px',
  xl: '1280px',
  '2xl': '1536px',
} as const;

/** Credential category metadata */
export const credentialCategories = {
  blood_work: {
    color: colors.credentialFolders.bloodWork,
    label: 'Blood Work',
    icon: 'droplet',
  },
  prescriptions: {
    color: colors.credentialFolders.prescriptions,
    label: 'Prescriptions',
    icon: 'pill',
  },
  vaccinations: {
    color: colors.credentialFolders.vaccinations,
    label: 'Vaccinations',
    icon: 'syringe',
  },
  imaging: {
    color: colors.credentialFolders.imaging,
    label: 'Imaging',
    icon: 'scan',
  },
  lab_results: {
    color: colors.credentialFolders.labResults,
    label: 'Lab Results',
    icon: 'flask-conical',
  },
  insurance: {
    color: colors.credentialFolders.insurance,
    label: 'Insurance',
    icon: 'shield-check',
  },
  general: {
    color: colors.credentialFolders.general,
    label: 'General',
    icon: 'file-text',
  },
} as const;

export type CredentialCategory = keyof typeof credentialCategories;

/** Helper to generate CSS variable reference */
export function cssVar(name: string): string {
  return `var(--${name})`;
}

/** Helper to create OKLCH color string */
export function oklch(l: number, c: number, h: number, alpha?: number): string {
  if (alpha !== undefined) {
    return `oklch(${l} ${c} ${h} / ${alpha})`;
  }
  return `oklch(${l} ${c} ${h})`;
}
