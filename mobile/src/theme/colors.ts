/**
 * SSI Healthcare Mobile - Design Tokens: Colors
 *
 * Centralized color system using semantic naming.
 * All hex values extracted from across the codebase.
 */

export const colors = {
  // -- Base Colors --
  base: {
    black: '#000000',
    white: '#FFFFFF',
  },

  // -- Background Colors --
  // LIGHT MODE is the default (owner, 29 Aug). The scale is inverted from the
  // original slate dark palette; brand and semantic colours are unchanged, so
  // they keep their contrast against a light surface.
  background: {
    primary: '#F8FAFC',    // Main app background (slate-50)
    secondary: '#FFFFFF',  // Card backgrounds
    tertiary: '#0F172A66', // Scrim over content — stays dark, it is an overlay
  },

  // -- Surface Colors --
  surface: {
    card: '#FFFFFF',       // Card surface
    elevated: '#FFFFFF',   // Elevated elements — lifted by shadow, not by tint
    input: '#F1F5F9',      // Input field background (slate-100)
    secondary: '#F1F5F9',  // Secondary surface
    tertiary: '#E2E8F0',   // Tertiary surface (slate-200)
  },

  // -- Border Colors --
  border: {
    default: '#E2E8F0',    // Default border (slate-200)
    subtle: '#94A3B840',   // Subtle borders with opacity
    focus: '#3B82F6',      // Focus state
  },

  // -- Text Colors --
  text: {
    primary: '#0F172A',    // Primary text (slate-900)
    secondary: '#475569',  // Secondary text (slate-600) — 7:1 on white
    tertiary: '#64748B',   // Tertiary text (slate-500) — 4.8:1, meets AA
    disabled: '#94A3B8',   // Disabled text (slate-400)
    inverse: '#F8FAFC',    // Text on dark/brand backgrounds
  },

  // -- Brand Colors --
  brand: {
    primary: '#3B82F6',    // Primary blue (blue-500)
    primaryLight: '#60A5FA', // Light blue (blue-400)
    primaryDark: '#2563EB', // Dark blue (blue-600)
    primaryMuted: '#3B82F620', // Blue with opacity
    primarySubtle: '#3B82F615', // Very subtle blue
    primaryBorder: '#3B82F640', // Blue border
  },

  // -- Semantic Colors --
  semantic: {
    success: '#10B981',     // Success green (emerald-500)
    successLight: '#10B98115', // Success background
    successBorder: '#10B98130', // Success border

    warning: '#F59E0B',     // Warning amber (amber-500)
    warningLight: '#F59E0B15', // Warning background
    warningBorder: '#F59E0B30', // Warning border

    error: '#EF4444',       // Error red (red-500)
    errorLight: '#EF444420', // Error background
    errorBorder: '#EF444440', // Error border

    info: '#06B6D4',        // Info cyan (cyan-500)
    infoLight: '#06B6D415', // Info background
    infoBorder: '#06B6D430', // Info border
  },

  // -- UI Element Colors --
  ui: {
    tabActive: '#3B82F6',   // Active tab
    tabInactive: '#64748B', // Inactive tab
    switchTrackOff: '#CBD5E1',
    switchTrackOn: '#3B82F640',
    switchThumbOff: '#64748B',
    switchThumbOn: '#3B82F6',
    divider: '#E2E8F0',
    skeleton: '#E2E8F0',
    red: '#EF4444',         // Red UI color
    purple: '#8B5CF6',      // Purple UI color
    green: '#10B981',       // Green UI color
    amber: '#F59E0B',       // Amber UI color
    cyan: '#06B6D4',        // Cyan UI color
  },

  // -- Credential Category Colors --
  credential: {
    medical: '#3B82F6',      // Blue for medical
    vaccination: '#10B981',  // Green for vaccination
    insurance: '#8B5CF6',    // Purple for insurance
    prescription: '#F59E0B', // Amber for prescriptions
    lab: '#06B6D4',          // Cyan for lab results
    emergency: '#EF4444',    // Red for emergency
    identity: '#6366F1',     // Indigo for identity
    other: '#6B7280',        // Gray for other
  },

  // NEUTRAL SURFACES, COLOURED MARKS.
  //
  // These used to tint whole cards — a blue card, a green card, an amber card —
  // which put four or five hues on one screen and made the interface read as
  // decorated rather than informative. The surface is now the same everywhere;
  // the icon keeps its colour, because a small mark identifies a category
  // without becoming the background behind the text.
  // -- Category Card accents --
  categoryCard: {
    medical: {
      bg: '#FFFFFF',
      border: '#E5E7EB',
      icon: '#1D4ED8',
    },
    vaccination: {
      bg: '#FFFFFF',
      border: '#E5E7EB',
      icon: '#15803D',
    },
    prescription: {
      bg: '#FFFFFF',
      border: '#E5E7EB',
      icon: '#B45309',
    },
    insurance: {
      bg: '#FFFFFF',
      border: '#E5E7EB',
      icon: '#7E22CE',
    },
    lab: {
      bg: '#FFFFFF',
      border: '#E5E7EB',
      icon: '#0E7490',
    },
    emergency: {
      bg: '#FFFFFF',
      border: '#E5E7EB',
      icon: '#B91C1C',
    },
    identity: {
      bg: '#FFFFFF',
      border: '#E5E7EB',
      icon: '#4338CA',
    },
    other: {
      bg: '#FFFFFF',
      border: '#E5E7EB',
      icon: '#374151',
    },
  },

  // -- Stat Card Colors --
  statCard: {
    // Same surface for both. The number and its label carry the meaning; a
    // tinted panel behind them added a hue and no information.
    blue: {
      bg: '#FFFFFF',
      border: '#E5E7EB',
    },
    green: {
      bg: '#FFFFFF',
      border: '#E5E7EB',
    },
  },

  // -- Gradient Presets (start, end) --
  gradients: {
    primary: ['#3B82F6', '#2563EB'],
    success: ['#10B981', '#059669'],
    warning: ['#F59E0B', '#D97706'],
    error: ['#EF4444', '#DC2626'],
  },
} as const;

// Standard opacity values (hex suffixes)
export const opacity = {
  transparent: '00', // 0%
  ultraSubtle: '08', // ~3%
  subtle: '15',      // ~8%
  light: '20',       // ~12%
  medium: '40',      // ~25%
  heavy: '80',       // ~50%
  opaque: 'FF',      // 100%
} as const;

// Type-safe color extraction
export type ColorKeys = keyof typeof colors;
export type BackgroundColor = keyof typeof colors.background;
export type TextColor = keyof typeof colors.text;
export type SemanticColor = keyof typeof colors.semantic;
export type BrandColor = keyof typeof colors.brand;
export type OpacityLevel = keyof typeof opacity;

// Helper function for creating transparent colors
export function withOpacity(color: string, opacity: number): string {
  const hex = Math.round(opacity * 255).toString(16).padStart(2, '0');
  return `${color}${hex}`;
}

// Helper for applying standard opacity tokens
export function withOpacityToken(color: string, level: OpacityLevel): string {
  return `${color}${opacity[level]}`;
}

export default colors;
