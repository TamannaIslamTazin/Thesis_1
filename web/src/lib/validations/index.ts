/**
 * SSI Healthcare - Client-side Validation Schemas
 * 
 * Zod schemas for form validation with detailed error messages.
 * These schemas mirror the backend validation but are optimized
 * for client-side user experience.
 */

import { z } from 'zod';

// ---------------------------------------------------------------------------
// Common Validators
// ---------------------------------------------------------------------------

/**
 * Email validation with common error cases
 */
export const emailSchema = z
  .string()
  .min(1, 'Email is required')
  .email('Please enter a valid email address')
  .max(255, 'Email must be less than 255 characters')
  .transform(v => v.toLowerCase().trim());

/**
 * Password validation with strength requirements
 */
export const passwordSchema = z
  .string()
  .min(1, 'Password is required')
  .min(8, 'Password must be at least 8 characters')
  .max(128, 'Password must be less than 128 characters')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number');

/**
 * Optional password for situations where strength isn't critical
 */
export const simplePasswordSchema = z
  .string()
  .min(1, 'Password is required')
  .min(6, 'Password must be at least 6 characters')
  .max(128, 'Password must be less than 128 characters');

/**
 * Name validation
 */
export const nameSchema = z
  .string()
  .min(1, 'Name is required')
  .min(2, 'Name must be at least 2 characters')
  .max(100, 'Name must be less than 100 characters')
  .regex(/^[a-zA-Z\s'-]+$/, 'Name can only contain letters, spaces, hyphens, and apostrophes')
  .transform(v => v.trim());

/**
 * Optional name validation
 */
export const optionalNameSchema = z
  .string()
  .max(100, 'Name must be less than 100 characters')
  .regex(/^[a-zA-Z\s'-]*$/, 'Name can only contain letters, spaces, hyphens, and apostrophes')
  .transform(v => v.trim())
  .optional()
  .or(z.literal(''));

/**
 * 6-digit verification code
 */
export const verificationCodeSchema = z
  .string()
  .min(1, 'Verification code is required')
  .length(6, 'Code must be exactly 6 digits')
  .regex(/^\d{6}$/, 'Code must be 6 digits');

/**
 * DID validation
 */
export const didSchema = z
  .string()
  .min(1, 'DID is required')
  .regex(/^did:[a-z]+:[a-zA-Z0-9._-]+$/, 'Invalid DID format');

/**
 * URL validation
 */
export const urlSchema = z
  .string()
  .min(1, 'URL is required')
  .url('Please enter a valid URL')
  .max(2048, 'URL is too long');

// ---------------------------------------------------------------------------
// Auth Form Schemas
// ---------------------------------------------------------------------------

/**
 * Login form validation
 */
export const loginSchema = z.object({
  email: emailSchema,
  password: simplePasswordSchema.optional(),
});

export type LoginInput = z.infer<typeof loginSchema>;

/**
 * Registration form validation
 */
export const registerSchema = z.object({
  email: emailSchema,
  firstName: optionalNameSchema,
  lastName: optionalNameSchema,
  password: passwordSchema.optional(),
  confirmPassword: z.string().optional(),
}).refine(
  (data) => {
    // Only validate password match if both are provided
    if (data.password && data.confirmPassword) {
      return data.password === data.confirmPassword;
    }
    return true;
  },
  {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  }
);

export type RegisterInput = z.infer<typeof registerSchema>;

/**
 * Email magic link request
 */
export const magicLinkSchema = z.object({
  email: emailSchema,
});

export type MagicLinkInput = z.infer<typeof magicLinkSchema>;

/**
 * Verification code validation
 */
export const verifyCodeSchema = z.object({
  email: emailSchema,
  code: verificationCodeSchema,
});

export type VerifyCodeInput = z.infer<typeof verifyCodeSchema>;

/**
 * OAuth callback validation
 * NOTE: Kept for backward compatibility. New auth uses passkey/DID/magic link.
 */
export const ssiAuthCallbackSchema = z.object({
  method: z.enum(['passkey', 'did_wallet', 'magic_link']),
  credential: z.unknown().optional(),
  token: z.string().optional(),
});

export type SsiAuthCallbackInput = z.infer<typeof ssiAuthCallbackSchema>;

// ---------------------------------------------------------------------------
// Wallet Setup Schemas
// ---------------------------------------------------------------------------

/**
 * Wallet type selection
 */
export const walletTypeSchema = z.enum(['CLOUD', 'DEVICE', 'HARDWARE', 'HYBRID'], {
  errorMap: () => ({ message: 'Please select a wallet type' }),
});

export type WalletType = z.infer<typeof walletTypeSchema>;

/**
 * Wallet setup form
 */
export const walletSetupSchema = z.object({
  walletType: walletTypeSchema,
  enableBiometrics: z.boolean().default(false),
  backupEnabled: z.boolean().default(true),
});

export type WalletSetupInput = z.infer<typeof walletSetupSchema>;

// ---------------------------------------------------------------------------
// User Profile Schemas
// ---------------------------------------------------------------------------

/**
 * Profile update form
 */
export const updateProfileSchema = z.object({
  firstName: optionalNameSchema,
  lastName: optionalNameSchema,
  displayName: z.string().max(100).optional(),
  image: z.string().url().optional().or(z.literal('')),
});

export type UpdateProfileInput = z.infer<typeof updateProfileSchema>;

/**
 * Emergency contact
 */
export const emergencyContactSchema = z.object({
  name: nameSchema,
  relationship: z.string().min(1, 'Relationship is required').max(50),
  email: emailSchema.optional().or(z.literal('')),
  phone: z.string()
    .min(1, 'Phone number is required')
    .regex(/^[+]?[\d\s()-]+$/, 'Invalid phone number format')
    .min(10, 'Phone number is too short')
    .max(20, 'Phone number is too long'),
});

export type EmergencyContactInput = z.infer<typeof emergencyContactSchema>;

// ---------------------------------------------------------------------------
// Consent Schemas
// ---------------------------------------------------------------------------

/**
 * Consent grant form
 */
export const consentGrantSchema = z.object({
  verifierId: z.string().min(1, 'Verifier is required'),
  credentialTypes: z.array(z.string()).min(1, 'Select at least one credential type'),
  purpose: z.string().min(1, 'Purpose is required').max(500),
  expiresAt: z.string().datetime().optional(),
  scope: z.array(z.string()).optional(),
});

export type ConsentGrantInput = z.infer<typeof consentGrantSchema>;

// ---------------------------------------------------------------------------
// Credential Schemas
// ---------------------------------------------------------------------------

/**
 * Credential issuance request
 */
export const credentialRequestSchema = z.object({
  type: z.string().min(1, 'Credential type is required'),
  holderDid: didSchema,
  claims: z.record(z.string(), z.unknown()),
});

export type CredentialRequestInput = z.infer<typeof credentialRequestSchema>;

/**
 * Selective disclosure selection
 */
export const selectiveDisclosureSchema = z.object({
  credentialId: z.string().min(1, 'Credential ID is required'),
  selectedClaims: z.array(z.string()).min(1, 'Select at least one claim to share'),
});

export type SelectiveDisclosureInput = z.infer<typeof selectiveDisclosureSchema>;

// ---------------------------------------------------------------------------
// Search & Filter Schemas
// ---------------------------------------------------------------------------

/**
 * Search query validation
 */
export const searchQuerySchema = z.object({
  q: z.string().max(200, 'Search query is too long').optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

export type SearchQueryInput = z.infer<typeof searchQuerySchema>;

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/**
 * Safely parse and validate form data
 * Returns either the validated data or formatted errors
 */
export function validateFormData<T extends z.ZodSchema>(
  schema: T,
  data: unknown
): { success: true; data: z.infer<T> } | { success: false; errors: Record<string, string> } {
  const result = schema.safeParse(data);
  
  if (result.success) {
    return { success: true, data: result.data };
  }
  
  const errors: Record<string, string> = {};
  for (const error of result.error.errors) {
    const path = error.path.join('.');
    if (!errors[path]) {
      errors[path] = error.message;
    }
  }
  
  return { success: false, errors };
}

/**
 * Get first error message from Zod error
 */
export function getFirstError(error: z.ZodError): string {
  return error.errors[0]?.message || 'Validation failed';
}

/**
 * Format Zod errors for display
 */
export function formatZodErrors(error: z.ZodError): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const e of error.errors) {
    const path = e.path.join('.');
    if (!errors[path]) {
      errors[path] = e.message;
    }
  }
  return errors;
}
