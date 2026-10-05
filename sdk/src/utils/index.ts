/**
 * SSI Healthcare SDK - Utility Functions
 *
 * Shared helpers for encoding, retry logic, and common patterns.
 */

// ============================================================
// Base64 URL Encoding/Decoding
// ============================================================

/**
 * Encode a string or ArrayBuffer to base64url (RFC 4648 §5).
 */
export function base64UrlEncode(input: string | ArrayBuffer): string {
  let binary: string;
  if (typeof input === 'string') {
    binary = input;
  } else {
    const bytes = new Uint8Array(input);
    // Build string in chunks to avoid max call stack with spread on large buffers
    const chunks: string[] = [];
    const CHUNK = 8192;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      chunks.push(String.fromCharCode(...bytes.subarray(i, i + CHUNK)));
    }
    binary = chunks.join('');
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode a base64url string to an ArrayBuffer.
 */
export function base64UrlDecode(str: string): ArrayBuffer {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Decode a base64url string to a UTF-8 string.
 */
export function base64UrlDecodeString(str: string): string {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return atob(base64);
}

// ============================================================
// JWT Helpers
// ============================================================

/**
 * Decode a JWT payload without verification.
 * Useful for inspecting token claims before sending to backend for verification.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const decoded = base64UrlDecodeString(parts[1]!);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

/**
 * Check if a JWT has expired based on its `exp` claim.
 * Returns true if expired or unparseable.
 *
 * FOR ACCESS TOKENS, NOT CREDENTIALS. A VC 2.0 credential JWT carries its
 * validity window as `validUntil` inside the credential and has no `exp` claim
 * at all, so passing one here reports it expired. Use `credentialValidUntil()`
 * on the decoded credential instead.
 */
export function isJwtExpired(token: string, clockSkewSeconds = 30): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== 'number') return true;
  // Subtract clock skew: consider token expired slightly BEFORE exp to handle clock drift
  return Date.now() / 1000 > payload.exp - clockSkewSeconds;
}

// ============================================================
// Retry Logic
// ============================================================

export interface RetryOptions {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Initial delay in ms before first retry (default: 1000) */
  initialDelayMs?: number;
  /** Backoff multiplier (default: 2) */
  backoffMultiplier?: number;
  /** Maximum delay in ms (default: 30000) */
  maxDelayMs?: number;
  /** Predicate to decide if the error is retryable */
  shouldRetry?: (error: unknown, attempt: number) => boolean;
}

/**
 * Retry an async operation with exponential backoff.
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const {
    maxRetries = 3,
    initialDelayMs = 1000,
    backoffMultiplier = 2,
    maxDelayMs = 30_000,
    shouldRetry = defaultShouldRetry,
  } = options;

  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt >= maxRetries || !shouldRetry(error, attempt)) {
        throw error;
      }
      const delay = Math.min(initialDelayMs * backoffMultiplier ** attempt, maxDelayMs);
      const jitter = delay * (0.5 + Math.random() * 0.5);
      await sleep(jitter);
    }
  }
  throw lastError;
}

function defaultShouldRetry(error: unknown): boolean {
  if (error instanceof Error) {
    // Network errors, timeouts
    if (error.name === 'AbortError' || error.name === 'TimeoutError') return true;
    if ('code' in error && typeof (error as { code: unknown }).code === 'string') {
      const code = (error as { code: string }).code;
      return ['ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ETIMEDOUT'].includes(code);
    }
  }
  return false;
}

// ============================================================
// Timing
// ============================================================

/**
 * Promise-based sleep.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================
// DID Utilities
// ============================================================

/**
 * Extract the method from a DID string (e.g., "did:key:z6Mk..." → "key").
 */
export function didMethod(did: string): string | null {
  const match = did.match(/^did:([^:]+):/);
  return match ? match[1]! : null;
}

/**
 * Validate that a string looks like a valid DID.
 */
export function isValidDid(did: string): boolean {
  return /^did:[a-z0-9]+:[a-zA-Z0-9._:%-]+$/.test(did);
}

// ============================================================
// Type Guards
// ============================================================

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}
