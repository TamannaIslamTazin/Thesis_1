/**
 * TOTP (Time-based One-Time Password) Service
 *
 * Provides TOTP secret generation, QR code URL generation, and code verification
 * using the RFC 6238 standard (compatible with Google Authenticator, Authy, etc.).
 */

import { generateSecret, verify, generateURI } from 'otplib';
import QRCode from 'qrcode';

const ISSUER = 'SSI Healthcare';

/**
 * Generate a new TOTP secret and QR code for the given user email.
 * The secret should be stored only after the user verifies it.
 */
export async function generateTotpSetup(email: string): Promise<{
  secret: string;
  otpauthUrl: string;
  qrCodeDataUrl: string;
}> {
  const secret = generateSecret();
  const otpauthUrl = generateURI({ label: email, issuer: ISSUER, secret });
  const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);

  return { secret, otpauthUrl, qrCodeDataUrl };
}

/**
 * Verify a TOTP token against a secret.
 * Returns true if the code is valid within a ±1 window (±30 seconds drift).
 */
export async function verifyTotpCode(token: string, secret: string): Promise<boolean> {
  const result = await verify({ token, secret });
  return result.valid;
}
