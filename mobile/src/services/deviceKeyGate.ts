import * as LocalAuthentication from 'expo-local-authentication';
import * as Crypto from 'expo-crypto';
import { bytesToBase64Url } from '@ssi-healthcare/shared';

import { biometricAuthService } from './biometricAuth';
import { secureStorage, STORAGE_KEYS } from './secureStorage';

const GUARD_SECRET_BYTES = 32;
const GUARD_SECRET_KEY = STORAGE_KEYS.APP_LOCK_GUARD_SECRET;

export type BiometricGateRefusalReason = 'UNAVAILABLE' | 'NOT_ENROLLED' | 'WEAK_ONLY';

export type BiometricGateCapability =
  | { readonly canBind: true }
  | { readonly canBind: false; readonly reason: BiometricGateRefusalReason };

export type BiometricGateEnableOutcome =
  | { readonly status: 'ENABLED' }
  | { readonly status: 'REFUSED'; readonly reason: BiometricGateRefusalReason }
  | { readonly status: 'FAILED'; readonly message: string };

export type BiometricGateReleaseOutcome =
  | { readonly status: 'RELEASED'; readonly secret: string }
  | { readonly status: 'NOT_ENABLED' }
  | { readonly status: 'INVALIDATED' }
  | { readonly status: 'FAILED'; readonly message: string };

async function checkCapability(): Promise<BiometricGateCapability> {
  const capabilities = await biometricAuthService.checkCapabilities();
  if (!capabilities.isAvailable) return { canBind: false, reason: 'UNAVAILABLE' };
  if (!capabilities.isEnrolled) return { canBind: false, reason: 'NOT_ENROLLED' };
  if (capabilities.securityLevel !== LocalAuthentication.SecurityLevel.BIOMETRIC_STRONG) {
    return { canBind: false, reason: 'WEAK_ONLY' };
  }
  return { canBind: true };
}

async function isEnabledOnThisDevice(): Promise<boolean> {
  return (await secureStorage.get(STORAGE_KEYS.BIOMETRIC_ENABLED)) === 'true';
}

async function enable(): Promise<BiometricGateEnableOutcome> {
  const capability = await checkCapability();
  if (!capability.canBind) {
    return { status: 'REFUSED', reason: capability.reason };
  }

  const secretBytes = await Crypto.getRandomBytesAsync(GUARD_SECRET_BYTES);
  const secret = bytesToBase64Url(secretBytes);

  const stored = await secureStorage.set(GUARD_SECRET_KEY, secret, {
    requireAuthentication: true,
    authenticationPrompt: 'Confirm your biometric to enable App Lock',
  });

  if (!stored) {
    return { status: 'FAILED', message: 'Could not bind a key to this device biometric.' };
  }

  const flagged = await secureStorage.set(STORAGE_KEYS.BIOMETRIC_ENABLED, 'true');
  if (!flagged) {
    await secureStorage.delete(GUARD_SECRET_KEY);
    return { status: 'FAILED', message: 'Could not save the App Lock preference.' };
  }

  return { status: 'ENABLED' };
}

async function disable(): Promise<void> {
  await secureStorage.delete(GUARD_SECRET_KEY);
  await secureStorage.set(STORAGE_KEYS.BIOMETRIC_ENABLED, 'false');
}

async function release(promptMessage: string): Promise<BiometricGateReleaseOutcome> {
  const wasEnabled = await isEnabledOnThisDevice();
  if (!wasEnabled) {
    return { status: 'NOT_ENABLED' };
  }

  let secret: string | null;
  try {
    secret = await secureStorage.getRequiringAuthentication(GUARD_SECRET_KEY, promptMessage);
  } catch (error) {
    return {
      status: 'FAILED',
      message: error instanceof Error ? error.message : 'Biometric authentication failed.',
    };
  }

  if (secret === null) {
    await disable();
    return { status: 'INVALIDATED' };
  }

  return { status: 'RELEASED', secret };
}

export const deviceKeyGate = {
  checkCapability,
  isEnabledOnThisDevice,
  enable,
  disable,
  release,
};
