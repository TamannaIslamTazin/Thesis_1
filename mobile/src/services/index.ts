/**
 * SSI Healthcare Mobile - Services Index
 * 
 * Export all mobile services for easy importing.
 */

// SSI SDK Client (preferred for credential/consent operations)
export { ssiClient, getSSIClient, resetSSIClient } from './ssiClient';

// Legacy API service (for auth and backend-specific endpoints)
export { apiService } from './api';

export { pushNotificationService } from './pushNotifications';
export type { 
  PushNotificationToken, 
  NotificationPayload, 
  NotificationType,
  NotificationListener,
} from './pushNotifications';

export { biometricAuthService, BiometricType } from './biometricAuth';
export type {
  BiometricCapabilities,
  AuthenticationOptions,
  AuthenticationResult,
} from './biometricAuth';

export { secureStorage, STORAGE_KEYS } from './secureStorage';
export type { StorageKey, SecureStorageOptions } from './secureStorage';

export { deviceKeyGate } from './deviceKeyGate';
export type {
  BiometricGateCapability,
  BiometricGateEnableOutcome,
  BiometricGateReleaseOutcome,
  BiometricGateRefusalReason,
} from './deviceKeyGate';

export { recoveryKeyRelease, RecoveryKeyReleaseError } from './recoveryKeyRelease';
export type { RecoveryKeyReleasePort } from './recoveryKeyRelease';

export { qrScannerService, useCameraPermissions, QRCodeType } from './qrScanner';
export type { ParsedQRCode } from './qrScanner';
