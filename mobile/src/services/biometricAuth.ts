/**
 * SSI Healthcare Mobile - Biometric Authentication Service
 * 
 * Provides secure biometric authentication using Face ID, Touch ID,
 * or fingerprint sensors. Used to protect sensitive operations like
 * sharing credentials or exporting keys.
 */

import * as LocalAuthentication from 'expo-local-authentication';
import { Platform } from 'react-native';

export enum BiometricType {
  FACE_ID = 'face_id',
  TOUCH_ID = 'touch_id',
  FINGERPRINT = 'fingerprint',
  IRIS = 'iris',
  NONE = 'none',
}

export interface BiometricCapabilities {
  isAvailable: boolean;
  isEnrolled: boolean;
  biometricTypes: BiometricType[];
  securityLevel: LocalAuthentication.SecurityLevel;
}

export interface AuthenticationOptions {
  promptMessage?: string;
  cancelLabel?: string;
  fallbackLabel?: string;
  disableDeviceFallback?: boolean;
  requireConfirmation?: boolean;
}

export interface AuthenticationResult {
  success: boolean;
  error?: string;
  warning?: string;
}

class BiometricAuthService {
  private cachedCapabilities: BiometricCapabilities | null = null;

  /**
   * Check if biometric authentication is available and enrolled.
   */
  async checkCapabilities(): Promise<BiometricCapabilities> {
    try {
      // Check hardware availability
      const isAvailable = await LocalAuthentication.hasHardwareAsync();
      
      // Check if biometrics are enrolled
      const isEnrolled = await LocalAuthentication.isEnrolledAsync();
      
      // Get supported authentication types
      const supportedTypes = await LocalAuthentication.supportedAuthenticationTypesAsync();
      
      // Get security level
      const securityLevel = await LocalAuthentication.getEnrolledLevelAsync();
      
      // Map to our biometric types
      const biometricTypes = supportedTypes.map((type) => {
        switch (type) {
          case LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION:
            return Platform.OS === 'ios' ? BiometricType.FACE_ID : BiometricType.FACE_ID;
          case LocalAuthentication.AuthenticationType.FINGERPRINT:
            return Platform.OS === 'ios' ? BiometricType.TOUCH_ID : BiometricType.FINGERPRINT;
          case LocalAuthentication.AuthenticationType.IRIS:
            return BiometricType.IRIS;
          default:
            return BiometricType.NONE;
        }
      }).filter((type) => type !== BiometricType.NONE);

      const capabilities: BiometricCapabilities = {
        isAvailable,
        isEnrolled,
        biometricTypes: biometricTypes.length > 0 ? biometricTypes : [BiometricType.NONE],
        securityLevel,
      };

      this.cachedCapabilities = capabilities;
      return capabilities;
    } catch (error) {
      console.error('[BiometricAuth] Failed to check capabilities:', error);
      return {
        isAvailable: false,
        isEnrolled: false,
        biometricTypes: [BiometricType.NONE],
        securityLevel: LocalAuthentication.SecurityLevel.NONE,
      };
    }
  }

  /**
   * Get cached capabilities or fetch fresh.
   */
  async getCapabilities(forceRefresh = false): Promise<BiometricCapabilities> {
    if (!forceRefresh && this.cachedCapabilities) {
      return this.cachedCapabilities;
    }
    return this.checkCapabilities();
  }

  /**
   * Check if biometric authentication is ready to use.
   */
  async isReady(): Promise<boolean> {
    const capabilities = await this.getCapabilities();
    return capabilities.isAvailable && capabilities.isEnrolled;
  }

  /**
   * Simple check if biometrics are available (alias for isReady).
   */
  async isAvailable(): Promise<boolean> {
    return this.isReady();
  }

  /**
   * Get a human-readable name for the available biometric type.
   */
  async getBiometricTypeName(): Promise<string> {
    const capabilities = await this.getCapabilities();
    
    if (capabilities.biometricTypes.includes(BiometricType.FACE_ID)) {
      return Platform.OS === 'ios' ? 'Face ID' : 'Face Recognition';
    }
    if (capabilities.biometricTypes.includes(BiometricType.TOUCH_ID)) {
      return 'Touch ID';
    }
    if (capabilities.biometricTypes.includes(BiometricType.FINGERPRINT)) {
      return 'Fingerprint';
    }
    if (capabilities.biometricTypes.includes(BiometricType.IRIS)) {
      return 'Iris Scanner';
    }
    
    return 'Biometric';
  }

  /**
   * Authenticate the user using biometrics.
   */
  async authenticate(options?: AuthenticationOptions): Promise<AuthenticationResult> {
    try {
      // Check if biometrics are available
      const capabilities = await this.getCapabilities();
      
      if (!capabilities.isAvailable) {
        return {
          success: false,
          error: 'Biometric authentication is not available on this device',
        };
      }

      if (!capabilities.isEnrolled) {
        return {
          success: false,
          error: 'No biometric data enrolled. Please set up biometrics in your device settings.',
        };
      }

      // Get biometric type name for the prompt
      const biometricName = await this.getBiometricTypeName();
      
      // Perform authentication
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: options?.promptMessage ?? `Authenticate with ${biometricName}`,
        cancelLabel: options?.cancelLabel ?? 'Cancel',
        fallbackLabel: options?.fallbackLabel ?? 'Use PIN',
        disableDeviceFallback: options?.disableDeviceFallback ?? false,
        requireConfirmation: options?.requireConfirmation ?? false,
      });

      if (result.success) {
        return { success: true };
      }

      // Handle specific error types
      let errorMessage = 'Authentication failed';
      let warning: string | undefined;

      switch (result.error) {
        case 'user_cancel':
          errorMessage = 'Authentication cancelled';
          break;
        case 'system_cancel':
          errorMessage = 'Authentication was cancelled by the system';
          break;
        case 'not_available':
          errorMessage = 'Biometric authentication is not available';
          break;
        case 'not_enrolled':
          errorMessage = 'No biometrics enrolled';
          break;
        case 'lockout':
          errorMessage = 'Too many failed attempts. Please try again later.';
          warning = 'Biometric authentication is temporarily locked';
          break;
        case 'passcode_not_set':
          errorMessage = 'Device passcode is not set. Please set up a PIN first.';
          break;
        default:
          // Handle lockout_permanent and other unknown errors
          if (result.error?.includes('lockout')) {
            errorMessage = 'Biometric authentication is locked. Please use your device PIN.';
            warning = 'Lockout - device PIN required';
          } else {
            errorMessage = result.error ?? 'Authentication failed';
          }
      }

      return { success: false, error: errorMessage, warning };
    } catch (error) {
      console.error('[BiometricAuth] Authentication error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown authentication error',
      };
    }
  }

  /**
   * Authenticate for a specific action with custom prompt.
   */
  async authenticateForAction(
    action: 'share_credential' | 'export_key' | 'delete_credential' | 'emergency_access' | 'settings_change'
  ): Promise<AuthenticationResult> {
    const prompts: Record<typeof action, string> = {
      share_credential: 'Authenticate to share your credential',
      export_key: 'Authenticate to export your private key',
      delete_credential: 'Authenticate to delete this credential',
      emergency_access: 'Authenticate to approve emergency access',
      settings_change: 'Authenticate to change security settings',
    };

    return this.authenticate({
      promptMessage: prompts[action],
      disableDeviceFallback: action === 'export_key', // Require biometric for key export
    });
  }

  /**
   * Clear cached capabilities (call when app resumes from background).
   */
  clearCache(): void {
    this.cachedCapabilities = null;
  }
}

// Export singleton instance
export const biometricAuthService = new BiometricAuthService();
