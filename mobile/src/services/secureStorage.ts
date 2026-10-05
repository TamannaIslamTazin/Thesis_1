/**
 * SSI Healthcare Mobile - Secure Storage Service
 * 
 * Provides encrypted storage for sensitive data using the device's
 * secure enclave or keystore. Used for storing private keys, tokens,
 * and other sensitive credential data.
 */

import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

// Storage keys
export const STORAGE_KEYS = {
  // Authentication
  ACCESS_TOKEN: 'ssi_access_token',
  REFRESH_TOKEN: 'ssi_refresh_token',
  AUTH_STATE: 'ssi_auth_state',
  
  // Identity
  /**
   * DO NOT READ THIS TO FIND THE HOLDER'S DID.
   *
   * Nothing writes it. `setIdentity` — its only writer — has no caller, because
   * the wallet moved to a device-held seed plus DID login (#398) and never
   * stores a private key. This key is kept only so `clearIdentity` can delete
   * values older builds left behind. Use `getUserDid()`.
   */
  USER_DID: 'ssi_user_did',
  PRIVATE_KEY: 'ssi_private_key',
  KEY_PAIR: 'ssi_key_pair',
  /**
   * The signed-in holder's profile, JSON-encoded exactly as the backend
   * returned it. This is the CANONICAL persisted identity, and `did` on it is
   * the wallet's DID. Written by every login/restore path in AuthContext.
   * Services that run outside React — the background sync drain above all —
   * read the DID from here, because they cannot reach the auth context.
   */
  USER_DATA: 'ssi_user_data',
  // Kept only so `clear()` can delete envelope copies written by older builds;
  // the live copy is in the keystore, reached by handle (#402).
  RECOVERY_KEY_ENVELOPE: 'ssi_recovery_key_envelope',
  // The E.164 handle the recovery envelope is filed under. Both sign-in and
  // restore address the keystore BY HANDLE (#402); without it this handset
  // cannot reach its own envelope.
  RECOVERY_HANDLE: 'ssi_recovery_handle',
  // The patient's #key-1 seed, biometric-gated. This is the holder's signing
  // component living where it belongs — see services/deviceSigner.ts.
  DEVICE_SIGNING_SEED: 'ssi_device_signing_seed',

  // Credentials
  CREDENTIAL_CACHE: 'ssi_credential_cache',
  CREDENTIAL_METADATA: 'ssi_credential_metadata',
  
  // Push notifications
  PUSH_TOKEN: 'ssi_push_token',
  NOTIFICATION_PREFERENCES: 'ssi_notification_prefs',
  
  // User preferences
  BIOMETRIC_ENABLED: 'ssi_biometric_enabled',
  APP_LOCK_GUARD_SECRET: 'ssi_app_lock_guard_secret',
  PIN_HASH: 'ssi_pin_hash',
  APP_LOCK_TIMEOUT: 'ssi_app_lock_timeout',
  ADVANCED_MODE: 'ssi_advanced_mode',
  /** The holder's chosen UI language. Not a secret, but this is where settings live. */
  LANGUAGE: 'ssi_language',
  /**
   * Where this holder's encrypted documents are stored. Empty or absent means
   * the ministry-hosted locker; a URL means the holder runs their own.
   * See SettingsContext for why this is a first-class setting.
   */
  STORAGE_SERVER: 'ssi_storage_server',
  /**
   * One host for the backend and both lockers, set by the holder. Empty means
   * use the addresses compiled into the build. This is what makes a preview
   * build usable on a network it was not built for.
   */
  SERVER_HOST: 'ssi_server_host',
  
  // Onboarding
  ONBOARDING_COMPLETE: 'ssi_onboarding_complete',
  BACKUP_REMINDER_SHOWN: 'ssi_backup_reminder',

  // Set only after the user re-enters the recovery words correctly. Deliberately
  // NOT the old `last_backup_date`, which recorded merely opening the screen —
  // renaming discards those values rather than carrying a false assurance forward.
  BACKUP_VERIFIED_AT: 'ssi_backup_verified_at',
} as const;

export type StorageKey = typeof STORAGE_KEYS[keyof typeof STORAGE_KEYS];

export interface SecureStorageOptions {
  requireAuthentication?: boolean;
  authenticationPrompt?: string;
}

class SecureStorageService {
  private readonly defaultOptions: SecureStore.SecureStoreOptions = {
    keychainService: 'com.ssihealthcare.wallet',
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  };

  /**
   * Check if secure storage is available on this device.
   */
  async isAvailable(): Promise<boolean> {
    try {
      // SecureStore is always available on iOS and Android
      // but we test by doing a write/read/delete cycle
      const testKey = '__secure_storage_test__';
      const testValue = 'test';
      
      await SecureStore.setItemAsync(testKey, testValue, this.defaultOptions);
      const retrieved = await SecureStore.getItemAsync(testKey, this.defaultOptions);
      await SecureStore.deleteItemAsync(testKey, this.defaultOptions);
      
      return retrieved === testValue;
    } catch (error) {
      console.error('[SecureStorage] Availability check failed:', error);
      return false;
    }
  }

  /**
   * Store a value securely.
   */
  async set(
    key: StorageKey | string, 
    value: string,
    options?: SecureStorageOptions
  ): Promise<boolean> {
    try {
      const storeOptions: SecureStore.SecureStoreOptions = {
        ...this.defaultOptions,
        requireAuthentication: options?.requireAuthentication ?? false,
        authenticationPrompt: options?.authenticationPrompt,
      };

      await SecureStore.setItemAsync(key, value, storeOptions);
      return true;
    } catch (error) {
      console.error(`[SecureStorage] Failed to set ${key}:`, error);
      return false;
    }
  }

  /**
   * Retrieve a value from secure storage.
   */
  async get(
    key: StorageKey | string,
    options?: SecureStorageOptions
  ): Promise<string | null> {
    try {
      const storeOptions: SecureStore.SecureStoreOptions = {
        ...this.defaultOptions,
        requireAuthentication: options?.requireAuthentication ?? false,
        authenticationPrompt: options?.authenticationPrompt,
      };

      return await SecureStore.getItemAsync(key, storeOptions);
    } catch (error) {
      console.error(`[SecureStorage] Failed to get ${key}:`, error);
      return null;
    }
  }

  async getRequiringAuthentication(
    key: StorageKey | string,
    authenticationPrompt: string
  ): Promise<string | null> {
    return SecureStore.getItemAsync(key, {
      ...this.defaultOptions,
      requireAuthentication: true,
      authenticationPrompt,
    });
  }

  /**
   * Delete a value from secure storage.
   */
  async delete(key: StorageKey | string): Promise<boolean> {
    try {
      await SecureStore.deleteItemAsync(key, this.defaultOptions);
      return true;
    } catch (error) {
      console.error(`[SecureStorage] Failed to delete ${key}:`, error);
      return false;
    }
  }

  /**
   * Check if a key exists in secure storage.
   */
  async exists(key: StorageKey | string): Promise<boolean> {
    const value = await this.get(key);
    return value !== null;
  }

  /**
   * Store a JSON object securely.
   */
  async setObject<T>(
    key: StorageKey | string, 
    value: T,
    options?: SecureStorageOptions
  ): Promise<boolean> {
    try {
      const jsonString = JSON.stringify(value);
      return await this.set(key, jsonString, options);
    } catch (error) {
      console.error(`[SecureStorage] Failed to serialize object for ${key}:`, error);
      return false;
    }
  }

  /**
   * Retrieve a JSON object from secure storage.
   */
  async getObject<T>(
    key: StorageKey | string,
    options?: SecureStorageOptions
  ): Promise<T | null> {
    try {
      const jsonString = await this.get(key, options);
      if (jsonString === null) return null;
      return JSON.parse(jsonString) as T;
    } catch (error) {
      console.error(`[SecureStorage] Failed to parse object for ${key}:`, error);
      return null;
    }
  }

  // =========================================================================
  // Convenience methods for common operations
  // =========================================================================

  /**
   * Store authentication tokens.
   */
  async setTokens(accessToken: string, refreshToken?: string): Promise<boolean> {
    const accessSuccess = await this.set(STORAGE_KEYS.ACCESS_TOKEN, accessToken);
    
    if (refreshToken) {
      const refreshSuccess = await this.set(STORAGE_KEYS.REFRESH_TOKEN, refreshToken);
      return accessSuccess && refreshSuccess;
    }
    
    return accessSuccess;
  }

  /**
   * Get authentication tokens.
   */
  async getTokens(): Promise<{ accessToken: string | null; refreshToken: string | null }> {
    const [accessToken, refreshToken] = await Promise.all([
      this.get(STORAGE_KEYS.ACCESS_TOKEN),
      this.get(STORAGE_KEYS.REFRESH_TOKEN),
    ]);
    
    return { accessToken, refreshToken };
  }

  /**
   * Clear authentication tokens.
   */
  async clearTokens(): Promise<void> {
    await Promise.all([
      this.delete(STORAGE_KEYS.ACCESS_TOKEN),
      this.delete(STORAGE_KEYS.REFRESH_TOKEN),
      this.delete(STORAGE_KEYS.AUTH_STATE),
    ]);
  }

  /**
   * Store user's DID and private key (requires biometric auth for retrieval).
   */
  async setIdentity(did: string, privateKey: string): Promise<boolean> {
    const didSuccess = await this.set(STORAGE_KEYS.USER_DID, did);
    const keySuccess = await this.set(STORAGE_KEYS.PRIVATE_KEY, privateKey, {
      requireAuthentication: Platform.OS === 'ios', // iOS supports this natively
      authenticationPrompt: 'Authenticate to store your private key securely',
    });
    
    return didSuccess && keySuccess;
  }

  /**
   * Get user's DID.
   *
   * Legacy: reads `USER_DID`, which nothing writes. Kept only for
   * `clearIdentity` symmetry. Use `getUserDid()`.
   */
  async getDID(): Promise<string | null> {
    return this.get(STORAGE_KEYS.USER_DID);
  }

  /**
   * The holder's DID, from the canonical persisted profile (`USER_DATA`).
   *
   * This is what a non-React consumer must use: the background sync drain has
   * no access to the auth context, and `USER_DID` is never populated.
   *
   * Returns null for a registered-but-not-yet-enrolled user, whose profile
   * carries no `did` — callers read that as "this wallet has no DID yet".
   */
  async getUserDid(): Promise<string | null> {
    const raw = await this.get(STORAGE_KEYS.USER_DATA);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as { did?: unknown };
      return typeof parsed.did === 'string' && parsed.did.length > 0 ? parsed.did : null;
    } catch {
      console.warn('[SecureStorage] stored user profile is not valid JSON');
      return null;
    }
  }

  /**
   * Get user's private key (requires authentication).
   */
  async getPrivateKey(): Promise<string | null> {
    return this.get(STORAGE_KEYS.PRIVATE_KEY, {
      requireAuthentication: Platform.OS === 'ios',
      authenticationPrompt: 'Authenticate to access your private key',
    });
  }

  /**
   * Clear identity data.
   */
  async clearIdentity(): Promise<void> {
    await Promise.all([
      this.delete(STORAGE_KEYS.USER_DID),
      this.delete(STORAGE_KEYS.PRIVATE_KEY),
      this.delete(STORAGE_KEYS.KEY_PAIR),
    ]);
  }

  /**
   * Store push notification token.
   */
  async setPushToken(token: string): Promise<boolean> {
    return this.set(STORAGE_KEYS.PUSH_TOKEN, token);
  }

  /**
   * Get push notification token.
   */
  async getPushToken(): Promise<string | null> {
    return this.get(STORAGE_KEYS.PUSH_TOKEN);
  }

  /**
   * Check if biometric is enabled.
   */
  async isBiometricEnabled(): Promise<boolean> {
    const value = await this.get(STORAGE_KEYS.BIOMETRIC_ENABLED);
    return value === 'true';
  }

  /**
   * Set biometric enabled state.
   */
  async setBiometricEnabled(enabled: boolean): Promise<boolean> {
    return this.set(STORAGE_KEYS.BIOMETRIC_ENABLED, enabled.toString());
  }

  /**
   * Check if onboarding is complete.
   */
  async isOnboardingComplete(): Promise<boolean> {
    const value = await this.get(STORAGE_KEYS.ONBOARDING_COMPLETE);
    return value === 'true';
  }

  /**
   * Mark onboarding as complete.
   */
  async setOnboardingComplete(): Promise<boolean> {
    return this.set(STORAGE_KEYS.ONBOARDING_COMPLETE, 'true');
  }

  /**
   * Clear all secure storage data.
   * Use with caution - this will remove all stored data!
   */
  async clearAll(): Promise<void> {
    const keys = Object.values(STORAGE_KEYS);
    await Promise.all(keys.map((key) => this.delete(key)));
  }
}

// Export singleton instance
export const secureStorage = new SecureStorageService();
