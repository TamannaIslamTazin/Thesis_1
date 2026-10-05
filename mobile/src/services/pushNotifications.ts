/**
 * SSI Healthcare Mobile - Push Notification Service
 * 
 * Handles Firebase Cloud Messaging (FCM) for push notifications.
 * Supports credential issuance alerts, verification requests,
 * and emergency access notifications.
 */

import * as Notifications from 'expo-notifications';
import * as Device from 'expo-device';
import { Platform } from 'react-native';
import Constants from 'expo-constants';
import { colors } from '../theme';

// Configure notification behavior
Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
    shouldShowBanner: true,
    shouldShowList: true,
  }),
});

export interface PushNotificationToken {
  token: string;
  type: 'expo' | 'fcm' | 'apns';
}

export interface NotificationPayload {
  title: string;
  body: string;
  data?: Record<string, unknown>;
}

export type NotificationType = 
  | 'credential_issued'
  | 'credential_revoked'
  | 'verification_request'
  | 'emergency_access_request'
  | 'emergency_access_granted'
  | 'consent_expiring'
  | 'consent_revoked';

export interface NotificationListener {
  remove: () => void;
}

class PushNotificationService {
  private expoPushToken: string | null = null;
  private notificationListener: Notifications.EventSubscription | null = null;
  private responseListener: Notifications.EventSubscription | null = null;

  /**
   * Initialize push notification service.
   * Call this on app startup.
   */
  async initialize(): Promise<string | null> {
    try {
      // Request permissions
      const hasPermission = await this.requestPermissions();
      if (!hasPermission) {
        console.warn('[Notifications] Permission not granted');
        return null;
      }

      // Get push token
      const token = await this.getExpoPushToken();
      this.expoPushToken = token;

      // Set up notification channels for Android
      if (Platform.OS === 'android') {
        await this.setupAndroidChannels();
      }

      console.log('[Notifications] Initialized with token:', token);
      return token;
    } catch (error) {
      console.error('[Notifications] Initialization failed:', error);
      return null;
    }
  }

  /**
   * Request notification permissions from the user.
   */
  async requestPermissions(): Promise<boolean> {
    if (!Device.isDevice) {
      console.warn('[Notifications] Must use physical device for push notifications');
      return false;
    }

    const { status: existingStatus } = await Notifications.getPermissionsAsync();
    let finalStatus = existingStatus;

    if (existingStatus !== 'granted') {
      const { status } = await Notifications.requestPermissionsAsync();
      finalStatus = status;
    }

    if (finalStatus !== 'granted') {
      console.warn('[Notifications] Permission denied');
      return false;
    }

    return true;
  }

  /**
   * Get the Expo push notification token.
   */
  private async getExpoPushToken(): Promise<string> {
    const projectId = Constants.expoConfig?.extra?.eas?.projectId ?? 
                      Constants.easConfig?.projectId;
    
    if (!projectId) {
      throw new Error('Project ID not found in app config');
    }

    const tokenData = await Notifications.getExpoPushTokenAsync({
      projectId,
    });

    return tokenData.data;
  }

  /**
   * Set up Android notification channels.
   */
  private async setupAndroidChannels(): Promise<void> {
    // Default channel for general notifications
    await Notifications.setNotificationChannelAsync('default', {
      name: 'Default',
      importance: Notifications.AndroidImportance.DEFAULT,
      vibrationPattern: [0, 250, 250, 250],
      lightColor: colors.brand.primary,
    });

    // High priority channel for credentials
    await Notifications.setNotificationChannelAsync('credentials', {
      name: 'Credentials',
      description: 'Notifications about your health credentials',
      importance: Notifications.AndroidImportance.HIGH,
      vibrationPattern: [0, 250, 250, 250],
      lightColor: colors.semantic.success,
    });

    // Urgent channel for emergency access
    await Notifications.setNotificationChannelAsync('emergency', {
      name: 'Emergency Access',
      description: 'Urgent notifications about emergency access to your records',
      importance: Notifications.AndroidImportance.MAX,
      vibrationPattern: [0, 500, 200, 500],
      lightColor: colors.semantic.error,
    });

    // Verification requests channel
    await Notifications.setNotificationChannelAsync('verification', {
      name: 'Verification Requests',
      description: 'Notifications about credential verification requests',
      importance: Notifications.AndroidImportance.HIGH,
      vibrationPattern: [0, 250, 250, 250],
      lightColor: colors.brand.primary,
    });
  }

  /**
   * Get the current push token.
   */
  getToken(): string | null {
    return this.expoPushToken;
  }

  /**
   * Add a listener for foreground notifications.
   */
  addNotificationReceivedListener(
    callback: (notification: Notifications.Notification) => void
  ): NotificationListener {
    this.notificationListener = Notifications.addNotificationReceivedListener(callback);
    return {
      remove: () => {
        if (this.notificationListener) {
          this.notificationListener.remove();
          this.notificationListener = null;
        }
      },
    };
  }

  /**
   * Add a listener for notification responses (user taps).
   */
  addNotificationResponseListener(
    callback: (response: Notifications.NotificationResponse) => void
  ): NotificationListener {
    this.responseListener = Notifications.addNotificationResponseReceivedListener(callback);
    return {
      remove: () => {
        if (this.responseListener) {
          this.responseListener.remove();
          this.responseListener = null;
        }
      },
    };
  }

  /**
   * Schedule a local notification.
   */
  async scheduleLocalNotification(
    payload: NotificationPayload,
    trigger?: Notifications.NotificationTriggerInput
  ): Promise<string> {
    const notificationId = await Notifications.scheduleNotificationAsync({
      content: {
        title: payload.title,
        body: payload.body,
        data: payload.data,
        sound: true,
      },
      trigger: trigger ?? null, // null = immediate
    });

    return notificationId;
  }

  /**
   * Cancel a scheduled notification.
   */
  async cancelNotification(notificationId: string): Promise<void> {
    await Notifications.cancelScheduledNotificationAsync(notificationId);
  }

  /**
   * Cancel all scheduled notifications.
   */
  async cancelAllNotifications(): Promise<void> {
    await Notifications.cancelAllScheduledNotificationsAsync();
  }

  /**
   * Get the badge count.
   */
  async getBadgeCount(): Promise<number> {
    return await Notifications.getBadgeCountAsync();
  }

  /**
   * Set the badge count.
   */
  async setBadgeCount(count: number): Promise<void> {
    await Notifications.setBadgeCountAsync(count);
  }

  /**
   * Clear the badge.
   */
  async clearBadge(): Promise<void> {
    await Notifications.setBadgeCountAsync(0);
  }

  /**
   * Get all delivered notifications.
   */
  async getDeliveredNotifications(): Promise<Notifications.Notification[]> {
    return await Notifications.getPresentedNotificationsAsync();
  }

  /**
   * Dismiss all delivered notifications.
   */
  async dismissAllNotifications(): Promise<void> {
    await Notifications.dismissAllNotificationsAsync();
  }

  /**
   * Clean up listeners.
   */
  cleanup(): void {
    if (this.notificationListener) {
      this.notificationListener.remove();
      this.notificationListener = null;
    }
    if (this.responseListener) {
      this.responseListener.remove();
      this.responseListener = null;
    }
  }
}

// Export singleton instance
export const pushNotificationService = new PushNotificationService();
