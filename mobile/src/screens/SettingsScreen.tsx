/**
 * SSI Healthcare Mobile - Settings Screen
 *
 * Account settings, key management, backup/recovery,
 * and app preferences.
 *
 * REFACTORED to use:
 * - Design tokens from theme system
 * - Reusable components
 * - Proper TypeScript types
 * - useCallback for event handlers
 * - Accessibility attributes
 */

import React, { useCallback, useMemo, useState } from 'react';
import { failureMessage } from '../utils/userFacingError';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
  Platform,
  TextInput,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { useAuth, useSettings } from '../contexts';
import type { BiometricGateRefusalReason } from '../services';
import { ssiClient } from '../services/ssiClient';
import { secureStorage } from '../services/secureStorage';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';
import { withOpacity } from '../theme/colors';
import { Button, Card, SectionHeader } from '../components/common';
import { BottomSheet, ConfirmationSheet, InfoSheet } from '../components/sheets';
import type { RootStackParamList } from '../types';

type SettingsNavigationProp = NativeStackNavigationProp<RootStackParamList>;

// -- Types --

interface SettingItem {
  id: string;
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  subtitle?: string;
  color: string;
  onPress?: () => void;
  danger?: boolean;
  toggle?: {
    value: boolean;
    onValueChange: (value: boolean) => void;
  };
}

interface SettingSection {
  title: string;
  items: SettingItem[];
}

// -- Sovereignty Progress Component --

interface SovereigntyProgressProps {
  level: number;
  percentage: number;
  description: string;
  hint: string;
}

const SovereigntyProgress = React.memo<SovereigntyProgressProps>(
  ({ level, percentage, description, hint }) => (
    <Card
      variant="default"
      style={styles.sovereigntyCard}
      accessibilityLabel={`Identity sovereignty level ${level}`}
    >
      <Text style={styles.sovereigntyTitle}>Identity Sovereignty</Text>
      <View style={styles.progressBar} accessibilityRole="progressbar" accessibilityValue={{ now: percentage, min: 0, max: 100 }}>
        <View style={[styles.progressFill, { width: `${percentage}%` }]} />
      </View>
      <Text style={styles.sovereigntyLevel}>{description}</Text>
      <Text style={styles.sovereigntyHint}>{hint}</Text>
    </Card>
  )
);

SovereigntyProgress.displayName = 'SovereigntyProgress';

// -- Setting Item Component --

interface SettingItemRowProps {
  item: SettingItem;
  isLast: boolean;
}

const SettingItemRow = React.memo<SettingItemRowProps>(({ item, isLast }) => {
  if (item.toggle) {
    return (
      <ToggleSettingRow
        icon={item.icon}
        label={item.label}
        subtitle={item.subtitle}
        color={item.color}
        value={item.toggle.value}
        onValueChange={item.toggle.onValueChange}
        isLast={isLast}
      />
    );
  }

  return (
    <TouchableOpacity
      style={[styles.settingItem, !isLast && styles.settingItemBorder]}
      onPress={item.onPress}
      activeOpacity={0.7}
      accessibilityRole="button"
      accessibilityLabel={item.label}
      accessibilityHint={item.subtitle}
    >
      <View style={[styles.settingIcon, { backgroundColor: withOpacity(item.color, 0.12) }]}>
        <Ionicons name={item.icon} size={20} color={item.color} />
      </View>
      <View style={styles.settingInfo}>
        <Text style={[styles.settingLabel, item.danger && styles.dangerLabel]}>
          {item.label}
        </Text>
        {item.subtitle && <Text style={styles.settingSubtitle}>{item.subtitle}</Text>}
      </View>
      <Ionicons name="chevron-forward" size={18} color={colors.text.disabled} />
    </TouchableOpacity>
  );
});

SettingItemRow.displayName = 'SettingItemRow';

// -- Toggle Setting Row Component --

interface ToggleSettingRowProps {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  subtitle?: string;
  color: string;
  value: boolean;
  onValueChange: (value: boolean) => void;
  isLast?: boolean;
}

const ToggleSettingRow = React.memo<ToggleSettingRowProps>(
  ({ icon, label, subtitle, color, value, onValueChange, isLast }) => (
    // A RADIO, NOT A SWITCH, and the whole row is the target.
    //
    // A platform switch animates between two states that look alike at a
    // glance, and on this screen the two states are "the app asks for your
    // fingerprint" and "it does not". A filled circle reads as chosen at any
    // size and in any theme, and it does not depend on the accent colour being
    // distinguishable from the track.
    //
    // The row is tappable rather than only the control: a 24px control on the
    // right edge is the smallest target on the screen, and this one changes a
    // security setting.
    <TouchableOpacity
      style={[styles.settingItem, !isLast && styles.settingItemBorder]}
      onPress={() => onValueChange(!value)}
      activeOpacity={0.7}
      accessibilityRole="radio"
      accessibilityState={{ selected: value }}
      accessibilityLabel={`${label}, ${value ? 'on' : 'off'}`}
    >
      <View style={[styles.settingIcon, { backgroundColor: withOpacity(color, 0.12) }]}>
        <Ionicons name={icon} size={20} color={color} />
      </View>
      <View style={styles.settingInfo}>
        <Text style={styles.settingLabel}>{label}</Text>
        {subtitle && <Text style={styles.settingSubtitle}>{subtitle}</Text>}
      </View>
      <Ionicons
        name={value ? 'radio-button-on' : 'radio-button-off'}
        size={24}
        color={value ? colors.brand.primary : colors.text.disabled}
      />
    </TouchableOpacity>
  )
);

ToggleSettingRow.displayName = 'ToggleSettingRow';

// -- Setting Section Component --

interface SettingSectionViewProps {
  section: SettingSection;
}

const SettingSectionView = React.memo<SettingSectionViewProps>(({ section }) => (
  <View style={styles.section}>
    <Text style={styles.sectionTitle}>{section.title}</Text>
    <Card variant="default" style={styles.sectionCard}>
      {section.items.map((item, index) => (
        <SettingItemRow
          key={item.id}
          item={item}
          isLast={index === section.items.length - 1}
        />
      ))}
    </Card>
  </View>
));

SettingSectionView.displayName = 'SettingSectionView';

function appLockRefusalMessage(reason: BiometricGateRefusalReason): string {
  if (reason === 'UNAVAILABLE') {
    return 'This device has no biometric hardware available.';
  }
  if (reason === 'NOT_ENROLLED') {
    return 'No fingerprint or face is enrolled on this device. Add one in your device settings, then try again.';
  }
  return 'This device only offers a weaker (Class 2) face or fingerprint check, which cannot protect a key held in the device keystore. Use a fingerprint sensor or a stronger face unlock if your device has one, or set a device PIN.';
}

// -- Screen Component --

export default function SettingsScreen() {
  // No navigator header on this tab, so nothing else supplies the status-bar gap.
  const insets = useSafeAreaInsets();
  const navigation = useNavigation<SettingsNavigationProp>();
  const { user, logout, isBiometricLockEnabled, setBiometricLockEnabled } = useAuth();
  const { isAdvancedMode, toggleAdvancedMode, storageServer, setStorageServer, serverHost, setServerHost, language, setLanguage } = useSettings();

  // Compute sovereignty level from user state
  // STATES THE TWO FACTS IT CAN ACTUALLY CHECK, not a progress bar.
  //
  // The old copy read "Level 2 of 4 (Phase 2 of 4)" against a four-stage
  // progression that exists nowhere in the system: no third or fourth stage is
  // defined, so the bar could never fill and the holder was shown a permanent
  // 50%. A progress indicator that cannot reach its end is a promise of work
  // that is not planned.
  //
  // What is checkable is whether an identifier exists and whether its key is
  // on this device. Both are properties of the wallet, not of a roadmap.
  const sovereigntyInfo = useMemo(() => {
    if (!user?.did) {
      return {
        level: 1,
        percentage: 40,
        description: 'Identifier not created yet',
        hint: 'Finish setup to get one.',
      };
    }
    return {
      level: 2,
      percentage: 100,
      description: 'Your identifier is on this device',
      hint: 'The signing key never leaves this phone. No server can act as you.',
    };
  }, [user]);

  // Sheet state management
  const [logoutSheetVisible, setLogoutSheetVisible] = useState(false);
  const [deleteDataSheetVisible, setDeleteDataSheetVisible] = useState(false);
  const [infoSheetVisible, setInfoSheetVisible] = useState(false);
  const [storageSheetVisible, setStorageSheetVisible] = useState(false);
  const [storageDraft, setStorageDraft] = useState('');
  const [storageError, setStorageError] = useState<string | null>(null);
  const [infoSheetConfig, setInfoSheetConfig] = useState({
    title: '',
    description: '',
    variant: 'info' as 'success' | 'error' | 'info' | 'warning',
  });

  // Show info helper
  const showInfo = useCallback((title: string, description: string, variant: 'success' | 'error' | 'info' | 'warning' = 'info') => {
    setInfoSheetConfig({ title, description, variant });
    setInfoSheetVisible(true);
  }, []);

  // Handlers
  const handleDIDManagement = useCallback(() => {
    const did = user?.did || 'Not configured';
    // "No one can take it away or deactivate it" was FALSE, and false about the
    // property this screen exists to explain. A patient DID is controlled by
    // [recovery key, issuing institution] as a 2-of-2 (S-1 8.1), so the
    // institution IS a controller, and deactivation on cheqd is terminal. The
    // guarantee the shape actually gives is RECOVERY without the device, which
    // is worth more to the holder and happens to be true.
    showInfo(
      'Your digital identity',
      `This identifier represents you across every service. It is yours, not an account on someone else's system.\n\n${did}\n\nIt is controlled jointly by your recovery key and the authority that enrolled you, so losing this phone does not lose your identity.`,
      'info'
    );
  }, [showInfo, user?.did]);

  const handleBackup = useCallback(() => {
    // Round 5: a passphrase-wrapped recovery envelope, stored in the
    // ministry keystore vault, is now real — see PassphraseSetupScreen and
    // AUTH-AND-KEYSTORE-API.md §2/§4. This used to say the feature did not
    // exist; leaving that claim here after building it would be exactly the
    // false-claim defect this project has spent rounds removing.
    (navigation as any).navigate('PassphraseSetup');
  }, [navigation]);

  const handleAppLockToggle = useCallback(
    async (value: boolean) => {
      const result = await setBiometricLockEnabled(value);
      if (result.status === 'ENABLED') {
        showInfo('App Lock Enabled', 'Your device biometric now unlocks the app.', 'success');
      } else if (result.status === 'DISABLED') {
        showInfo('App Lock Disabled', 'Biometric unlock has been turned off on this device.', 'info');
      } else if (result.status === 'REFUSED') {
        showInfo('App Lock Unavailable', appLockRefusalMessage(result.reason), 'warning');
      } else {
        showInfo('App Lock Failed', result.message, 'error');
      }
    },
    [setBiometricLockEnabled, showInfo]
  );

  const handleAuditLog = useCallback(() => {
    navigation.navigate('ActivityLog');
  }, [navigation]);

  const handleStorageServer = useCallback(() => {
    setStorageDraft(serverHost ?? '');
    setStorageError(null);
    setStorageSheetVisible(true);
  }, [storageServer]);

  const handleAbout = useCallback(() => {
    const appVersion = '0.1.0';
    const platform = Platform.OS === 'ios' ? 'iOS' : 'Android';
    showInfo(
      'About SSI Healthcare',
      // The old text said signing keys were "held in custody by the
      // BDHealthTrust backend on your behalf". That stopped being true when
      // enrolment moved the key onto the device: the backend's signer now
      // REFUSES for a patient DID because it holds no key mapping. Leaving the
      // claim would have understated the one property the design is for, in
      // the one place a user goes to read what the app does.
      `Version ${appVersion} on ${platform}.\n\nCredentials are issued to your own identifier. The signing key is generated on this phone and never leaves it, so no server can act as you.\n\nBuilt on W3C Verifiable Credentials and Credo-TS.`,
      'info'
    );
  }, [showInfo]);

  const handleLogout = useCallback(() => {
    setLogoutSheetVisible(true);
  }, []);

  const handleDeleteData = useCallback(() => {
    setDeleteDataSheetVisible(true);
  }, []);

  const handleDeleteDataConfirm = useCallback(async () => {
    try {
      // Server-side first: only clear anything locally once the account and
      // its data are confirmed gone. A failure here leaves the app exactly as
      // it was rather than reporting a deletion that did not happen.
      await ssiClient.deleteAccount();
      await logout();
      await secureStorage.clearAll();
      showInfo('Data Deleted', 'Your account and all associated credentials, consents, and records have been permanently deleted.', 'success');
    } catch (err) {
      showInfo('Delete Failed', 'Could not delete your account. Please try again.', 'error');
    }
  }, [logout, showInfo]);

  // Build sections with memoization
  const sections = useMemo<SettingSection[]>(
    () => [
      {
        title: 'Identity',
        items: [
          {
            id: 'did-management',
            icon: 'finger-print',
            label: 'Your identifier',
            subtitle: user?.did ? `${user.did.substring(0, 20)}…` : 'Not configured',
            color: colors.brand.primary,
            onPress: handleDIDManagement,
          },
          {
            id: 'backup-recovery',
            icon: 'cloud-upload',
            label: 'Recovery',
            subtitle: 'Phone number and passphrase',
            color: colors.brand.primary,
            onPress: handleBackup,
          },
        ],
      },
      {
        title: 'Security',
        items: [
          {
            id: 'app-lock',
            icon: 'lock-closed',
            label: 'App Lock',
            subtitle: isBiometricLockEnabled ? 'Biometric enabled' : 'Biometric disabled',
            color: colors.brand.primary,
            toggle: {
              value: isBiometricLockEnabled,
              onValueChange: handleAppLockToggle,
            },
          },
          {
            id: 'audit-log',
            icon: 'list',
            label: 'Activity',
            subtitle: 'Every time a credential was used',
            color: colors.brand.primary,
            onPress: handleAuditLog,
          },
        ],
      },
      {
        title: 'App',
        items: [
          {
            // REPLACED THE "Language" ROW, which opened a dialog explaining
            // that English was the only language — a setting that settled
            // nothing. This one decides where a holder's encrypted documents
            // actually live, which the design calls a first-class choice and
            // which had no surface at all until now.
            id: 'storage-server',
            icon: 'server',
            label: 'Server address',
            subtitle: serverHost ?? storageServer ?? 'Built in to this build',
            color: colors.brand.primary,
            onPress: handleStorageServer,
          },
          {
            id: 'about',
            icon: 'information-circle',
            label: 'About',
            subtitle: 'Version 0.1.0',
            color: colors.brand.primary,
            onPress: handleAbout,
          },
        ],
      },
      {
        title: 'Account',
        items: [
          {
            id: 'logout',
            icon: 'log-out',
            label: 'Sign Out',
            subtitle: user?.email || 'Not signed in',
            color: colors.semantic.error,
            danger: true,
            onPress: handleLogout,
          },
        ],
      },
      {
        title: 'Delete',
        items: [
          {
            id: 'delete-data',
            icon: 'trash',
            label: 'Delete everything',
            subtitle: 'Account and credentials. Cannot be undone.',
            color: colors.semantic.error,
            danger: true,
            onPress: handleDeleteData,
          },
        ],
      },
    ],
    [
      user,
      isBiometricLockEnabled,
      handleAppLockToggle,
      showInfo,
      handleDIDManagement,
      handleBackup,
      handleAuditLog,
      handleStorageServer,
      storageServer,
      serverHost,
      handleAbout,
      handleLogout,
      handleDeleteData,
    ]
  );

  return (
    <View style={styles.screenContainer}>
      <ScrollView
        style={styles.container}
        contentContainerStyle={[styles.content, { paddingTop: spacing.screenPadding }]}
        accessibilityLabel="Settings screen"
      >
        {/* Identity Sovereignty Progress */}
        <SovereigntyProgress
          level={sovereigntyInfo.level}
          percentage={sovereigntyInfo.percentage}
          description={sovereigntyInfo.description}
          hint={sovereigntyInfo.hint}
        />

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Detail</Text>
          <Card variant="default" style={styles.sectionCard}>
            <ToggleSettingRow
              icon="code-slash"
              label="Technical detail"
              subtitle={isAdvancedMode ? 'Identifiers and raw data shown' : 'Hidden'}
              color={colors.brand.primary}
              value={isAdvancedMode}
              onValueChange={toggleAdvancedMode}
              isLast
            />
          </Card>
          <Text style={styles.modeHint}>
            {isAdvancedMode
              ? 'Identifiers, signatures and raw payloads appear throughout the app.'
              : 'Turn this on to see identifiers and signatures.'}
          </Text>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Language</Text>
          <Card variant="default" style={styles.sectionCard}>
            <ToggleSettingRow
              icon="language"
              label="বাংলা (Bangla)"
              subtitle={language === 'bn' ? 'The app is shown in Bangla' : 'Tap to show the app in Bangla'}
              color={colors.brand.primary}
              value={language === 'bn'}
              onValueChange={(on) => setLanguage(on ? 'bn' : 'en')}
              isLast
            />
          </Card>
          <Text style={styles.modeHint}>
            An untranslated line falls back to English, so nothing is left blank.
          </Text>
        </View>

        {/* Setting Sections */}
        {sections.map((section) => (
          <SettingSectionView key={section.title} section={section} />
        ))}
      </ScrollView>

      {/* Sign Out Confirmation */}
      <ConfirmationSheet
        visible={logoutSheetVisible}
        onClose={() => setLogoutSheetVisible(false)}
        onConfirm={logout}
        title="Sign Out?"
        description="You'll need to sign in again to access your identity wallet. Your credentials remain safely stored on this device."
        confirmText="Sign Out"
        cancelText="Stay Signed In"
        variant="warning"
        icon="log-out-outline"
      />

      {/* Delete Data Confirmation */}
      <ConfirmationSheet
        visible={deleteDataSheetVisible}
        onClose={() => setDeleteDataSheetVisible(false)}
        onConfirm={handleDeleteDataConfirm}
        title="Delete All Data?"
        description="This cannot be undone. Your account, DID, credentials, and consent records will be permanently deleted from BDHealthTrust's servers and this device."
        confirmText="Delete Everything"
        cancelText="Keep My Data"
        variant="destructive"
        icon="trash-outline"
      />

      {/* Info Sheet */}
      <InfoSheet
        visible={infoSheetVisible}
        onClose={() => setInfoSheetVisible(false)}
        title={infoSheetConfig.title}
        description={infoSheetConfig.description}
        variant={infoSheetConfig.variant}
      />

      {/* Where documents are stored. Government by default, own server on request. */}
      <BottomSheet
        visible={storageSheetVisible}
        onClose={() => setStorageSheetVisible(false)}
        snapPoint={0.55}
        scrollable={false}
      >
        <View style={styles.storageSheet}>
          <Text style={styles.storageTitle}>Storage server</Text>
          <Text style={styles.storageBody}>
            One address for the whole system. Documents are encrypted on this phone before upload,
            so the server holds them and cannot read them.
          </Text>

          <TouchableOpacity
            style={styles.storageOption}
            onPress={() => {
              setStorageDraft('');
              setStorageError(null);
            }}
            accessibilityRole="radio"
            accessibilityState={{ selected: storageDraft.trim().length === 0 }}
          >
            <Ionicons
              name={storageDraft.trim().length === 0 ? 'radio-button-on' : 'radio-button-off'}
              size={22}
              color={colors.brand.primary}
            />
            <View style={styles.storageOptionText}>
              <Text style={styles.storageOptionLabel}>Use this build's addresses</Text>
              <Text style={styles.storageOptionHint}>Whatever was set when the app was built.</Text>
            </View>
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.storageOption}
            onPress={() => {
              if (storageDraft.trim().length === 0) setStorageDraft('192.168.0.');
              setStorageError(null);
            }}
            accessibilityRole="radio"
            accessibilityState={{ selected: storageDraft.trim().length > 0 }}
          >
            <Ionicons
              name={storageDraft.trim().length > 0 ? 'radio-button-on' : 'radio-button-off'}
              size={22}
              color={colors.brand.primary}
            />
            <View style={styles.storageOptionText}>
              <Text style={styles.storageOptionLabel}>A different address</Text>
              <Text style={styles.storageOptionHint}>For a network this build was not made for.</Text>
            </View>
          </TouchableOpacity>

          {storageDraft.trim().length > 0 && (
            <TextInput
              style={styles.storageInput}
              value={storageDraft}
              onChangeText={(text: string) => {
                setStorageDraft(text);
                setStorageError(null);
              }}
              placeholder="192.168.0.110"
              placeholderTextColor={colors.text.disabled}
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
            />
          )}

          {storageError !== null && <Text style={styles.storageErrorText}>{storageError}</Text>}

          <Button
            label="Save"
            onPress={() => {
              void (async () => {
                try {
                  await setServerHost(storageDraft.trim() || null);
                  setStorageSheetVisible(false);
                } catch (error) {
                  setStorageError(failureMessage(error));
                }
              })();
            }}
            fullWidth
          />
        </View>
      </BottomSheet>
    </View>
  );
}

// -- Styles --

const styles = StyleSheet.create({
  screenContainer: {
    flex: 1,
    backgroundColor: colors.background.primary,
  },
  container: {
    flex: 1,
    backgroundColor: colors.background.primary,
  },
  content: {
    padding: spacing.screenPadding,
    paddingBottom: spacing.huge,
  },
  sovereigntyCard: {
    marginBottom: spacing.xl,
    padding: spacing.lg,
  },
  sovereigntyTitle: {
    color: colors.text.primary,
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.bold,
    marginBottom: spacing.md,
  },
  progressBar: {
    height: 8,
    backgroundColor: colors.surface.tertiary,
    borderRadius: borderRadius.sm,
    overflow: 'hidden',
    marginBottom: spacing.sm,
  },
  progressFill: {
    height: '100%',
    backgroundColor: colors.brand.primary,
    borderRadius: borderRadius.sm,
  },
  sovereigntyLevel: {
    color: colors.brand.primaryLight,
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
  },
  sovereigntyHint: {
    color: colors.text.disabled,
    fontSize: fontSizes.xs,
    marginTop: spacing.xs,
  },
  section: {
    marginBottom: spacing.lg,
  },
  sectionTitle: {
    color: colors.text.secondary,
    fontSize: fontSizes.xs,
    fontWeight: fontWeights.semibold,
    textTransform: 'uppercase',
    letterSpacing: 1,
    marginBottom: spacing.sm,
    paddingHorizontal: spacing.xs,
  },
  sectionCard: {
    padding: 0,
    overflow: 'hidden',
  },
  settingItem: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: spacing.md,
    gap: spacing.md,
  },
  settingItemBorder: {
    borderBottomWidth: 1,
    borderBottomColor: colors.border.default,
  },
  settingIcon: {
    width: 36,
    height: 36,
    borderRadius: borderRadius.md,
    justifyContent: 'center',
    alignItems: 'center',
  },
  settingInfo: {
    flex: 1,
  },
  settingLabel: {
    color: colors.text.primary,
    fontSize: fontSizes.md,
    fontWeight: fontWeights.semibold,
  },
  dangerLabel: {
    color: colors.semantic.error,
  },
  settingSubtitle: {
    color: colors.text.disabled,
    fontSize: fontSizes.xs,
    marginTop: spacing.xxs,
  },
  storageSheet: { gap: spacing.md, paddingBottom: spacing.md },
  storageTitle: {
    color: colors.text.primary,
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.semibold,
  },
  storageBody: { color: colors.text.secondary, fontSize: fontSizes.sm },
  storageOption: { flexDirection: 'row', alignItems: 'center', gap: spacing.md },
  storageOptionText: { flex: 1 },
  storageOptionLabel: { color: colors.text.primary, fontSize: fontSizes.md },
  storageOptionHint: { color: colors.text.tertiary, fontSize: fontSizes.xs, marginTop: spacing.xxs },
  storageInput: {
    borderWidth: 1,
    borderColor: colors.border.default,
    borderRadius: borderRadius.md,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    color: colors.text.primary,
    fontSize: fontSizes.sm,
  },
  storageErrorText: { color: colors.semantic.error, fontSize: fontSizes.sm },
  modeHint: {
    color: colors.text.tertiary,
    fontSize: fontSizes.xs,
    marginTop: spacing.sm,
    paddingHorizontal: spacing.xs,
    lineHeight: fontSizes.xs * 1.4,
  },
});
