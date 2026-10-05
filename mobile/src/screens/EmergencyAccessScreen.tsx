/**
 * SSI Healthcare Mobile - Emergency Access Screen
 *
 * Break-glass emergency access (Paradigm B).
 * Shows emergency access history and allows viewing
 * currently active emergency accesses.
 *
 * REFACTORED to use:
 * - Zustand store for state management
 * - Design tokens from theme system
 * - Reusable components
 * - Proper TypeScript types
 * - Accessibility attributes
 */

import React, { useEffect, useCallback, useState } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
  RefreshControl,
  Switch,
} from 'react-native';
import * as SecureStore from 'expo-secure-store';
import { Ionicons } from '@expo/vector-icons';
import type { ComponentProps } from 'react';
import { useAuth } from '../contexts';
import { useEmergencyStore } from '../store';
import { useLiveRefresh } from '../hooks/useLiveRefresh';
import { colors, spacing, fontSizes, fontWeights, borderRadius, lineHeights, opacity, lineHeightFor} from '../theme';
import { withOpacity } from '../theme/colors';
import { ConfirmationSheet, InfoSheet } from '../components/sheets';
import {
  BackButton,
  LoadingSpinner,
  ErrorState,
  EmptyState,
  Card,
  SectionHeader,
  Badge,
  Button,
} from '../components/common';
import type { EmergencyRecord, EmergencyStatus } from '../types';

type IoniconsName = ComponentProps<typeof Ionicons>['name'];

// -- Emergency Override Settings Interface --

interface EmergencyOverrideSettings {
  enabled: boolean;
  allowedProviderTypes: string[];
  autoExpireHours: number;
  notifyContacts: boolean;
}

// -- Helper Functions --

/**
 * THE PALETTE WAS INVERTED, and on this screen that inversion is the message.
 *
 * `granted` — a hospital reading your records RIGHT NOW — was green with a
 * shield-check, the same treatment this app uses for "your privacy held".
 * `revoked` — the state the holder acted to reach — was red. So the one entry
 * that should pull the eye looked like the reassuring one, and stopping an
 * access looked like something had gone wrong.
 */
const getStatusColor = (status: EmergencyStatus): string => {
  switch (status) {
    case 'granted':
      return colors.semantic.error;
    case 'expired':
      return colors.text.secondary;
    case 'revoked':
      return colors.semantic.success;
    default:
      return colors.text.secondary;
  }
};

const getStatusIcon = (status: EmergencyStatus): IoniconsName => {
  switch (status) {
    case 'granted':
      return 'alert-circle';
    case 'expired':
      return 'time';
    case 'revoked':
      return 'shield-checkmark';
    default:
      return 'help-circle';
  }
};

const formatDateTime = (dateString: string): string => {
  return new Date(dateString).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
};

// -- Provider Type Configuration --

const PROVIDER_TYPES = [
  { id: 'emt', label: 'Emergency Medical Technicians', icon: 'medkit-outline' as IoniconsName },
  { id: 'er_doctor', label: 'ER Physicians', icon: 'medical-outline' as IoniconsName },
  { id: 'nurse', label: 'Registered Nurses', icon: 'person-outline' as IoniconsName },
  { id: 'paramedic', label: 'Paramedics', icon: 'car-outline' as IoniconsName },
];

// -- Info Banner Component --

const InfoBanner = React.memo(() => (
  <Card
    variant="default"
    style={styles.infoBanner}
    accessibilityLabel="Break-glass access information"
  >
    <Ionicons name="alert-circle" size={24} color={colors.semantic.warning} />
    <View style={styles.infoContent}>
      <Text style={styles.infoTitle}>Break-Glass Access</Text>
      {/* SAY WHAT ACTUALLY HAPPENS.
          This used to end "...and your family is notified", which was untrue in
          the strongest sense: no notification code exists, and the record was
          ALSO stamped with a notification time, so the app and the audit trail
          agreed on something that never happened. Describing the real model —
          granted immediately, visible here, revocable, time-limited — is both
          honest and more useful, because it tells the holder what their actual
          recourse is. */}
      <Text style={styles.infoText}>
        In a life-threatening emergency, a hospital can open your records without
        waiting for your approval — you may be unconscious, and waiting could cost
        your life. Access is not silent: it appears here immediately, it expires
        by itself within an hour, and you can stop it at any time.
      </Text>
      <Text style={styles.infoTextMuted}>
        Alerting a family member is not built yet, so do not rely on someone else
        being told. Check this screen.
      </Text>
    </View>
  </Card>
));

InfoBanner.displayName = 'InfoBanner';

// -- Current Status Component --

interface CurrentStatusProps {
  hasActiveEmergency: boolean;
  activeCount: number;
}

const CurrentStatus = React.memo<CurrentStatusProps>(({ hasActiveEmergency, activeCount }) => (
  <Card
    variant="default"
    style={[
      styles.statusCard,
      hasActiveEmergency ? styles.statusCardActive : styles.statusCardSafe,
    ]}
    accessibilityLabel={hasActiveEmergency ? `${activeCount} active emergency access` : 'No active emergency access'}
  >
    <View style={styles.statusIndicator}>
      <View
        style={[
          styles.statusDot,
          hasActiveEmergency ? styles.statusDotActive : styles.statusDotSafe,
        ]}
      />
      <Text style={hasActiveEmergency ? styles.statusActiveText : styles.statusSafeText}>
        {hasActiveEmergency
          ? `${activeCount} Active Emergency Access`
          : 'No Active Emergency Access'}
      </Text>
    </View>
    <Text style={styles.statusSubtext}>
      {hasActiveEmergency
        ? 'A healthcare provider currently has temporary access to your credentials.'
        : 'Your credentials are protected. Emergency providers can request temporary access through verified hospital systems.'}
    </Text>
  </Card>
));

CurrentStatus.displayName = 'CurrentStatus';

/**
 * What break-glass actually does, in the holder's own terms.
 *
 * Replaces a settings block whose switches changed nothing outside this device.
 * Stating the rule plainly is worth more than a control that cannot enforce it:
 * a holder who knows access is immediate and revocable will check this screen,
 * whereas one who believes approval is required will not.
 */
const HowThisWorks = React.memo(() => (
  <Card variant="default" style={styles.howCard} accessibilityLabel="How emergency access works">
    {[
      ['flash-outline', 'A hospital can open your records straight away, without asking you first.'],
      ['eye-outline', 'Every opening is recorded here, including which records were actually read.'],
      ['timer-outline', 'Access ends by itself within an hour.'],
      ['hand-left-outline', 'You can stop it at any moment using the button on the record below.'],
    ].map(([icon, text]) => (
      <View key={text} style={styles.howRow}>
        <Ionicons name={icon as never} size={16} color={colors.text.secondary} />
        <Text style={styles.howText}>{text}</Text>
      </View>
    ))}
  </Card>
));

HowThisWorks.displayName = 'HowThisWorks';

// -- Emergency Record Card Component --

interface EmergencyRecordCardProps {
  record: EmergencyRecord;
  /** Present only where revoking is possible; absent for finished records. */
  onRevoke?: (record: EmergencyRecord) => void;
  isRevoking?: boolean;
}

const EmergencyRecordCard = React.memo<EmergencyRecordCardProps>(({ record, onRevoke, isRevoking }) => {
  const statusColor = getStatusColor(record.status);
  const statusIcon = getStatusIcon(record.status);

  return (
    <Card
      variant="default"
      style={styles.recordCard}
      accessibilityLabel={`Emergency access by ${record.providerName}`}
    >
      <View style={styles.recordHeader}>
        <View style={styles.recordIcon}>
          <Ionicons name="medkit" size={24} color={colors.semantic.error} />
        </View>
        <View style={styles.recordInfo}>
          <Text style={styles.recordProvider}>{record.providerName}</Text>
          <Text style={styles.recordTime}>{formatDateTime(record.requestedAt)}</Text>
        </View>
        {/* AN ACTIVE GRANT IS NOT A SUCCESS.
            `granted` was rendered green. Green is what this app uses for "your
            privacy held" — a stranger reading your records right now is the one
            state on this screen that most needs to look alarming, and a revoked
            grant is the reassuring one. The palette was exactly inverted. */}
        <Badge
          label={record.status === 'granted' ? 'Active now' : record.status.charAt(0).toUpperCase() + record.status.slice(1)}
          variant={record.status === 'granted' ? 'error' : record.status === 'revoked' ? 'success' : 'warning'}
          icon={statusIcon}
          size="small"
        />
      </View>

      <Text style={styles.recordReason}>{record.reason}</Text>

      <View style={styles.recordMeta}>
        <View style={styles.metaItem}>
          <Ionicons name="time-outline" size={14} color={colors.text.secondary} />
          <Text style={styles.metaText}>
            Duration: {formatDateTime(record.requestedAt)} → {formatDateTime(record.expiresAt)}
          </Text>
        </View>
        {/* "Family was notified" was rendered in green from `record.familyNotified`,
            a field the backend set whenever a contact DID was supplied — while
            nothing sent anything. It is gone rather than reworded: a reassurance
            about a safeguard that does not exist is the most damaging thing this
            card could say, because the holder stops looking for the alarm. */}
      </View>

      {record.status === 'granted' && onRevoke && (
        <Button
          label="Stop this access now"
          onPress={() => onRevoke(record)}
          variant="danger"
          size="medium"
          icon="close-circle-outline"
          loading={isRevoking}
          fullWidth
          style={styles.revokeButton}
        />
      )}
    </Card>
  );
});

EmergencyRecordCard.displayName = 'EmergencyRecordCard';

// -- Family Contact Card Component --

/* THE "EMERGENCY CONTACT" CARD WAS REMOVED, and it made three promises in a
   row for one feature that does not exist:

     the card      "will be notified during emergency access"
     the sheet     "They'll be able to access critical health information"
     the outcome   "Coming Soon ... Stay tuned!"

   The middle one is the worst: it describes GRANTING a third party access to
   health records, which nothing in this system does and which no holder should
   believe they have arranged. Same defect as the fabricated `familyNotified`
   audit field removed from the backend — a holder told a safeguard is in place
   stops looking for the alarm, and under auto-grant the alarm is the control.

   Nothing replaces it. The break-glass explanation above and the revoke button
   on each active grant are real, and are what this screen is for. */

// -- Emergency Override Settings Component --

interface OverrideSettingsProps {
  settings: EmergencyOverrideSettings;
  onToggleEnabled: () => void;
  onToggleProvider: (providerId: string) => void;
  onToggleNotify: () => void;
}

const EmergencyOverrideSettings = React.memo<OverrideSettingsProps>(({
  settings,
  onToggleEnabled,
  onToggleProvider,
  onToggleNotify,
}) => (
  <Card variant="default" style={styles.overrideCard}>
    {/* Main Toggle */}
    <View style={styles.overrideHeader}>
      <View style={styles.overrideHeaderLeft}>
        <Ionicons 
          name={settings.enabled ? 'shield-checkmark' : 'shield-outline'} 
          size={24} 
          color={settings.enabled ? colors.semantic.success : colors.text.tertiary} 
        />
        <View style={styles.overrideHeaderText}>
          <Text style={styles.overrideTitle}>Emergency Override</Text>
          <Text style={styles.overrideSubtitle}>
            {settings.enabled 
              ? 'Verified providers can access critical data' 
              : 'Emergency access requires manual approval'
            }
          </Text>
        </View>
      </View>
      <Switch
        value={settings.enabled}
        onValueChange={onToggleEnabled}
        trackColor={{ 
          false: colors.ui.switchTrackOff, 
          true: colors.ui.switchTrackOn 
        }}
        thumbColor={settings.enabled ? colors.ui.switchThumbOn : colors.ui.switchThumbOff}
        accessibilityLabel="Toggle emergency override"
        accessibilityRole="switch"
      />
    </View>

    {/* Expanded Settings */}
    {settings.enabled && (
      <>
        <View style={styles.overrideDivider} />
        
        {/* Allowed Provider Types */}
        <Text style={styles.overrideSectionTitle}>Allow Access From:</Text>
        {PROVIDER_TYPES.map((provider) => {
          const isEnabled = settings.allowedProviderTypes.includes(provider.id);
          return (
            <TouchableOpacity
              key={provider.id}
              style={styles.providerRow}
              onPress={() => onToggleProvider(provider.id)}
              accessibilityRole="checkbox"
              accessibilityState={{ checked: isEnabled }}
            >
              <Ionicons 
                name={provider.icon} 
                size={18} 
                color={isEnabled ? colors.brand.primary : colors.text.tertiary} 
              />
              <Text style={[
                styles.providerLabel,
                isEnabled && styles.providerLabelEnabled
              ]}>
                {provider.label}
              </Text>
              <Ionicons 
                name={isEnabled ? 'checkmark-circle' : 'ellipse-outline'} 
                size={20} 
                color={isEnabled ? colors.brand.primary : colors.text.disabled} 
              />
            </TouchableOpacity>
          );
        })}
        
        <View style={styles.overrideDivider} />
        
        {/* Auto-expire Info */}
        <View style={styles.autoExpireRow}>
          <Ionicons name="time-outline" size={18} color={colors.text.secondary} />
          <Text style={styles.autoExpireText}>
            Access automatically expires after {settings.autoExpireHours} hours
          </Text>
        </View>
        
        {/* Notification Toggle */}
        <View style={styles.notifyRow}>
          <Ionicons name="notifications-outline" size={18} color={colors.text.secondary} />
          <Text style={styles.notifyText}>Notify emergency contacts</Text>
          <Switch
            value={settings.notifyContacts}
            onValueChange={onToggleNotify}
            trackColor={{ 
              false: colors.ui.switchTrackOff, 
              true: colors.ui.switchTrackOn 
            }}
            thumbColor={settings.notifyContacts ? colors.ui.switchThumbOn : colors.ui.switchThumbOff}
            accessibilityLabel="Toggle contact notifications"
          />
        </View>
      </>
    )}
  </Card>
));

EmergencyOverrideSettings.displayName = 'EmergencyOverrideSettings';

// -- Screen Component --

export default function EmergencyAccessScreen() {
  const { user } = useAuth();
  const {
    records,
    activeRecords,
    isLoading,
    lastCheckFailed,
    isRevoking,
    error,
    fetchRecords,
    revokeAccess,
    clearError,
  } = useEmergencyStore();

  // Sheet visibility states
  
  // Emergency override settings persisted in SecureStore
  const OVERRIDE_SETTINGS_KEY = 'emergency_override_settings';
  const [overrideSettings, setOverrideSettings] = useState<EmergencyOverrideSettings>({
    enabled: false,
    allowedProviderTypes: ['emt', 'er_doctor'],
    autoExpireHours: 24,
    notifyContacts: true,
  });

  // Load persisted settings on mount
  useEffect(() => {
    SecureStore.getItemAsync(OVERRIDE_SETTINGS_KEY).then((raw) => {
      if (raw) {
        try {
          const saved = JSON.parse(raw) as EmergencyOverrideSettings;
          setOverrideSettings(saved);
        } catch {
          // ignore corrupt data
        }
      }
    });
  }, []);

  // Not "on mount": a tab screen stays mounted for the whole session, and a
  // grant is raised by someone else. See useLiveRefresh for what that cost.
  useLiveRefresh(useCallback(() => fetchRecords(user?.did), [fetchRecords, user?.did]));

  // Handle retry
  const handleRetry = useCallback(() => {
    clearError();
    fetchRecords(user?.did);
  }, [clearError, fetchRecords, user?.did]);

  /** Stop a live grant. The holder's only lever under an auto-grant model. */
  const handleRevokeAccess = useCallback(
    (record: EmergencyRecord) => {
      void revokeAccess(record.id);
    },
    [revokeAccess],
  );

  // Handle override toggle
  const handleToggleOverride = useCallback(() => {
    setOverrideSettings(prev => {
      const next = { ...prev, enabled: !prev.enabled };
      SecureStore.setItemAsync(OVERRIDE_SETTINGS_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  // Handle provider toggle
  const handleToggleProvider = useCallback((providerId: string) => {
    setOverrideSettings(prev => {
      const newProviders = prev.allowedProviderTypes.includes(providerId)
        ? prev.allowedProviderTypes.filter(id => id !== providerId)
        : [...prev.allowedProviderTypes, providerId];
      const next = { ...prev, allowedProviderTypes: newProviders };
      SecureStore.setItemAsync(OVERRIDE_SETTINGS_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  // Handle notify toggle
  const handleToggleNotify = useCallback(() => {
    setOverrideSettings(prev => {
      const next = { ...prev, notifyContacts: !prev.notifyContacts };
      SecureStore.setItemAsync(OVERRIDE_SETTINGS_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  // -- Loading State --
  if (isLoading && records.length === 0) {
    return <LoadingSpinner fullScreen message="Loading emergency records..." />;
  }

  // NO FULL-SCREEN ERROR STATE HERE, DELIBERATELY.
  //
  // Replacing this screen with "Failed to Load" was the offline failure the
  // holder actually met: no network, whole surface gone, and the one place that
  // reports whether a hospital is reading their records showing nothing at all.
  // The screen now always renders, with a banner above the records saying the
  // check did not complete. A failure to look is not an answer of "none".
  //
  // The raw error text is not shown. It named an endpoint and a status code,
  // which tells the holder nothing they can act on; it goes to the dev client.
  if (error) {
    if (__DEV__) console.warn('[Emergency] check failed:', error);
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={[styles.content, { paddingTop: spacing.screenPadding }]}
      refreshControl={
        <RefreshControl
          refreshing={isLoading}
          onRefresh={() => fetchRecords(user?.did)}
          tintColor={colors.brand.primary}
          colors={[colors.brand.primary]}
        />
      }
      accessibilityLabel="Emergency access screen"
    >
      {/* Sub-screen: the round back control is the way out, not a header bar. */}
      <BackButton style={styles.backButton} />

      {/* Emergency Info Banner */}
      {(error || lastCheckFailed) && (
        <Card variant="default" style={styles.staleCard}>
          <View style={styles.staleRow}>
            <Ionicons name="cloud-offline-outline" size={20} color={colors.semantic.warning} />
            <Text style={styles.staleTitle}>Could not check just now</Text>
          </View>
          <Text style={styles.staleBody}>
            {records.length > 0
              ? 'Showing the last known state. This is not confirmation that nothing has changed.'
              : 'This is not confirmation that no hospital has opened your records.'}
          </Text>
          <TouchableOpacity onPress={handleRetry} accessibilityRole="button">
            <Text style={styles.staleAction}>Try again</Text>
          </TouchableOpacity>
        </Card>
      )}

      <InfoBanner />

      {/* Current Status */}
      <CurrentStatus
        hasActiveEmergency={activeRecords.length > 0}
        activeCount={activeRecords.length}
      />

      {/* THE "EMERGENCY OVERRIDE" SETTINGS BLOCK WAS REMOVED HERE.
          It rendered a switch labelled "Emergency access requires manual
          approval", stored the value in SecureStore, and sent it NOWHERE. The
          backend consults no patient preference at any point, so the control
          described a rule that did not exist, in the direction that matters:
          a holder reading it would believe no one could reach their records
          without asking them.
          It is not reworded into a working toggle because the grant model is a
          deliberate decision, not a preference (owner, 9 Sep): the patient may
          be unconscious, and a switch that can fail closed in that moment is
          the failure break-glass exists to prevent. What replaces it is a
          statement of how it actually behaves, and the revoke control on each
          active grant below — which is real. */}
      <HowThisWorks />

      {/* Emergency History */}
      <SectionHeader title="Access History" style={styles.historyHeader} />

      {records.length === 0 ? (
        <EmptyState
          title="No Emergency Records"
          message="No hospital has opened your records in an emergency"
          icon="shield-outline"
          style={styles.emptyState}
        />
      ) : (
        records.map((record: EmergencyRecord) => (
          <EmergencyRecordCard
            key={record.id}
            record={record}
            onRevoke={handleRevokeAccess}
            isRevoking={isRevoking === record.id}
          />
        ))
      )}

    </ScrollView>
  );
}

// -- Styles --

const styles = StyleSheet.create({
  staleCard: {
    marginBottom: spacing.md,
    borderWidth: 1,
    borderColor: colors.semantic.warningBorder,
    backgroundColor: colors.semantic.warningLight,
  },
  staleRow: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm },
  staleTitle: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  staleBody: {
    marginTop: spacing.xs,
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
  },
  staleAction: {
    marginTop: spacing.sm,
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
    color: colors.brand.primary,
  },
  container: {
    flex: 1,
    backgroundColor: colors.background.primary,
  },
  content: {
    padding: spacing.screenPadding,
    paddingBottom: spacing.huge,
  },
  backButton: {
    marginBottom: spacing.md,
  },
  infoBanner: {
    flexDirection: 'row',
    // Flat on purpose: Android draws elevation from the view's own
    // background, so a tinted card gains a coloured halo around a lighter
    // interior. The tint already separates these from the page.
    elevation: 0,
    shadowOpacity: 0,
    backgroundColor: '#FEF6E8',
    borderColor: '#F6DFB4',
    padding: spacing.md,
    gap: spacing.md,
    marginBottom: spacing.md,
  },
  infoContent: {
    flex: 1,
  },
  infoTitle: {
    color: colors.semantic.warning,
    fontSize: fontSizes.md,
    fontWeight: fontWeights.bold,
  },
  infoText: {
    color: colors.text.secondary,
    fontSize: fontSizes.sm,
    marginTop: spacing.xs,
    lineHeight: lineHeightFor(fontSizes.sm, lineHeights.relaxed),
  },
  statusCard: {
    // Flat on purpose: Android draws elevation from the view's own
    // background, so a tinted card gains a coloured halo around a lighter
    // interior. The tint already separates these from the page.
    elevation: 0,
    shadowOpacity: 0,
    borderRadius: borderRadius.lg,
    padding: spacing.lg,
    marginBottom: spacing.xl,
  },
  statusCardSafe: {
    backgroundColor: '#EFFAF5',
    borderColor: '#C9EBDD',
  },
  statusCardActive: {
    backgroundColor: '#FDF2F2',
    borderColor: '#F5CFCF',
  },
  statusIndicator: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    marginBottom: spacing.sm,
  },
  statusDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
  },
  statusDotSafe: {
    backgroundColor: colors.semantic.success,
  },
  statusDotActive: {
    backgroundColor: colors.semantic.error,
  },
  statusSafeText: {
    color: colors.semantic.success,
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.bold,
  },
  statusActiveText: {
    color: colors.semantic.error,
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.bold,
  },
  statusSubtext: {
    color: colors.text.disabled,
    fontSize: fontSizes.sm,
    lineHeight: lineHeightFor(fontSizes.sm, lineHeights.relaxed),
  },
  howCard: {
    padding: spacing.md,
    gap: spacing.sm,
    marginBottom: spacing.lg,
  },
  howRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: spacing.sm,
  },
  howText: {
    flex: 1,
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
    lineHeight: lineHeightFor(fontSizes.sm, lineHeights.relaxed),
  },
  infoTextMuted: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    marginTop: spacing.xs,
    lineHeight: lineHeightFor(fontSizes.xs, lineHeights.relaxed),
  },
  revokeButton: {
    marginTop: spacing.md,
  },
  emptyState: {
    marginVertical: spacing.xl,
  },
  recordCard: {
    marginBottom: spacing.md,
  },
  recordHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
    marginBottom: spacing.sm,
  },
  recordIcon: {
    width: 44,
    height: 44,
    borderRadius: borderRadius.md,
    backgroundColor: withOpacity(colors.semantic.error, 0.08),
    justifyContent: 'center',
    alignItems: 'center',
  },
  recordInfo: {
    flex: 1,
  },
  recordProvider: {
    color: colors.text.primary,
    fontSize: fontSizes.md,
    fontWeight: fontWeights.bold,
  },
  recordTime: {
    color: colors.text.disabled,
    fontSize: fontSizes.xs,
    marginTop: spacing.xxs,
  },
  recordReason: {
    color: colors.text.secondary,
    fontSize: fontSizes.sm,
    lineHeight: lineHeightFor(fontSizes.sm, lineHeights.relaxed),
    marginBottom: spacing.md,
  },
  recordMeta: {
    gap: spacing.xs,
  },
  metaItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
  },
  metaText: {
    color: colors.text.secondary,
    fontSize: fontSizes.xs,
  },
  familyCard: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: spacing.md,
    gap: spacing.md,
  },
  familyInfo: {
    flex: 1,
  },
  familyTitle: {
    color: colors.text.primary,
    fontSize: fontSizes.md,
    fontWeight: fontWeights.semibold,
  },
  familyText: {
    color: colors.text.disabled,
    fontSize: fontSizes.sm,
    marginTop: spacing.xxs,
  },
  // Override settings styles
  historyHeader: {
    marginTop: spacing.lg,
  },
  overrideCard: {
    marginBottom: spacing.lg,
  },
  overrideHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  overrideHeaderLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
    flex: 1,
  },
  overrideHeaderText: {
    flex: 1,
  },
  overrideTitle: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  overrideSubtitle: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    marginTop: spacing.xxs,
  },
  overrideDivider: {
    height: 1,
    backgroundColor: colors.border.default,
    marginVertical: spacing.md,
  },
  overrideSectionTitle: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.medium,
    color: colors.text.secondary,
    marginBottom: spacing.sm,
  },
  providerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: spacing.sm,
    gap: spacing.sm,
  },
  providerLabel: {
    flex: 1,
    fontSize: fontSizes.sm,
    color: colors.text.tertiary,
  },
  providerLabelEnabled: {
    color: colors.text.primary,
    fontWeight: fontWeights.medium,
  },
  autoExpireRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    paddingVertical: spacing.xs,
  },
  autoExpireText: {
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
  },
  notifyRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    marginTop: spacing.sm,
  },
  notifyText: {
    flex: 1,
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
  },
});
