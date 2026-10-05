/**
 * SSI Healthcare Mobile - Home Screen
 *
 * Dashboard with credential overview, recent activity,
 * and quick-action cards for common operations.
 *
 * REFACTORED to use:
 * - Design tokens from theme system
 * - Reusable components
 * - Zustand stores for state management
 * - Proper TypeScript types
 * - Accessibility attributes
 */

import React, { useEffect, useCallback, useMemo, useState } from 'react';
import { showAlert } from '../components/AppAlertHost';
import { View, Text, ScrollView, StyleSheet, Pressable, TouchableOpacity, RefreshControl, Alert } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import * as Clipboard from 'expo-clipboard';
import { useNavigation } from '@react-navigation/native';
import { useLiveRefresh } from '../hooks/useLiveRefresh';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { RootTabParamList, QuickAction, Credential } from '../types';
import { useAuth } from '../contexts';
import { apiService } from '../services/api';
import { useCredentialStore, useConsentStore, useActivityStore, useEmergencyStore } from '../store';
import { relativeTime } from '../utils/format';
import { HEALTH_CARD_CREDENTIAL_TYPE } from '@ssi-healthcare/shared';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';
import {
  LoadingSpinner,
  ErrorState,
  SectionHeader,
  StatCard,
  Card,
  Badge,
} from '../components/common';

// -- Type Definitions --

type NavigationProp = NativeStackNavigationProp<RootTabParamList>;

interface ActivityItemData {
  id: string;
  action: string;
  from: string;
  time: string;
  icon: keyof typeof Ionicons.glyphMap;
}

// -- Screen Component --

/** `did:key:z6Mk...` -> `did:key:z6Mk…w9Xk` — short enough for a badge, still recognisable. */
function truncateDid(did: string): string {
  if (did.length <= 24) return did;
  return `${did.slice(0, 16)}…${did.slice(-6)}`;
}

export default function HomeScreen() {
  const navigation = useNavigation<NavigationProp>();
  // This tab has no header, so nothing else supplies the status-bar gap.
  const insets = useSafeAreaInsets();
  const { user } = useAuth();

  // Zustand stores
  const {
    credentials,
    isLoading: isCredentialsLoading,
    isRefreshing: isCredentialsRefreshing,
    error: credentialsError,
    fetchCredentials,
    refreshCredentials,
    clearError: clearCredentialsError,
  } = useCredentialStore();

  const {
    activeConsents,
    isLoading: isConsentsLoading,
    fetchConsents,
  } = useConsentStore();

  const {
    activities,
    isLoading: isActivitiesLoading,
    fetchActivities,
  } = useActivityStore();

  // DERIVED, NOT FETCHED (#375). The badge must come from holding a valid
  // unrevoked health-card credential, never from a backend flag. Reading
  // GET /api/users/me also made the badge VANISH offline — measured 22 Sep
  // 2026, the badge disappeared the moment the backend went down, for a wallet
  // holding four valid cards. The credential is on-device, so derive it from
  // what the wallet holds: null means "no card yet, say nothing", not "false".
  const identityVerified = useMemo<boolean | null>(() => {
    const healthCards = credentials.filter((c) => c.type === HEALTH_CARD_CREDENTIAL_TYPE);
    if (healthCards.length === 0) return null;
    return healthCards.some((c) => c.status === 'valid');
  }, [credentials]);

  // Break-glass grants are auto-granted, so the home screen is where the holder
  // must find out about one. See the alarm card below.
  const {
    activeRecords: activeEmergencies,
    fetchRecords: fetchEmergencies,
    lastCheckFailed: emergencyCheckFailed,
    lastCheckedAt: emergencyCheckedAt,
  } = useEmergencyStore();

  /**
   * RE-CHECK FOR BREAK-GLASS EVERY TIME THIS SCREEN IS SHOWN.
   *
   * The mount effect below is not enough for an alarm. A tab that is already
   * mounted does not re-run it, so a grant raised while the app sat open stayed
   * invisible until something forced a remount — measured 9 Sep, two live grants
   * and a silent home screen. Under an auto-grant model the alarm IS the control
   * (#293), and an alarm that is only as fresh as the last navigation is not one.
   *
   * Deliberately just this one fetch: credentials and consents are not
   * time-critical, and refetching everything on every tab switch would trade a
   * real problem for a battery one.
   */
  // Focus AND return-from-background. Focus alone missed the case where the
  // app is backgrounded on this very screen and a grant is raised meanwhile —
  // React Navigation sees no focus change, so nothing re-checked.
  useLiveRefresh(
    useCallback(() => {
      if (user?.did) void fetchEmergencies(user.did);
    }, [fetchEmergencies, user?.did]),
  );

  // Credential STATUS re-checked on the same return-from-background edge, but
  // NOT on focus: a revocation matters after the phone has been in a pocket,
  // and refetching on every tab switch is the battery trade the note above
  // warns against. This is the only path that notices a revocation while the
  // app was closed, since the background worker cannot complete a network call
  // on this device (#488).
  useLiveRefresh(
    useCallback(() => {
      void fetchCredentials();
    }, [fetchCredentials]),
    { onFocus: false },
  );

  // -- Dispense tokens (A1) --
  //
  // The pharmacy mints the queue number, so the wallet cannot know it exists; it
  // reads here. The STATE comes from the backend, decided from the SERVER clock.
  // The wallet must never decide expiry itself, because a device clock can be
  // changed — that is the failure the design note records (steno #584).
  const [liveTokens, setLiveTokens] = useState<
    Array<{ dispenseId: string; queueToken: number | null; pharmacyDid: string; issuedAt: string; state: string }>
  >([]);

  const loadTokens = useCallback(async () => {
    try {
      const res = await apiService.getMyTokens();
      setLiveTokens(res.live ?? []);
    } catch {
      // A failed read must NOT clear the card. Emptying it would tell the holder
      // they have no token when the truth is that we could not ask, and the token
      // is what the counter addresses them by. Leaving the last known value is
      // the safer direction, and the next successful read corrects it.
    }
  }, []);

  // On the same return-from-background edge as the emergency alarm, because a
  // token is only useful while the holder is standing at the counter.
  useLiveRefresh(useCallback(() => { void loadTokens(); }, [loadTokens]));

  // Fetch data on mount
  useEffect(() => {
    fetchCredentials();
    fetchConsents();
    fetchActivities();
    // Needs the DID: the store refuses to fetch without one rather than
    // returning an empty list, so an omitted argument would silently mean
    // "no emergency access" — the one answer that must never be guessed.
    if (user?.did) fetchEmergencies(user.did);
    void loadTokens();
  }, [fetchCredentials, fetchConsents, fetchActivities, fetchEmergencies, user?.did, loadTokens]);

  // Handle refresh
  const handleRefresh = useCallback(async () => {
    await Promise.all([
      refreshCredentials(),
      fetchConsents(),
      fetchActivities(),
      user?.did ? fetchEmergencies(user.did) : Promise.resolve(),
    ]);
  }, [refreshCredentials, fetchConsents, fetchActivities, fetchEmergencies, user?.did]);

  // Get greeting based on time of day
  const greeting = useMemo(() => {
    const hour = new Date().getHours();
    if (hour < 12) return 'Good morning';
    if (hour < 18) return 'Good afternoon';
    return 'Good evening';
  }, []);

  // Get user's display name
  const displayName = useMemo(() => {
    if (user?.displayName) return user.displayName.split(' ')[0];
    if (user?.firstName) return user.firstName;
    if (user?.email) return user.email.split('@')[0];
    return 'User';
  }, [user]);

  // Quick actions
  const quickActions = useMemo<QuickAction[]>(() => [
    {
      id: 'scan',
      icon: 'qr-code',
      label: 'Scan QR',
      color: colors.brand.primary,
      route: 'ScanTab',
    },
    {
      id: 'share',
      icon: 'share',
      label: 'Share',
      color: colors.brand.primary,
      action: () => {
        navigation.navigate('CredentialsTab');
      },
    },
    {
      id: 'consent',
      icon: 'shield-checkmark',
      label: 'Consent',
      color: colors.brand.primary,
      route: 'ConsentTab',
    },
    {
      id: 'submit-documents',
      icon: 'document-attach',
      label: 'Submit documents',
      color: colors.brand.primary,
      action: () => {
        (navigation as any).navigate('DocumentSubmission');
      },
    },
    {
      id: 'submission-status',
      icon: 'list',
      label: 'My submissions',
      color: colors.brand.primary,
      action: () => {
        (navigation as any).navigate('SubmissionStatus');
      },
    },
    {
      id: 'emergency',
      icon: 'medkit',
      label: 'Emergency access',
      color: colors.semantic.error,
      // The emergency surface lives under Consent now; the quick action still
      // goes straight to it, because an emergency is the one case where making
      // the holder find the Consent tab first would be the wrong friction.
      action: () => {
        (navigation as any).navigate('EmergencyAccess');
      },
    },
  ], [navigation]);

  // Copy the user's DID to the clipboard for sharing/verification elsewhere
  const handleCopyDid = useCallback(async () => {
    if (!user?.did) return;
    await Clipboard.setStringAsync(user.did);
    showAlert('Copied', 'Your DID has been copied to the clipboard.');
  }, [user?.did]);

  // Handle quick action press
  const handleQuickAction = useCallback((action: QuickAction) => {
    if (action.action) {
      action.action();
    } else if (action.route) {
      navigation.navigate(action.route as keyof RootTabParamList);
    }
  }, [navigation]);

  const recentActivity = useMemo<ActivityItemData[]>(() => {
    return activities.slice(0, 5).map((a: { id: string; title: string; description: string; timestamp: string; type: string }) => ({
      id: a.id,
      action: a.title,
      from: a.description,
      time: formatRelativeTime(a.timestamp),
      icon: getActivityIcon(a.type),
    }));
  }, [activities]);

  // Loading state — true only while the dashboard has nothing to show yet.
  // Checked before the error branch below so a first fetch in flight never
  // renders as a failure.
  const isInitialLoading =
    (isCredentialsLoading || isConsentsLoading) &&
    credentials.length === 0 &&
    activeConsents.length === 0;
  const isRefreshing = isCredentialsRefreshing;

  if (isInitialLoading) {
    return <LoadingSpinner fullScreen message="Loading your dashboard..." />;
  }

  // Error state
  if (credentialsError && credentials.length === 0) {
    return (
      <ErrorState
        title="Failed to Load"
        message={credentialsError}
        onRetry={() => {
          clearCredentialsError();
          fetchCredentials();
        }}
      />
    );
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={[styles.content, { paddingTop: spacing.screenPadding }]}
      refreshControl={
        <RefreshControl
          refreshing={isRefreshing}
          onRefresh={handleRefresh}
          tintColor={colors.brand.primary}
          colors={[colors.brand.primary]}
        />
      }
      accessibilityLabel="Home dashboard"
    >
      {/* Welcome Card */}
      {/* AN ACTIVE BREAK-GLASS GRANT IS AN ALARM, NOT A TAB.
          Access is granted without the holder's approval, so the only thing
          standing between "a hospital opened my records" and "I never found out"
          is whether the app tells them where they are looking. Requiring them to
          find the emergency screen to discover it makes the notice conditional on
          suspecting it already. This is #293 in the interface: under an
          auto-grant model, detection latency IS the security control. */}
      {/* The emergency surface moved UNDER CONSENT, so this tap is now a
          ROOT-ROUTE navigation and carries the same `(navigation as any)`
          accommodation the other root-route taps here use (DocumentSubmission,
          SubmissionStatus). The destination literal lives here, in one place. */}
      {/* "COULD NOT CHECK" IS NOT "NOTHING IS HAPPENING".
          When the emergency fetch fails — an expired session, the backend
          unreachable — `activeRecords` stays empty and the alarm below simply
          does not render, which is indistinguishable from an all-clear. That is
          fail-OPEN on the one control protecting a holder under an auto-grant
          model. Measured 9 Sep: two live grants, a failed fetch, and a silent
          home screen. Say so instead. */}
      {emergencyCheckFailed && activeEmergencies.length === 0 && (
        <Card variant="default" style={styles.emergencyUnknownCard}>
          <Ionicons name="help-circle" size={22} color={colors.semantic.warning} />
          <View style={styles.emergencyAlarmContent}>
            <Text style={styles.emergencyUnknownTitle}>
              Could not check for emergency access
            </Text>
            <Text style={styles.emergencyAlarmText}>
              {emergencyCheckedAt
                ? `Not an all-clear — last confirmed ${relativeTime(emergencyCheckedAt)}. Pull down to retry.`
                : 'This is not an all-clear — pull down to retry.'}
            </Text>
          </View>
        </Card>
      )}

      {activeEmergencies.length > 0 && (
        <TouchableOpacity
          onPress={() => (navigation as any).navigate('EmergencyAccess')}
          accessibilityRole="button"
          accessibilityLabel={`${activeEmergencies.length} emergency access active right now. Open to stop it.`}
        >
          <Card variant="default" style={styles.emergencyAlarmCard}>
            <Ionicons name="alert-circle" size={24} color={colors.semantic.error} />
            <View style={styles.emergencyAlarmContent}>
              <Text style={styles.emergencyAlarmTitle}>
                {activeEmergencies.length === 1
                  ? 'A hospital is reading your records now'
                  : `${activeEmergencies.length} hospitals are reading your records now`}
              </Text>
              <Text style={styles.emergencyAlarmText}>
                {activeEmergencies[0]?.providerName ?? 'A provider'} opened your records in an
                emergency. Tap to see what they took and stop it.
              </Text>
            </View>
            <Ionicons name="chevron-forward" size={20} color={colors.semantic.error} />
          </Card>
        </TouchableOpacity>
      )}

      <Card variant="default" style={styles.welcomeCard}>
        <Text style={styles.welcomeGreeting}>{greeting}</Text>
        <Text style={styles.welcomeName}>{displayName}</Text>
        {/* "Your health identity is secure" was removed here, deliberately.
            It was stated unconditionally and would have said exactly the same
            thing with the device key missing or the DID unresolvable — an
            unfalsifiable reassurance sitting in larger type directly above
            "Identity verified", which IS derived (from holding a valid,
            unrevoked health card, steno #375). Do not reintroduce a claim about
            security that nothing computes. */}
        {user?.did && user?.walletSetup ? (
          <Pressable
            onPress={handleCopyDid}
            accessibilityRole="button"
            accessibilityLabel="Your decentralized identifier, tap to copy"
            accessibilityHint="Copies your full DID to the clipboard"
          >
            <Badge
              label={truncateDid(user.did)}
              variant="neutral"
              icon="finger-print"
              style={styles.statusBadge}
            />
          </Pressable>
        ) : (
          <Badge
            label="No DID yet"
            variant="warning"
            icon="alert-circle-outline"
            style={styles.statusBadge}
          />
        )}
        {user?.did && user?.walletSetup && identityVerified !== null && (
          <Badge
            label={identityVerified ? 'Identity verified' : 'Not verified yet'}
            variant={identityVerified ? 'success' : 'neutral'}
            icon={identityVerified ? 'shield-checkmark' : 'shield-outline'}
            style={styles.statusBadge}
          />
        )}
      </Card>

      {/* Stats Row */}
      <View
        style={styles.statsRow}
        accessible={true}
        accessibilityLabel="Statistics"
      >
        <StatCard
          label="Credentials"
          value={credentials.length}
          icon="folder"
          iconColor={colors.brand.primaryLight}
          style={[styles.statCard, styles.statCardBlue]}
        />
        <StatCard
          label="Active Consents"
          value={activeConsents.length}
          icon="shield-checkmark"
          iconColor={colors.brand.primaryLight}
          style={[styles.statCard, styles.statCardBlue]}
        />
      </View>

      {/* Token Number — the counter's queue number, shown from the moment the
          pharmacy dispenses until the token is settled or abandoned. It is
          deliberately BELOW the credentials count, because it is transient: it
          appears for one encounter and then goes. Only a live (ISSUED) token is
          shown; a settled or abandoned one has already been logged and must not
          linger on the home screen. */}
      {liveTokens.length > 0 && (
        <Card variant="default" style={styles.welcomeCard}>
          <View style={{ flexDirection: 'row', alignItems: 'center' }}>
            <Ionicons name="ticket-outline" size={20} color={colors.brand.primaryLight} />
            <Text style={{ marginLeft: 8, fontSize: fontSizes.sm, fontWeight: fontWeights.semibold, color: colors.text.secondary }}>
              Token Number
            </Text>
          </View>
          {liveTokens.map((token) => (
            <View key={token.dispenseId} style={{ marginTop: spacing.sm }}>
              <Text style={{ fontSize: 30, fontWeight: fontWeights.bold, color: colors.text.primary }}>
                {token.queueToken ?? '—'}
              </Text>
              <Text style={{ marginTop: 2, fontSize: fontSizes.xs, color: colors.text.secondary }}>
                at {token.pharmacyDid.split(':').pop()} · {relativeTime(Date.parse(token.issuedAt))}
              </Text>
            </View>
          ))}
        </Card>
      )}

      {/* Quick Actions */}
      <SectionHeader title="Quick Actions" />
      <View
        style={styles.actionsRow}
        accessible={true}
        accessibilityLabel="Quick actions"
      >
        {quickActions.map((action) => (
          <Pressable
            key={action.id}
            style={({ pressed }) => [
              styles.actionCard,
              pressed && styles.actionCardPressed,
            ]}
            onPress={() => handleQuickAction(action)}
            accessibilityRole="button"
            accessibilityLabel={action.label}
            accessibilityHint={`Navigate to ${action.label}`}
          >
            <View style={styles.actionIconBg}>
              <Ionicons name={action.icon as keyof typeof Ionicons.glyphMap} size={24} color={action.color} />
            </View>
            <Text style={styles.actionLabel}>{action.label}</Text>
          </Pressable>
        ))}
      </View>

      {/* Recent Activity */}
      <SectionHeader
        title="Recent Activity"
        actionLabel="See all"
        onAction={() => {
          (navigation as any).navigate('ActivityLog');
        }}
      />
      <View
        style={styles.activityList}
        accessibilityRole="list"
        accessibilityLabel="Recent activity"
      >
        {isActivitiesLoading && recentActivity.length === 0 ? (
          <LoadingSpinner size="small" message="Loading activity..." />
        ) : recentActivity.length === 0 ? (
          <View style={styles.emptyActivity}>
            <Text style={styles.emptyActivityText}>No recent activity</Text>
          </View>
        ) : (
          recentActivity.map((item, index) => (
            <View
              key={item.id}
              style={[
                styles.activityItem,
                index === recentActivity.length - 1 && styles.activityItemLast,
              ]}
              accessible={true}
            >
              <View style={styles.activityIcon}>
                <Ionicons name={item.icon} size={20} color={colors.text.secondary} />
              </View>
              <View style={styles.activityContent}>
                <Text style={styles.activityAction}>{item.action}</Text>
                <Text style={styles.activityFrom}>{item.from}</Text>
              </View>
              <Text style={styles.activityTime}>{item.time}</Text>
            </View>
          ))
        )}
      </View>
    </ScrollView>
  );
}

// -- Helper Functions --

function formatRelativeTime(timestamp: string): string {
  const now = new Date();
  const date = new Date(timestamp);
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffMinutes = Math.floor(diffMs / (1000 * 60));

  if (diffMinutes < 1) return 'Just now';
  if (diffMinutes < 60) return `${diffMinutes} min ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
  if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
  return date.toLocaleDateString();
}

function getActivityIcon(type: string): keyof typeof Ionicons.glyphMap {
  switch (type) {
    case 'credential_issued':
      return 'document-text';
    case 'credential_shared':
      return 'share';
    case 'consent_granted':
      return 'shield-checkmark';
    case 'consent_revoked':
      return 'shield-outline';
    case 'verification_request':
      return 'checkmark-circle';
    case 'login':
      return 'log-in';
    default:
      return 'information-circle';
  }
}

// -- Styles --

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background.primary,
  },
  content: {
    padding: spacing.screenPadding,
    paddingBottom: spacing.xxxl,
  },
  emergencyUnknownCard: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
    padding: spacing.md,
    marginBottom: spacing.md,
    borderWidth: 1,
    borderColor: colors.semantic.warning,
  },
  emergencyUnknownTitle: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.semibold,
    color: colors.semantic.warning,
    marginBottom: spacing.xxs,
  },
  emergencyAlarmCard: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
    padding: spacing.md,
    marginBottom: spacing.md,
    borderWidth: 2,
    borderColor: colors.semantic.error,
    backgroundColor: colors.semantic.errorLight,
  },
  emergencyAlarmContent: {
    flex: 1,
  },
  emergencyAlarmTitle: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.bold,
    color: colors.semantic.error,
    marginBottom: spacing.xxs,
  },
  emergencyAlarmText: {
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
  },
  welcomeCard: {
    marginBottom: spacing.xl,
    padding: spacing.cardPaddingLarge,
  },
  welcomeGreeting: {
    color: colors.text.secondary,
    fontSize: fontSizes.base,
    fontWeight: fontWeights.normal,
  },
  welcomeName: {
    color: colors.text.primary,
    fontSize: fontSizes['5xl'],
    fontWeight: fontWeights.extrabold,
    marginTop: spacing.xs,
  },
  welcomeSubtext: {
    color: colors.text.tertiary,
    fontSize: fontSizes.md,
    fontWeight: fontWeights.normal,
    marginTop: spacing.sm,
  },
  statusBadge: {
    alignSelf: 'flex-start',
    marginTop: spacing.md,
  },
  statsRow: {
    flexDirection: 'row',
    gap: spacing.md,
    marginBottom: spacing.sectionGap,
  },
  statCard: {
    flex: 1,
  },
  statCardBlue: {
    backgroundColor: colors.statCard.blue.bg,
    borderColor: colors.statCard.blue.border,
  },
  statCardGreen: {
    backgroundColor: colors.statCard.green.bg,
    borderColor: colors.statCard.green.border,
  },
  actionsRow: {
    flexDirection: 'row',
    // WRAPS. Six tiles sharing one row with flex:1 gave each about 55px, so
    // every label broke one or two characters to a line — "Su bm it do cu me
    // nts" for "Submit documents". Three per row is the widest that fits.
    flexWrap: 'wrap',
    gap: spacing.md,
    marginBottom: spacing.sectionGap,
  },
  actionCard: {
    // 30% leaves room for the two gaps between three tiles. Not flex:1, which
    // is what forced all six onto one line.
    flexBasis: '30%',
    flexGrow: 1,
    backgroundColor: colors.surface.card,
    borderRadius: borderRadius.card,
    paddingVertical: spacing.md,
    paddingHorizontal: spacing.sm,
    alignItems: 'center',
    gap: spacing.sm,
    borderWidth: 1,
    borderColor: colors.border.default,
  },
  actionCardPressed: {
    opacity: 0.8,
    transform: [{ scale: 0.98 }],
  },
  actionIconBg: {
    backgroundColor: colors.surface.elevated,
    borderWidth: 1,
    borderColor: colors.border.default,
    width: 48,
    height: 48,
    borderRadius: borderRadius.md,
    justifyContent: 'center',
    alignItems: 'center',
  },
  actionLabel: {
    color: colors.text.primary,
    fontSize: fontSizes.xs,
    fontWeight: fontWeights.semibold,
  },
  activityList: {
    backgroundColor: colors.surface.card,
    borderRadius: borderRadius.card,
    borderWidth: 1,
    borderColor: colors.border.default,
    overflow: 'hidden',
  },
  activityItem: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: spacing.lg,
    borderBottomWidth: 1,
    borderBottomColor: colors.border.default,
    gap: spacing.md,
  },
  activityItemLast: {
    borderBottomWidth: 0,
  },
  activityIcon: {
    width: 40,
    height: 40,
    borderRadius: borderRadius.md,
    backgroundColor: colors.surface.elevated,
    justifyContent: 'center',
    alignItems: 'center',
  },
  activityContent: {
    flex: 1,
  },
  activityAction: {
    color: colors.text.primary,
    fontSize: fontSizes.base,
    fontWeight: fontWeights.semibold,
  },
  activityFrom: {
    color: colors.text.secondary,
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.normal,
    marginTop: spacing.xxs,
  },
  activityTime: {
    color: colors.text.tertiary,
    fontSize: fontSizes.xs,
    fontWeight: fontWeights.normal,
  },
  emptyActivity: {
    padding: spacing.xl,
    alignItems: 'center',
  },
  emptyActivityText: {
    color: colors.text.tertiary,
    fontSize: fontSizes.base,
    fontWeight: fontWeights.normal,
  },
});
