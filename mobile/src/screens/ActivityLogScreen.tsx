/**
 * SSI Healthcare Mobile - Activity Log Screen
 *
 * Displays a detailed audit trail of all identity-related activities:
 * - Credential issuances and verifications
 * - Consent grants and revocations
 * - Emergency access events
 * - Authentication events
 *
 * Uses plain language to explain what happened and when.
 */

import React, { useEffect, useState, useCallback, useMemo } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  RefreshControl,
  TouchableOpacity,
  TextInput,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import type { ComponentProps } from 'react';
import { colors, spacing, fontSizes, fontWeights, borderRadius, opacity } from '../theme';
import {
  LoadingSpinner,
  EmptyState,
  ErrorState,
  Card,
  Badge,
} from '../components/common';
import { apiService } from '../services/api';
import { transformActivities } from '../store/activityStore';
import type { ActivityKind } from '../types/domain';

type IoniconsName = ComponentProps<typeof Ionicons>['name'];

// -- Activity Types --

/**
 * The shared vocabulary, not a second one. Keying the table below on a local
 * union let it drift from what the store actually emits — see ActivityKind.
 */
type ActivityType = ActivityKind;

type ActivityFilter = 'all' | 'credentials' | 'consents' | 'access' | 'security';

interface ActivityItem {
  id: string;
  type: ActivityType;
  title: string;
  description: string;
  timestamp: string;
  metadata?: {
    requester?: string;
    credentialType?: string;
    dataTypes?: string[];
    location?: string;
    device?: string;
    ipAddress?: string;
  };
}

// -- Activity Configuration --

const ACTIVITY_CONFIG: Record<ActivityType, {
  icon: IoniconsName;
  color: string;
  category: ActivityFilter;
  plainLanguagePrefix: string;
}> = {
  credential_issued: {
    icon: 'add-circle',
    color: colors.semantic.success,
    category: 'credentials',
    plainLanguagePrefix: 'You received',
  },
  credential_verified: {
    icon: 'checkmark-circle',
    color: colors.brand.primary,
    category: 'credentials',
    plainLanguagePrefix: 'You shared',
  },
  credential_revoked: {
    icon: 'close-circle',
    color: colors.semantic.error,
    category: 'credentials',
    plainLanguagePrefix: 'Credential revoked:',
  },
  consent_granted: {
    icon: 'shield-checkmark',
    color: colors.semantic.success,
    category: 'consents',
    plainLanguagePrefix: 'You allowed',
  },
  consent_revoked: {
    icon: 'shield-outline',
    color: colors.semantic.warning,
    category: 'consents',
    plainLanguagePrefix: 'You revoked access for',
  },
  emergency_access: {
    icon: 'alert-circle',
    color: colors.semantic.error,
    category: 'access',
    plainLanguagePrefix: 'Emergency access by',
  },
  login: {
    icon: 'log-in',
    color: colors.semantic.info,
    category: 'security',
    plainLanguagePrefix: 'You signed in',
  },
  logout: {
    icon: 'log-out',
    color: colors.text.tertiary,
    category: 'security',
    plainLanguagePrefix: 'You signed out',
  },
  backup_created: {
    icon: 'cloud-upload',
    color: colors.semantic.success,
    category: 'security',
    plainLanguagePrefix: 'Backup created',
  },
  recovery_completed: {
    icon: 'key',
    color: colors.semantic.warning,
    category: 'security',
    plainLanguagePrefix: 'Recovery completed',
  },
  credential_shared: {
    icon: 'share-outline',
    color: colors.brand.primary,
    category: 'credentials',
    plainLanguagePrefix: 'You shared',
  },
  verification_request: {
    icon: 'shield-checkmark',
    color: colors.brand.primary,
    category: 'access',
    plainLanguagePrefix: 'You shared with',
  },
  other: {
    icon: 'ellipse-outline',
    color: colors.text.secondary,
    category: 'all',
    plainLanguagePrefix: '',
  },
};

/**
 * Look a kind up through here, NEVER by indexing ACTIVITY_CONFIG directly.
 *
 * This is an audit surface, so an event whose kind we do not recognise is
 * precisely the event a holder most needs to see. It must degrade to a neutral
 * row — never vanish, and never take the screen down with it, which is what
 * `ACTIVITY_CONFIG[activity.type].color` did the moment presentation events
 * became visible: `type` was undefined, and the whole log rendered a red box.
 */
function configFor(type: string) {
  return (
    ACTIVITY_CONFIG[type as ActivityType] ?? {
      icon: 'help-circle-outline' as IoniconsName,
      color: colors.text.secondary,
      category: 'all' as ActivityFilter,
      plainLanguagePrefix: '',
    }
  );
}

const FILTER_OPTIONS: { key: ActivityFilter; label: string; icon: IoniconsName }[] = [
  { key: 'all', label: 'All', icon: 'list' },
  { key: 'credentials', label: 'Credentials', icon: 'folder-outline' },
  { key: 'consents', label: 'Consents', icon: 'shield-outline' },
  { key: 'access', label: 'Access', icon: 'eye-outline' },
  { key: 'security', label: 'Security', icon: 'lock-closed-outline' },
];

// NOTE: This screen must never synthesise placeholder rows. It is an audit
// surface, so a fabricated entry is indistinguishable from a real one and also
// corrupts the "Total Events" / "This Week" counters. A genuinely empty log is
// rendered by <EmptyState>; a failed fetch is rendered by <ErrorState>. The two
// must stay distinguishable.

// -- Time Constants --

const MS_PER_MINUTE = 1000 * 60;
const MS_PER_HOUR = MS_PER_MINUTE * 60;
const MS_PER_DAY = MS_PER_HOUR * 24;
const MS_PER_WEEK = MS_PER_DAY * 7;
const MS_PER_MONTH = MS_PER_DAY * 30;

// -- Helper Functions --

function toActivityErrorMessage(err: unknown): string {
  const detail = err instanceof Error ? err.message : String(err);
  return `Could not load your activity log. This is a loading failure, not an empty log — do not treat it as "no activity". ${detail}`;
}

function formatRelativeTime(timestamp: string): string {
  const now = Date.now();
  const time = new Date(timestamp).getTime();
  const diff = now - time;

  const minutes = Math.floor(diff / MS_PER_MINUTE);
  const hours = Math.floor(diff / MS_PER_HOUR);
  const days = Math.floor(diff / MS_PER_DAY);

  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  if (days < 30) return `${Math.floor(days / 7)}w ago`;
  return new Date(timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function formatFullDate(timestamp: string): string {
  return new Date(timestamp).toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

function groupActivitiesByDate(activities: ActivityItem[]): Map<string, ActivityItem[]> {
  const groups = new Map<string, ActivityItem[]>();
  
  activities.forEach(activity => {
    const date = new Date(activity.timestamp);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    
    let key: string;
    if (date.toDateString() === today.toDateString()) {
      key = 'Today';
    } else if (date.toDateString() === yesterday.toDateString()) {
      key = 'Yesterday';
    } else if (date > new Date(today.getTime() - MS_PER_WEEK)) {
      key = 'This Week';
    } else if (date > new Date(today.getTime() - MS_PER_MONTH)) {
      key = 'This Month';
    } else {
      key = 'Earlier';
    }
    
    const existing = groups.get(key) || [];
    existing.push(activity);
    groups.set(key, existing);
  });
  
  return groups;
}

// -- Screen Component --

export default function ActivityLogScreen() {
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<ActivityFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Load activities on mount with cleanup
  useEffect(() => {
    let isMounted = true;
    
    const loadActivities = async () => {
      try {
        // THROUGH THE STORE'S TRANSFORM, not a cast.
        //
        // `apiService.getActivity()` returns the backend audit shape
        // (`{ eventType, action, timestamp }`), and this screen reads
        // `activity.type` / `.title` / `.description`. The `as ActivityItem[]`
        // that used to sit here asserted the two were the same and silenced the
        // one check that would have noticed they were not.
        const data = transformActivities(await apiService.getActivity());
        if (isMounted) {
          setActivities(data);
          setError(null);
        }
      } catch (err) {
        if (isMounted) {
          // A fetch failure is NOT an empty audit log. Surface it as an error
          // so the user is never told "no activity" when we simply could not
          // read the activity.
          setActivities([]);
          setError(toActivityErrorMessage(err));
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    };
    
    loadActivities();
    
    return () => {
      isMounted = false;
    };
  }, []);

  // Refresh handler with abort protection
  const handleRefresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiService.getActivity() as ActivityItem[];
      setActivities(data);
      setError(null);
    } catch (err) {
      // Keep any previously loaded entries so a failed refresh does not destroy
      // the visible log, but always record the error. The render path shows a
      // banner over stale data and a full ErrorState when there is no data.
      setError(toActivityErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Filter and search activities
  const filteredActivities = useMemo(() => {
    let result = [...activities];

    // Apply category filter
    if (filter !== 'all') {
      result = result.filter(a => configFor(a.type).category === filter);
    }

    // Apply search
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      result = result.filter(
        a =>
          a.title.toLowerCase().includes(query) ||
          a.description.toLowerCase().includes(query) ||
          a.metadata?.requester?.toLowerCase().includes(query)
      );
    }

    // Sort by timestamp (newest first)
    return result.sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }, [activities, filter, searchQuery]);

  // Group activities
  const groupedActivities = useMemo(
    () => groupActivitiesByDate(filteredActivities),
    [filteredActivities]
  );

  // Toggle expanded state
  const toggleExpanded = useCallback((id: string) => {
    setExpandedId(prev => (prev === id ? null : id));
  }, []);

  // -- Loading State --
  if (isLoading && activities.length === 0) {
    return <LoadingSpinner fullScreen message="Loading activity..." />;
  }

  // -- Error State --
  // Only reachable when there is nothing to show. When a refresh fails over
  // already-loaded entries we keep them and render the banner below instead,
  // so stale audit data is never presented as current and complete.
  if (error && activities.length === 0) {
    return (
      <ErrorState
        title="Failed to Load"
        message={error}
        onRetry={handleRefresh}
      />
    );
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={
        <RefreshControl
          refreshing={isLoading}
          onRefresh={handleRefresh}
          tintColor={colors.brand.primary}
          colors={[colors.brand.primary]}
        />
      }
      accessibilityLabel="Activity log screen"
    >
      {/* Stale-data warning: refresh failed but earlier entries are still shown */}
      {error && (
        <View style={styles.staleBanner} accessibilityRole="alert">
          <Ionicons
            name="alert-circle"
            size={18}
            color={colors.semantic.error}
            style={styles.staleBannerIcon}
          />
          <Text style={styles.staleBannerText}>
            Showing previously loaded activity. Refresh failed, so this list may be
            incomplete or out of date.
          </Text>
        </View>
      )}

      {/* Header Stats */}
      <View style={styles.statsRow}>
        <View style={styles.statItem}>
          <Text style={styles.statNumber}>{activities.length}</Text>
          <Text style={styles.statLabel}>Total Events</Text>
        </View>
        <View style={styles.statDivider} />
        <View style={styles.statItem}>
          <Text style={styles.statNumber}>
            {activities.filter(a => a.type === 'emergency_access').length}
          </Text>
          <Text style={styles.statLabel}>Emergency</Text>
        </View>
        <View style={styles.statDivider} />
        <View style={styles.statItem}>
          <Text style={styles.statNumber}>
            {activities.filter(a => 
              new Date(a.timestamp) > new Date(Date.now() - MS_PER_WEEK)
            ).length}
          </Text>
          <Text style={styles.statLabel}>This Week</Text>
        </View>
      </View>

      {/* Search Bar */}
      <View style={styles.searchContainer}>
        <Ionicons name="search" size={20} color={colors.text.tertiary} style={styles.searchIcon} />
        <TextInput
          style={styles.searchInput}
          placeholder="Search activity..."
          placeholderTextColor={colors.text.tertiary}
          value={searchQuery}
          onChangeText={setSearchQuery}
          accessibilityLabel="Search activity log"
        />
        {searchQuery.length > 0 && (
          <TouchableOpacity onPress={() => setSearchQuery('')} accessibilityLabel="Clear search">
            <Ionicons name="close-circle" size={20} color={colors.text.tertiary} />
          </TouchableOpacity>
        )}
      </View>

      {/* Filter Chips */}
      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        style={styles.filterScroll}
        contentContainerStyle={styles.filterContainer}
      >
        {FILTER_OPTIONS.map(option => (
          <TouchableOpacity
            key={option.key}
            style={[styles.filterChip, filter === option.key && styles.filterChipActive]}
            onPress={() => setFilter(option.key)}
            accessibilityLabel={`Filter by ${option.label}`}
            accessibilityState={{ selected: filter === option.key }}
          >
            <Ionicons
              name={option.icon}
              size={14}
              color={filter === option.key ? colors.brand.primary : colors.text.tertiary}
            />
            <Text style={[styles.filterChipText, filter === option.key && styles.filterChipTextActive]}>
              {option.label}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      {/* Results Count */}
      <Text style={styles.resultsCount}>
        {filteredActivities.length} event{filteredActivities.length !== 1 ? 's' : ''}
      </Text>

      {/* Activity List */}
      {filteredActivities.length === 0 ? (
        <EmptyState
          title={searchQuery ? 'No Results' : 'No Activity'}
          message={
            searchQuery
              ? `No events match "${searchQuery}"`
              : 'Your activity log is empty'
          }
          icon="time-outline"
          style={styles.emptyState}
        />
      ) : (
        Array.from(groupedActivities.entries()).map(([dateGroup, items]) => (
          <View key={dateGroup} style={styles.dateGroup}>
            <Text style={styles.dateGroupTitle}>{dateGroup}</Text>
            {items.map(activity => {
              const config = configFor(activity.type);
              const isExpanded = expandedId === activity.id;
              
              return (
                <TouchableOpacity
                  key={activity.id}
                  style={styles.activityCard}
                  onPress={() => toggleExpanded(activity.id)}
                  activeOpacity={0.7}
                  accessibilityLabel={`${activity.title}, ${activity.description}`}
                  accessibilityHint="Tap to see details"
                >
                  <View style={styles.activityHeader}>
                    <View style={[styles.activityIcon, { backgroundColor: config.color + opacity.subtle }]}>
                      <Ionicons name={config.icon} size={18} color={config.color} />
                    </View>
                    <View style={styles.activityInfo}>
                      <Text style={styles.activityTitle}>{activity.title}</Text>
                      <Text style={styles.activityDescription} numberOfLines={isExpanded ? undefined : 1}>
                        {activity.description}
                      </Text>
                    </View>
                    <View style={styles.activityMeta}>
                      <Text style={styles.activityTime}>{formatRelativeTime(activity.timestamp)}</Text>
                      <Ionicons
                        name={isExpanded ? 'chevron-up' : 'chevron-down'}
                        size={16}
                        color={colors.text.tertiary}
                      />
                    </View>
                  </View>

                  {isExpanded && (
                    <View style={styles.activityDetails}>
                      {/* Full timestamp */}
                      <View style={styles.detailRow}>
                        <Ionicons name="calendar-outline" size={14} color={colors.text.secondary} />
                        <Text style={styles.detailText}>{formatFullDate(activity.timestamp)}</Text>
                      </View>

                      {/* Requester */}
                      {activity.metadata?.requester && (
                        <View style={styles.detailRow}>
                          <Ionicons name="business-outline" size={14} color={colors.text.secondary} />
                          <Text style={styles.detailText}>{activity.metadata.requester}</Text>
                        </View>
                      )}

                      {/* Location */}
                      {activity.metadata?.location && (
                        <View style={styles.detailRow}>
                          <Ionicons name="location-outline" size={14} color={colors.text.secondary} />
                          <Text style={styles.detailText}>{activity.metadata.location}</Text>
                        </View>
                      )}

                      {/* Device */}
                      {activity.metadata?.device && (
                        <View style={styles.detailRow}>
                          <Ionicons name="phone-portrait-outline" size={14} color={colors.text.secondary} />
                          <Text style={styles.detailText}>{activity.metadata.device}</Text>
                        </View>
                      )}

                      {/* Data types */}
                      {activity.metadata?.dataTypes && activity.metadata.dataTypes.length > 0 && (
                        <View style={styles.dataTypesSection}>
                          <Text style={styles.dataTypesLabel}>Data accessed:</Text>
                          <View style={styles.dataTypesList}>
                            {activity.metadata.dataTypes.map(dt => (
                              <Badge key={dt} label={dt} variant="default" size="small" />
                            ))}
                          </View>
                        </View>
                      )}
                    </View>
                  )}
                </TouchableOpacity>
              );
            })}
          </View>
        ))
      )}
    </ScrollView>
  );
}

// -- Styles --

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background.primary,
  },
  content: {
    padding: spacing.screenPadding,
    paddingBottom: spacing.huge,
  },
  // Stats row
  statsRow: {
    flexDirection: 'row',
    backgroundColor: colors.surface.elevated,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginBottom: spacing.md,
    alignItems: 'center',
  },
  statItem: {
    flex: 1,
    alignItems: 'center',
  },
  statNumber: {
    fontSize: fontSizes.xl,
    fontWeight: fontWeights.bold,
    color: colors.text.primary,
  },
  statLabel: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    marginTop: spacing.xxs,
  },
  statDivider: {
    width: 1,
    height: 30,
    backgroundColor: colors.border.default,
  },
  // Search
  searchContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.surface.elevated,
    borderRadius: borderRadius.md,
    paddingHorizontal: spacing.md,
    marginBottom: spacing.md,
  },
  searchIcon: {
    marginRight: spacing.sm,
  },
  searchInput: {
    flex: 1,
    paddingVertical: spacing.md,
    fontSize: fontSizes.md,
    color: colors.text.primary,
  },
  // Filters
  filterScroll: {
    marginBottom: spacing.sm,
  },
  filterContainer: {
    flexDirection: 'row',
    gap: spacing.sm,
    paddingRight: spacing.md,
  },
  filterChip: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderRadius: borderRadius.full,
    backgroundColor: colors.surface.elevated,
    borderWidth: 1,
    borderColor: colors.border.default,
  },
  filterChipActive: {
    backgroundColor: colors.brand.primaryMuted,
    borderColor: colors.brand.primary,
  },
  filterChipText: {
    fontSize: fontSizes.sm,
    color: colors.text.tertiary,
    fontWeight: fontWeights.medium,
  },
  filterChipTextActive: {
    color: colors.brand.primary,
    fontWeight: fontWeights.semibold,
  },
  // Results count
  resultsCount: {
    fontSize: fontSizes.sm,
    color: colors.text.tertiary,
    marginBottom: spacing.md,
  },
  // Stale-data banner (refresh failed, older entries still displayed)
  staleBanner: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    backgroundColor: colors.semantic.error + '1A',
    borderColor: colors.semantic.error,
    borderWidth: 1,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginBottom: spacing.md,
  },
  staleBannerIcon: {
    marginRight: spacing.sm,
  },
  staleBannerText: {
    flex: 1,
    fontSize: fontSizes.sm,
    color: colors.semantic.error,
  },
  // Empty state
  emptyState: {
    marginVertical: spacing.xl,
  },
  // Date groups
  dateGroup: {
    marginBottom: spacing.lg,
  },
  dateGroupTitle: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
    color: colors.text.secondary,
    marginBottom: spacing.sm,
    paddingLeft: spacing.xs,
  },
  // Activity card
  activityCard: {
    backgroundColor: colors.surface.elevated,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginBottom: spacing.sm,
    borderWidth: 1,
    borderColor: colors.border.default,
  },
  activityHeader: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: spacing.md,
  },
  activityIcon: {
    width: 36,
    height: 36,
    borderRadius: borderRadius.sm,
    justifyContent: 'center',
    alignItems: 'center',
  },
  activityInfo: {
    flex: 1,
  },
  activityTitle: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  activityDescription: {
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
    marginTop: spacing.xxs,
  },
  activityMeta: {
    alignItems: 'flex-end',
    gap: spacing.xs,
  },
  activityTime: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
  },
  // Activity details
  activityDetails: {
    marginTop: spacing.md,
    paddingTop: spacing.md,
    borderTopWidth: 1,
    borderTopColor: colors.border.default,
    gap: spacing.sm,
  },
  detailRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
  },
  detailText: {
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
  },
  dataTypesSection: {
    marginTop: spacing.xs,
  },
  dataTypesLabel: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    marginBottom: spacing.xs,
  },
  dataTypesList: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.xs,
  },
});
