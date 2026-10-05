/**
 * SSI Healthcare Mobile - Consent Management Screen
 *
 * Shows active consent grants, allows revoking access,
 * and viewing the consent audit trail.
 *
 * REFACTORED to use:
 * - Zustand store for state management
 * - Design tokens from theme system
 * - Reusable components
 * - Proper TypeScript types
 * - Accessibility attributes
 */

import React, { useEffect, useCallback, useState, useMemo } from 'react';
import { View, Text, ScrollView, StyleSheet, RefreshControl, TextInput, TouchableOpacity, LayoutAnimation, Platform, UIManager } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useNavigation } from '@react-navigation/native';
import type { ComponentProps } from 'react';
import { useConsentStore } from '../store';
import { colors, spacing, fontSizes, fontWeights, borderRadius, typography, opacity } from '../theme';
import {
  LoadingSpinner,
  ErrorState,
  EmptyState,
  SectionHeader,
  Card,
  Badge,
  Button,
} from '../components/common';
import { ConfirmationSheet, InfoSheet } from '../components/sheets';
import type { Consent } from '../types';
import { formatClaimLabel } from '../utils/plainLanguage';

// Enable LayoutAnimation on Android
if (Platform.OS === 'android' && UIManager.setLayoutAnimationEnabledExperimental) {
  UIManager.setLayoutAnimationEnabledExperimental(true);
}

type IoniconsName = ComponentProps<typeof Ionicons>['name'];

// -- Filter Type --

type ConsentFilter = 'all' | 'active' | 'revoked' | 'expiring';

// -- Pre-defined Consent Templates --

interface ConsentTemplate {
  id: string;
  name: string;
  description: string;
  icon: IoniconsName;
  dataTypes: string[];
  duration: '30d' | '90d' | '1y' | 'indefinite';
  color: string;
}

const CONSENT_TEMPLATES: ConsentTemplate[] = [
  {
    id: 'basic-identity',
    name: 'Basic Identity',
    // NOT "name and email". Email was removed from this system entirely
    // (steno #398): signup and login never collect one, so a consent offering
    // to share an email describes something the wallet does not hold and could
    // not disclose if asked.
    description: 'Your name and health identifier',
    icon: 'person-outline',
    dataTypes: ['name', 'did'],
    duration: '90d',
    color: colors.semantic.success,
  },
  {
    id: 'healthcare-full',
    name: 'Full Healthcare',
    description: 'Complete medical access for providers',
    icon: 'medical-outline',
    dataTypes: ['name', 'dateOfBirth', 'medicalRecord', 'vaccination', 'prescription', 'labResults', 'allergies', 'bloodType', 'insurance'],
    duration: '1y',
    color: colors.brand.primary,
  },
  {
    id: 'pharmacy',
    name: 'Pharmacy Visit',
    description: 'Prescription pickup & insurance',
    icon: 'medkit-outline',
    dataTypes: ['name', 'dateOfBirth', 'prescription', 'insurance', 'allergies'],
    duration: '30d',
    color: colors.semantic.info,
  },
  {
    id: 'emergency',
    name: 'Emergency Access',
    description: 'Critical info for emergencies',
    icon: 'alert-circle-outline',
    dataTypes: ['name', 'dateOfBirth', 'bloodType', 'allergies', 'emergencyContact', 'medicalRecord'],
    duration: 'indefinite',
    color: colors.semantic.error,
  },
  {
    id: 'insurance-claim',
    name: 'Insurance Claim',
    description: 'Info needed for claims processing',
    icon: 'card-outline',
    dataTypes: ['name', 'dateOfBirth', 'insurance', 'medicalRecord', 'prescription', 'labResults'],
    duration: '90d',
    color: colors.semantic.warning,
  },
];

const DURATION_LABELS: Record<string, string> = {
  '30d': '30 days',
  '90d': '3 months',
  '1y': '1 year',
  'indefinite': 'Until revoked',
};

// -- Plain Language Data Type Mapping --

const DATA_TYPE_DISPLAY: Record<string, { label: string; icon: IoniconsName; sensitive: boolean }> = {
  name: { label: 'Your Name', icon: 'person-outline', sensitive: false },
  // The holder's DID. Not sensitive in the way a medical record is, but it is
  // the identifier every disclosure is linked by, so it is named plainly.
  did: { label: 'Your health identifier', icon: 'finger-print-outline', sensitive: false },
  email: { label: 'Email Address', icon: 'mail-outline', sensitive: true },
  phone: { label: 'Phone Number', icon: 'call-outline', sensitive: true },
  address: { label: 'Home Address', icon: 'home-outline', sensitive: true },
  dateOfBirth: { label: 'Date of Birth', icon: 'calendar-outline', sensitive: true },
  ssn: { label: 'Social Security Number', icon: 'shield-outline', sensitive: true },
  medicalRecord: { label: 'Medical Records', icon: 'medical-outline', sensitive: true },
  vaccination: { label: 'Vaccination History', icon: 'medkit-outline', sensitive: true },
  prescription: { label: 'Prescriptions', icon: 'document-text-outline', sensitive: true },
  labResults: { label: 'Lab Results', icon: 'flask-outline', sensitive: true },
  insurance: { label: 'Insurance Info', icon: 'card-outline', sensitive: true },
  allergies: { label: 'Allergies', icon: 'warning-outline', sensitive: true },
  bloodType: { label: 'Blood Type', icon: 'water-outline', sensitive: true },
  emergencyContact: { label: 'Emergency Contacts', icon: 'people-outline', sensitive: false },
  nursingLicense: { label: 'Nursing License', icon: 'ribbon-outline', sensitive: false },
  medicalLicense: { label: 'Medical License', icon: 'ribbon-outline', sensitive: false },
  identity: { label: 'Identity Proof', icon: 'id-card-outline', sensitive: true },
  // `credentialSubject.id` is the holder's DID and is ALWAYS disclosed — it is
  // never withheld and was never chosen. Withholding it is what lets a thief
  // present a stolen credential as their own (steno #195), so it is not a
  // toggle and must not be listed as though the holder picked it.
  id: { label: 'Your health identifier', icon: 'finger-print-outline', sensitive: false },
};

/**
 * Claims that travel by construction rather than by choice.
 *
 * Shown, because concealing them would be its own dishonesty — the holder
 * should know their identifier went. Excluded from the "shared" COUNT, because
 * counting them inflates a number the holder reads as "things I agreed to":
 * selecting one claim produced "2 data types shared".
 */
const ALWAYS_DISCLOSED = new Set(['id', 'did']);

/**
 * Chip labels, in the same words as the counters.
 *
 * The filter KEYS stay as they are — they are internal and renaming them would
 * touch the store — but what the holder reads must match what the counters say
 * one row above.
 */
const FILTER_LABELS: Record<ConsentFilter, string> = {
  all: 'All',
  active: 'Shared',
  expiring: 'Ongoing',
  revoked: 'Revoked',
};

function getDataTypeDisplay(dataType: string): { label: string; icon: IoniconsName; sensitive: boolean } {
  return DATA_TYPE_DISPLAY[dataType] || {
    // NEVER the raw path. The fallback here used to be a bare camelCase split,
    // which is how a holder came to read "Medication.start Date" and
    // "Patient Id" — it never split the dot and left every word after the first
    // lowercase. formatClaimLabel is now the ONE humaniser, so this screen and
    // the credential detail cannot disagree about what a claim is called.
    label: formatClaimLabel(dataType),
    icon: 'document-outline',
    sensitive: false,
  };
}

// -- Screen Component --

export default function ConsentScreen() {
  // No navigator header on this tab, so nothing else supplies the status-bar gap.
  const insets = useSafeAreaInsets();
  // Emergency access is reached from HERE now; this screen is its way in.
  const navigation = useNavigation();
  const {
    activeConsents,
    revokedConsents,
    isLoading,
    isRevoking,
    error,
    fetchConsents,
    revokeConsent,
    clearError,
  } = useConsentStore();

  // Filter and search state
  const [filter, setFilter] = useState<ConsentFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  
  // Expanded consents state (for granular permissions)
  const [expandedConsents, setExpandedConsents] = useState<Set<string>>(new Set());
  
  // Template expansion and selection
  const [showTemplates, setShowTemplates] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<ConsentTemplate | null>(null);
  const [templateDetailVisible, setTemplateDetailVisible] = useState(false);

  // Sheet state
  const [revokeSheetVisible, setRevokeSheetVisible] = useState(false);
  const [selectedConsent, setSelectedConsent] = useState<Consent | null>(null);
  const [successSheetVisible, setSuccessSheetVisible] = useState(false);

  // Toggle expanded state for a consent
  const toggleExpanded = useCallback((consentId: string) => {
    LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
    setExpandedConsents(prev => {
      const next = new Set(prev);
      if (next.has(consentId)) {
        next.delete(consentId);
      } else {
        next.add(consentId);
      }
      return next;
    });
  }, []);

  // Toggle templates section
  const toggleTemplates = useCallback(() => {
    LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
    setShowTemplates(prev => !prev);
  }, []);

  // Handle template selection
  const handleTemplateSelect = useCallback((template: ConsentTemplate) => {
    setSelectedTemplate(template);
    setTemplateDetailVisible(true);
  }, []);

  // Fetch consents on mount
  useEffect(() => {
    fetchConsents();
  }, [fetchConsents]);

  // Compute filtered consents
  const allConsents = useMemo(
    () => [...activeConsents, ...revokedConsents],
    [activeConsents, revokedConsents]
  );

  /**
   * Access that genuinely CONTINUES.
   *
   * Everything else on this screen is a record of a disclosure that already
   * finished. Keeping them apart is the whole correction: they were previously
   * counted as "Active" AND "Expiring" simultaneously, so three records read as
   * six things, and every one of them showed a red expiry warning seconds after
   * being created — an alarm that always fires distinguishes nothing.
   */
  const standingConsents = useMemo(
    () => activeConsents.filter((c) => c.standingAccess === true),
    [activeConsents]
  );

  /** Completed disclosures: the verifier already has the claims. */
  const disclosureRecords = useMemo(
    () => activeConsents.filter((c) => c.standingAccess !== true),
    [activeConsents]
  );

  const filteredConsents = useMemo(() => {
    let consents: Consent[];
    
    switch (filter) {
      case 'active':
        // Completed disclosures only. Pointing this at `activeConsents` would
        // include standing grants too, so the "Shared" chip and the "Shared"
        // counter would disagree about what the word means.
        consents = disclosureRecords;
        break;
      case 'revoked':
        consents = revokedConsents;
        break;
      case 'expiring':
        consents = standingConsents;
        break;
      default:
        consents = allConsents;
    }

    // Apply search filter
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      consents = consents.filter(
        (c) =>
          c.requesterName.toLowerCase().includes(query) ||
          c.purpose.name.toLowerCase().includes(query) ||
          c.scope.dataTypes.some((dt) => dt.toLowerCase().includes(query))
      );
    }

    // Sort by most recent first
    return consents.sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }, [filter, searchQuery, activeConsents, revokedConsents, standingConsents, allConsents]);

  /**
   * Collapse repeat disclosures to the same verifier for the same purpose.
   *
   * Every scan writes a record, so a pharmacy visited weekly produces a wall of
   * rows that are identical apart from a timestamp — and the timestamp was not
   * even shown. What the holder wants to know is "who has had my data, and how
   * often", which is a property of the GROUP, not of any single row.
   *
   * Grouped on (verifier, purpose) rather than verifier alone: the same clinic
   * asking for identity today and prescriptions tomorrow are different
   * disclosures and merging them would hide the second behind the first.
   *
   * Standing access is never grouped — each grant is separately revocable, and
   * collapsing two would leave one of them unreachable.
   */
  const groupedConsents = useMemo(() => {
    const groups = new Map<string, { key: string; latest: Consent; all: Consent[] }>();
    for (const consent of filteredConsents) {
      const key = consent.standingAccess
        ? `standing:${consent.id}`
        : `${consent.requesterId}::${consent.purpose.name}::${consent.status}`;
      const existing = groups.get(key);
      if (existing) {
        existing.all.push(consent);
        if (new Date(consent.createdAt) > new Date(existing.latest.createdAt)) {
          existing.latest = consent;
        }
      } else {
        groups.set(key, { key, latest: consent, all: [consent] });
      }
    }
    return Array.from(groups.values());
  }, [filteredConsents]);

  // Handle revoke consent - show confirmation sheet
  const handleRevoke = useCallback((consent: Consent) => {
    setSelectedConsent(consent);
    setRevokeSheetVisible(true);
  }, []);

  // Confirm revoke
  const handleRevokeConfirm = useCallback(async () => {
    if (!selectedConsent) return;
    try {
      await revokeConsent(selectedConsent.id);
      setSuccessSheetVisible(true);
    } catch (err) {
      // Error is already set in store state and displayed via error prop
      // Log for debugging/monitoring purposes
      console.warn('[ConsentScreen] Revoke failed:', err);
    }
  }, [selectedConsent, revokeConsent]);

  // Handle retry
  const handleRetry = useCallback(() => {
    clearError();
    fetchConsents();
  }, [clearError, fetchConsents]);

  // Format date for display
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  /**
   * Date AND time.
   *
   * Three separate shares on one day all rendered "Sep 9, 2026" and were
   * indistinguishable from each other in a list whose whole job is to let the
   * holder tell one disclosure from another.
   */
  const formatDateTime = (dateString: string) => {
    const d = new Date(dateString);
    return `${d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}, ${d.toLocaleTimeString(
      'en-US',
      { hour: 'numeric', minute: '2-digit' },
    )}`;
  };

  // Get relative time until expiry
  const getExpiryCountdown = (expiresAt: string): { text: string; urgent: boolean } => {
    const now = Date.now();
    const expires = new Date(expiresAt).getTime();
    const diffMs = expires - now;
    
    if (diffMs <= 0) {
      return { text: 'Expired', urgent: true };
    }
    
    const days = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
    const hours = Math.ceil(diffMs / (1000 * 60 * 60));
    
    if (days <= 1) {
      return { text: `Expires in ${hours} hour${hours !== 1 ? 's' : ''}`, urgent: true };
    } else if (days <= 7) {
      return { text: `Expires in ${days} day${days !== 1 ? 's' : ''}`, urgent: true };
    } else if (days <= 30) {
      return { text: `Expires in ${days} days`, urgent: false };
    } else {
      const months = Math.floor(days / 30);
      return { text: `Expires in ${months} month${months !== 1 ? 's' : ''}`, urgent: false };
    }
  };

  // -- Loading State --
  if (isLoading && activeConsents.length === 0 && revokedConsents.length === 0) {
    return <LoadingSpinner fullScreen message="Loading consents..." />;
  }

  // -- Error State --
  if (error && activeConsents.length === 0) {
    return (
      <ErrorState
        title="Failed to Load"
        message={error}
        onRetry={handleRetry}
      />
    );
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={[styles.content, { paddingTop: spacing.screenPadding }]}
      refreshControl={
        <RefreshControl
          refreshing={isLoading}
          onRefresh={fetchConsents}
          tintColor={colors.brand.primary}
          colors={[colors.brand.primary]}
        />
      }
      accessibilityLabel="Consent management screen"
    >
      {/* Stats Summary */}
      <View style={styles.statsContainer}>
        {/* Disjoint by construction: a record is a finished disclosure, or
            standing access, or revoked. Never two of them at once. */}
        <View style={styles.statCard}>
          <Ionicons name="share-outline" size={24} color={colors.brand.primary} />
          <Text style={styles.statNumber}>{disclosureRecords.length}</Text>
          <Text style={styles.statLabel}>Shared</Text>
        </View>
        <View style={styles.statCard}>
          <Ionicons name="shield-checkmark" size={24} color={colors.semantic.success} />
          <Text style={styles.statNumber}>{standingConsents.length}</Text>
          <Text style={styles.statLabel}>Ongoing</Text>
        </View>
        <View style={styles.statCard}>
          <Ionicons
            name="close-circle-outline"
            size={24}
            color={revokedConsents.length > 0 ? colors.semantic.error : colors.text.tertiary}
          />
          <Text style={styles.statNumber}>{revokedConsents.length}</Text>
          <Text style={styles.statLabel}>Revoked</Text>
        </View>
      </View>

      {/* EMERGENCY ACCESS LIVES UNDER CONSENT. An emergency read is one of the
          ways records are opened, so it is reached from the screen about who
          has access, not from a tab of its own. The tab it used to occupy now
          carries the medicine balances. */}
      <TouchableOpacity
        style={styles.emergencyEntry}
        onPress={() => (navigation as any).navigate('EmergencyAccess')}
        accessibilityRole="button"
        accessibilityLabel="Emergency access. See who opened your records in an emergency."
      >
        <View style={styles.emergencyEntryIcon}>
          <Ionicons name="medkit-outline" size={20} color={colors.semantic.error} />
        </View>
        <View style={styles.emergencyEntryText}>
          <Text style={styles.emergencyEntryTitle}>Emergency access</Text>
          <Text style={styles.emergencyEntrySubtitle}>
            Hospitals that opened your records without asking
          </Text>
        </View>
        <Ionicons name="chevron-forward" size={18} color={colors.text.tertiary} />
      </TouchableOpacity>

      {/* Consent Templates Section */}
      <View style={styles.templatesSection}>
        <TouchableOpacity
          style={styles.templatesHeader}
          onPress={toggleTemplates}
          accessibilityLabel={`${showTemplates ? 'Hide' : 'Show'} consent templates`}
          accessibilityRole="button"
        >
          <View style={styles.templatesHeaderLeft}>
            <Ionicons name="copy-outline" size={20} color={colors.brand.primary} />
            <View>
              <Text style={styles.templatesTitle}>Quick Templates</Text>
              <Text style={styles.templatesSubtitle}>What common requests look like</Text>
            </View>
          </View>
          <Ionicons 
            name={showTemplates ? 'chevron-up' : 'chevron-down'} 
            size={20} 
            color={colors.text.tertiary} 
          />
        </TouchableOpacity>
        
        {showTemplates && (
          <View style={styles.templatesGrid}>
            {CONSENT_TEMPLATES.map((template) => (
              <TouchableOpacity
                key={template.id}
                style={styles.templateCard}
                onPress={() => handleTemplateSelect(template)}
                accessibilityLabel={`${template.name} template: ${template.description}`}
                accessibilityRole="button"
              >
                <View style={[styles.templateIcon, { backgroundColor: template.color + opacity.subtle }]}>
                  <Ionicons name={template.icon} size={20} color={template.color} />
                </View>
                <Text style={styles.templateName} numberOfLines={1}>{template.name}</Text>
                <Text style={styles.templateDescription} numberOfLines={2}>
                  {template.description}
                </Text>
                <View style={styles.templateMeta}>
                  <Ionicons name="time-outline" size={10} color={colors.text.tertiary} />
                  <Text style={styles.templateDuration}>
                    {DURATION_LABELS[template.duration]}
                  </Text>
                </View>
              </TouchableOpacity>
            ))}
          </View>
        )}
      </View>

      {/* Search Bar */}
      <View style={styles.searchContainer}>
        <Ionicons name="search" size={20} color={colors.text.tertiary} style={styles.searchIcon} />
        <TextInput
          style={styles.searchInput}
          placeholder="Search by organization or data type..."
          placeholderTextColor={colors.text.tertiary}
          value={searchQuery}
          onChangeText={setSearchQuery}
          accessibilityLabel="Search consents"
        />
        {searchQuery.length > 0 && (
          <TouchableOpacity onPress={() => setSearchQuery('')} accessibilityLabel="Clear search">
            <Ionicons name="close-circle" size={20} color={colors.text.tertiary} />
          </TouchableOpacity>
        )}
      </View>

      {/* Filter Chips */}
      <View style={styles.filterContainer}>
        {(['all', 'active', 'revoked', 'expiring'] as ConsentFilter[]).map((f) => (
          <TouchableOpacity
            key={f}
            style={[styles.filterChip, filter === f && styles.filterChipActive]}
            onPress={() => setFilter(f)}
            accessibilityLabel={`Filter by ${f}`}
            accessibilityState={{ selected: filter === f }}
          >
            <Text style={[styles.filterChipText, filter === f && styles.filterChipTextActive]}>
              {/* Labelled from the SAME vocabulary as the counters above.
                  Deriving a label by capitalising the internal filter key left
                  the chips saying "Active / Expiring" beside counters reading
                  "Shared / Ongoing" — two names for one thing on one screen. */}
              {FILTER_LABELS[f]}
            </Text>
          </TouchableOpacity>
        ))}
      </View>

      {/* Results Count */}
      <Text style={styles.resultsCount}>
        {/* Records, then organisations — the list now shows one card per
            (organisation, purpose), so counting cards would contradict the
            counters above, and counting only records would not explain why
            fewer cards appear than the number claims. */}
        {filteredConsents.length} record{filteredConsents.length !== 1 ? 's' : ''}
        {groupedConsents.length !== filteredConsents.length
          ? ` · ${groupedConsents.length} organisation${groupedConsents.length !== 1 ? 's' : ''}`
          : ''}
      </Text>

      {/* Consent List */}
      {filteredConsents.length === 0 ? (
        <EmptyState
          title={searchQuery ? 'No Results' : 'No Consents'}
          message={searchQuery 
            ? `No consents match "${searchQuery}"`
            : 'You haven\'t granted access to any organizations yet'
          }
          icon="shield-outline"
          style={styles.emptyState}
        />
      ) : (
        groupedConsents.map((group) => {
          const consent = group.latest;
          const repeats = group.all.length;
          const isRevoked = consent.status === 'revoked' || consent.status === 'expired';
          // Standing access can expire; a completed disclosure cannot — there is
          // nothing left to lapse. Reading `expiresAt` on the latter is what put
          // a red "Expires in 24 hours" on records seconds old.
          const isStanding = consent.standingAccess === true;
          const isExpiring = !isRevoked && isStanding && consent.expiresAt &&
            Math.ceil((new Date(consent.expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24)) <= 30;
          const chosenTypes = consent.scope.dataTypes.filter((dt) => !ALWAYS_DISCLOSED.has(dt));
          
          return (
            <Card
              key={group.key}
              variant="default"
              style={[styles.consentCard, isRevoked && styles.revokedCard]}
              accessibilityLabel={`Consent for ${consent.requesterName}`}
            >
              {/* Header */}
              <View style={styles.consentHeader}>
                <View style={styles.consentIcon}>
                  <Ionicons 
                    name="person-circle" 
                    size={40} 
                    color={isRevoked ? colors.text.disabled : colors.brand.primaryLight} 
                  />
                </View>
                <View style={styles.consentInfo}>
                  <Text style={[styles.consentName, isRevoked && styles.revokedText]}>
                    {consent.requesterName}
                  </Text>
                  <Text style={styles.consentPurpose}>{consent.purpose.name}</Text>
                </View>
                <Badge
                  label={
                    isRevoked ? 'Revoked' : isExpiring ? 'Expiring' : isStanding ? 'Ongoing' : 'Shared'
                  }
                  variant={
                    isRevoked ? 'error' : isExpiring ? 'warning' : isStanding ? 'success' : 'default'
                  }
                  icon="ellipse"
                  size="small"
                />
              </View>

              {/* Details */}
              <View style={styles.consentDetails}>
                {/* Expandable data types header */}
                <TouchableOpacity
                  style={styles.detailItemExpand}
                  onPress={() => toggleExpanded(consent.id)}
                  accessibilityLabel={`${expandedConsents.has(consent.id) ? 'Collapse' : 'Expand'} shared data details`}
                  accessibilityRole="button"
                >
                  <Ionicons name="folder-outline" size={14} color={colors.text.secondary} />
                  <Text style={styles.detailText}>
                    {chosenTypes.length} data type
                    {chosenTypes.length !== 1 ? 's' : ''} shared
                  </Text>
                  <Ionicons 
                    name={expandedConsents.has(consent.id) ? 'chevron-up' : 'chevron-down'} 
                    size={16} 
                    color={colors.text.secondary} 
                  />
                </TouchableOpacity>
                
                {/* Expanded granular permissions */}
                {expandedConsents.has(consent.id) && (
                  <View style={styles.granularPermissions}>
                    <Text style={styles.granularTitle}>
                      {consent.requesterName} can access:
                    </Text>
                    {consent.scope.dataTypes.map((dataType) => {
                      const display = getDataTypeDisplay(dataType);
                      return (
                        <View key={dataType} style={styles.dataTypeItem}>
                          <View style={[
                            styles.dataTypeIcon,
                            display.sensitive && styles.dataTypeIconSensitive
                          ]}>
                            <Ionicons 
                              name={display.icon} 
                              size={14} 
                              color={display.sensitive ? colors.semantic.warning : colors.text.secondary} 
                            />
                          </View>
                          <Text style={[
                            styles.dataTypeLabel,
                            display.sensitive && styles.dataTypeLabelSensitive
                          ]}>
                            {display.label}
                          </Text>
                          {ALWAYS_DISCLOSED.has(dataType) && (
                            <Badge label="Always included" variant="default" size="small" />
                          )}
                          {display.sensitive && (
                            <Badge 
                              label="Sensitive" 
                              variant="warning" 
                              size="small" 
                            />
                          )}
                        </View>
                      );
                    })}
                    {consent.scope.dataTypes.some(dt => getDataTypeDisplay(dt).sensitive) && (
                      <View style={styles.sensitiveWarning}>
                        <Ionicons name="warning" size={14} color={colors.semantic.warning} />
                        <Text style={styles.sensitiveWarningText}>
                          Contains sensitive personal data
                        </Text>
                      </View>
                    )}
                  </View>
                )}
                
                <View style={styles.detailItem}>
                  <Ionicons name="calendar-outline" size={14} color={colors.text.secondary} />
                  <Text style={styles.detailText}>
                    {/* WITH THE TIME. Three scans on one day all read
                        "Granted: Sep 9, 2026" and were indistinguishable. */}
                    {isStanding ? 'Granted' : 'Shared'} {formatDateTime(consent.createdAt)}
                  </Text>
                </View>
                
                {/* Time-based expiry with countdown — STANDING ACCESS ONLY. */}
                {isStanding && consent.expiresAt && (() => {
                  const countdown = getExpiryCountdown(consent.expiresAt);
                  return (
                    <View style={[
                      styles.expiryContainer,
                      countdown.urgent && styles.expiryContainerUrgent
                    ]}>
                      <View style={styles.expiryHeader}>
                        <Ionicons 
                          name={countdown.urgent ? 'warning' : 'time-outline'} 
                          size={14} 
                          color={countdown.urgent ? colors.semantic.error : colors.semantic.warning} 
                        />
                        <Text style={[
                          styles.expiryCountdown,
                          countdown.urgent && styles.expiryCountdownUrgent
                        ]}>
                          {countdown.text}
                        </Text>
                      </View>
                      <Text style={styles.expiryDate}>
                        ({formatDate(consent.expiresAt)})
                      </Text>
                    </View>
                  );
                })()}
                
                {isStanding && !consent.expiresAt && !isRevoked && (
                  <View style={styles.detailItem}>
                    <Ionicons name="infinite-outline" size={14} color={colors.text.secondary} />
                    <Text style={styles.detailText}>No expiration set</Text>
                  </View>
                )}

                {/* Access count belongs to STANDING access, where it counts
                    something that can change. On a completed disclosure it said
                    "Accessed 0 times" on a record that exists BECAUSE it was
                    accessed — the most misleading line on the screen. */}
                {isStanding && consent.accessCount !== undefined && (
                  <View style={styles.detailItem}>
                    <Ionicons name="eye-outline" size={14} color={colors.text.secondary} />
                    <Text style={styles.detailText}>
                      Accessed {consent.accessCount} time{consent.accessCount !== 1 ? 's' : ''}
                    </Text>
                  </View>
                )}

                {repeats > 1 && (
                  <View style={styles.detailItem}>
                    <Ionicons name="repeat-outline" size={14} color={colors.text.secondary} />
                    <Text style={styles.detailText}>
                      Shared {repeats} times ·{' '}
                      {group.all
                        .map((c) => formatDateTime(c.createdAt))
                        .slice(0, 4)
                        .join(', ')}
                      {repeats > 4 ? ` and ${repeats - 4} more` : ''}
                    </Text>
                  </View>
                )}

                {!isStanding && !isRevoked && (
                  <View style={styles.finishedNote}>
                    <Ionicons name="lock-closed-outline" size={14} color={colors.text.tertiary} />
                    <Text style={styles.finishedNoteText}>
                      This was a one-time share and is already complete.{' '}
                      {consent.requesterName} cannot request more using this record, and
                      what was shared cannot be taken back.
                    </Text>
                  </View>
                )}
              </View>

              {/* REVOKE IS FOR STANDING ACCESS ONLY.
                  Offering it on a completed disclosure advertised a power the
                  holder does not have: the claims are already in the verifier's
                  hands and nothing this app does can retrieve them. A control
                  whose promise the system cannot keep is worse than no control,
                  because the holder acts on the belief that it worked. */}
              {!isRevoked && isStanding && (
                <Button
                  label="Stop future access"
                  onPress={() => handleRevoke(consent)}
                  variant="danger"
                  size="medium"
                  icon="close-circle-outline"
                  loading={isRevoking === consent.id}
                  disabled={isRevoking !== null}
                  fullWidth
                  style={styles.revokeButton}
                  accessibilityHint="Revokes this consent and removes access"
                />
              )}
            </Card>
          );
        })
      )}

      {/* Revoke Confirmation Sheet */}
      <ConfirmationSheet
        visible={revokeSheetVisible}
        onClose={() => setRevokeSheetVisible(false)}
        onConfirm={handleRevokeConfirm}
        title="Stop future access?"
        description={selectedConsent
          ? `${selectedConsent.requesterName} will not be able to read anything further. ` +
            'Anything already shared with them stays shared — this cannot take it back. ' +
            'You can grant access again later if you need to.'
          : 'Stop this organisation from reading anything further?'
        }
        confirmText="Revoke Access"
        cancelText="Keep Access"
        variant="destructive"
        icon="shield-outline"
        infoItems={selectedConsent ? [
          { label: 'Shared Data', value: `${selectedConsent.scope.dataTypes.length} types` },
          { label: 'Granted', value: new Date(selectedConsent.createdAt).toLocaleDateString() },
        ] : undefined}
      />

      {/* Success Sheet */}
      <InfoSheet
        visible={successSheetVisible}
        onClose={() => setSuccessSheetVisible(false)}
        title="Access Revoked"
        description="The organization can no longer access your shared credentials. This takes effect immediately."
        variant="success"
        autoDismissMs={3000}
      />
      
      {/* Template Detail Sheet */}
      {selectedTemplate && (
        <ConfirmationSheet
          visible={templateDetailVisible}
          onClose={() => setTemplateDetailVisible(false)}
          onConfirm={() => {
            // Templates are informational — consent is granted when a verifier
            // sends a real OID4VP request that matches one of these patterns
            setTemplateDetailVisible(false);
          }}
          title={selectedTemplate.name}
          description={`${selectedTemplate.description}. When a verifier requests this type of data, you'll see a prompt matching this template.`}
          confirmText="Got It"
          cancelText="Close"
          variant="default"
          icon={selectedTemplate.icon}
          infoItems={[
            { label: 'Duration', value: DURATION_LABELS[selectedTemplate.duration] },
            // EVERY field, never "+N more".
            //
            // This listed three and hid the rest behind "+6 more", with nothing
            // to tap to see them. On a screen about consent that is the one
            // thing that must not be abbreviated: a holder cannot weigh what
            // they are not shown, and the count alone ("9 fields shared") tells
            // them how much is hidden without telling them what.
            ...selectedTemplate.dataTypes.map((dt, index) => ({
              label: index === 0 ? 'Includes' : ' ',
              value: getDataTypeDisplay(dt).label,
            })),
          ]}
        />
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
  sectionHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: spacing.lg,
  },
  emptyState: {
    marginVertical: spacing.xl,
  },
  consentCard: {
    marginBottom: spacing.md,
  },
  revokedCard: {
    opacity: 0.6,
  },
  consentHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
  },
  consentIcon: {},
  consentInfo: {
    flex: 1,
  },
  consentName: {
    color: colors.text.primary,
    fontSize: fontSizes.xl,
    fontWeight: fontWeights.bold,
  },
  consentPurpose: {
    color: colors.text.secondary,
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.normal,
    marginTop: spacing.xxs,
  },
  revokedText: {
    color: colors.text.tertiary,
  },
  consentDetails: {
    marginTop: spacing.md,
    paddingTop: spacing.md,
    borderTopWidth: 1,
    borderTopColor: colors.border.default,
    gap: spacing.sm,
  },
  detailItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
  },
  detailText: {
    color: colors.text.secondary,
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.normal,
  },
  finishedNote: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: spacing.xs,
    marginTop: spacing.sm,
    paddingTop: spacing.sm,
    borderTopWidth: 1,
    borderTopColor: colors.border.subtle,
  },
  finishedNoteText: {
    ...typography.bodySmall,
    color: colors.text.tertiary,
    flex: 1,
    lineHeight: 18,
  },
  revokeButton: {
    marginTop: spacing.md,
  },
  revokedSectionHeader: {
    marginTop: spacing.sectionGap,
  },
  // Stats styles
  statsContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: spacing.lg,
  },
  statCard: {
    flex: 1,
    backgroundColor: colors.surface.elevated,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    alignItems: 'center',
    marginHorizontal: spacing.xxs,
  },
  statNumber: {
    fontSize: fontSizes.xxl,
    fontWeight: fontWeights.bold,
    color: colors.text.primary,
    marginTop: spacing.xs,
  },
  statLabel: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    marginTop: spacing.xxs,
  },
  // Emergency access entry (moved here from its own tab)
  emergencyEntry: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
    backgroundColor: colors.surface.elevated,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginBottom: spacing.lg,
  },
  emergencyEntryIcon: {
    width: 36,
    height: 36,
    borderRadius: borderRadius.sm,
    backgroundColor: colors.semantic.error + opacity.subtle,
    justifyContent: 'center',
    alignItems: 'center',
  },
  emergencyEntryText: {
    flex: 1,
  },
  emergencyEntryTitle: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  emergencyEntrySubtitle: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    marginTop: spacing.xxs,
  },
  // Search styles
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
  // Filter styles
  filterContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.sm,
    marginBottom: spacing.md,
  },
  filterChip: {
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
    color: colors.text.secondary,
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
  // Granular permissions styles
  detailItemExpand: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    paddingVertical: spacing.xs,
  },
  granularPermissions: {
    backgroundColor: colors.surface.elevated,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginVertical: spacing.sm,
  },
  granularTitle: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
    marginBottom: spacing.sm,
  },
  dataTypeItem: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: spacing.xs,
    gap: spacing.sm,
  },
  dataTypeIcon: {
    width: 24,
    height: 24,
    borderRadius: borderRadius.sm,
    backgroundColor: colors.surface.secondary,
    justifyContent: 'center',
    alignItems: 'center',
  },
  dataTypeIconSensitive: {
    backgroundColor: colors.semantic.warning + opacity.subtle,
  },
  dataTypeLabel: {
    flex: 1,
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
  },
  dataTypeLabelSensitive: {
    color: colors.text.primary,
    fontWeight: fontWeights.medium,
  },
  sensitiveWarning: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
    marginTop: spacing.md,
    paddingTop: spacing.sm,
    borderTopWidth: 1,
    borderTopColor: colors.border.default,
  },
  sensitiveWarningText: {
    fontSize: fontSizes.xs,
    color: colors.semantic.warning,
    fontWeight: fontWeights.medium,
  },
  // Expiry countdown styles
  expiryContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: spacing.xs,
    paddingHorizontal: spacing.sm,
    backgroundColor: colors.semantic.warning + opacity.ultraSubtle,
    borderRadius: borderRadius.sm,
    marginTop: spacing.xs,
  },
  expiryContainerUrgent: {
    backgroundColor: colors.semantic.error + opacity.ultraSubtle,
    borderWidth: 1,
    borderColor: colors.semantic.error + opacity.light,
  },
  expiryHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
  },
  expiryCountdown: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
    color: colors.semantic.warning,
  },
  expiryCountdownUrgent: {
    color: colors.semantic.error,
  },
  expiryDate: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
  },
  // Templates section styles
  templatesSection: {
    backgroundColor: colors.surface.elevated,
    borderRadius: borderRadius.md,
    marginBottom: spacing.md,
    overflow: 'hidden',
  },
  templatesHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: spacing.md,
  },
  templatesHeaderLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
  },
  templatesTitle: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  templatesSubtitle: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    marginTop: spacing.xxs,
  },
  templatesGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    padding: spacing.sm,
    paddingTop: 0,
    gap: spacing.sm,
  },
  templateCard: {
    width: '48%',
    backgroundColor: colors.surface.secondary,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    borderWidth: 1,
    borderColor: colors.border.default,
  },
  templateIcon: {
    width: 36,
    height: 36,
    borderRadius: borderRadius.sm,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: spacing.sm,
  },
  templateName: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  templateDescription: {
    fontSize: fontSizes.xs,
    color: colors.text.secondary,
    marginTop: spacing.xxs,
    lineHeight: fontSizes.xs * 1.4,
  },
  templateMeta: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xxs,
    marginTop: spacing.sm,
  },
  templateDuration: {
    fontSize: fontSizes.xxs,
    color: colors.text.tertiary,
  },
});
