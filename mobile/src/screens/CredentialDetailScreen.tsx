/**
 * SSI Healthcare Mobile - Credential Detail Screen
 *
 * Shows individual credential details with:
 * - Selective disclosure toggles
 * - Share action
 * - Verification status
 * - Issuance info
 *
 * REFACTORED to use:
 * - Design tokens from theme system
 * - Reusable components
 * - Zustand store for state management
 * - Proper TypeScript types
 * - Accessibility attributes
 */

import React, { useEffect, useCallback, useMemo, useState, useRef } from 'react';
import { View, ScrollView, StyleSheet } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { CredentialStackParamList, CredentialField } from '../types';
import { useCredentialStore } from '../store';
import { useSettings } from '../contexts';
import { colors, spacing, borderRadius } from '../theme';
import {
  LoadingSpinner,
  ErrorState,
  Button,
  SectionHeader,
  VerificationBadge,
  Badge,
} from '../components/common';
import { FieldToggleRow, CredentialMetadata, ExpirationBadge } from '../components/credentials';
import { PresentationShareSheet, InfoSheet } from '../components/sheets';
import { useAuth } from '../contexts';
import { truncateDid } from '../utils/format';
import {
  getCredentialTypeName,
  getFieldDisplayName,
  isSensitiveField,
} from '../utils/plainLanguage';
import { renderClaimValue } from '../store/credentialTransform';

// -- Plain Language Mappings --



/** Maps credential types to plain English descriptions */


// -- Type Definitions --

type Props = NativeStackScreenProps<CredentialStackParamList, 'CredentialDetail'>;

// -- Screen Component --

export default function CredentialDetailScreen({ route, navigation }: Props) {
  const { credentialId } = route.params;

  // Settings context for plain/advanced mode
  const { isAdvancedMode } = useSettings();
  const { user } = useAuth();

  // Ref for cleanup of navigation timer
  const navigationTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Sheet visibility state
  const [shareSheetVisible, setShareSheetVisible] = useState(false);
  const [shareMode, setShareMode] = useState<'qr' | 'send'>('qr');
  const [infoSheetVisible, setInfoSheetVisible] = useState(false);
  const [infoSheetConfig, setInfoSheetConfig] = useState({
    title: '',
    description: '',
    variant: 'info' as 'success' | 'error' | 'info' | 'warning',
  });

  // Zustand store state and actions
  const {
    selectedCredential,
    disclosureState,
    isLoading,
    error,
    fetchCredentialById,
    toggleFieldDisclosure,
    clearError,
  } = useCredentialStore();

  // Cleanup timer on unmount
  useEffect(() => {
    return () => {
      if (navigationTimerRef.current) {
        clearTimeout(navigationTimerRef.current);
      }
    };
  }, []);

  // ===================================================================
  // THIS SCREEN MUST NOT INHERIT ANOTHER SCREEN'S FAILURE
  // ===================================================================
  // `error` and `selectedCredential` are SHARED store state. On a cold start
  // the screen mounted, read an `error` left behind by whatever failed last —
  // typically the credentials list, or a request made while the session was
  // expiring — and rendered "Failed to Load" INSTANTLY, before its own fetch
  // had been issued. The message was true of something, just not of this
  // screen, and retrying appeared to fix a fault that had never been here.
  //
  // The mirror image was equally wrong: `isLoading && !selectedCredential`
  // skipped the loading state whenever the store still held a DIFFERENT
  // credential, so the screen rendered someone else's data as though it were
  // the requested one, then swapped it out when the fetch landed.
  //
  // `settled` tracks THIS screen's own fetch. Until it is true the screen is
  // loading — never failed, never showing another credential's contents.
  const [settled, setSettled] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setSettled(false);
    // Clear first, so a stale error cannot be read during the fetch.
    clearError();
    void Promise.resolve(fetchCredentialById(credentialId)).finally(() => {
      if (!cancelled) setSettled(true);
    });
    return () => {
      cancelled = true;
    };
  }, [credentialId, fetchCredentialById, clearError]);

  // Extract fields from credential with plain language support
  const fields = useMemo((): CredentialField[] => {
    if (!selectedCredential?.verifiableCredential?.credentialSubject) {
      return [];
    }

    const subject = selectedCredential.verifiableCredential.credentialSubject;
    const credDisclosure = disclosureState[credentialId] || {};

    return Object.entries(subject)
      .filter(([key]) => key !== 'id')
      .map(([key, value]) => ({
        id: key,
        label: isAdvancedMode ? formatFieldLabel(key) : getFieldDisplayName(key),
        value: formatFieldValue(key, value),
        // DEFAULT CLOSED. This is a presentation builder, and the project's
        // disclosure posture is that every extra claim costs a deliberate tap.
        // It used to default every non-sensitive field to shared, so a
        // holder's first act on this screen was to UN-share their own data —
        // the same failure the disclosure sheet was corrected for (#225).
        disclosed: credDisclosure[key] ?? false,
        required: key === 'type',
        sensitive: isSensitiveField(key),
      }));
  }, [selectedCredential, disclosureState, credentialId, isAdvancedMode]);

  // Count disclosed fields
  const disclosedCount = useMemo(
    () => fields.filter((f) => f.disclosed).length,
    [fields]
  );

  // Handle field toggle
  const handleFieldToggle = useCallback(
    (fieldId: string, _disclosed: boolean) => {
      toggleFieldDisclosure(credentialId, fieldId);
    },
    [credentialId, toggleFieldDisclosure]
  );

  /**
   * Both share buttons start the same exchange; they differ only in the first
   * move. A presentation cannot be signed before the verifier supplies its
   * single-use nonce, or the artifact would be replayable by anyone who saw it.
   */
  const startShare = useCallback(
    (mode: 'qr' | 'send') => {
      if (!selectedCredential?.credentialJwt) {
        setInfoSheetConfig({
          title: 'Cannot Share',
          description: 'This credential carries no signed envelope on this device, so there is nothing to present.',
          variant: 'warning',
        });
        setInfoSheetVisible(true);
        return;
      }
      if (fields.filter((f) => f.disclosed).length === 0) {
        setInfoSheetConfig({
          title: 'No Fields Selected',
          description: 'Choose at least one item to share. Toggle the switches next to the items you want to include.',
          variant: 'warning',
        });
        setInfoSheetVisible(true);
        return;
      }
      setShareMode(mode);
      setShareSheetVisible(true);
    },
    [fields, selectedCredential],
  );

  const handleShareCredential = useCallback(() => startShare('send'), [startShare]);

  // Generate QR code: the holder's OFFER, shown for the verifier to scan.
  const handleGenerateQR = useCallback(() => startShare('qr'), [startShare]);

  // Stable identity for the share sheet's effect key. Inline, this was a new
  // array on every render, which re-created the offer endlessly and put two
  // system share sheets on screen for one tap (measured 19 Sep 2026).
  const selectedClaimIds = useMemo(
    () => fields.filter((f) => f.disclosed).map((f) => f.id),
    [fields],
  );

  // Handle retry
  const handleRetry = useCallback(() => {
    setSettled(false);
    clearError();
    void Promise.resolve(fetchCredentialById(credentialId)).finally(() => setSettled(true));
  }, [clearError, fetchCredentialById, credentialId]);

  // -- Loading State --
  // Until this screen's own fetch settles there is nothing truthful to show
  // but a spinner: the store's contents belong to whatever ran before.
  if (!settled || isLoading) {
    return <LoadingSpinner fullScreen message="Loading credential" />;
  }

  // -- Error State --
  if (error) {
    return (
      <ErrorState
        title="Failed to Load"
        message={error}
        onRetry={handleRetry}
      />
    );
  }

  // -- Empty State --
  if (!selectedCredential) {
    return (
      <ErrorState
        title="Credential Not Found"
        message="The requested credential could not be found."
        icon="document"
        onRetry={() => navigation.goBack()}
        retryLabel="Go Back"
      />
    );
  }

  // -- Extract metadata for display --
  // Name if a pinned authority resolved it; otherwise the identifier itself.
  // Never "Unknown Issuer" while the DID is right there to show.
  const issuerName =
    selectedCredential.issuer?.name ??
    (selectedCredential.issuer?.id
      ? truncateDid(selectedCredential.issuer.id)
      : 'Unknown Issuer');

  const issuanceDate = new Date(selectedCredential.issuanceDate).toLocaleDateString(
    'en-US',
    { year: 'numeric', month: 'long', day: 'numeric' }
  );

  const expirationDate = selectedCredential.expirationDate
    ? new Date(selectedCredential.expirationDate).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      })
    : 'No Expiration';

  // Get credential type label based on mode
  const credentialTypeLabel = isAdvancedMode 
    ? selectedCredential.type 
    : getCredentialTypeName(selectedCredential.type);

  const metadataRows = isAdvancedMode
    ? [
        { label: 'Type', value: selectedCredential.type },
        { label: 'ID', value: truncateId(selectedCredential.id) },
        { label: 'Expires', value: expirationDate },
        { label: 'Format', value: 'JSON-LD' },
      ]
    : [
        { label: 'Document', value: credentialTypeLabel },
        { label: 'Valid Until', value: expirationDate },
      ];

  // -- Render --
  return (
    <View style={styles.screenContainer}>
      <ScrollView
        style={styles.container}
        contentContainerStyle={styles.content}
        accessibilityLabel="Credential detail screen"
      >
        {/* Verification Badge */}
        <VerificationBadge
          status={selectedCredential.status}
          issuer={issuerName}
          issuedDate={issuanceDate}
          style={styles.verificationBadge}
        />

        {/* Expiration Warning (only shows if expired or expiring soon) */}
        <ExpirationBadge 
          expirationDate={selectedCredential.expirationDate}
          style={styles.expirationBadge}
        />

        {/* Selective Disclosure Section */}
        <View style={styles.disclosureSection}>
          <SectionHeader
            title={isAdvancedMode ? "Selective Disclosure" : "What to Share"}
            subtitle={isAdvancedMode 
              ? "Toggle which fields to include in the verifiable presentation" 
              : "Choose what information to share"}
          />
          <Badge
            label={`${disclosedCount}/${fields.length} shared`}
            variant="default"
            size="small"
            style={styles.disclosureCountBadge}
          />
        </View>

        {/* Fields List */}
      <View
        style={styles.fieldsList}
        accessibilityRole="list"
        accessibilityLabel="Credential fields"
      >
        {fields.map((field) => (
          <FieldToggleRow
            key={field.id}
            field={field}
            onToggle={handleFieldToggle}
          />
        ))}
      </View>

      {/* Actions */}
      <View style={styles.actions}>
        <Button
          label="Share Credential"
          onPress={handleShareCredential}
          variant="primary"
          size="large"
          icon="share-outline"
          fullWidth
          accessibilityHint="Opens credential sharing options"
        />

        <Button
          label="Generate QR Code"
          onPress={handleGenerateQR}
          variant="secondary"
          size="large"
          icon="qr-code-outline"
          fullWidth
          accessibilityHint="Generates a QR code for this credential"
        />
      </View>

      {/* Metadata */}
      <CredentialMetadata rows={metadataRows} />
      </ScrollView>

      {/* Share Sheet */}
      <PresentationShareSheet
        visible={shareSheetVisible}
        onClose={() => setShareSheetVisible(false)}
        holderDid={user?.did ?? ''}
        credentialId={selectedCredential.id}
        credentialType={selectedCredential.type}
        credentialJwt={selectedCredential.credentialJwt ?? ''}
        selectedClaims={selectedClaimIds}
        initialMode={shareMode}
      />

      {/* Info Sheet */}
      <InfoSheet
        visible={infoSheetVisible}
        onClose={() => setInfoSheetVisible(false)}
        title={infoSheetConfig.title}
        description={infoSheetConfig.description}
        variant={infoSheetConfig.variant}
      />
    </View>
  );
}

// -- Helper Functions --

/** Format field key in technical camelCase to readable form */
function formatFieldLabel(key: string): string {
  return key
    .replace(/([A-Z])/g, ' $1')
    .replace(/_/g, ' ')
    .replace(/^\w/, (c) => c.toUpperCase())
    .trim();
}


/** Render a claim value the way a holder should read it. */
function formatFieldValue(key: string, value: unknown): string {
  // Objects and arrays are ordinary claim values here — the prescription's
  // `medication` and `prescribedBy` are objects by schema. `String(value)` on
  // them printed the literal text "[object Object]" on the card.
  const raw = renderClaimValue(value);

  // ISO 8601 timestamps: honest on the wire, unreadable in a list. Only a date
  // the platform can actually parse is reformatted; anything else is left alone
  // rather than risk "Invalid Date" over a real value.
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(raw)) {
    const parsed = new Date(raw);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
      });
    }
  }

  // Machine slugs (`nid-record-comparison`). Only for keys known to carry one:
  // the same shape is also how a bare lowercase UUID looks, and expanding a
  // UUID into words would mangle an identifier.
  if (key === 'verificationMethod' && /^[a-z0-9]+(-[a-z0-9]+)+$/.test(raw)) {
    return raw.replace(/-/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
  }

  return raw;
}

function truncateId(id: string): string {
  if (id.length <= 20) return id;
  return `${id.slice(0, 8)}...${id.slice(-8)}`;
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
  verificationBadge: {
    marginBottom: spacing.md,
  },
  expirationBadge: {
    marginBottom: spacing.sectionGap,
  },
  disclosureSection: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: spacing.lg,
  },
  disclosureCountBadge: {
    marginTop: spacing.xxs,
  },
  fieldsList: {
    backgroundColor: colors.surface.card,
    borderRadius: borderRadius.card,
    borderWidth: 1,
    borderColor: colors.border.default,
    overflow: 'hidden',
    marginBottom: spacing.sectionGap,
  },
  actions: {
    gap: spacing.md,
    marginBottom: spacing.sectionGap,
  },
});
