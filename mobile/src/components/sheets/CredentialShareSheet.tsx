/**
 * SSI Healthcare Mobile - Credential Share Sheet
 *
 * A sheet component for confirming credential sharing with clear,
 * plain-English explanations of what's being shared.
 *
 * Replaces Alert.alert for credential sharing - provides:
 * - Visual display of fields being shared
 * - Clear requester identification
 * - Ability to toggle fields (selective disclosure)
 * - Biometric confirmation prompt
 */

import React, { useState, useMemo } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Switch,
  ScrollView,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { BottomSheet } from './BottomSheet';
import { colors } from '../../theme/colors';
import { spacing } from '../../theme/spacing';
import { borderRadius } from '../../theme/borderRadius';
import { typography } from '../../theme/typography';
import { getCredentialTypeName } from '../../utils/plainLanguage';

interface FieldToShare {
  /** Unique field identifier */
  id: string;
  /** Human-readable field name */
  name: string;
  /** Field value (shown or masked based on sensitivity) */
  value: string;
  /** Whether this field is being shared */
  sharing: boolean;
  /** Whether this is sensitive data (SSN, DOB, etc.) */
  sensitive?: boolean;
  /** Whether this field is required by the verifier */
  required?: boolean;
}

interface RequesterInfo {
  /** Organization/app name */
  name: string;
  /** Whether the requester is verified */
  verified: boolean;
  /** Why they're requesting (in plain English) */
  purpose: string;
  /** Optional DID for advanced mode */
  did?: string;
}

interface CredentialShareSheetProps {
  /** Whether the sheet is visible */
  visible: boolean;
  /** Callback when sheet is closed */
  onClose: () => void;
  /** Callback when user confirms sharing */
  onConfirm: (selectedFields: FieldToShare[]) => void;
  /** The credential type being shared */
  credentialType: string;
  /** Information about who's requesting */
  requester: RequesterInfo;
  /** Fields that can be shared */
  fields: FieldToShare[];
  /** Whether in advanced mode */
  advancedMode?: boolean;
  /**
   * True when the HOLDER opened this sheet, rather than answering a request.
   *
   * The sheet was written for verifier-driven sharing, and its framing —
   * "Share Request", "Unverified request", "Wants to confirm", "Decline" —
   * described a counterparty that does not exist when the holder starts the
   * share themselves (measured 19 Sep 2026). Same controls, honest framing.
   */
  selfInitiated?: boolean;
}

export function CredentialShareSheet({
  visible,
  onClose,
  onConfirm,
  credentialType,
  requester,
  fields: initialFields,
  advancedMode = false,
  selfInitiated = false,
}: CredentialShareSheetProps) {
  const [fields, setFields] = useState(initialFields);

  // Reset fields when sheet opens
  React.useEffect(() => {
    if (visible) {
      setFields(initialFields);
    }
  }, [visible, initialFields]);

  const toggleField = (fieldId: string) => {
    setFields((prev) =>
      prev.map((field) =>
        field.id === fieldId && !field.required
          ? { ...field, sharing: !field.sharing }
          : field
      )
    );
  };

  const selectedFields = useMemo(
    () => fields.filter((f) => f.sharing),
    [fields]
  );

  const hasSelectedFields = selectedFields.length > 0;

  const handleConfirm = () => {
    if (hasSelectedFields) {
      onConfirm(selectedFields);
      onClose();
    }
  };

  return (
    <BottomSheet
      visible={visible}
      onClose={onClose}
      snapPoint={0.75}
      scrollable={false}
      testID="credential-share-sheet"
    >
      {/* Header */}
      <View style={styles.header}>
        <View style={styles.requesterBadge}>
          {selfInitiated ? (
            <Ionicons name="share-outline" size={24} color={colors.brand.primary} />
          ) : requester.verified ? (
            <Ionicons name="shield-checkmark" size={24} color={colors.semantic.success} />
          ) : (
            <Ionicons name="shield-outline" size={24} color={colors.semantic.warning} />
          )}
        </View>
        <View style={styles.headerText}>
          <Text style={styles.requesterName}>
            {selfInitiated ? 'Share this credential' : requester.name}
          </Text>
          <Text style={styles.verifiedText}>
            {selfInitiated
              ? 'You choose what is included'
              : requester.verified
                ? 'Verified organization'
                : 'Unverified request'}
          </Text>
        </View>
      </View>

      {/* Purpose */}
      <View style={styles.purposeContainer}>
        <Text style={styles.purposeLabel}>
          {selfInitiated ? 'You are sharing' : 'Wants to confirm'}
        </Text>
        <Text style={styles.purposeText}>{requester.purpose}</Text>
      </View>

      {/* Credential being shared */}
      <View style={styles.credentialBadge}>
        <Ionicons name="document-text-outline" size={20} color={colors.brand.primary} />
        <Text style={styles.credentialType}>{getCredentialTypeName(credentialType)}</Text>
      </View>

      {/* Field selection */}
      <ScrollView style={styles.fieldsList} showsVerticalScrollIndicator={false}>
        <Text style={styles.fieldsHeader}>Choose what to share</Text>

        {fields.map((field) => (
          <View key={field.id} style={styles.fieldRow}>
            <View style={styles.fieldInfo}>
              <View style={styles.fieldNameRow}>
                <Text style={styles.fieldName}>{field.name}</Text>
                {field.sensitive && (
                  <Ionicons
                    name="lock-closed"
                    size={14}
                    color={colors.semantic.warning}
                    style={styles.sensitiveIcon}
                  />
                )}
                {field.required && (
                  <View style={styles.requiredBadge}>
                    <Text style={styles.requiredText}>Required</Text>
                  </View>
                )}
              </View>
              <Text style={[styles.fieldValue, !field.sharing && styles.fieldValueHidden]}>
                {field.sharing ? field.value : '••••••••'}
              </Text>
            </View>
            <Switch
              value={field.sharing}
              onValueChange={() => toggleField(field.id)}
              disabled={field.required}
              trackColor={{
                false: colors.ui.switchTrackOff,
                true: colors.ui.switchTrackOn,
              }}
              thumbColor={field.sharing ? colors.ui.switchThumbOn : colors.ui.switchThumbOff}
              accessibilityLabel={`Share ${field.name}`}
              accessibilityHint={field.required ? 'This field is required' : 'Toggle to share or hide'}
            />
          </View>
        ))}
      </ScrollView>

      {/* Advanced info */}
      {advancedMode && !selfInitiated && requester.did && (
        <View style={styles.advancedInfo}>
          <Text style={styles.advancedLabel}>Requester DID</Text>
          <Text style={styles.advancedValue} numberOfLines={1} ellipsizeMode="middle">
            {requester.did}
          </Text>
        </View>
      )}

      {/* Summary */}
      <View style={styles.summary}>
        <Ionicons
          name={hasSelectedFields ? 'information-circle-outline' : 'warning-outline'}
          size={18}
          color={hasSelectedFields ? colors.text.secondary : colors.semantic.warning}
        />
        <Text style={styles.summaryText}>
          {hasSelectedFields
            ? `Sharing ${selectedFields.length} of ${fields.length} fields`
            : 'Select at least one field to share'}
        </Text>
      </View>

      {/* Actions */}
      <View style={styles.actions}>
        <TouchableOpacity
          style={styles.cancelButton}
          onPress={onClose}
          activeOpacity={0.7}
          accessibilityRole="button"
          accessibilityLabel={selfInitiated ? 'Cancel sharing' : 'Decline sharing'}
        >
          <Text style={styles.cancelButtonText}>{selfInitiated ? 'Cancel' : 'Decline'}</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.confirmButton, !hasSelectedFields && styles.confirmButtonDisabled]}
          onPress={handleConfirm}
          disabled={!hasSelectedFields}
          activeOpacity={0.7}
          accessibilityRole="button"
          accessibilityLabel="Confirm sharing"
        >
          <Ionicons name="finger-print" size={20} color={colors.text.primary} />
          <Text style={styles.confirmButtonText}>Share</Text>
        </TouchableOpacity>
      </View>
    </BottomSheet>
  );
}

const styles = StyleSheet.create({
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: spacing.lg,
  },
  requesterBadge: {
    width: 48,
    height: 48,
    borderRadius: borderRadius.full,
    backgroundColor: colors.background.secondary,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: spacing.md,
  },
  headerText: {
    flex: 1,
  },
  requesterName: {
    ...typography.headingMd,
    color: colors.text.primary,
  },
  verifiedText: {
    ...typography.bodySmall,
    color: colors.text.secondary,
    marginTop: 2,
  },
  purposeContainer: {
    backgroundColor: colors.background.secondary,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginBottom: spacing.md,
  },
  purposeLabel: {
    ...typography.caption,
    color: colors.text.tertiary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  purposeText: {
    ...typography.bodyMedium,
    color: colors.text.primary,
    marginTop: spacing.xs,
  },
  credentialBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.brand.primaryMuted,
    alignSelf: 'flex-start',
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.xs,
    borderRadius: borderRadius.full,
    marginBottom: spacing.lg,
  },
  credentialType: {
    ...typography.labelMedium,
    color: colors.brand.primary,
    marginLeft: spacing.xs,
  },
  fieldsList: {
    maxHeight: 200,
    marginBottom: spacing.md,
  },
  fieldsHeader: {
    ...typography.labelMedium,
    color: colors.text.secondary,
    marginBottom: spacing.sm,
  },
  fieldRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: colors.border.subtle,
  },
  fieldInfo: {
    flex: 1,
    marginRight: spacing.md,
  },
  fieldNameRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  fieldName: {
    ...typography.bodyMedium,
    color: colors.text.primary,
  },
  sensitiveIcon: {
    marginLeft: spacing.xs,
  },
  requiredBadge: {
    backgroundColor: colors.semantic.warningLight,
    paddingHorizontal: spacing.xs,
    paddingVertical: 2,
    borderRadius: borderRadius.sm,
    marginLeft: spacing.xs,
  },
  requiredText: {
    ...typography.caption,
    color: colors.semantic.warning,
    fontSize: 10,
  },
  fieldValue: {
    ...typography.bodySmall,
    color: colors.text.secondary,
    marginTop: 2,
  },
  fieldValueHidden: {
    color: colors.text.tertiary,
  },
  advancedInfo: {
    backgroundColor: colors.background.secondary,
    borderRadius: borderRadius.sm,
    padding: spacing.sm,
    marginBottom: spacing.md,
  },
  advancedLabel: {
    ...typography.caption,
    color: colors.text.tertiary,
  },
  advancedValue: {
    ...typography.mono,
    color: colors.text.secondary,
    fontSize: 12,
  },
  summary: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: spacing.lg,
  },
  summaryText: {
    ...typography.bodySmall,
    color: colors.text.secondary,
    marginLeft: spacing.xs,
  },
  actions: {
    flexDirection: 'row',
    gap: spacing.md,
  },
  cancelButton: {
    flex: 1,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    backgroundColor: colors.surface.elevated,
    alignItems: 'center',
    justifyContent: 'center',
  },
  cancelButtonText: {
    ...typography.labelMedium,
    color: colors.text.primary,
  },
  confirmButton: {
    flex: 2,
    flexDirection: 'row',
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    backgroundColor: colors.brand.primary,
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.xs,
  },
  confirmButtonDisabled: {
    backgroundColor: colors.surface.elevated,
    opacity: 0.5,
  },
  confirmButtonText: {
    ...typography.labelMedium,
    color: colors.text.primary,
  },
});

export default CredentialShareSheet;
