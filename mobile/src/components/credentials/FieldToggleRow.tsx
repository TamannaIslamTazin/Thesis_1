/**
 * SSI Healthcare Mobile - Field Toggle Row Component
 *
 * Displays a credential field with disclosure toggle.
 * Features:
 * - Sensitive field indicators with icon
 * - Required field badge
 * - Visual disclosure state
 */

import React, { useCallback } from 'react';
import { View, Text, StyleSheet, Switch } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../../theme';
import type { CredentialField } from '../../types';

interface FieldToggleRowProps {
  field: CredentialField;
  onToggle: (fieldId: string, disclosed: boolean) => void;
  disabled?: boolean;
}

export const FieldToggleRow = React.memo(function FieldToggleRow({
  field,
  onToggle,
  disabled = false,
}: FieldToggleRowProps) {
  const handleToggle = useCallback(
    (value: boolean) => {
      onToggle(field.id, value);
    },
    [field.id, onToggle]
  );

  return (
    <View
      style={[
        styles.container,
        field.sensitive && styles.containerSensitive,
      ]}
      accessibilityRole="switch"
      accessibilityLabel={`${field.label}: ${field.disclosed ? 'shared' : 'hidden'}${field.sensitive ? ', sensitive data' : ''}`}
      accessibilityState={{ checked: field.disclosed, disabled }}
    >
      <View style={styles.fieldInfo}>
        {/* Label Row with Badges */}
        <View style={styles.labelRow}>
          <Text style={styles.label}>{field.label}</Text>
          {field.sensitive && (
            <View style={styles.sensitiveBadge}>
              <Ionicons 
                name="shield-outline" 
                size={12} 
                color={colors.semantic.warning} 
              />
              <Text style={styles.sensitiveBadgeText}>Sensitive</Text>
            </View>
          )}
          {field.required && (
            <View style={styles.requiredBadge}>
              <Text style={styles.requiredBadgeText}>Required</Text>
            </View>
          )}
        </View>
        
        {/* Value */}
        <Text
          style={[
            styles.value,
            !field.disclosed && styles.valueHidden,
            field.sensitive && field.disclosed && styles.valueSensitive,
          ]}
        >
          {field.disclosed ? field.value : '••••••••'}
        </Text>
        
        {/* Sensitive Warning */}
        {field.sensitive && field.disclosed && (
          <View style={styles.sensitiveWarning}>
            <Ionicons 
              name="warning-outline" 
              size={12} 
              color={colors.semantic.warning} 
            />
            <Text style={styles.sensitiveHint}>
              Consider if you need to share this
            </Text>
          </View>
        )}
      </View>
      
      <Switch
        value={field.disclosed}
        onValueChange={handleToggle}
        disabled={disabled || field.required}
        trackColor={{
          false: colors.ui.switchTrackOff,
          true: field.sensitive ? colors.semantic.warning + '40' : colors.ui.switchTrackOn,
        }}
        thumbColor={
          field.disclosed 
            ? (field.sensitive ? colors.semantic.warning : colors.ui.switchThumbOn)
            : colors.ui.switchThumbOff
        }
        accessibilityLabel={`Share ${field.label}`}
      />
    </View>
  );
});

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
    borderBottomWidth: 1,
    borderBottomColor: colors.border.default,
  },
  containerSensitive: {
    backgroundColor: colors.semantic.warning + '08',
  },
  fieldInfo: {
    flex: 1,
    marginRight: spacing.md,
  },
  labelRow: {
    flexDirection: 'row',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: spacing.xs,
  },
  label: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.medium,
    color: colors.text.secondary,
  },
  sensitiveBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 2,
    backgroundColor: colors.semantic.warning + '20',
    paddingHorizontal: spacing.xs,
    paddingVertical: 2,
    borderRadius: borderRadius.full,
  },
  sensitiveBadgeText: {
    fontSize: fontSizes.xxs,
    fontWeight: fontWeights.medium,
    color: colors.semantic.warning,
  },
  requiredBadge: {
    backgroundColor: colors.text.disabled + '30',
    paddingHorizontal: spacing.xs,
    paddingVertical: 2,
    borderRadius: borderRadius.full,
  },
  requiredBadgeText: {
    fontSize: fontSizes.xxs,
    fontWeight: fontWeights.medium,
    color: colors.text.secondary,
  },
  value: {
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
    marginTop: spacing.xxs,
  },
  valueHidden: {
    color: colors.text.disabled,
  },
  valueSensitive: {
    color: colors.text.primary,
  },
  sensitiveWarning: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xxs,
    marginTop: spacing.xxs,
  },
  sensitiveHint: {
    fontSize: fontSizes.xs,
    fontWeight: fontWeights.normal,
    color: colors.semantic.warning,
  },
});

export default FieldToggleRow;
