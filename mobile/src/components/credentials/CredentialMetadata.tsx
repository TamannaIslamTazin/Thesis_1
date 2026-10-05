/**
 * SSI Healthcare Mobile - Credential Metadata Component
 *
 * Displays credential metadata in a table format.
 */

import React from 'react';
import { View, Text, StyleSheet, ViewStyle } from 'react-native';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../../theme';

interface MetadataRow {
  label: string;
  value: string;
}

interface CredentialMetadataProps {
  rows: MetadataRow[];
  title?: string;
  style?: ViewStyle;
}

export function CredentialMetadata({
  rows,
  title = 'Credential Info',
  style,
}: CredentialMetadataProps) {
  return (
    <View style={[styles.container, style]}>
      <Text style={styles.title}>{title}</Text>
      {rows.map((row, index) => (
        <View
          key={row.label}
          style={[
            styles.row,
            index === rows.length - 1 && styles.lastRow,
          ]}
        >
          <Text style={styles.label}>{row.label}</Text>
          <Text style={styles.value} numberOfLines={1}>
            {row.value}
          </Text>
        </View>
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    backgroundColor: colors.surface.card,
    borderRadius: borderRadius.card,
    padding: spacing.cardPadding,
    borderWidth: 1,
    borderColor: colors.border.default,
  },
  title: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.bold,
    color: colors.text.primary,
    marginBottom: spacing.md,
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: colors.border.subtle,
  },
  lastRow: {
    borderBottomWidth: 0,
  },
  label: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.normal,
    color: colors.text.secondary,
  },
  value: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.medium,
    color: colors.text.primary,
    maxWidth: '60%',
    textAlign: 'right',
  },
});

export default CredentialMetadata;
