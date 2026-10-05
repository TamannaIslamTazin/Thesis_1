/**
 * SSI Healthcare Mobile - Credential Folder Card Component
 *
 * Displays a credential category as a folder icon.
 */

import React, { useCallback } from 'react';
import { View, Text, StyleSheet, Pressable, ViewStyle } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../../theme';
import type { CredentialFolder } from '../../types';

interface FolderCardProps {
  folder: CredentialFolder;
  onPress: (folder: CredentialFolder) => void;
  style?: ViewStyle;
}

export const FolderCard = React.memo(function FolderCard({
  folder,
  onPress,
  style,
}: FolderCardProps) {
  const handlePress = useCallback(() => {
    onPress(folder);
  }, [folder, onPress]);

  return (
    <Pressable
      style={({ pressed }) => [
        styles.container,
        pressed && styles.pressed,
        style,
      ]}
      onPress={handlePress}
      accessibilityRole="button"
      accessibilityLabel={`${folder.name} folder, ${folder.count} credentials`}
      accessibilityHint="Double tap to view credentials in this folder"
    >
      <View style={[styles.iconContainer, { backgroundColor: `${folder.color}20` }]}>
        <Ionicons
          name={folder.icon as keyof typeof Ionicons.glyphMap}
          size={32}
          color={folder.color}
        />
      </View>
      <Text style={styles.name} numberOfLines={1}>
        {folder.name}
      </Text>
      <View style={styles.countContainer}>
        <Text style={styles.count}>{folder.count}</Text>
        <Text style={styles.countLabel}>
          {folder.count === 1 ? 'credential' : 'credentials'}
        </Text>
      </View>
    </Pressable>
  );
});

const styles = StyleSheet.create({
  container: {
    backgroundColor: colors.surface.card,
    borderRadius: borderRadius.card,
    padding: spacing.cardPadding,
    borderWidth: 1,
    borderColor: colors.border.default,
    alignItems: 'center',
    minWidth: 140,
    maxWidth: 180,
  },
  pressed: {
    opacity: 0.8,
    transform: [{ scale: 0.98 }],
  },
  iconContainer: {
    width: 64,
    height: 64,
    borderRadius: borderRadius.lg,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: spacing.md,
  },
  name: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
    textAlign: 'center',
    marginBottom: spacing.xs,
  },
  countContainer: {
    flexDirection: 'row',
    alignItems: 'baseline',
    gap: spacing.xs,
  },
  count: {
    fontSize: fontSizes.xl,
    fontWeight: fontWeights.bold,
    color: colors.brand.primary,
  },
  countLabel: {
    fontSize: fontSizes.xs,
    fontWeight: fontWeights.normal,
    color: colors.text.tertiary,
  },
});

export default FolderCard;
