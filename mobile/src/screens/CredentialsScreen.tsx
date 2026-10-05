/**
 * SSI Healthcare Mobile - Credentials Screen
 *
 * Skeuomorphic folder view for healthcare credentials.
 * Credentials are organized by category (color-coded folders).
 *
 * REFACTORED to use:
 * - Zustand store for state management
 * - Reusable FolderCard component
 * - Design tokens from theme system
 * - Proper TypeScript types
 * - Accessibility attributes
 */

import React, { useEffect, useCallback } from 'react';
import { View, Text, FlatList, StyleSheet, RefreshControl } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { CredentialStackParamList, CredentialFolder, CredentialCategory, Credential } from '../types';
import { useCredentialStore } from '../store';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';
import { LoadingSpinner, ErrorState, EmptyState } from '../components/common';
import { CATEGORY_CONFIG, FolderCard, PendingOffers } from '../components/credentials';

// -- Type Definitions --

type Props = NativeStackScreenProps<CredentialStackParamList, 'CredentialsList'>;

// -- Screen Component --

export default function CredentialsScreen({ navigation }: Props) {
  const {
    credentials,
    folders,
    isLoading,
    isRefreshing,
    error,
    fetchCredentials,
    refreshCredentials,
    clearError,
  } = useCredentialStore();

  // Fetch credentials on mount
  useEffect(() => {
    fetchCredentials();
  }, [fetchCredentials]);

  // Open the folder. NEVER straight to its first credential: with more than
  // one credential in a category that made the others unreachable, and even
  // with exactly one it hid the fact that the folder had been opened at all.
  const handleFolderPress = useCallback(
    (folder: CredentialFolder) => {
      navigation.navigate('CredentialsByCategory', { category: folder.category });
    },
    [navigation]
  );

  // Handle retry
  const handleRetry = useCallback(() => {
    clearError();
    fetchCredentials();
  }, [clearError, fetchCredentials]);

  // Transform store folders to include display config
  const displayFolders = folders.map((folder: CredentialFolder) => {
    const config = CATEGORY_CONFIG[folder.category as CredentialCategory] || CATEGORY_CONFIG.other;
    return {
      ...folder,
      name: config.label,
      icon: config.iconName,
      color: config.border,
    };
  });

  // Render folder item
  const renderFolder = useCallback(
    ({ item }: { item: CredentialFolder }) => (
      <FolderCard
        folder={item}
        onPress={handleFolderPress}
        style={styles.folderCard}
      />
    ),
    [handleFolderPress]
  );

  // Key extractor
  const keyExtractor = useCallback((item: CredentialFolder) => item.id, []);

  // -- Loading State --
  if (isLoading && folders.length === 0) {
    return <LoadingSpinner fullScreen message="Loading credentials..." />;
  }

  // -- Error State --
  if (error && folders.length === 0) {
    return (
      <ErrorState
        title="Failed to Load"
        message={error}
        onRetry={handleRetry}
      />
    );
  }

  // -- Empty State --
  // PendingOffers renders ABOVE this, never inside it. A holder with no
  // credentials yet is precisely the holder most likely to have one waiting —
  // the first credential anyone receives arrives as an offer — and the early
  // return that used to be here hid it behind "No Credentials Yet".
  if (folders.length === 0) {
    return (
      <View style={styles.container}>
        <PendingOffers onAccepted={refreshCredentials} />
        <EmptyState
          title="No Credentials Yet"
          message="Credentials appear here once an authority issues one to you and you accept it."
          icon="folder-open"
        />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <PendingOffers onAccepted={refreshCredentials} />

      {/* Header info */}
      <View
        style={styles.headerInfo}
        accessibilityRole="text"
      >
        <Ionicons
          name="information-circle-outline"
          size={16}
          color={colors.text.tertiary}
        />
        <Text style={styles.headerInfoText}>
          Credentials are organized by medical category
        </Text>
      </View>

      {/* Folder grid */}
      <FlatList
        data={displayFolders}
        renderItem={renderFolder}
        keyExtractor={keyExtractor}
        numColumns={2}
        columnWrapperStyle={styles.row}
        contentContainerStyle={styles.listContent}
        showsVerticalScrollIndicator={false}
        refreshControl={
          <RefreshControl
            refreshing={isRefreshing}
            onRefresh={refreshCredentials}
            tintColor={colors.brand.primary}
            colors={[colors.brand.primary]}
          />
        }
        accessibilityRole="list"
        accessibilityLabel="Credential folders"
      />
    </View>
  );
}

// -- Styles --

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background.primary,
  },
  headerInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: spacing.screenPadding,
    paddingVertical: spacing.md,
    gap: spacing.sm,
  },
  headerInfoText: {
    color: colors.text.tertiary,
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.normal,
  },
  listContent: {
    padding: spacing.md,
    gap: spacing.md,
  },
  row: {
    gap: spacing.md,
    justifyContent: 'space-between',
  },
  folderCard: {
    flex: 1,
    maxWidth: '48%',
  },
});
