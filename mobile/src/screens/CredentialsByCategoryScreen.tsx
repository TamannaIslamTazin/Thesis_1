/**
 * One folder's contents.
 *
 * The folder grid summarises; this screen is where a holder actually reaches a
 * credential. It exists because the folder press used to jump straight to the
 * FIRST credential in the category, which made every other one unreachable and
 * gave no account of what the folder held (steno #441 is the same class of
 * failure: a surface that cannot show what it is looking at).
 *
 * The route and its parameter type were already declared in `types/domain.ts`;
 * only the screen was missing.
 */
import React, { useCallback } from 'react';
import { View, FlatList, StyleSheet, RefreshControl } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { CredentialStackParamList, Credential } from '../types';
import { useCredentialStore } from '../store';
import { CredentialCard, CATEGORY_CONFIG } from '../components/credentials';
import { EmptyState, ScreenTitle } from '../components/common';
import { colors, spacing, fontSizes, fontWeights } from '../theme';

type Props = NativeStackScreenProps<CredentialStackParamList, 'CredentialsByCategory'>;

export default function CredentialsByCategoryScreen({ route, navigation }: Props) {
  const { category } = route.params;
  const credentials = useCredentialStore((state) => state.credentials);
  const isRefreshing = useCredentialStore((state) => state.isRefreshing);
  const refreshCredentials = useCredentialStore((state) => state.refreshCredentials);

  const config = CATEGORY_CONFIG[category];
  const items = credentials.filter((credential) => credential.category === category);

  const handleOpen = useCallback(
    (credential: Credential) => {
      navigation.navigate('CredentialDetail', { credentialId: credential.id });
    },
    [navigation],
  );

  return (
    <View style={styles.container}>
      <FlatList
        data={items}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <CredentialCard credential={item} onPress={handleOpen} style={styles.card} />
        )}
        ListHeaderComponent={
          <View style={styles.header}>
            <ScreenTitle>{config.label}</ScreenTitle>
          </View>
        }
        ListEmptyComponent={
          <EmptyState
            title={`Nothing in ${config.label}`}
            message="Pull down to refresh. Credentials appear here once an authority issues one to you and you accept it."
            icon={config.iconName}
          />
        }
        contentContainerStyle={styles.content}
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
        accessibilityLabel={`${config.label} credentials`}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background.primary,
  },
  header: {
    paddingTop: spacing.md,
  },
  content: {
    padding: spacing.screenPadding,
    gap: spacing.md,
  },
  card: {
    marginBottom: spacing.md,
  },
});
