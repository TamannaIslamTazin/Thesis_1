/**
 * SSI Healthcare Mobile - Submission Status Screen
 *
 * The holder's own issuance requests and their outcomes, including a
 * rejection reason when one exists. Read-only except for withdrawing a
 * still-PENDING request.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { showAlert } from '../components/AppAlertHost';
import { failureMessage } from '../utils/userFacingError';
import { View, Text, FlatList, StyleSheet, RefreshControl, Alert } from 'react-native';
import { useRoute } from '@react-navigation/native';

import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';
import { Card, Badge, Button, LoadingSpinner, ErrorState, EmptyState } from '../components/common';
import { apiService, type IssuanceRequestSummary } from '../services/api';
import type { BadgeVariant } from '../components/common';

type ScreenState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; requests: IssuanceRequestSummary[] };

function statusBadge(status: IssuanceRequestSummary['status']): { label: string; variant: BadgeVariant } {
  switch (status) {
    case 'PENDING':
      return { label: 'Pending review', variant: 'warning' };
    case 'APPROVED':
      return { label: 'Approved', variant: 'success' };
    case 'REJECTED':
      return { label: 'Rejected', variant: 'error' };
    case 'WITHDRAWN':
      return { label: 'Withdrawn', variant: 'neutral' };
  }
}

export default function SubmissionStatusScreen() {
  const route = useRoute();
  const focusRequestId = (route.params as { focusRequestId?: string } | undefined)?.focusRequestId;

  const [state, setState] = useState<ScreenState>({ status: 'loading' });
  const [refreshing, setRefreshing] = useState(false);
  const [withdrawingId, setWithdrawingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const { requests } = await apiService.listIssuanceRequests();
      setState({ status: 'ready', requests });
    } catch (error) {
      setState({ status: 'error', message: failureMessage(error) });
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    await load();
    setRefreshing(false);
  }, [load]);

  const handleWithdraw = useCallback(
    (id: string) => {
      showAlert('Withdraw submission?', 'This cannot be undone. The authority will no longer review it.', [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Withdraw',
          style: 'destructive',
          onPress: async () => {
            setWithdrawingId(id);
            try {
              await apiService.withdrawIssuanceRequest(id);
              await load();
            } catch (error) {
              showAlert('Could not withdraw', failureMessage(error));
            } finally {
              setWithdrawingId(null);
            }
          },
        },
      ]);
    },
    [load],
  );

  if (state.status === 'loading') {
    return <LoadingSpinner fullScreen message="Loading your submissions…" />;
  }
  if (state.status === 'error') {
    return <ErrorState message={state.message} onRetry={load} />;
  }
  if (state.requests.length === 0) {
    return (
      <EmptyState
        icon="document-text-outline"
        title="No submissions yet"
        message="Documents you submit for verification will appear here."
      />
    );
  }

  return (
    <FlatList
      style={styles.container}
      contentContainerStyle={styles.content}
      data={state.requests}
      keyExtractor={(item) => item.id}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={handleRefresh} />}
      renderItem={({ item }) => {
        const badge = statusBadge(item.status);
        const isFocused = item.id === focusRequestId;
        return (
          <Card variant={isFocused ? 'success' : 'default'} style={styles.card}>
            <View style={styles.headerRow}>
              <Text style={styles.documentType}>{item.documentType}</Text>
              <Badge label={badge.label} variant={badge.variant} />
            </View>
            <Text style={styles.meta}>Submitted {new Date(item.createdAt).toLocaleDateString()}</Text>
            <Text style={styles.meta}>{item.documents.length} document(s)</Text>
            {item.status === 'REJECTED' && item.rejectionReason && (
              <View style={styles.reasonBox}>
                <Text style={styles.reasonLabel}>Reason</Text>
                <Text style={styles.reasonText}>{item.rejectionReason}</Text>
              </View>
            )}
            {item.status === 'PENDING' && (
              <Button
                label="Withdraw"
                variant="ghost"
                size="small"
                onPress={() => handleWithdraw(item.id)}
                loading={withdrawingId === item.id}
                disabled={withdrawingId !== null}
                style={styles.withdrawButton}
              />
            )}
          </Card>
        );
      }}
    />
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.background.primary },
  content: { padding: spacing.md, paddingBottom: spacing.xxl },
  card: { marginBottom: spacing.md },
  headerRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  documentType: { fontSize: fontSizes.md, fontWeight: fontWeights.semibold, color: colors.text.primary },
  meta: { fontSize: fontSizes.sm, color: colors.text.secondary, marginTop: spacing.xs },
  reasonBox: {
    marginTop: spacing.sm,
    padding: spacing.sm,
    backgroundColor: colors.semantic.errorLight,
    borderRadius: borderRadius.sm,
  },
  reasonLabel: { fontSize: fontSizes.xs, fontWeight: fontWeights.semibold, color: colors.semantic.error },
  reasonText: { fontSize: fontSizes.sm, color: colors.text.primary, marginTop: 2 },
  withdrawButton: { marginTop: spacing.sm, alignSelf: 'flex-start' },
});
