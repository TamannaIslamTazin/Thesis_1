/**
 * Medicine balance: what is left on each prescription.
 *
 * WHY IT IS A SCREEN OF ITS OWN. A holder leaving a pharmacy has one question
 * the app could not answer: how much of the prescription is left to collect.
 * The numbers are recomputed from the holder's own dispense appends (see
 * utils/medicineBalances.ts) and the medicine names come from the holder's own
 * credentials, so the operator never sees clinical detail and the wallet never
 * stores a balance that could drift from the ledger's.
 *
 * OFFLINE. The last successful read stays on screen when a refresh fails, with
 * a banner saying the check did not complete. Emptying the list would tell the
 * holder they have no medicine when the truth is that we could not ask - the
 * rule the emergency screen already applies to a failed check.
 */
import React, { useCallback, useMemo, useState } from 'react';
import { RefreshControl, ScrollView, StyleSheet, Text, View } from 'react-native';
import { Ionicons } from '@expo/vector-icons';

import { useCredentialStore } from '../store';
import { apiService } from '../services/api';
import { useLiveRefresh } from '../hooks/useLiveRefresh';
import {
  Card,
  EmptyState,
  LoadingSpinner,
  ScreenTitle,
} from '../components/common';
import { colors, spacing, fontSizes, fontWeights, borderRadius, lineHeightFor, lineHeights } from '../theme';
import {
  computeMedicineBalances,
  readHeldPrescription,
  type MedicineBalance,
  type RecordedDispense,
} from '../utils/medicineBalances';

function BalanceCard({ balance }: { balance: MedicineBalance }) {
  return (
    <Card variant="default" style={styles.balanceCard}>
      <Text style={styles.medicineName}>{balance.medicineName}</Text>

      <View style={styles.numbersRow}>
        <View style={styles.numberBlock}>
          <Text style={styles.number}>{balance.bought}</Text>
          <Text style={styles.numberLabel}>Bought</Text>
        </View>
        <View style={styles.numbersDivider} />
        <View style={styles.numberBlock}>
          <Text style={styles.number}>{balance.left === null ? '\u2014' : balance.left}</Text>
          <Text style={styles.numberLabel}>Left</Text>
        </View>
        {balance.authorised !== null && (
          <>
            <View style={styles.numbersDivider} />
            <View style={styles.numberBlock}>
              <Text style={styles.number}>{balance.authorised}</Text>
              <Text style={styles.numberLabel}>Prescribed</Text>
            </View>
          </>
        )}
      </View>

      {balance.left === null && (
        <Text style={styles.note}>The prescription does not state how many were authorised.</Text>
      )}

      {balance.pending > 0 && (
        <View style={styles.noteRow}>
          <Ionicons name="time-outline" size={14} color={colors.text.secondary} />
          <Text style={styles.note}>
            {balance.pending} not settled at the pharmacy yet
          </Text>
        </View>
      )}

      {balance.abandoned > 0 && (
        <View style={styles.noteRow}>
          <Ionicons name="close-circle-outline" size={14} color={colors.text.secondary} />
          <Text style={styles.note}>{balance.abandoned} recorded but not collected</Text>
        </View>
      )}
    </Card>
  );
}

export default function MedicineBalanceScreen() {
  const credentials = useCredentialStore((state) => state.credentials);
  const fetchCredentials = useCredentialStore((state) => state.fetchCredentials);
  const [dispenses, setDispenses] = useState<RecordedDispense[] | null>(null);
  const [lastCheckFailed, setLastCheckFailed] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await apiService.getMyDispenses();
      setDispenses(res.dispenses);
      setLastCheckFailed(false);
    } catch {
      // Keep whatever is on screen. A failed read is not an answer of "none".
      setLastCheckFailed(true);
    }
  }, []);

  useLiveRefresh(
    useCallback(() => {
      void load();
      void fetchCredentials();
    }, [load, fetchCredentials]),
  );

  const balances = useMemo(() => {
    if (dispenses === null) return null;
    const held = credentials
      .map(readHeldPrescription)
      .filter((entry): entry is NonNullable<typeof entry> => entry !== null);
    return computeMedicineBalances(held, dispenses);
  }, [credentials, dispenses]);

  if (balances === null && !lastCheckFailed) {
    return <LoadingSpinner fullScreen message="Loading medicine balances..." />;
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={[styles.content, { paddingTop: spacing.screenPadding }]}
      refreshControl={
        <RefreshControl
          refreshing={false}
          onRefresh={() => void load()}
          tintColor={colors.brand.primary}
          colors={[colors.brand.primary]}
        />
      }
      accessibilityLabel="Medicine balance screen"
    >
      <ScreenTitle>Medicine balance</ScreenTitle>

      {lastCheckFailed && (
        <Card variant="default" style={styles.staleCard}>
          <View style={styles.staleRow}>
            <Ionicons name="cloud-offline-outline" size={20} color={colors.semantic.warning} />
            <Text style={styles.staleTitle}>Could not check just now</Text>
          </View>
          <Text style={styles.staleBody}>
            {balances && balances.length > 0
              ? 'Showing the last known balance. This is not confirmation that nothing has changed.'
              : 'This is not confirmation that you have no medicines.'}
          </Text>
        </Card>
      )}

      {balances === null || balances.length === 0 ? (
        <EmptyState
          title="No medicines yet"
          message="When a pharmacy dispenses a prescription, its balance appears here."
          icon="medkit-outline"
          style={styles.emptyState}
        />
      ) : (
        balances.map((balance) => <BalanceCard key={balance.key} balance={balance} />)
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background.primary,
  },
  content: {
    padding: spacing.screenPadding,
    paddingBottom: spacing.huge,
  },
  balanceCard: {
    marginBottom: spacing.md,
  },
  medicineName: {
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.bold,
    color: colors.text.primary,
  },
  numbersRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: spacing.md,
  },
  numberBlock: {
    flex: 1,
    alignItems: 'center',
  },
  numbersDivider: {
    width: 1,
    alignSelf: 'stretch',
    backgroundColor: colors.border.default,
  },
  number: {
    fontSize: fontSizes.xxl,
    fontWeight: fontWeights.bold,
    color: colors.text.primary,
  },
  numberLabel: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    marginTop: spacing.xxs,
  },
  noteRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
    marginTop: spacing.sm,
  },
  note: {
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
    marginTop: spacing.sm,
    lineHeight: lineHeightFor(fontSizes.sm, lineHeights.relaxed),
  },
  staleCard: {
    marginBottom: spacing.md,
    borderWidth: 1,
    borderColor: colors.semantic.warningBorder,
    backgroundColor: colors.semantic.warningLight,
  },
  staleRow: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm },
  staleTitle: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  staleBody: {
    marginTop: spacing.xs,
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
  },
  emptyState: {
    marginVertical: spacing.xl,
  },
});
