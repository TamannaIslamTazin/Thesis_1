/**
 * SSI Healthcare Mobile - Pending credential offers
 *
 * ===========================================================================
 * WHY THIS EXISTS
 * ===========================================================================
 * An authority approving a submission does NOT push a credential onto the
 * handset. It creates an offer, and the holder accepts it. That is the right
 * shape — receiving a credential into your own wallet is your act, not the
 * issuer's — but the wallet had no surface for it, so the offer was invisible.
 * The submissions screen said "Approved" and stopped there; the credential sat
 * PENDING forever, claimable only by an HTTP call made outside the app.
 *
 * Measured on 9 Sep 2026: a BMDC-approved ProfessionalLicenceCredential for a
 * doctor whose wallet showed 0 credentials and no indication anything was
 * waiting.
 *
 * ===========================================================================
 * THREE FAILSAFES, ALL LEARNED THE HARD WAY
 * ===========================================================================
 * 1. RE-CHECKS ON FOCUS, not only on mount. An offer created while the app is
 *    open must become visible without a restart — the same defect the
 *    break-glass alarm had (#419).
 * 2. A FAILED CHECK IS NOT AN ALL-CLEAR. If the fetch fails, this says so
 *    explicitly rather than rendering the same empty space as "nothing is
 *    waiting". Silence that means two different things is the recurring shape
 *    of every fail-open defect in this codebase.
 * 3. ACCEPTANCE IS ALWAYS AN EXPLICIT TAP. Nothing is claimed automatically,
 *    even though the offer is already addressed to this holder — the same
 *    principle as the restore flow's step 6 (#402): retrieval is its own
 *    consent, never a side effect of arriving somewhere.
 */
import React, { useCallback, useState } from 'react';
import { failureMessage } from '../../utils/userFacingError';
import { View, Text, StyleSheet, ActivityIndicator } from 'react-native';
import { useFocusEffect } from '@react-navigation/native';
import { Ionicons } from '@expo/vector-icons';

import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../../theme';
import { Button } from '../common';
import { apiService, type CredentialOfferSummary } from '../../services/api';

type OffersState =
  | { status: 'loading' }
  /** The check ran and answered. An empty list here genuinely means none. */
  | { status: 'ready'; offers: CredentialOfferSummary[] }
  /** The check did NOT answer. Never rendered as "no offers". */
  | { status: 'unavailable'; message: string };

/** "ProfessionalLicenceCredential" -> "Professional Licence". */
function readableType(credentialType: string): string {
  const withoutSuffix = credentialType.replace(/Credential$/, '');
  const spaced = withoutSuffix.replace(/([a-z])([A-Z])/g, '$1 $2').trim();
  return spaced.length > 0 ? spaced : credentialType;
}

export function PendingOffers({ onAccepted }: { onAccepted?: () => void }): React.ReactElement | null {
  const [state, setState] = useState<OffersState>({ status: 'loading' });
  const [claimingId, setClaimingId] = useState<string | null>(null);
  const [claimError, setClaimError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const offers = await apiService.listCredentialOffers();
      setState({ status: 'ready', offers: Array.isArray(offers) ? offers : [] });
    } catch (error) {
      setState({
        status: 'unavailable',
        message: failureMessage(error),
      });
    }
  }, []);

  useFocusEffect(
    useCallback(() => {
      void load();
    }, [load]),
  );

  const accept = useCallback(
    async (offer: CredentialOfferSummary) => {
      setClaimError(null);
      setClaimingId(offer.id);
      try {
        await apiService.acceptCredentialOffer(offer.id);
        await load();
        onAccepted?.();
      } catch (error) {
        // Named, not swallowed: a PIN-protected offer is refused here on
        // purpose and the holder needs to be told which path to use.
        setClaimError(failureMessage(error));
      } finally {
        setClaimingId(null);
      }
    },
    [load, onAccepted],
  );

  if (state.status === 'loading') return null;

  if (state.status === 'unavailable') {
    return (
      <View style={[styles.container, styles.unavailable]}>
        <Ionicons name="cloud-offline-outline" size={18} color={colors.semantic.warning} />
        <Text style={styles.unavailableText}>
          Could not check for credentials waiting for you — this is not confirmation that there are
          none. Pull down to try again.
        </Text>
      </View>
    );
  }

  if (state.offers.length === 0) return null;

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Ionicons name="gift-outline" size={18} color={colors.brand.primary} />
        <Text style={styles.headerText}>
          {state.offers.length === 1
            ? 'A credential is waiting for you'
            : `${state.offers.length} credentials are waiting for you`}
        </Text>
      </View>
      <Text style={styles.subtext}>
        An authority has approved and signed it. It is added to your wallet only when you accept.
      </Text>

      {claimError !== null && <Text style={styles.error}>{claimError}</Text>}

      {state.offers.map((offer) => (
        <View key={offer.id} style={styles.offerRow}>
          <View style={styles.offerText}>
            <Text style={styles.offerTitle}>{readableType(offer.credentialType)}</Text>
            <Text style={styles.offerIssuer} numberOfLines={1} ellipsizeMode="middle">
              from {offer.issuerDid}
            </Text>
          </View>
          {claimingId === offer.id ? (
            <ActivityIndicator color={colors.brand.primary} />
          ) : (
            <Button
              label="Add to wallet"
              size="small"
              onPress={() => {
                void accept(offer);
              }}
              disabled={claimingId !== null}
            />
          )}
        </View>
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    marginHorizontal: spacing.md,
    marginBottom: spacing.md,
    padding: spacing.md,
    backgroundColor: colors.background.secondary,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.brand.primary,
  },
  unavailable: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: spacing.sm,
    borderColor: colors.semantic.warning,
  },
  unavailableText: {
    flex: 1,
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
  },
  headerText: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  subtext: {
    marginTop: spacing.xs,
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
  },
  error: {
    marginTop: spacing.sm,
    fontSize: fontSizes.sm,
    color: colors.semantic.error,
  },
  offerRow: {
    marginTop: spacing.md,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: spacing.md,
  },
  offerText: {
    flex: 1,
  },
  offerTitle: {
    fontSize: fontSizes.base,
    fontWeight: fontWeights.medium,
    color: colors.text.primary,
  },
  offerIssuer: {
    marginTop: 2,
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
  },
});
