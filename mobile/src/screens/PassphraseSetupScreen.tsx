/**
 * SSI Healthcare Mobile - Passphrase Setup Screen
 *
 * Generates a recovery key on-device, wraps it under a chosen passphrase,
 * and stores the envelope in the ministry keystore vault under an E.164
 * phone handle. See __docs__/backend/AUTH-AND-KEYSTORE-API.md §2/§4.
 */
import React, { useCallback, useState } from 'react';
import { showAlert } from '../components/AppAlertHost';
import { View, Text, StyleSheet, TextInput, ScrollView, Alert } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import {
  ed25519PublicKeyToMultibase,
  generateRecoveryKeySeed,
  recoveryKeyPublicKey,
} from '@ssi-healthcare/shared';
import { useNavigation } from '@react-navigation/native';

import { useAuth } from '../contexts';

import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';
import { Button, Card, SectionHeader } from '../components/common';
import { recoveryKeyRelease } from '../services/recoveryKeyRelease';
import { loadOrCreateDeviceSeed } from '../services/deviceSigner';
import { apiService } from '../services/api';
import { secureStorage, STORAGE_KEYS } from '../services/secureStorage';

const E164_PATTERN = /^\+[1-9]\d{7,14}$/;
const MIN_PASSPHRASE_LENGTH = 10;

interface Props {
  /**
   * Supplied only on the enrolment path, where this screen is the gate between
   * registering and reaching the wallet. Its presence is what distinguishes the
   * two callers: with it the screen hands control forward, without it it is a
   * settings page and returns whence it came.
   */
  onComplete?: () => void;
}

export default function PassphraseSetupScreen({ onComplete }: Props) {
  // No navigator header on this screen, so nothing else supplies the
  // status-bar gap and the title was drawing underneath the clock.
  const insets = useSafeAreaInsets();
  const navigation = useNavigation();
  const { user, refreshUser } = useAuth();
  const userId = user?.id ?? '';
  const isEnrolment = typeof onComplete === 'function';
  const [handle, setHandle] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(async () => {
    setError(null);

    if (!E164_PATTERN.test(handle.trim())) {
      setError('Enter your phone number in international format, e.g. +8801XXXXXXXXX.');
      return;
    }
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
      setError(`Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
      return;
    }
    if (passphrase !== confirmPassphrase) {
      setError('Passphrases do not match.');
      return;
    }

    setSubmitting(true);
    try {
      const normalisedHandle = handle.trim();

      // The overwrite guard that used to live here is gone, and deliberately.
      // It existed when envelopes were filed by handle in one shared table, so a
      // second run could clobber another record. The keystore locker namespaces
      // every object under the subject's own DID, and this DID is minted a few
      // lines below, so there is nothing of anyone else's here to overwrite.

      // Reuse the seed this handset already holds. A retry that minted a fresh
      // one would store a key absent from the DID document, because
      // `setupWallet` does not retrofit `#key-1` on an account that already has
      // a DID — see `loadOrCreateDeviceSeed`.
      const { seed } = await loadOrCreateDeviceSeed(generateRecoveryKeySeed);

      // MINT THE DID WITH THIS KEY, BEFORE THE ENVELOPE IS STORED.
      //
      // The seed's public half becomes the patient DID's `#key-1`, so the
      // holder ends up with a key that appears in their own DID document and
      // can sign a login challenge. Doing it the other way round — provisioning
      // the wallet first, as registration used to — mints an agent-generated
      // key and leaves the device unable to authenticate, which is why the
      // email path stayed load-bearing. See __docs__/REMOVING-EMAIL-FROM-AUTH.md.
      //
      // Idempotent: an account that already has a DID gets it back unchanged
      // and the key is NOT retrofitted. That is precisely why the seed above is
      // REUSED rather than regenerated — a fresh seed here would leave the
      // handset holding a key this document does not name.

      const publicKeyMultibase = ed25519PublicKeyToMultibase(recoveryKeyPublicKey(seed));
      const wallet = await apiService.setupWallet('CLOUD', publicKeyMultibase);

      // The cached user was stored at registration, before the DID existed, so
      // without this the wallet opens reporting "No DID yet" for an account that
      // has one. Refreshing here rather than on Home keeps the stale value from
      // ever being rendered.
      await refreshUser();

      await recoveryKeyRelease.provision(wallet.did, normalisedHandle, seed, passphrase);
      // Written only after the envelope is stored. Recording the handle first
      // would leave the app believing recovery exists when it does not.
      // Stored WITH the account it belongs to. A bare handle was inherited by
      // the next account signed in on this handset, which then skipped the
      // enrolment gate entirely — clearing it in `logout()` was not enough,
      // because the session-expiry path dispatches LOGOUT directly and never
      // calls it. Comparing the owner makes any mismatch re-gate, whatever
      // route the previous session ended by.
      await secureStorage.set(
        STORAGE_KEYS.RECOVERY_HANDLE,
        // The DID is kept alongside the handle so signing back in on THIS
        // handset needs only the passphrase. A new device has neither, and goes
        // through the restore flow instead.
        JSON.stringify({ userId, handle: normalisedHandle, did: wallet.did }),
      );
      showAlert(
        'Recovery set up',
        'If you ever sign in on a new device, you will need this phone number and passphrase to restore your wallet. Nobody else can recover it for you — write the passphrase down somewhere safe.',
        [{ text: 'Done', onPress: () => (isEnrolment ? onComplete!() : navigation.goBack()) }],
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  }, [handle, passphrase, confirmPassphrase, navigation, isEnrolment, onComplete, userId, refreshUser]);

  return (
    <ScrollView style={styles.container} contentContainerStyle={[styles.content, { paddingTop: spacing.lg }]}>
      <SectionHeader
        title={isEnrolment ? 'One last step: account recovery' : 'Set up account recovery'}
      />
      <Text style={styles.helperText}>
        {isEnrolment
          ? 'Before you can use your wallet, set up the only way to get it back. If you lose this device, this phone number and passphrase are what restore it. There is no email or password reset.'
          : 'This is the ONLY way to restore your wallet on a new device. There is no email or password reset. If you lose this passphrase and this device, recovery falls back to your guardians.'}
      </Text>

      <Card style={styles.card}>
        <Text style={styles.label}>Phone number</Text>
        <TextInput
          style={styles.input}
          value={handle}
          onChangeText={setHandle}
          placeholder="+8801XXXXXXXXX"
          keyboardType="phone-pad"
          autoCapitalize="none"
          accessibilityLabel="Phone number for account recovery"
        />

        <Text style={styles.label}>Choose a passphrase</Text>
        <TextInput
          style={styles.input}
          value={passphrase}
          onChangeText={setPassphrase}
          placeholder="At least 10 characters"
          secureTextEntry
          autoCapitalize="none"
          accessibilityLabel="Recovery passphrase"
        />

        <Text style={styles.label}>Confirm passphrase</Text>
        <TextInput
          style={styles.input}
          value={confirmPassphrase}
          onChangeText={setConfirmPassphrase}
          placeholder="Re-enter your passphrase"
          secureTextEntry
          autoCapitalize="none"
          accessibilityLabel="Confirm recovery passphrase"
        />

        {error && <Text style={styles.errorText}>{error}</Text>}

        <Button
          label={submitting ? 'Setting up…' : 'Set up recovery'}
          onPress={handleSubmit}
          loading={submitting}
          disabled={submitting}
          fullWidth
          style={styles.submitButton}
        />
      </Card>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.background.primary },
  content: { padding: spacing.md, paddingBottom: spacing.xxl },
  helperText: { fontSize: fontSizes.sm, color: colors.text.secondary, marginBottom: spacing.md },
  card: { padding: spacing.md },
  label: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
    marginTop: spacing.sm,
    marginBottom: spacing.xs,
  },
  input: {
    // Filled rather than outlined, and taller. A 1px hairline on white gives
    // no sense of where the tap target is, and the old padding made a 36px
    // field on a screen where every entry is typed.
    backgroundColor: colors.background.primary,
    borderWidth: 1,
    borderColor: colors.border.subtle,
    borderRadius: borderRadius.md,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.md,
    minHeight: 52,
    fontSize: fontSizes.md,
    color: colors.text.primary,
  },
  errorText: { color: colors.semantic.error, fontSize: fontSizes.sm, marginTop: spacing.sm },
  submitButton: { marginTop: spacing.md },
});
