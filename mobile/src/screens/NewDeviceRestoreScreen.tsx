/**
 * SSI Healthcare Mobile - New-Device Restore Screen
 *
 * IDENTITY-AND-ISSUANCE-SPEC.md §6: four separate steps — handle, passphrase,
 * a confirmation screen, then the data fetch — not one combined form.
 * Steps 1-3 are wired against the live keystore vault. Step 4 stops at a
 * 'blocked' state; see __docs__/frontend/WALLET-CUSTODY-NOTE.md §3.
 */
import React, { useCallback, useState } from 'react';
import { View, Text, StyleSheet, TextInput, ScrollView } from 'react-native';

import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';
import { Button, Card, SectionHeader } from '../components/common';
import { recoverFromHandle, RecoveryKeyReleaseError, type SnapshotBinding } from '../services/recoveryKeyRelease';
import { storeDeviceSeed } from '../services/deviceSigner';
import { restoreWalletFromLocker, WalletRestoreError } from '../db/restore';

type Step =
  | { name: 'handle' }
  | { name: 'passphrase'; handle: string }
  | { name: 'confirm'; handle: string; seed: Uint8Array; did: string; backupBinding: SnapshotBinding | null }
  | { name: 'restoring'; handle: string }
  | { name: 'restored'; handle: string; bytes: number }
  | { name: 'blocked'; handle: string };

const E164_PATTERN = /^\+[1-9]\d{7,14}$/;

export default function NewDeviceRestoreScreen() {
  const [step, setStep] = useState<Step>({ name: 'handle' });
  const [handleInput, setHandleInput] = useState('');
  const [passphraseInput, setPassphraseInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleIdentify = useCallback(() => {
    setError(null);
    if (!E164_PATTERN.test(handleInput.trim())) {
      setError('Enter your phone number in international format, e.g. +8801XXXXXXXXX.');
      return;
    }
    setStep({ name: 'passphrase', handle: handleInput.trim() });
  }, [handleInput]);

  const handleVerifyPassphrase = useCallback(async () => {
    if (step.name !== 'passphrase') return;
    setError(null);
    setBusy(true);
    try {
      // Step 1: phone number and passphrase, nothing else. The keystore returns
      // the sealed envelope and the DID it belongs to, because this handset
      // knows neither. See steno #402 for the flow this implements.
      const { seed, did, backupBinding } = await recoverFromHandle(step.handle, passphraseInput);

      // The key is now on this device and can sign for the identity. What it
      // must NOT do is go and fetch the user's health data as a side effect —
      // that is a separate decision, and step 'confirm' is where it is asked.
      await storeDeviceSeed(seed);
      setStep({ name: 'confirm', handle: step.handle, seed, did, backupBinding });
    } catch (err) {
      setError(
        err instanceof RecoveryKeyReleaseError
          ? err.message
          : 'That passphrase did not unlock a recovery key for this number.',
      );
    } finally {
      setBusy(false);
    }
  }, [step, passphraseInput]);

  const handleConfirmRestore = useCallback(async () => {
    if (step.name !== 'confirm') return;
    setError(null);
    setBusy(true);
    try {
      // A wallet that confirmed its identity but never recorded a backup
      // binding has nothing we can open. Saying so is the honest answer; it is
      // not a failure of the restore, it is an absence of anything to restore.
      if (!step.backupBinding) {
        throw new WalletRestoreError(
          'This account has no wallet backup recorded yet, so there is nothing to fetch.',
        );
      }
      // Step 4: fetch and decrypt the wallet data for the DID the envelope
      // named — `recoverFromHandle` returned it, because a handset that has
      // never enrolled cannot know its own DID.
      const result = await restoreWalletFromLocker(step.did, step.backupBinding);
      setStep({ name: 'restored', handle: step.handle, bytes: result.plaintextBytes });
    } catch (err) {
      setError(err instanceof WalletRestoreError ? err.message : 'The restore could not complete.');
      setStep({ name: 'blocked', handle: step.handle });
    } finally {
      setBusy(false);
    }
  }, [step]);

  if (step.name === 'handle') {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <SectionHeader title="Restore on this device" />
        <Text style={styles.helperText}>Step 1 of 4 — identify your account.</Text>
        <Card style={styles.card}>
          <Text style={styles.label}>Phone number</Text>
          <TextInput
            style={styles.input}
            value={handleInput}
            onChangeText={setHandleInput}
            placeholder="+8801XXXXXXXXX"
            keyboardType="phone-pad"
            autoCapitalize="none"
            accessibilityLabel="Phone number"
          />
          {error && <Text style={styles.errorText}>{error}</Text>}
          <Button label="Continue" onPress={handleIdentify} fullWidth style={styles.button} />
        </Card>
      </ScrollView>
    );
  }

  if (step.name === 'passphrase') {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <SectionHeader title="Restore on this device" />
        <Text style={styles.helperText}>
          Step 2 of 4 — this is the only factor available on a device that has never enrolled.
        </Text>
        <Card style={styles.card}>
          <Text style={styles.label}>Passphrase</Text>
          <TextInput
            style={styles.input}
            value={passphraseInput}
            onChangeText={setPassphraseInput}
            placeholder="Your recovery passphrase"
            secureTextEntry
            autoCapitalize="none"
            accessibilityLabel="Recovery passphrase"
          />
          {error && <Text style={styles.errorText}>{error}</Text>}
          <Button
            label={busy ? 'Verifying…' : 'Verify'}
            onPress={handleVerifyPassphrase}
            loading={busy}
            disabled={busy}
            fullWidth
            style={styles.button}
          />
        </Card>
      </ScrollView>
    );
  }

  if (step.name === 'confirm') {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <SectionHeader title="Restore on this device" />
        <Text style={styles.helperText}>
          Step 3 of 4 — your passphrase is correct. Retrieving your data is a separate action
          from proving who you are; nothing has been fetched yet.
        </Text>
        <Card style={styles.card} variant="success">
          <Text style={styles.label}>Ready to restore</Text>
          <Text style={styles.helperText}>
            Continuing will fetch and decrypt your wallet data on this device.
          </Text>
          {error && <Text style={styles.errorText}>{error}</Text>}
          <Button
            label={busy ? 'Fetching…' : 'Fetch and restore my data'}
            onPress={handleConfirmRestore}
            loading={busy}
            disabled={busy}
            fullWidth
            style={styles.button}
          />
        </Card>
      </ScrollView>
    );
  }

  if (step.name === 'restored') {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <SectionHeader title="Restore on this device" />
        <Card style={styles.card} variant="success">
          <Text style={styles.label}>Data restored</Text>
          <Text style={styles.helperText}>
            Your wallet data is on this device again. It was decrypted here; the locker never
            held the key.
          </Text>
        </Card>
      </ScrollView>
    );
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <SectionHeader title="Restore on this device" />
      <Card style={styles.card} variant="warning">
        <Text style={styles.label}>Restore could not complete</Text>
        <Text style={styles.helperText}>
          {error ??
            'Your phone number and passphrase are correct, and your key is on this device. Fetching ' +
              'your wallet data did not succeed.'}
        </Text>
      </Card>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.background.primary },
  content: { padding: spacing.md, paddingBottom: spacing.xxl },
  helperText: { fontSize: fontSizes.sm, color: colors.text.secondary, marginBottom: spacing.md },
  card: { padding: spacing.md },
  label: { fontSize: fontSizes.sm, fontWeight: fontWeights.semibold, color: colors.text.primary, marginBottom: spacing.xs },
  input: {
    borderWidth: 1,
    borderColor: colors.border.default,
    borderRadius: borderRadius.sm,
    padding: spacing.sm,
    fontSize: fontSizes.md,
    color: colors.text.primary,
  },
  errorText: { color: colors.semantic.error, fontSize: fontSizes.sm, marginTop: spacing.sm },
  button: { marginTop: spacing.md },
});
