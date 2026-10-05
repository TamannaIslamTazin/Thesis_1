/**
 * SSI Healthcare Mobile — sign in and create an account.
 *
 * NO EMAIL, ANYWHERE. Identity is the patient DID, whose `#key-1` is a key this
 * handset generated at enrolment. Signing in means proving control of that key:
 * the passphrase opens the keystore envelope, the recovered seed signs a
 * server-issued challenge, and the seed is discarded. The previous screen sent a
 * code to an email address, which made a third-party IAM provider part of the
 * identity and put the operator in the loop. See
 * __docs__/REMOVING-EMAIL-FROM-AUTH.md.
 *
 * Two ways in, and the difference is what this handset already knows:
 *   - It holds a recovery record (handle + DID) -> ask only for the passphrase.
 *   - It holds nothing -> the restore flow, which asks for the phone number too.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TextInput,
  ScrollView,
  TouchableOpacity,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';
import { Button, Card } from '../components/common';
import { useAuth } from '../contexts';
import { secureStorage, STORAGE_KEYS } from '../services';

type Mode = 'signIn' | 'register';

interface RecoveryRecord {
  userId?: string;
  handle?: string;
  did?: string;
}

export default function AuthScreen() {
  const navigation = useNavigation();
  const insets = useSafeAreaInsets();
  const { register, passphraseLogin, biometricLogin, isBiometricAvailable } = useAuth();

  const [mode, setMode] = useState<Mode>('signIn');
  const [record, setRecord] = useState<RecoveryRecord | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // What this handset knows decides which way in it can offer.
  useEffect(() => {
    let cancelled = false;
    secureStorage
      .get(STORAGE_KEYS.RECOVERY_HANDLE)
      .then((stored) => {
        if (cancelled || !stored) return;
        try {
          const parsed = JSON.parse(stored) as RecoveryRecord;
          if (parsed.handle && parsed.did) setRecord(parsed);
        } catch {
          // A record we cannot read is one we cannot use. The restore flow
          // still works, so this is a downgrade rather than a failure.
        }
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSignIn = useCallback(async () => {
    if (!record?.handle || !record?.did) return;
    if (passphrase.length === 0) {
      setError('Enter your passphrase.');
      return;
    }
    setError(null);
    setBusy(true);
    try {
      await passphraseLogin(record.handle, passphrase);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
      setPassphrase('');
    }
  }, [record, passphrase, passphraseLogin]);

  const handleRegister = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      await register(name.trim() || undefined);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [name, register]);

  const handleBiometric = useCallback(async () => {
    setError(null);
    try {
      await biometricLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [biometricLogin]);

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
    >
      <ScrollView
        contentContainerStyle={[styles.content, { paddingTop: insets.top + spacing.xl }]}
        keyboardShouldPersistTaps="handled"
      >
        <View style={styles.badge}>
          <Ionicons name="shield-checkmark" size={44} color={colors.brand.primary} />
        </View>
        <Text style={styles.title}>SSI Healthcare</Text>

        {mode === 'signIn' ? (
          <>
            <Text style={styles.subtitle}>Welcome back</Text>
            <Text style={styles.hint}>
              {record
                ? 'Enter the passphrase you chose when you set up recovery.'
                : 'This device has no wallet yet. Create an account, or restore one you already have.'}
            </Text>

            {record && (
              <Card style={styles.card}>
                <Text style={styles.label}>Phone number</Text>
                <Text style={styles.readOnly}>{record.handle}</Text>

                <Text style={styles.label}>Passphrase</Text>
                <TextInput
                  style={styles.input}
                  value={passphrase}
                  onChangeText={setPassphrase}
                  placeholder="Your recovery passphrase"
                  placeholderTextColor={colors.text.tertiary}
                  secureTextEntry
                  autoCapitalize="none"
                  accessibilityLabel="Recovery passphrase"
                />

                {error && <Text style={styles.error}>{error}</Text>}

                <Button
                  label={busy ? 'Signing in…' : 'Sign in'}
                  onPress={handleSignIn}
                  loading={busy}
                  disabled={busy}
                  fullWidth
                  style={styles.action}
                />
              </Card>
            )}

            {!record && error && <Text style={styles.error}>{error}</Text>}

            {isBiometricAvailable && record && (
              <TouchableOpacity
                style={styles.secondary}
                onPress={handleBiometric}
                accessibilityRole="button"
                accessibilityLabel="Sign in with biometrics"
              >
                <Ionicons name="finger-print" size={22} color={colors.brand.primary} />
                <Text style={styles.secondaryText}>Sign in with biometrics</Text>
              </TouchableOpacity>
            )}
          </>
        ) : (
          <>
            <Text style={styles.subtitle}>Create your account</Text>
            <Text style={styles.hint}>
              No email and no password. Your identity is a key this phone creates and keeps.
            </Text>

            <Card style={styles.card}>
              <Text style={styles.label}>Your name (optional)</Text>
              <TextInput
                style={styles.input}
                value={name}
                onChangeText={setName}
                placeholder="How should we greet you?"
                placeholderTextColor={colors.text.tertiary}
                accessibilityLabel="Your name, optional"
              />

              {error && <Text style={styles.error}>{error}</Text>}

              <Button
                label={busy ? 'Creating…' : 'Create account'}
                onPress={handleRegister}
                loading={busy}
                disabled={busy}
                fullWidth
                style={styles.action}
              />
            </Card>
          </>
        )}

        <View style={styles.footer}>
          <Text style={styles.footerText}>
            {mode === 'signIn' ? "Don't have an account?" : 'Already have an account?'}
          </Text>
          <TouchableOpacity
            onPress={() => {
              setMode(mode === 'signIn' ? 'register' : 'signIn');
              setError(null);
            }}
            accessibilityRole="button"
            accessibilityLabel={mode === 'signIn' ? 'Create account' : 'Sign in'}
          >
            <Text style={styles.footerLink}>{mode === 'signIn' ? 'Create one' : 'Sign in'}</Text>
          </TouchableOpacity>
        </View>

        <TouchableOpacity
          style={styles.restore}
          onPress={() => (navigation as never as { navigate: (r: string) => void }).navigate('NewDeviceRestore')}
          accessibilityRole="button"
          accessibilityLabel="Restore your wallet on this new device"
        >
          <Text style={styles.restoreText}>Restoring on a new device?</Text>
        </TouchableOpacity>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.background.primary },
  content: { padding: spacing.lg, paddingBottom: spacing.xxl, alignItems: 'stretch' },
  badge: { alignSelf: 'center', marginBottom: spacing.md },
  title: {
    fontSize: fontSizes['4xl'],
    fontWeight: fontWeights.bold,
    color: colors.text.primary,
    textAlign: 'center',
  },
  subtitle: {
    fontSize: fontSizes.lg,
    color: colors.text.secondary,
    textAlign: 'center',
    marginTop: spacing.sm,
  },
  hint: {
    fontSize: fontSizes.sm,
    color: colors.text.tertiary,
    textAlign: 'center',
    marginTop: spacing.xs,
    marginBottom: spacing.lg,
  },
  card: { padding: spacing.md },
  label: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
    marginTop: spacing.sm,
    marginBottom: spacing.xs,
  },
  readOnly: {
    fontSize: fontSizes.md,
    color: colors.text.secondary,
    paddingVertical: spacing.sm,
  },
  input: {
    borderWidth: 1,
    borderColor: colors.border.default,
    borderRadius: borderRadius.sm,
    padding: spacing.sm,
    fontSize: fontSizes.md,
    color: colors.text.primary,
  },
  error: { color: colors.semantic.error, fontSize: fontSizes.sm, marginTop: spacing.sm },
  action: { marginTop: spacing.md },
  secondary: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.sm,
    marginTop: spacing.lg,
    paddingVertical: spacing.md,
    borderWidth: 1,
    borderColor: colors.border.default,
    borderRadius: borderRadius.card,
  },
  secondaryText: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  footer: {
    flexDirection: 'row',
    justifyContent: 'center',
    gap: spacing.xs,
    marginTop: spacing.xl,
  },
  footerText: { fontSize: fontSizes.sm, color: colors.text.secondary },
  footerLink: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
    color: colors.brand.primary,
  },
  restore: { marginTop: spacing.lg, alignItems: 'center' },
  restoreText: { fontSize: fontSizes.sm, color: colors.text.tertiary },
});
