/**
 * In-app replacement for `Alert.alert`.
 *
 * ===========================================================================
 * WHY NOT THE PLATFORM DIALOG
 * ===========================================================================
 * A native alert is drawn by Android, not by this app: it ignores the theme,
 * has square corners and a system accent that match nothing else on screen,
 * and its buttons are laid out by the platform. Seven of them were the only
 * places in the wallet where the interface visibly changed identity, and two
 * carried consequential choices, withdrawing a submission and confirming a
 * recovery passphrase, where looking like a system message rather than part of
 * the app is exactly wrong.
 *
 * THE CALL SHAPE IS DELIBERATELY IDENTICAL to Alert.alert, so replacing a call
 * site is one identifier and nothing else. A rewrite of seven dialogs into
 * bespoke sheets would have been a larger diff with more to get wrong, on the
 * last day.
 *
 *   showAlert('Title', 'Message', [{ text: 'Cancel', style: 'cancel' },
 *                                  { text: 'Delete', style: 'destructive', onPress }])
 *
 * With no buttons it renders a single dismissing action, which is what
 * Alert.alert does.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';

import { BottomSheet } from './sheets/BottomSheet';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';

export interface AlertButton {
  text: string;
  onPress?: () => void;
  style?: 'default' | 'cancel' | 'destructive';
}

interface AlertRequest {
  title: string;
  message?: string;
  buttons: AlertButton[];
}

// A module-level slot rather than context: call sites are ordinary functions
// deep inside handlers, and threading a hook through all of them would change
// far more than the dialog.
let emit: ((request: AlertRequest) => void) | null = null;

export function showAlert(title: string, message?: string, buttons?: AlertButton[]): void {
  const list = buttons && buttons.length > 0 ? buttons : [{ text: 'OK' }];
  if (emit) {
    emit({ title, message, buttons: list });
  } else if (__DEV__) {
    // Never silently swallow: a dialog that does not appear is a decision the
    // user was never offered.
    // eslint-disable-next-line no-console
    console.warn('[AppAlertHost] not mounted; alert dropped:', title, message);
  }
}

export function AppAlertHost(): React.ReactElement {
  const [request, setRequest] = useState<AlertRequest | null>(null);

  useEffect(() => {
    emit = (next) => setRequest(next);
    return () => {
      emit = null;
    };
  }, []);

  const dismiss = useCallback(() => setRequest(null), []);

  const press = useCallback(
    (button: AlertButton) => {
      // Close first, then act. A handler that navigates while the sheet is
      // still mounted leaves it over the destination.
      setRequest(null);
      button.onPress?.();
    },
    [],
  );

  return (
    <BottomSheet
      visible={request !== null}
      onClose={dismiss}
      snapPoint={0.4}
      scrollable={false}
    >
      {request && (
        <View style={styles.body}>
          <Text style={styles.title}>{request.title}</Text>
          {request.message ? <Text style={styles.message}>{request.message}</Text> : null}
          <View style={styles.actions}>
            {request.buttons.map((button) => (
              <TouchableOpacity
                key={button.text}
                style={[
                  styles.button,
                  button.style === 'destructive' && styles.buttonDestructive,
                  button.style === 'cancel' && styles.buttonCancel,
                ]}
                onPress={() => press(button)}
                activeOpacity={0.7}
                accessibilityRole="button"
              >
                <Text
                  style={[
                    styles.buttonText,
                    button.style === 'destructive' && styles.buttonTextDestructive,
                    button.style === 'cancel' && styles.buttonTextCancel,
                  ]}
                >
                  {button.text}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        </View>
      )}
    </BottomSheet>
  );
}

const styles = StyleSheet.create({
  body: { paddingBottom: spacing.sm },
  title: {
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  message: {
    marginTop: spacing.sm,
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
    lineHeight: fontSizes.sm * 1.5,
  },
  actions: { marginTop: spacing.lg, gap: spacing.sm },
  button: {
    minHeight: 48,
    borderRadius: borderRadius.button,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: colors.brand.primary,
  },
  buttonCancel: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: colors.border.default,
  },
  buttonDestructive: { backgroundColor: colors.semantic.error },
  buttonText: {
    fontSize: fontSizes.md,
    fontWeight: fontWeights.semibold,
    color: colors.base.white,
  },
  buttonTextCancel: { color: colors.text.primary },
  buttonTextDestructive: { color: colors.base.white },
});
