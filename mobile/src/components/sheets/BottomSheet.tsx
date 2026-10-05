/**
 * SSI Healthcare Mobile - Bottom Sheet Component
 *
 * A reusable bottom sheet modal that slides up from the bottom.
 * Uses React Native's built-in Modal for reliability across platforms.
 *
 * Used for:
 * - Credential sharing confirmations
 * - Consent revocation
 * - Destructive action confirmations
 * - Information displays
 */

import React, { useCallback, useEffect, useRef } from 'react';
import {
  Modal,
  View,
  TouchableOpacity,
  Pressable,
  StyleSheet,
  Animated,
  Dimensions,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { colors } from '../../theme/colors';
import { spacing } from '../../theme/spacing';
import { borderRadius } from '../../theme/borderRadius';

const SCREEN_HEIGHT = Dimensions.get('window').height;

interface BottomSheetProps {
  /** Whether the sheet is visible */
  visible: boolean;
  /** Callback when sheet is dismissed */
  onClose: () => void;
  /** Sheet content */
  children: React.ReactNode;
  /** Whether tapping outside closes the sheet (default: true) */
  dismissOnBackdrop?: boolean;
  /** Whether the sheet can be dismissed (default: true) */
  dismissable?: boolean;
  /** Snap point as percentage of screen height (default: 0.5) */
  snapPoint?: number;
  /**
   * Scroll the content when it is taller than the sheet (default: true).
   *
   * The sheet caps itself at `snapPoint` of the screen and used to render its
   * children in a plain `View`, so anything past that height was CLIPPED AND
   * UNREACHABLE — no scroll, no indicator, no way to know something was there.
   * On a consent sheet that meant the holder could be shown three of nine
   * fields and the confirm button could sit off-screen entirely.
   *
   * Pass `false` only from a sheet that scrolls its own content; nesting two
   * vertical scroll views makes both behave unpredictably.
   */
  scrollable?: boolean;
  /** Test ID for testing */
  testID?: string;
}

export function BottomSheet({
  visible,
  onClose,
  children,
  dismissOnBackdrop = true,
  dismissable = true,
  snapPoint = 0.5,
  scrollable = true,
  testID,
}: BottomSheetProps) {
  const translateY = useRef(new Animated.Value(SCREEN_HEIGHT)).current;
  const backdropOpacity = useRef(new Animated.Value(0)).current;

  const animateIn = useCallback(() => {
    Animated.parallel([
      Animated.spring(translateY, {
        toValue: 0,
        useNativeDriver: true,
        tension: 65,
        friction: 11,
      }),
      Animated.timing(backdropOpacity, {
        toValue: 1,
        duration: 200,
        useNativeDriver: true,
      }),
    ]).start();
  }, [translateY, backdropOpacity]);

  const animateOut = useCallback(
    (callback?: () => void) => {
      Animated.parallel([
        Animated.timing(translateY, {
          toValue: SCREEN_HEIGHT,
          duration: 250,
          useNativeDriver: true,
        }),
        Animated.timing(backdropOpacity, {
          toValue: 0,
          duration: 200,
          useNativeDriver: true,
        }),
      ]).start(callback);
    },
    [translateY, backdropOpacity]
  );

  useEffect(() => {
    if (visible) {
      animateIn();
    }
  }, [visible, animateIn]);

  const handleClose = useCallback(() => {
    if (!dismissable) return;
    animateOut(() => onClose());
  }, [dismissable, animateOut, onClose]);

  const handleBackdropPress = useCallback(() => {
    if (dismissOnBackdrop && dismissable) {
      handleClose();
    }
  }, [dismissOnBackdrop, dismissable, handleClose]);

  // THE ACTION BAR MUST NOT SIT UNDER THE GESTURE BAR.
  //
  // `statusBarTranslucent` makes this Modal span the FULL display, including
  // the system bars, while `SCREEN_HEIGHT` comes from the window. On a device
  // with gesture navigation the sheet therefore ends beneath the gesture area,
  // and the confirm row lands in it.
  //
  // Measured 9 Sep 2026 on a Redmi (1080x2400): the disclosure sheet's
  // "Share 3 items" button occupied y=2388..2400 — TWELVE pixels, at the very
  // edge — and a tap aimed at it was consumed as a back gesture instead. The
  // holder could read the whole consent decision and could not act on it. That
  // is the worst place for this bug to land: the one screen where a mis-tap
  // should cost nothing is the screen whose mis-tap silently navigated away.
  const insets = useSafeAreaInsets();
  const bottomInset = Math.max(insets.bottom, spacing.md);

  const sheetHeight = SCREEN_HEIGHT * snapPoint;

  return (
    <Modal
      visible={visible}
      transparent
      animationType="none"
      onRequestClose={handleClose}
      statusBarTranslucent
      testID={testID}
    >
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        style={styles.container}
      >
        {/* Backdrop */}
        <Animated.View
          style={[
            styles.backdrop,
            { opacity: backdropOpacity },
          ]}
        >
          <Pressable style={styles.backdropPressable} onPress={handleBackdropPress} />
        </Animated.View>

        {/* Sheet Content */}
        <Animated.View
          style={[
            styles.sheet,
            {
              // Room for the content PLUS the inset, so lifting the sheet clear
              // of the gesture bar does not cost the last row of content.
              maxHeight: sheetHeight + bottomInset,
              paddingBottom: bottomInset,
              transform: [{ translateY }],
            },
          ]}
        >
          {/* Handle */}
          <View style={styles.handleContainer}>
            <TouchableOpacity
              onPress={handleClose}
              disabled={!dismissable}
              activeOpacity={0.7}
              accessibilityRole="button"
              accessibilityLabel="Close sheet"
            >
              <View style={styles.handle} />
            </TouchableOpacity>
          </View>

          {/* Content */}
          {scrollable ? (
            <ScrollView
              style={styles.scrollArea}
              contentContainerStyle={styles.content}
              showsVerticalScrollIndicator
              // Let a tap on a control inside work on the first touch rather
              // than being eaten dismissing the keyboard.
              keyboardShouldPersistTaps="handled"
              bounces={false}
            >
              {children}
            </ScrollView>
          ) : (
            // flexShrink keeps a non-scrolling sheet's own scroll area inside
            // the sheet; without it the wrapper overflows maxHeight and the last
            // row is drawn under the nav bar (measured y=2360..2400 of 2400).
            <View style={[styles.content, styles.contentShrink]}>{children}</View>
          )}
        </Animated.View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'flex-end',
  },
  backdrop: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
  },
  backdropPressable: {
    flex: 1,
  },
  sheet: {
    backgroundColor: colors.surface.card,
    borderTopLeftRadius: borderRadius.xl,
    borderTopRightRadius: borderRadius.xl,
    paddingBottom: spacing.xl,
  },
  handleContainer: {
    alignItems: 'center',
    paddingVertical: spacing.sm,
  },
  handle: {
    width: 36,
    height: 4,
    backgroundColor: colors.surface.elevated,
    borderRadius: 2,
  },
  // The scroll view must be allowed to SHRINK to its content. Without
  // `flexShrink`, it takes the sheet's full capped height and the sheet renders
  // half-empty for short content; without a bounded parent it cannot scroll at
  // all. `flexGrow: 0` keeps a two-line sheet two lines tall.
  scrollArea: {
    flexGrow: 0,
    flexShrink: 1,
  },
  content: {
    paddingHorizontal: spacing.lg,
    // Room for the last control to clear the gesture bar; a confirm button
    // flush against the bottom edge is hard to hit and easy to miss.
    paddingBottom: spacing.lg,
  },
  contentShrink: {
    flexShrink: 1,
  },
});

export default BottomSheet;
