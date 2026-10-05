/**
 * The back control for SUB-SCREENS.
 *
 * Only pushed screens get one, and it is a BUTTON rather than a header bar: the
 * app's screens draw their own content from the top, and a full header costs a
 * fifth of the viewport and repeats a name the screen already states. The circle
 * is outlined rather than filled so it reads as a control on the page
 * background and on a card alike.
 */
import React from 'react';
import {
  StyleSheet,
  TouchableOpacity,
  type StyleProp,
  type ViewStyle,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';

import { colors, borderRadius } from '../../theme';

interface BackButtonProps {
  /** Defaults to going back in the nearest navigator. */
  onPress?: () => void;
  style?: StyleProp<ViewStyle>;
  accessibilityLabel?: string;
}

export function BackButton({ onPress, style, accessibilityLabel = 'Go back' }: BackButtonProps) {
  const navigation = useNavigation();
  return (
    <TouchableOpacity
      style={[styles.button, style]}
      onPress={onPress ?? (() => navigation.goBack())}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel}
      hitSlop={8}
    >
      <Ionicons name="chevron-back" size={20} color={colors.text.primary} />
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  button: {
    width: 36,
    height: 36,
    borderRadius: borderRadius.full,
    borderWidth: 1,
    borderColor: colors.border.default,
    backgroundColor: colors.surface.card,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
