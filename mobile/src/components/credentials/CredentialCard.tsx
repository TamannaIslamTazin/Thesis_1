/**
 * SSI Healthcare Mobile - Credential Card Component
 *
 * Displays a credential summary in a list with expiration warnings.
 */

import React, { useCallback, useMemo } from 'react';
import { View, Text, StyleSheet, Pressable, ViewStyle } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../../theme';
import { Badge } from '../common/Badge';
import { ExpirationBadge } from './ExpirationBadge';
import { truncateDid } from '../../utils/format';
import { getCredentialTypeName } from '../../utils/plainLanguage';
import type { Credential } from '../../types';

interface CredentialCardProps {
  credential: Credential;
  onPress: (credential: Credential) => void;
  style?: ViewStyle;
}


/**
 * The one fact that tells THIS credential from its siblings.
 *
 * Five prescriptions rendered identically — same title "Prescription", same
 * issuer, same date — so the holder could not tell them apart, and could not
 * choose one at a pharmacy either. Recognition, not recall (Nielsen H6): the
 * distinguishing fact has to be on the card, not remembered.
 *
 * The medicine name and strength are the identifying facts for a prescription.
 * Everything else here is a fallback for credential types that have no such
 * detail, so the card still reads sensibly when there is nothing to distinguish.
 *
 * Read from the UNSIGNED credential body, which is fine for display: this is not
 * a trust decision, and the signed envelope is untouched.
 */
function identifyingDetail(credential: Credential): string | null {
  const subject = (credential.verifiableCredential as
    | { credentialSubject?: Record<string, unknown> }
    | undefined)?.credentialSubject;
  if (!subject || typeof subject !== 'object') return null;

  const medication = subject.medication as { name?: unknown; dosage?: unknown } | undefined;
  if (medication && typeof medication.name === 'string' && medication.name.trim().length > 0) {
    const name = medication.name.trim();
    const dosage = typeof medication.dosage === 'string' ? medication.dosage.trim() : '';
    // "Lisinopril 10mg" — the pair a pharmacist asks for and a holder recognises.
    return dosage.length > 0 ? `${name} ${dosage}` : name;
  }

  const vaccine = subject.vaccine as { name?: unknown } | undefined;
  if (vaccine && typeof vaccine.name === 'string' && vaccine.name.trim().length > 0) {
    return vaccine.name.trim();
  }

  return null;
}

const CATEGORY_ICONS: Record<string, keyof typeof Ionicons.glyphMap> = {
  medical_record: 'document-text',
  vaccination: 'medical',
  prescription: 'medkit',
  lab_result: 'flask',
  insurance: 'shield-checkmark',
  emergency: 'alert-circle',
  identity: 'person',
  other: 'folder',
};

const STATUS_VARIANTS = {
  valid: 'success',
  expired: 'warning',
  revoked: 'error',
  pending: 'info',
} as const;

export const CredentialCard = React.memo(function CredentialCard({
  credential,
  onPress,
  style,
}: CredentialCardProps) {
  // WHAT THE CARD SAYS, and why it is not simply the type name.
  const detail = useMemo(() => identifyingDetail(credential), [credential]);

  const handlePress = useCallback(() => {
    onPress(credential);
  }, [credential, onPress]);

  // The name when a pinned authority resolved it; otherwise the identifier
  // itself, truncated. Never "Unknown Issuer" while an identifier is in hand.
  const issuerName =
    credential.issuer?.name ??
    (credential.issuer?.id ? truncateDid(credential.issuer.id) : 'Unknown Issuer');

  // Prefer a name the issuer gave this credential; otherwise the plain label
  // for its TYPE — never the wire name (`HealthCardCredential`) in the list a
  // holder reads.
  const typeName =
    credential.metadata?.displayName && credential.metadata.displayName !== credential.type
      ? credential.metadata.displayName
      : getCredentialTypeName(credential.type);

  // THE IDENTIFYING FACT WINS THE HEADLINE. For a prescription that is the
  // medicine and its strength, because five cards reading "Prescription" are not
  // a list — they are a wall. The type name survives as the subtitle so the
  // holder still knows what kind of document this is.
  const displayName = detail ?? typeName;
  const showTypeAsSubtitle = detail !== null;
  const icon = CATEGORY_ICONS[credential.category] || CATEGORY_ICONS.other;
  const categoryColor = colors.credential[credential.category as keyof typeof colors.credential] || colors.text.tertiary;

  // Check if credential is expiring soon or expired
  const needsExpirationWarning = useMemo(() => {
    if (!credential.expirationDate) return false;
    const expDate = new Date(credential.expirationDate);
    const now = new Date();
    const diffDays = Math.ceil((expDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    return diffDays <= 30; // Show warning within 30 days or expired
  }, [credential.expirationDate]);

  return (
    <Pressable
      style={({ pressed }) => [
        styles.container,
        pressed && styles.pressed,
        style,
      ]}
      onPress={handlePress}
      accessibilityRole="button"
      accessibilityLabel={`${displayName} from ${issuerName}, status: ${credential.status}`}
      accessibilityHint="Double tap to view credential details"
    >
      <View style={[styles.iconContainer, { backgroundColor: `${categoryColor}20` }]}>
        <Ionicons name={icon} size={24} color={categoryColor} />
      </View>
      
      <View style={styles.content}>
        <View style={styles.header}>
          <Text style={styles.name} numberOfLines={1}>
            {displayName}
          </Text>
          {!needsExpirationWarning && (
            <Badge
              label={credential.status}
              variant={STATUS_VARIANTS[credential.status]}
              size="small"
            />
          )}
        </View>
        
        {showTypeAsSubtitle && (
          <Text style={styles.typeLine} numberOfLines={1}>
            {typeName}
          </Text>
        )}

        <Text style={styles.issuer} numberOfLines={1}>
          {issuerName}
        </Text>
        
        {needsExpirationWarning ? (
          <ExpirationBadge 
            expirationDate={credential.expirationDate} 
            compact 
            style={styles.expirationBadge}
          />
        ) : (
          <Text style={styles.date}>
            Issued: {new Date(credential.issuanceDate).toLocaleDateString()}
          </Text>
        )}
      </View>
      
      <Ionicons
        name="chevron-forward"
        size={20}
        color={colors.text.tertiary}
      />
    </Pressable>
  );
});

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.surface.card,
    borderRadius: borderRadius.card,
    padding: spacing.cardPadding,
    borderWidth: 1,
    borderColor: colors.border.default,
    gap: spacing.md,
  },
  pressed: {
    opacity: 0.8,
    transform: [{ scale: 0.99 }],
  },
  iconContainer: {
    width: 48,
    height: 48,
    borderRadius: borderRadius.md,
    justifyContent: 'center',
    alignItems: 'center',
  },
  content: {
    flex: 1,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: spacing.sm,
  },
  name: {
    flex: 1,
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.semibold,
    color: colors.text.primary,
  },
  typeLine: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    fontWeight: fontWeights.medium,
    marginTop: 1,
  },
  issuer: {
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.normal,
    color: colors.text.secondary,
    marginTop: spacing.xxs,
  },
  date: {
    fontSize: fontSizes.xs,
    fontWeight: fontWeights.normal,
    color: colors.text.tertiary,
    marginTop: spacing.xxs,
  },
  expirationBadge: {
    marginTop: spacing.xxs,
    alignSelf: 'flex-start',
  },
});

export default CredentialCard;
