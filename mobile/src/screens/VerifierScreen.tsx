/**
 * SSI Healthcare Mobile — Verifier Mode.
 *
 * The screen a professional uses to check a patient's credential, inside the
 * same wallet they hold their own credentials in. A holder is several groups at
 * once — patient first, and possibly doctor, nurse or pharmacist — so a
 * pharmacist who is also a patient carries one app, not two.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS SCREEN IS FOR, AND WHAT IT DELIBERATELY DOES NOT DO
 * ---------------------------------------------------------------------------
 * It does three things:
 *
 *   1. States which licence the professional is acting under, READ FROM THE
 *      CREDENTIAL — not from the group they picked at onboarding, and not from
 *      any profile field. If the wording on this screen could be produced by a
 *      self-declaration, R4's claim would be false in the client even while it
 *      held in the backend.
 *   2. Says what that licence covers, in verbs rather than in scope atoms.
 *   3. Hands off to the scanner, which is the wallet's existing and only
 *      verification pipeline.
 *
 * It does NOT decide anything. No screen in this app can grant authority, and
 * saying so plainly is part of the design rather than a disclaimer bolted on:
 * a professional who believes the app approved something will not understand
 * why the pharmacy system later refused. The banner at the bottom is there for
 * that reason and should not be quietly dropped as clutter.
 *
 * ---------------------------------------------------------------------------
 * USABILITY NOTES — THE PART THAT IS THE THESIS CONTRIBUTION
 * ---------------------------------------------------------------------------
 * Aimed at a low-technical-literacy population on mid-range Android:
 *
 *   - ONE primary action, full width, at a fixed place on the screen. Scanning
 *     is the only thing a professional comes here to do.
 *   - No DIDs on screen. A DID is unreadable and unverifiable by eye; the
 *     accrediting authority is named ("BMDC") or the app admits it does not
 *     recognise the issuer. "Unknown" beats a 60-character string nobody can
 *     check.
 *   - Practice scopes are rendered as plain verbs. `administer-medication` is
 *     vocabulary from a trust framework, not from a nurse's working day.
 *   - A licence that has expired is SHOWN, greyed, with the reason, rather than
 *     disappearing. A credential that silently vanishes is indistinguishable
 *     from one the app lost, and the second reading destroys trust in a wallet.
 *   - Selection is only offered when there is something to select. A picker
 *     with one option is a decision the user did not need to make.
 */

import React, { useCallback, useMemo, useState } from 'react';
import { View, Text, ScrollView, StyleSheet, Pressable } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import type { HeldProfessionalLicence, PracticeScope } from '@ssi-healthcare/sdk';
import type { RootStackParamList } from '../types';
import { useCredentialStore } from '../store';
import { licencesInWallet } from '../store/professionalLicence';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';
import { Button, EmptyState } from '../components/common';

/**
 * Practice scopes in the words a professional would use.
 *
 * The atoms are the trust framework's vocabulary and are correct there; they
 * are not what a nurse in a district hospital calls the thing she does. An
 * unmapped scope falls back to the atom with its hyphens removed rather than to
 * a blank, because showing something imperfect beats showing nothing.
 */
const SCOPE_IN_PLAIN_WORDS: Record<PracticeScope, string> = {
  'view-patient-record': 'See patient records',
  'write-patient-record': 'Add to patient records',
  prescribe: 'Write prescriptions',
  dispense: 'Give out medicine',
  'administer-medication': 'Give medicine to patients',
  'order-diagnostic': 'Order tests',
};

function plainScope(scope: PracticeScope): string {
  return SCOPE_IN_PLAIN_WORDS[scope] ?? scope.replace(/-/g, ' ');
}

const PROFESSION_TITLE: Record<HeldProfessionalLicence['profession'], string> = {
  doctor: 'Doctor',
  nurse: 'Nurse',
  pharmacist: 'Pharmacist',
};

function LicenceCard({
  licence,
  selected,
  selectable,
  onSelect,
}: {
  licence: HeldProfessionalLicence;
  selected: boolean;
  selectable: boolean;
  onSelect: () => void;
}) {
  const usable = licence.inForce;

  return (
    <Pressable
      onPress={usable && selectable ? onSelect : undefined}
      disabled={!usable || !selectable}
      style={[
        styles.licenceCard,
        selected && styles.licenceCardSelected,
        !usable && styles.licenceCardUnusable,
      ]}
      accessibilityRole={selectable ? 'radio' : 'text'}
      accessibilityState={{ selected, disabled: !usable }}
      accessibilityLabel={
        // Spoken as one sentence. A screen reader walking six separate <Text>
        // nodes reads a licence as disconnected fragments.
        `${PROFESSION_TITLE[licence.profession]}, licence ${licence.licenceNumber}, ` +
        `${licence.accreditedByName ? `issued by ${licence.accreditedByName}` : 'issuer not recognised'}` +
        `${usable ? '' : `. Not usable: ${licence.notInForceReasons.join('. ')}`}`
      }
    >
      <View style={styles.licenceHeader}>
        <Text style={styles.profession}>{PROFESSION_TITLE[licence.profession]}</Text>
        {selected && usable ? (
          <Ionicons name="checkmark-circle" size={22} color={colors.brand.primary} />
        ) : null}
      </View>

      <Text style={styles.licenceNumber}>{licence.licenceNumber}</Text>
      <Text style={styles.register}>{licence.register}</Text>

      <View style={styles.authorityRow}>
        <Ionicons
          name={licence.accreditedByName ? 'ribbon-outline' : 'help-circle-outline'}
          size={16}
          color={licence.accreditedByName ? colors.semantic.success : colors.text.tertiary}
        />
        <Text style={styles.authorityText}>
          {licence.accreditedByName
            ? `Issued by ${licence.accreditedByName}`
            : // Not a refusal. The verifier's list of recognised authorities may
              // differ from this app's, and the verifier's is the one that counts.
              'This app does not recognise who issued this'}
        </Text>
      </View>

      {!usable ? (
        <View style={styles.warningRow}>
          <Ionicons name="alert-circle" size={16} color={colors.semantic.warning} />
          <Text style={styles.warningText}>{licence.notInForceReasons.join('. ')}</Text>
        </View>
      ) : null}
    </Pressable>
  );
}

export default function VerifierScreen() {
  // `useNavigation` rather than screen props: this is a TAB screen, so the
  // props it receives describe the tab navigator, which does not know about
  // `Scanner`. The scanner is registered on the ROOT stack and the call bubbles
  // up to it — typing against the root stack is what makes that legible instead
  // of a cast.
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const credentials = useCredentialStore((state) => state.credentials);

  const licences = useMemo(() => licencesInWallet(credentials), [credentials]);
  const usable = useMemo(() => licences.filter((licence) => licence.inForce), [licences]);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const active = usable.find((licence) => licence.credentialId === selectedId) ?? usable[0];

  const handleScan = useCallback(() => {
    // The scanner is the wallet's ONE verification pipeline. Building a second
    // one here would mean two code paths deciding what a scanned artifact is,
    // and the one used less often would be the one that rots.
    navigation.navigate('Scanner', {});
  }, [navigation]);

  // Reachable only when the wallet holds a usable licence, so this is the
  // "credential was revoked while the screen was open" case rather than the
  // ordinary one. It still has to say something true.
  if (!active) {
    return (
      <EmptyState
        title="No usable licence"
        message="Verifier mode needs a professional licence that is currently valid. Your wallet does not have one right now."
        icon="shield-outline"
      />
    );
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <Text style={styles.eyebrow}>You are checking as</Text>

      {licences.map((licence) => (
        <LicenceCard
          key={licence.credentialId}
          licence={licence}
          selected={licence.credentialId === active.credentialId}
          // A picker with one option is a decision the user did not need to
          // make, so cards are inert until there is a genuine choice.
          selectable={usable.length > 1}
          onSelect={() => setSelectedId(licence.credentialId)}
        />
      ))}

      <Text style={styles.sectionTitle}>This licence lets you</Text>
      <View style={styles.scopeList}>
        {active.practiceScope.map((scope) => (
          <View key={scope} style={styles.scopeRow}>
            <Ionicons name="checkmark" size={18} color={colors.semantic.success} />
            <Text style={styles.scopeText}>{plainScope(scope)}</Text>
          </View>
        ))}
      </View>

      <Button
        label="Scan patient's code"
        onPress={handleScan}
        icon="scan"
        size="large"
        fullWidth
        style={styles.primaryAction}
        accessibilityLabel="Scan a patient's code to check their credential"
        accessibilityHint="Opens the camera"
      />

      <View style={styles.notice}>
        <Ionicons name="information-circle-outline" size={18} color={colors.text.secondary} />
        <Text style={styles.noticeText}>
          This app shows what a patient chose to share. It cannot approve a treatment or a
          prescription on its own — the hospital or pharmacy system checks your licence each
          time you act.
        </Text>
      </View>
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
    paddingBottom: spacing.xl,
    gap: spacing.md,
  },
  eyebrow: {
    color: colors.text.secondary,
    fontSize: fontSizes.sm,
    fontWeight: fontWeights.semibold,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  licenceCard: {
    backgroundColor: colors.surface.card,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border.default,
    padding: spacing.lg,
    gap: spacing.xs,
  },
  licenceCardSelected: {
    borderColor: colors.brand.primary,
    backgroundColor: colors.brand.primarySubtle,
  },
  licenceCardUnusable: {
    opacity: 0.6,
  },
  licenceHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  profession: {
    color: colors.text.primary,
    // The largest thing on the card: it is the one word a professional needs to
    // confirm at a glance before they act.
    fontSize: fontSizes.xl,
    fontWeight: fontWeights.bold,
  },
  licenceNumber: {
    color: colors.text.primary,
    fontSize: fontSizes.md,
    fontWeight: fontWeights.semibold,
  },
  register: {
    color: colors.text.secondary,
    fontSize: fontSizes.sm,
  },
  authorityRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
    marginTop: spacing.xs,
  },
  authorityText: {
    color: colors.text.secondary,
    fontSize: fontSizes.sm,
    flexShrink: 1,
  },
  warningRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: spacing.xs,
    marginTop: spacing.xs,
  },
  warningText: {
    color: colors.semantic.warning,
    fontSize: fontSizes.sm,
    flexShrink: 1,
  },
  sectionTitle: {
    color: colors.text.primary,
    fontSize: fontSizes.md,
    fontWeight: fontWeights.bold,
    marginTop: spacing.md,
  },
  scopeList: {
    gap: spacing.sm,
  },
  scopeRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
  },
  scopeText: {
    color: colors.text.primary,
    fontSize: fontSizes.md,
    flexShrink: 1,
  },
  primaryAction: {
    marginTop: spacing.lg,
  },
  notice: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: spacing.sm,
    backgroundColor: colors.surface.secondary,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginTop: spacing.sm,
  },
  noticeText: {
    color: colors.text.secondary,
    fontSize: fontSizes.sm,
    lineHeight: 20,
    flexShrink: 1,
  },
});
