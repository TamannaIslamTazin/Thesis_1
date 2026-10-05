/**
 * SSI Healthcare Mobile - Selective Disclosure Sheet
 *
 * The one screen where a human decides what a verifier learns about them.
 *
 * ===========================================================================
 * THIS IS WHERE A PRIVACY FEATURE BECOMES A DARK PATTERN
 * ===========================================================================
 * Selective disclosure is a cryptographic capability. Whether anyone ever uses
 * it is a UI question, and the UI answer is almost entirely the DEFAULT. A
 * sheet that opens with every claim switched on produces exactly as much
 * disclosure as having no sheet at all — plus a consent record saying the
 * holder chose it. That is strictly worse than not shipping the feature,
 * because it MANUFACTURES CONSENT for full disclosure and makes the resulting
 * over-disclosure look deliberate to anyone auditing it later.
 *
 * Six choices follow from that, and each is a decision rather than a style
 * preference:
 *
 *   1. THE DEFAULT IS THE MINIMUM THAT SATISFIES THE VERIFIER, computed by
 *      `buildDisclosureChoices` in the shared policy module. Required claims
 *      start on; optional ones and unrequested ones start off. Not "all on"
 *      (which is the dark pattern) and not "all off" (which makes the honest
 *      path cost N taps, so holders either give up or reach for a bulk
 *      control — and the bulk control is how "all on" comes back).
 *
 *   2. THERE IS NO "SHARE EVERYTHING" BUTTON. Nowhere in this sheet can a
 *      holder over-disclose in one action. The asymmetry IS the enforcement:
 *      minimal disclosure costs zero taps and the confirm button is live
 *      immediately, while each additional claim costs one deliberate tap.
 *
 *   3. REQUIRED CLAIMS ARE SHOWN AND LOCKED, BUT THE WHOLE SHEET IS REFUSABLE.
 *      A toggle whose only outcome is a presentation the verifier will reject
 *      is a false choice — worse than no control, because it implies a
 *      possibility that does not exist. The real decision at that point is
 *      whether to deal with this verifier at all, so "Don't share" is a peer of
 *      the confirm button, not a de-emphasised escape hatch.
 *
 *   4. CLAIMS THE VERIFIER DID NOT ASK FOR LIVE IN A SEPARATE, COLLAPSED
 *      SECTION. Mixing them into one list makes the whole list read as "the
 *      ask", which is how a holder volunteers a diagnosis believing it was
 *      required. Separating them is what makes "you are about to offer this
 *      unprompted" legible.
 *
 *   5. THE SUMMARY IS PHRASED AS WHAT THE RECIPIENT LEARNS, AND NAMES THEM.
 *      "Dhaka Pharmacy will learn your HIV status" is the privacy consequence.
 *      "3 of 7 fields shared" is a progress bar. The first is refusable; the
 *      second is not something a person can meaningfully object to.
 *
 *   6. OVER-DISCLOSURE IS ALLOWED, AND NAMED THE MOMENT IT HAPPENS. Blocking it
 *      would be paternalistic and sometimes wrong — a holder may have a reason.
 *      Saying nothing would make us complicit. So it is possible, and it is
 *      labelled.
 *
 * ---------------------------------------------------------------------------
 * THE LEAK THIS SHEET CANNOT CLOSE, STATED HONESTLY
 * ---------------------------------------------------------------------------
 * A claim's ABSENCE can be as informative as its value. If a verifier always
 * asks for `hivStatus` and this holder alone returns nothing, the refusal is
 * itself the signal — and no arrangement of toggles fixes that, because the
 * verifier learns it from the shape of the response, not from its contents.
 *
 * Two consequences, both deliberate:
 *   - The sheet TELLS THE HOLDER when declining a REQUESTED claim is itself
 *     visible (`WITHHELD_IS_VISIBLE_NOTE`). They cannot act on a risk nobody
 *     names, and quietly letting them believe a refusal is invisible would be
 *     the more dishonest option.
 *   - It is NOT fixed here, because it cannot be. Mitigating it needs decoy
 *     digests (`_sd_decoy`, declared in the shared frame type and currently
 *     never emitted) and a verifier that cannot distinguish "withheld" from
 *     "never present" — an issuance-side and protocol-side change. Recorded as
 *     follow-up rather than papered over.
 */

import React, { useState, useMemo, useCallback } from 'react';
import { View, Text, StyleSheet, TouchableOpacity, Switch, ScrollView } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import {
  buildDisclosureChoices,
  volunteeredClaims,
  unsatisfiableRequirements,
  type DisclosableClaim,
  type DisclosureChoice,
  type VerifierClaimRequest,
} from '@ssi-healthcare/sdk';
import { BottomSheet } from './BottomSheet';
import { getFieldDisplayName, isSensitiveField } from '../../utils/plainLanguage';
import { colors } from '../../theme/colors';
import { spacing } from '../../theme/spacing';
import { borderRadius } from '../../theme/borderRadius';
import { typography } from '../../theme/typography';

/** Shown against a requested claim the holder has switched off. See the header. */
const WITHHELD_IS_VISIBLE_NOTE =
  'They asked for this. Leaving it off is something they can notice.';

export interface DisclosureRecipient {
  /** Organisation name, in the holder's language. */
  name: string;
  /** Whether this verifier's identity has been established. */
  verified: boolean;
  /** Why they are asking, in plain English. */
  purpose: string;
  /** Shown only in advanced mode. */
  did?: string;
}

export interface DisclosureSheetProps {
  visible: boolean;
  onClose: () => void;
  /**
   * Confirm. Receives the selected LEAF PATHS, which the caller turns into a
   * presentation frame with `presentationFrameForChoices`.
   *
   * Deliberately not a frame: building one requires the shared policy module's
   * measured semantics (naming a container alone discloses it EMPTY), and a
   * component assembling one itself is how a second, subtly wrong
   * implementation gets written.
   */
  onConfirm: (selectedPaths: string[]) => void;
  /** The credential type being presented, for display. */
  credentialType: string;
  recipient: DisclosureRecipient;
  /** Every claim the ISSUER made selectively disclosable, from the credential. */
  disclosable: DisclosableClaim[];
  /** What this verifier stated it needs. */
  requests: VerifierClaimRequest[];
  advancedMode?: boolean;
}

/** Render a claim value for display without leaking a huge blob into the row. */
function displayValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

/**
 * A claim's label, derived from the last segment of its path.
 *
 * `prescriber.licence` reads as "Licence" under a "Prescriber" heading rather
 * than as the raw path. Array elements keep their index because "Medication"
 * three times in a row is not a choice anyone can make.
 */
function claimLabel(path: string): string {
  const arrayMatch = path.match(/^(.*)\[(\d+)\]$/);
  if (arrayMatch) {
    const [, base, index] = arrayMatch;
    return `${getFieldDisplayName(base!.split('.').pop() ?? base!)} ${Number(index) + 1}`;
  }
  return getFieldDisplayName(path.split('.').pop() ?? path);
}

export function DisclosureSheet({
  visible,
  onClose,
  onConfirm,
  credentialType,
  recipient,
  disclosable,
  requests,
  advancedMode = false,
}: DisclosureSheetProps) {
  // THE DEFAULT COMES FROM THE SHARED POLICY MODULE, NOT FROM THIS COMPONENT.
  // Recomputed whenever the sheet opens so a previous session's widened
  // selection never carries into a new request — consent does not persist
  // across asks, and a sheet that reopens pre-widened is one that ratchets.
  const initialChoices = useMemo(
    () => buildDisclosureChoices(disclosable, requests),
    [disclosable, requests],
  );
  const [choices, setChoices] = useState<DisclosureChoice[]>(initialChoices);
  const [showUnrequested, setShowUnrequested] = useState(false);

  React.useEffect(() => {
    if (visible) {
      setChoices(initialChoices);
      // The unrequested section re-collapses every time. Expanding it is part
      // of the deliberate act of volunteering, and it should cost that act
      // again on the next request rather than staying open from last time.
      setShowUnrequested(false);
    }
  }, [visible, initialChoices]);

  const toggle = useCallback((path: string) => {
    setChoices((previous) =>
      previous.map((choice) =>
        choice.path === path && !choice.locked
          ? { ...choice, disclosed: !choice.disclosed }
          : choice,
      ),
    );
  }, []);

  const required = useMemo(() => choices.filter((c) => c.requirement === 'required'), [choices]);
  const optional = useMemo(() => choices.filter((c) => c.requirement === 'optional'), [choices]);
  const unrequested = useMemo(() => choices.filter((c) => c.requirement === null), [choices]);

  const selected = useMemo(() => choices.filter((c) => c.disclosed), [choices]);
  const volunteered = useMemo(() => volunteeredClaims(choices), [choices]);
  const unsatisfiable = useMemo(
    () => unsatisfiableRequirements(disclosable, requests),
    [disclosable, requests],
  );

  const handleConfirm = useCallback(() => {
    onConfirm(selected.map((c) => c.path));
    onClose();
  }, [onConfirm, onClose, selected]);

  const renderRow = (choice: DisclosureChoice) => {
    const sensitive = isSensitiveField(choice.path.split('.').pop() ?? choice.path);
    // Only meaningful for a claim they ASKED for: declining something never
    // requested is not visible to them at all.
    const withheldAndNoticeable = choice.requirement !== null && !choice.disclosed;

    return (
      <View key={choice.path} style={styles.row}>
        <View style={styles.rowInfo}>
          <View style={styles.rowLabelLine}>
            <Text style={styles.rowLabel}>{claimLabel(choice.path)}</Text>
            {sensitive && (
              <Ionicons
                name="lock-closed"
                size={13}
                color={colors.semantic.warning}
                style={styles.rowIcon}
              />
            )}
            {choice.locked && (
              <View style={styles.requiredBadge}>
                <Text style={styles.requiredBadgeText}>Needed</Text>
              </View>
            )}
          </View>

          {/* The value is shown ONLY when it is actually going to be sent.
              Rendering the real value next to an off switch invites the reading
              "they can see it anyway", which is exactly backwards. */}
          <Text
            style={[styles.rowValue, !choice.disclosed && styles.rowValueHidden]}
            numberOfLines={2}
          >
            {choice.disclosed ? displayValue(choice.value) : 'Not shared'}
          </Text>

          {choice.purpose && <Text style={styles.rowPurpose}>{choice.purpose}</Text>}

          {withheldAndNoticeable && (
            <Text style={styles.rowNotice}>{WITHHELD_IS_VISIBLE_NOTE}</Text>
          )}
        </View>

        <Switch
          value={choice.disclosed}
          onValueChange={() => toggle(choice.path)}
          disabled={choice.locked}
          trackColor={{ false: colors.ui.switchTrackOff, true: colors.ui.switchTrackOn }}
          thumbColor={choice.disclosed ? colors.ui.switchThumbOn : colors.ui.switchThumbOff}
          accessibilityLabel={`Share ${claimLabel(choice.path)}`}
          accessibilityHint={
            choice.locked
              ? `${recipient.name} requires this. To refuse it, decline the whole request.`
              : choice.disclosed
              ? 'On. Tap to stop sharing this.'
              : 'Off. Tap to share this as well.'
          }
        />
      </View>
    );
  };

  return (
    <BottomSheet visible={visible} onClose={onClose} snapPoint={0.85} scrollable={false} testID="disclosure-sheet">
      <ScrollView style={styles.scroll} showsVerticalScrollIndicator={false}>
        {/* Who is asking */}
        <View style={styles.header}>
          <View style={styles.recipientBadge}>
            <Ionicons
              name={recipient.verified ? 'shield-checkmark' : 'shield-outline'}
              size={24}
              color={recipient.verified ? colors.semantic.success : colors.semantic.warning}
            />
          </View>
          <View style={styles.headerText}>
            <Text style={styles.recipientName}>{recipient.name}</Text>
            <Text style={styles.recipientStatus}>
              {recipient.verified ? 'Verified organisation' : 'Unverified request'}
            </Text>
          </View>
        </View>

        <View style={styles.purposeBox}>
          <Text style={styles.purposeLabel}>Why they are asking</Text>
          <Text style={styles.purposeText}>{recipient.purpose}</Text>
        </View>

        <View style={styles.credentialBadge}>
          <Ionicons name="document-text-outline" size={18} color={colors.brand.primary} />
          <Text style={styles.credentialType}>{credentialType}</Text>
        </View>

        {/* WHAT THEY LEARN — recipient-framed, live. See decision 5. */}
        <View style={styles.learnBox}>
          <Text style={styles.learnLabel}>{recipient.name} will learn</Text>
          {selected.length === 0 ? (
            <Text style={styles.learnNothing}>
              Nothing about you — only that this credential is genuine, unrevoked and yours.
            </Text>
          ) : (
            selected.map((choice) => (
              <Text key={choice.path} style={styles.learnItem}>
                {`• ${claimLabel(choice.path)}: ${displayValue(choice.value)}`}
              </Text>
            ))
          )}
        </View>

        {/* Over-disclosure, named the moment it is true. See decision 6. */}
        {volunteered.length > 0 && (
          <View style={styles.volunteerNotice}>
            <Ionicons name="alert-circle-outline" size={18} color={colors.semantic.warning} />
            <Text style={styles.volunteerText}>
              {volunteered.length === 1
                ? 'You are sharing 1 thing they did not require.'
                : `You are sharing ${volunteered.length} things they did not require.`}
            </Text>
          </View>
        )}

        {/* A requirement this credential cannot meet, surfaced BEFORE consent. */}
        {unsatisfiable.length > 0 && (
          <View style={styles.blockedNotice}>
            <Ionicons name="close-circle-outline" size={18} color={colors.semantic.error} />
            <Text style={styles.blockedText}>
              {`This credential does not contain ${unsatisfiable
                .map(claimLabel)
                .join(', ')}, which they require. Sharing may still be refused.`}
            </Text>
          </View>
        )}

        {required.length > 0 && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>They need</Text>
            <Text style={styles.sectionHint}>
              Required for this check. To refuse, decline the whole request.
            </Text>
            {required.map(renderRow)}
          </View>
        )}

        {optional.length > 0 && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>They asked, but said it is optional</Text>
            <Text style={styles.sectionHint}>Off by default. They can proceed without these.</Text>
            {optional.map(renderRow)}
          </View>
        )}

        {/* Unrequested claims: separate, collapsed. See decision 4. */}
        {unrequested.length > 0 && (
          <View style={styles.section}>
            <TouchableOpacity
              style={styles.disclosureToggle}
              onPress={() => setShowUnrequested((s) => !s)}
              accessibilityRole="button"
              accessibilityLabel={
                showUnrequested
                  ? 'Hide things they did not ask for'
                  : 'Show things they did not ask for'
              }
            >
              <Ionicons
                name={showUnrequested ? 'chevron-down' : 'chevron-forward'}
                size={18}
                color={colors.text.secondary}
              />
              <Text style={styles.sectionTitle}>
                {`They did not ask for these (${unrequested.length})`}
              </Text>
            </TouchableOpacity>
            {showUnrequested && (
              <>
                <Text style={styles.sectionHint}>
                  Sharing anything here is entirely your choice. They have not requested it and do
                  not need it.
                </Text>
                {unrequested.map(renderRow)}
              </>
            )}
          </View>
        )}

        {advancedMode && recipient.did && (
          <View style={styles.advancedBox}>
            <Text style={styles.advancedLabel}>Recipient DID</Text>
            <Text style={styles.advancedValue} numberOfLines={1} ellipsizeMode="middle">
              {recipient.did}
            </Text>
          </View>
        )}
      </ScrollView>

      {/* Decline is a PEER of confirm, not an escape hatch. See decision 3. */}
      <View style={styles.actions}>
        <TouchableOpacity
          style={styles.declineButton}
          onPress={onClose}
          activeOpacity={0.7}
          accessibilityRole="button"
          accessibilityLabel="Do not share anything"
        >
          <Text style={styles.declineButtonText}>Don&apos;t share</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.confirmButton}
          onPress={handleConfirm}
          activeOpacity={0.7}
          accessibilityRole="button"
          accessibilityLabel={
            selected.length === 0
              ? 'Share nothing but proof the credential is genuine'
              : `Share ${selected.length} ${selected.length === 1 ? 'item' : 'items'} with ${recipient.name}`
          }
        >
          <Ionicons name="finger-print" size={20} color={colors.text.primary} />
          <Text style={styles.confirmButtonText}>
            {selected.length === 0 ? 'Share proof only' : `Share ${selected.length}`}
          </Text>
        </TouchableOpacity>
      </View>
    </BottomSheet>
  );
}

const styles = StyleSheet.create({
  // MUST shrink, or the actions row is pushed out of the sheet: an unconstrained
  // ScrollView grows to content height and can never scroll. Measured 22 Sep
  // 2026 — the confirm button landed at y=2358 of 2400, under the nav bar.
  scroll: { flexShrink: 1 },
  header: { flexDirection: 'row', alignItems: 'center', marginBottom: spacing.md },
  recipientBadge: {
    width: 48,
    height: 48,
    borderRadius: borderRadius.full,
    backgroundColor: colors.background.secondary,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: spacing.md,
  },
  headerText: { flex: 1 },
  recipientName: { ...typography.headingMd, color: colors.text.primary },
  recipientStatus: { ...typography.bodySmall, color: colors.text.secondary, marginTop: 2 },

  purposeBox: {
    backgroundColor: colors.background.secondary,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginBottom: spacing.md,
  },
  purposeLabel: {
    ...typography.caption,
    color: colors.text.tertiary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  purposeText: { ...typography.bodyMedium, color: colors.text.primary, marginTop: spacing.xs },

  credentialBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.brand.primaryMuted,
    alignSelf: 'flex-start',
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.xs,
    borderRadius: borderRadius.full,
    marginBottom: spacing.md,
  },
  credentialType: {
    ...typography.labelMedium,
    color: colors.brand.primary,
    marginLeft: spacing.xs,
  },

  learnBox: {
    backgroundColor: colors.background.secondary,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginBottom: spacing.md,
    borderLeftWidth: 3,
    borderLeftColor: colors.brand.primary,
  },
  learnLabel: {
    ...typography.labelMedium,
    color: colors.text.primary,
    marginBottom: spacing.xs,
  },
  learnItem: { ...typography.bodySmall, color: colors.text.secondary, marginTop: 2 },
  learnNothing: { ...typography.bodySmall, color: colors.text.secondary, fontStyle: 'italic' },

  volunteerNotice: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
    backgroundColor: colors.semantic.warningLight,
    borderRadius: borderRadius.sm,
    padding: spacing.sm,
    marginBottom: spacing.md,
  },
  volunteerText: { ...typography.bodySmall, color: colors.semantic.warning, flex: 1 },

  blockedNotice: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
    borderRadius: borderRadius.sm,
    padding: spacing.sm,
    marginBottom: spacing.md,
    borderWidth: 1,
    borderColor: colors.semantic.error,
  },
  blockedText: { ...typography.bodySmall, color: colors.semantic.error, flex: 1 },

  section: { marginBottom: spacing.lg },
  sectionTitle: { ...typography.labelMedium, color: colors.text.primary },
  sectionHint: {
    ...typography.caption,
    color: colors.text.tertiary,
    marginTop: 2,
    marginBottom: spacing.xs,
  },
  disclosureToggle: { flexDirection: 'row', alignItems: 'center', gap: spacing.xs },

  row: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: colors.border.subtle,
  },
  rowInfo: { flex: 1, marginRight: spacing.md },
  rowLabelLine: { flexDirection: 'row', alignItems: 'center' },
  rowLabel: { ...typography.bodyMedium, color: colors.text.primary },
  rowIcon: { marginLeft: spacing.xs },
  requiredBadge: {
    backgroundColor: colors.brand.primaryMuted,
    paddingHorizontal: spacing.xs,
    paddingVertical: 2,
    borderRadius: borderRadius.sm,
    marginLeft: spacing.xs,
  },
  requiredBadgeText: { ...typography.caption, color: colors.brand.primary, fontSize: 10 },
  rowValue: { ...typography.bodySmall, color: colors.text.secondary, marginTop: 2 },
  rowValueHidden: { color: colors.text.tertiary, fontStyle: 'italic' },
  rowPurpose: { ...typography.caption, color: colors.text.tertiary, marginTop: 2 },
  rowNotice: { ...typography.caption, color: colors.semantic.warning, marginTop: 2 },

  advancedBox: {
    backgroundColor: colors.background.secondary,
    borderRadius: borderRadius.sm,
    padding: spacing.sm,
    marginBottom: spacing.md,
  },
  advancedLabel: { ...typography.caption, color: colors.text.tertiary },
  advancedValue: { ...typography.mono, color: colors.text.secondary, fontSize: 12 },

  actions: { flexDirection: 'row', gap: spacing.md, paddingTop: spacing.md },
  // Equal visual weight with confirm. Declining is a first-class outcome.
  declineButton: {
    flex: 1,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    backgroundColor: colors.surface.elevated,
    alignItems: 'center',
    justifyContent: 'center',
  },
  declineButtonText: { ...typography.labelMedium, color: colors.text.primary },
  confirmButton: {
    flex: 1,
    flexDirection: 'row',
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    backgroundColor: colors.brand.primary,
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.xs,
  },
  confirmButtonText: { ...typography.labelMedium, color: colors.text.primary },
});

export default DisclosureSheet;
