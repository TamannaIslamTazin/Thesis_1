/**
 * Holder-initiated share: show the offer, take the verifier's answer, sign.
 *
 * The two buttons that open this sheet say "Share Credential" and "Generate QR
 * Code"; both start the same exchange (see `services/presentationOffer.ts` for
 * why a single QR of the credential would be a replayable bearer token). This
 * sheet is the whole conversation:
 *
 *   offer (QR or link)  ->  verifier's challenge (scan or deep link)  ->
 *   confirm the audience  ->  fingerprint  ->  delivered or handed over.
 *
 * The confirm step exists because a challenge is not signed: the holder must
 * SEE who will receive the presentation and where it goes before the key is
 * used. The fingerprint prompt is the second, physical confirmation.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Image, Share, StyleSheet, Text, TouchableOpacity, View } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';

import { BottomSheet } from './BottomSheet';
import { Button } from '../common/Button';
import { qrPngDataUri } from '../../utils/qr';
import { usePresentationShareStore } from '../../store/presentationShareStore';
import {
  createPresentationOffer,
  parseChallenge,
  presentForChallenge,
  type PresentationChallenge,
  type PresentationOffer,
} from '../../services/presentationOffer';
import { colors, spacing, borderRadius, fontSizes, fontWeights } from '../../theme';

type Phase = 'offer' | 'confirm' | 'signing' | 'done' | 'manual' | 'error';

interface PresentationShareSheetProps {
  visible: boolean;
  onClose: () => void;
  holderDid: string;
  credentialId: string;
  credentialType: string;
  credentialJwt: string;
  /** Claim paths the holder chose on the detail screen. Paths only, no values. */
  selectedClaims: string[];
  /** Which half of the exchange to lead with. */
  initialMode?: 'qr' | 'send';
}

export function PresentationShareSheet({
  visible,
  onClose,
  holderDid,
  credentialId,
  credentialType,
  credentialJwt,
  selectedClaims,
  initialMode = 'qr',
}: PresentationShareSheetProps) {
  const navigation = useNavigation();
  const pendingChallenge = usePresentationShareStore((state) => state.pendingChallenge);
  const setPendingChallenge = usePresentationShareStore((state) => state.setPendingChallenge);

  const [offer, setOffer] = useState<{ offer: PresentationOffer; url: string } | null>(null);
  const [challenge, setChallenge] = useState<PresentationChallenge | null>(null);
  const [phase, setPhase] = useState<Phase>('offer');
  const [message, setMessage] = useState<string | null>(null);
  const [receiptId, setReceiptId] = useState<string | null>(null);
  const [manualToken, setManualToken] = useState<string | null>(null);

  // A FRESH OFFER EVERY TIME THE SHEET OPENS. A reused offerId would let a
  // challenge from an earlier conversation be answered again.
  //
  // ONCE PER OPENING, not once per render. `selectedClaims` can arrive as a new
  // array, and keying only on identity re-created the offer on every parent
  // render — each re-creation re-triggering the share below, which is how one
  // tap produced two system share sheets (measured 19 Sep 2026).
  const wasVisible = useRef(false);
  useEffect(() => {
    if (!visible) {
      wasVisible.current = false;
      return;
    }
    if (wasVisible.current) return;
    wasVisible.current = true;
    const created = createPresentationOffer({ holderDid, credentialId, credentialType, claims: selectedClaims });
    if (__DEV__) {
      // Dev-only, and safe to print: an offer carries claim PATHS, never values.
      // It is what tools/verifyHolderExchange.mjs is driven with when testing a
      // single handset without a second camera.
      console.log('[presentation-share] offer', created.url);
    }
    setOffer(created);
    setChallenge(null);
    setMessage(null);
    setReceiptId(null);
    setManualToken(null);
    setPhase('offer');
  }, [visible, holderDid, credentialId, credentialType, selectedClaims]);

  // "Share Credential" leads with the system share sheet, because the holder
  // said share, not show. ONCE per offer, for the same reason as above.
  const sharedOfferId = useRef<string | null>(null);
  useEffect(() => {
    if (!visible || initialMode !== 'send' || !offer) return;
    if (sharedOfferId.current === offer.offer.offerId) return;
    sharedOfferId.current = offer.offer.offerId;
    void Share.share({
      message: `Scan or send this to receive my credential presentation: ${offer.url}`,
    });
  }, [visible, initialMode, offer]);

  // The verifier's answer, from the scanner or a deep link.
  useEffect(() => {
    if (!visible || !offer || !pendingChallenge) return;
    const parsed = parseChallenge(pendingChallenge);
    setPendingChallenge(null);
    if (!parsed) {
      setMessage('That code is not a response to a share request. Ask the verifier for their response code.');
      setPhase('error');
      return;
    }
    if (parsed.offerId !== offer.offer.offerId) {
      setMessage('That response is for a different share. Close this and start again.');
      setPhase('error');
      return;
    }
    setChallenge(parsed);
    setPhase('confirm');
  }, [visible, offer, pendingChallenge, setPendingChallenge]);

  const qrUri = useMemo(
    () => (offer && phase === 'offer' ? qrPngDataUri(offer.url, { scale: 6 }) : null),
    [offer, phase],
  );

  const handleScanResponse = useCallback(() => {
    (navigation as { navigate: (name: string) => void }).navigate('Scanner');
  }, [navigation]);

  const handleSendLink = useCallback(() => {
    if (!offer) return;
    void Share.share({
      message: `Scan or send this to receive my credential presentation: ${offer.url}`,
    });
  }, [offer]);

  const handleApprove = useCallback(async () => {
    if (!offer || !challenge) return;
    setPhase('signing');
    try {
      const result = await presentForChallenge({ offer: offer.offer, challenge, credentialJwt });
      setReceiptId(result.receiptId);
      if (result.delivered) {
        setPhase('done');
      } else {
        setManualToken(result.vpToken);
        setPhase('manual');
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The presentation could not be sent.');
      setPhase('error');
    }
  }, [offer, challenge, credentialJwt]);

  const handleSharePresentation = useCallback(() => {
    if (!manualToken) return;
    void Share.share({ message: manualToken });
  }, [manualToken]);

  const claimCount = selectedClaims.length;

  return (
    <BottomSheet visible={visible} onClose={onClose} snapPoint={0.8} testID="presentation-share-sheet">
      <View style={styles.header}>
        <Ionicons name="share-outline" size={24} color={colors.brand.primary} />
        <View style={styles.headerText}>
          <Text style={styles.title}>Share this credential</Text>
          <Text style={styles.subtitle}>
            {claimCount} {claimCount === 1 ? 'item' : 'items'} selected. The verifier only ever sees these.
          </Text>
        </View>
      </View>

      {phase === 'offer' && qrUri && (
        <>
          <View style={styles.qrWrap}>
            <Image source={{ uri: qrUri }} style={styles.qr} accessibilityLabel="Share code for the verifier to scan" />
          </View>
          <Text style={styles.body}>
            Show this code to the verifier. When they answer with their own code, scan it and you will be asked to approve.
          </Text>
          <Button label="Send link instead" onPress={handleSendLink} variant="secondary" size="large" fullWidth />
          <View style={styles.spacer} />
          <Button label="Scan verifier response" onPress={handleScanResponse} variant="primary" size="large" fullWidth />
        </>
      )}

      {phase === 'confirm' && challenge && (
        <>
          <Text style={styles.body}>
            This presentation will be signed for:
          </Text>
          <View style={styles.detailBox}>
            <Text style={styles.detailLabel}>Audience</Text>
            <Text style={styles.detailValue} numberOfLines={2}>
              {challenge.audienceName ?? challenge.audience}
            </Text>
            {challenge.responseUri && (
              <>
                <Text style={styles.detailLabel}>Sent to</Text>
                <Text style={styles.detailValue} numberOfLines={2}>{challenge.responseUri}</Text>
              </>
            )}
            {!challenge.responseUri && (
              <>
                <Text style={styles.detailLabel}>Delivery</Text>
                <Text style={styles.detailValue}>No destination given. You will send it yourself.</Text>
              </>
            )}
          </View>
          <Button label="Approve and sign" onPress={handleApprove} variant="primary" size="large" fullWidth />
        </>
      )}

      {phase === 'signing' && (
        <Text style={styles.body}>Waiting for your fingerprint to sign the presentation…</Text>
      )}

      {phase === 'done' && (
        <>
          <View style={styles.resultRow}>
            <Ionicons name="checkmark-circle" size={26} color={colors.semantic.success} />
            <Text style={styles.resultText}>The verifier received the presentation.</Text>
          </View>
          {receiptId && <Text style={styles.receipt}>Receipt {receiptId}</Text>}
          <Button label="Close" onPress={onClose} variant="primary" size="large" fullWidth />
        </>
      )}

      {phase === 'manual' && (
        <>
          <Text style={styles.body}>
            The verifier did not give an address, so send them the presentation directly. It is valid only for this exchange.
          </Text>
          {receiptId && <Text style={styles.receipt}>Receipt {receiptId}</Text>}
          <Button label="Send presentation" onPress={handleSharePresentation} variant="primary" size="large" fullWidth />
        </>
      )}

      {phase === 'error' && (
        <>
          <Text style={styles.errorText}>{message}</Text>
          <TouchableOpacity onPress={onClose} style={styles.linkButton} accessibilityRole="button">
            <Text style={styles.linkText}>Close</Text>
          </TouchableOpacity>
        </>
      )}
    </BottomSheet>
  );
}

const styles = StyleSheet.create({
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
    marginBottom: spacing.md,
  },
  headerText: { flex: 1 },
  title: {
    fontSize: fontSizes.lg,
    fontWeight: fontWeights.bold,
    color: colors.text.primary,
  },
  subtitle: {
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
    marginTop: spacing.xs,
  },
  qrWrap: {
    alignItems: 'center',
    marginVertical: spacing.md,
  },
  qr: {
    width: 240,
    height: 240,
    borderRadius: borderRadius.md,
    backgroundColor: colors.surface.card,
  },
  body: {
    fontSize: fontSizes.md,
    color: colors.text.secondary,
    marginBottom: spacing.md,
    lineHeight: 20,
  },
  detailBox: {
    backgroundColor: colors.surface.input,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginBottom: spacing.md,
    gap: spacing.xs,
  },
  detailLabel: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    textTransform: 'uppercase',
    fontWeight: fontWeights.semibold,
  },
  detailValue: {
    fontSize: fontSizes.sm,
    color: colors.text.primary,
    marginBottom: spacing.sm,
  },
  resultRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    marginBottom: spacing.md,
  },
  resultText: {
    fontSize: fontSizes.md,
    color: colors.text.primary,
    flex: 1,
  },
  receipt: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    marginBottom: spacing.md,
  },
  errorText: {
    fontSize: fontSizes.md,
    color: colors.semantic.error,
    marginBottom: spacing.md,
  },
  linkButton: {
    alignSelf: 'center',
    padding: spacing.md,
  },
  linkText: {
    color: colors.brand.primary,
    fontSize: fontSizes.md,
    fontWeight: fontWeights.semibold,
  },
  spacer: { height: spacing.sm },
});
