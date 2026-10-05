/**
 * SSI Healthcare Mobile - QR Result Sheet
 *
 * A specialized sheet for handling QR scan results.
 * Replaces Alert.alert for credential offers, presentation requests, and DID exchanges.
 *
 * Integrates with:
 * - ssiClient for OID4VCI/OID4VP flows
 * - Backend Credo agent for cryptographic operations
 * - Plain language utilities for user-friendly messages
 * - Biometric authentication for secure sharing
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { failureMessage } from '../../utils/userFacingError';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ActivityIndicator,
  ScrollView,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { BottomSheet } from './BottomSheet';
import { DisclosureSheet } from './DisclosureSheet';
import {
  enumerateDisclosableClaims,
  claimRequestsFromPresentationRequest,
  type DisclosableClaim,
  type VerifierClaimRequest,
} from '@ssi-healthcare/sdk';
import type { WalletCredential } from '@ssi-healthcare/sdk';
import { ssiClient } from '../../services/ssiClient';
import { useCredentialStore } from '../../store/credentialStore';
import { listCredentialEnvelopes } from '../../db';
import { useConsentStore } from '../../store';
import { presentOverOid4vp, type Oid4vpRequest } from '../../services/presentation';
import { colors } from '../../theme/colors';
import * as Clipboard from 'expo-clipboard';
import { spacing } from '../../theme/spacing';
import { borderRadius } from '../../theme/borderRadius';
import { typography } from '../../theme/typography';
import {
  formatPresentationRequest,
  getPresentationSummary,
} from '../../utils/plainLanguage';
import type { ParsedQRCode } from '../../services/qrScanner';
import { QRCodeType } from '../../services/qrScanner';

/**
 * One entry from the SDK's `getMatchingCredentials`.
 *
 * The credential is the SDK's own `WalletCredential`, NOT a hand-written mirror.
 * A local copy typed `credentialJwt` as `unknown` and the compiler caught it —
 * which is the point: mirroring a type means the two drift silently the moment
 * either changes.
 */
type MatchingCredential = {
  credential: WalletCredential;
  matchedAttributes: string[];
};

/** What `formatPresentationRequest` returns; the util does not export it. */
type PreparedRequest = ReturnType<typeof formatPresentationRequest>;

/**
 * Rank matches so the credential that can honour MINIMISATION comes first.
 *
 * An sd-jwt (`~` in the compact form) can withhold claims; a plain `vc+jwt`
 * cannot, so presenting it discloses every claim it carries. Stable within each
 * group, so this only ever reorders across the sd-jwt / plain-jwt boundary.
 *
 * This is a DEFAULT, not a decision — see `handlePresentationRequest`, which now
 * asks the holder whenever more than one credential matches.
 */
/**
 * The one detail that tells two otherwise-identical credentials apart.
 *
 * A holder with two prescriptions sees two identical "Prescription" rows unless
 * something distinguishes them, and choosing blind is not choosing. This reads
 * the medicine's name from the SIGNED subject; when there is nothing to show it
 * returns null and the row falls back to a generic prompt rather than inventing
 * a label from an unsigned field.
 */
function readMedicineLabel(subject: Record<string, unknown>): string | null {
  const medication = subject.medication;
  if (medication && typeof medication === 'object') {
    const name = (medication as { name?: unknown }).name;
    const dosage = (medication as { dosage?: unknown }).dosage;
    if (typeof name === 'string' && name.trim().length > 0) {
      return typeof dosage === 'string' && dosage.trim().length > 0
        ? `${name} — ${dosage}`
        : name;
    }
  }
  return null;
}


/**
 * The credential types the verifier actually asked for.
 *
 * WHY THIS EXISTS, AND WHY THE SERVER'S FILTER WAS NOT ENOUGH.
 * `getMatchingCredentials` sends `types` to the backend, derived from
 * `request.requestedCredentials` — BUT THAT FIELD IS ABSENT from what the backend
 * serves. Measured 24 Sep 2026 against a live request: the response carries
 * `presentation_definition.input_descriptors[]` and no `requestedCredentials` at
 * all. So the type list was empty, no filter was sent, and the backend returned
 * EVERY credential the holder had.
 *
 * The result, at a pharmacy counter: the verifier asked for a
 * PrescriptionCredential and the wallet offered a HEALTH CARD, which the counter
 * then correctly refused. The holder was asked to choose from credentials that
 * could never satisfy the request.
 *
 * So the types are read HERE, from the request's own presentation definition
 * where they actually live. The OID4VP field is `filter.contains.const` — NOT
 * `filter.const`, which is the obvious wrong guess and yields nothing.
 *
 * The caller REFUSES when no type can be read. Offering everything is the
 * fail-open direction and is what produced this bug.
 */
function requestedTypes(request: {
  requestedCredentials?: unknown;
  presentation_definition?: {
    input_descriptors?: Array<{
      name?: unknown;
      constraints?: {
        fields?: Array<{ filter?: { const?: unknown; contains?: { const?: unknown } } }>;
      };
    }>;
  };
}): string[] {
  const out = new Set<string>();

  const rc = request.requestedCredentials;
  if (Array.isArray(rc)) {
    for (const entry of rc) {
      if (entry && typeof entry === 'object' && typeof (entry as { type?: unknown }).type === 'string') {
        out.add((entry as { type: string }).type);
      }
    }
  } else if (rc && typeof rc === 'object') {
    // The shape the backend persists internally: { types: [...] }.
    const types = (rc as { types?: unknown }).types;
    if (Array.isArray(types)) for (const t of types) if (typeof t === 'string') out.add(t);
  }

  // WHERE THEY ACTUALLY LIVE. The descriptor's `name` is the credential type for
  // the requests this system generates, and the field filter is the standard
  // place. Both are read, because a verifier may populate either.
  for (const d of request.presentation_definition?.input_descriptors ?? []) {
    if (typeof d.name === 'string' && d.name.length > 0) out.add(d.name);
    for (const f of d.constraints?.fields ?? []) {
      const containsConst = f.filter?.contains?.const;
      if (typeof containsConst === 'string') out.add(containsConst);
      const direct = f.filter?.const;
      if (typeof direct === 'string') out.add(direct);
    }
  }

  return [...out];
}

function rankForNarrowing(matches: MatchingCredential[]): MatchingCredential[] {
  return [...matches].sort((a, b) => {
    const aSd = a.credential?.credentialJwt?.includes('~') ? 0 : 1;
    const bSd = b.credential?.credentialJwt?.includes('~') ? 0 : 1;
    return aSd - bSd;
  });
}

// -- Types --

type QRResultStatus = 'preview' | 'choosing' | 'loading' | 'success' | 'error';

interface QRResultSheetProps {
  /** Whether the sheet is visible */
  visible: boolean;
  /** Callback when sheet is closed */
  onClose: () => void;
  /** The parsed QR code result */
  scanResult: ParsedQRCode | null;
  /** Callback when action is completed successfully */
  onSuccess?: () => void;
  /** Callback when action fails */
  onError?: (error: string) => void;
}

interface ResultConfig {
  icon: keyof typeof Ionicons.glyphMap;
  iconColor: string;
  iconBgColor: string;
  title: string;
  description: string;
  primaryAction: string;
  secondaryAction?: string;
}

// -- Configuration --

const RESULT_CONFIGS: Record<QRCodeType, ResultConfig> = {
  [QRCodeType.CREDENTIAL_OFFER]: {
    icon: 'document-text',
    iconColor: colors.semantic.success,
    iconBgColor: colors.semantic.successLight,
    title: 'Credential Offer',
    description: "You've been offered a verifiable credential. Review the details and accept to add it to your wallet.",
    primaryAction: 'Accept Credential',
    secondaryAction: 'Cancel',
  },
  [QRCodeType.PRESENTATION_REQUEST]: {
    icon: 'shield-checkmark',
    iconColor: colors.brand.primary,
    iconBgColor: colors.brand.primaryMuted,
    title: 'Verification Request',
    description: "A verifier is requesting to see your credentials. Only share what you're comfortable with.",
    primaryAction: 'Review & Share',
    secondaryAction: 'Decline',
  },
  [QRCodeType.PRESENTATION_CHALLENGE]: {
    // Reached only if a challenge somehow lands on the generic result path:
    // the scanner normally hands it straight to the waiting share session.
    icon: 'shield-checkmark',
    iconColor: colors.brand.primary,
    iconBgColor: colors.brand.primaryMuted,
    title: 'Verifier Response',
    description: 'This answers a share request you started. Open the share screen to approve it.',
    primaryAction: 'Continue',
    secondaryAction: 'Close',
  },
  [QRCodeType.DID]: {
    icon: 'finger-print',
    iconColor: colors.ui.purple,
    iconBgColor: colors.brand.primaryMuted,
    title: 'DID Detected',
    description: 'Found a decentralized identifier. You can copy it to use elsewhere.',
    primaryAction: 'Copy DID',
    secondaryAction: 'Close',
  },
  [QRCodeType.UNKNOWN]: {
    icon: 'help-circle',
    iconColor: colors.semantic.warning,
    iconBgColor: colors.semantic.warningLight,
    title: 'Unknown QR Code',
    description: 'This QR code format is not recognized by the SSI wallet.',
    primaryAction: 'Close',
  },
};

// -- Animation Constants --

const ACTION_FEEDBACK_DELAY_MS = 1500;

// -- Presentation Request State --

interface PresentationState {
  showShareSheet: boolean;
  verifierName: string;
  verifierVerified: boolean;
  verifierDid?: string;
  purpose: string;
  credentialType: string;
  credentialId: string;
  /** Every claim the ISSUER made selectively disclosable, as leaf paths. */
  disclosable: DisclosableClaim[];
  /** What this verifier stated it needs. Empty means it stated nothing. */
  claimRequests: VerifierClaimRequest[];
  presentationRequest: unknown;
  /**
   * The SIGNED artifact. A VC 2.0 credential carries its proof only in the
   * envelope, so presenting the rendered JSON would present something with no
   * signature attached (steno #185).
   */
  credentialJwt?: string;
  /** Whose key signs the presentation. */
  holderDid?: string;
}

// -- Component --

export function QRResultSheet({
  visible,
  onClose,
  scanResult,
  onSuccess,
  onError,
}: QRResultSheetProps) {
  const [status, setStatus] = useState<QRResultStatus>('preview');
  /**
   * Set when a request matches MORE THAN ONE credential and the holder has not
   * yet said which to share. Holding it here rather than picking silently is the
   * whole point: `ranked[0]` used to decide, and the holder was never told a
   * choice had been made for them.
   */
  const [candidates, setCandidates] = useState<{
    request: unknown;
    plainLanguageRequest: PreparedRequest;
    matches: MatchingCredential[];
  } | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [presentationState, setPresentationState] = useState<PresentationState | null>(null);
  /**
   * What the verifier is asking for, read BEFORE the holder is asked to agree.
   *
   * This slot used to render the raw `openid4vp://?request_uri=…` string, which
   * told a holder nothing they could act on — the decision "should I share?"
   * was offered next to a URL-encoded URI. The request carries the verifier's
   * name, its purpose and the exact claims it wants, so show those.
   */
  const [requestPreview, setRequestPreview] = useState<{
    verifierName: string;
    verifierDid: string;
    selfAsserted: boolean;
    recognised: boolean;
    purpose: string;
    claims: string[];
    types: string[];
  } | null>(null);
  
  // Ref for setTimeout cleanup to prevent memory leaks
  const successTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  
  // Cleanup timer on unmount or when sheet closes
  useEffect(() => {
    return () => {
      if (successTimerRef.current) {
        clearTimeout(successTimerRef.current);
        successTimerRef.current = null;
      }
    };
  }, []);

  // Reset state when sheet opens/closes
  React.useEffect(() => {
    if (visible) {
      setStatus('preview');
      setErrorMessage(null);
      setSuccessMessage(null);
      setPresentationState(null);
      setRequestPreview(null);

      // Fetch the request up front for a PRESENTATION only. A credential offer
      // is redeemed by a single-use code, so fetching it to preview it would
      // SPEND it — the mistake that once cost users the offer as well as the
      // error (steno #235).
      if (scanResult?.type === QRCodeType.PRESENTATION_REQUEST) {
        void (async () => {
          try {
            const request = await ssiClient.parsePresentationRequest(scanResult.rawData);
            const info = formatPresentationRequest(request);
            const claims = claimRequestsFromPresentationRequest(request).map((c) => c.path);
            setRequestPreview({
              verifierName: info.verifierName,
              verifierDid: info.verifierDid,
              selfAsserted: info.verifierNameIsSelfAsserted,
              recognised: info.isVerified,
              purpose: info.purpose,
              claims,
              types: info.requestedTypes,
            });
          } catch {
            // Leave the preview empty. The share attempt surfaces the real
            // error; failing quietly here avoids two errors for one cause.
          }
        })();
      }
    } else {
      // Clear any pending timers when sheet closes
      if (successTimerRef.current) {
        clearTimeout(successTimerRef.current);
        successTimerRef.current = null;
      }
    }
    // KEYED ON THE REQUEST, NOT ONLY ON VISIBILITY.
    //
    // A second request can arrive while this sheet is already open — a deep link
    // now makes that ordinary. With `[visible]` alone the reset never ran, so the
    // sheet kept rendering the PREVIOUS request's name, purpose and claim list
    // while holding the new one. The holder would have been reading request A
    // and approving request B, which is the worst possible failure for a consent
    // surface. Observed 9 Sep: an HMS login link rendered as a pharmacy request.
  }, [visible, scanResult]);

/**
 * Map the verifier's stated purpose onto `ConsentPurpose`.
 *
 * THE ENUM CANNOT SAY WHAT THE VERIFIER SAID. A pharmacy asking to "confirm
 * this is your health identity before dispensing" is recorded as TREATMENT,
 * which is close but is not their words. The fixed vocabulary is a property of
 * consent being a backend row; the holder-signed receipt in steno #279 carries
 * the verifier's own text and is the real fix. Documented here rather than
 * hidden behind a default.
 */
function consentPurposeFor(purpose: string): 'treatment' | 'insurance_claim' | 'research' | 'emergency' | 'referral' {
  // LOWERCASE on the wire. `ConsentPurpose` members are TREATMENT etc. in the
  // schema but each carries `@map("treatment")`, and the API validates the
  // mapped value — sending the member name is rejected as an invalid enum.
  const p = purpose.toLowerCase();
  if (p.includes('emergency')) return 'emergency';
  if (p.includes('insurance') || p.includes('claim')) return 'insurance_claim';
  if (p.includes('research') || p.includes('study')) return 'research';
  if (p.includes('referral') || p.includes('refer')) return 'referral';
  return 'treatment';
}

/** `verifiedAt` -> `Verified at`, `prescriber.name` -> `Prescriber name`. */
function formatClaimName(path: string): string {
  const words = path
    .split('.')
    .join(' ')
    .replace(/\[(\d+)\]/g, ' $1')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

  const config = scanResult 
    ? RESULT_CONFIGS[scanResult.type] || RESULT_CONFIGS[QRCodeType.UNKNOWN]
    : RESULT_CONFIGS[QRCodeType.UNKNOWN];

  // -- Handlers --

  const handleCredentialOffer = useCallback(async () => {
    if (!scanResult?.rawData) {
      setStatus('error');
      setErrorMessage('Invalid credential offer data');
      return;
    }

    setStatus('loading');

    try {
      // The rawData is the scanned `openid-credential-offer://` URI. The client
      // runs the OID4VCI pre-authorized code flow against the issuer named IN
      // the offer; the issuer signs and returns the credential.
      const issued = await ssiClient.acceptCredentialOffer({
        uri: scanResult.rawData,
      });

      // WRITE IT DOWN. The issuer keeps no copy for us — only the national
      // backend used to persist on accept — so without this the credential is
      // received, reported as success, and then discarded. Writing it into the
      // local encrypted database also enqueues it for the datastore sync.
      const issuedJwt = (issued as { credential?: unknown } | null)?.credential;
      if (typeof issuedJwt === 'string' && issuedJwt.length > 0) {
        await useCredentialStore.getState().ingestIssuedCredential(issuedJwt);
      } else {
        await useCredentialStore.getState().refreshCredentials();
      }

      setStatus('success');
      setSuccessMessage('Credential added to your wallet!');
      
      successTimerRef.current = setTimeout(() => {
        onSuccess?.();
        onClose();
      }, ACTION_FEEDBACK_DELAY_MS);
    } catch (error) {
      setStatus('error');
      const message = failureMessage(error);
      setErrorMessage(message);
      onError?.(message);
    }
  }, [scanResult, onSuccess, onError, onClose]);

  /**
   * Build the presentation state for ONE chosen credential.
   *
   * Split out of `handlePresentationRequest` so that the single-match path and
   * the holder-chosen path run the SAME code. Two copies of the disclosure
   * wiring is how the dark pattern of #225 got in — the sheet's behaviour drifted
   * from the policy module's intent because the logic lived in more than one
   * place.
   *
   * @param match  one entry from `rankForNarrowing`, already ranked
   */
  const preparePresentation = useCallback(
    (match: MatchingCredential, request: unknown, plainLanguageRequest: PreparedRequest) => {
      const credential = match.credential;
      // on the envelope. Reading `credential.credentialSubject` yielded `{}`,
      // which is why this share sheet listed no fields to disclose.
      const credentialSubject = credential.credential.credentialSubject || {};
      
      // Determine credential type
      const credentialTypes = credential.type || [];
      const specificType = credentialTypes.find((t: string) => t !== 'VerifiableCredential') || 'Credential';

      // ===================================================================
      // WHAT THE HOLDER IS OFFERED, AND WHAT IS PRE-SELECTED
      // ===================================================================
      // Both come from the shared disclosure policy module rather than from
      // this component. What replaced what, and why it mattered:
      //
      //   WAS: `sharing: matchedAttributes.includes(key) || matchedAttributes.length === 0`
      //        `matchedAttributes` is every claim on the credential (the SDK
      //        derives it from `Object.keys(credentialSubject)`), so this was
      //        `true` for every field — the sheet opened with EVERYTHING
      //        switched on. It also set `required` from the same list, and the
      //        old sheet disables required switches, so every field was on AND
      //        locked. The holder's only available action was "Share".
      //
      //        That is the dark pattern in its complete form: it produced full
      //        disclosure on every presentation while recording a consent event
      //        that made the disclosure look chosen.
      //
      //   NOW: the verifier states what it needs, and only that is pre-selected.
      //        Anything else is one deliberate tap each. See the header of
      //        DisclosureSheet.tsx for the six decisions this rests on.
      //
      // `enumerateDisclosableClaims` also walks INTO containers and arrays, so
      // a holder can disclose one medication out of three or a prescriber's
      // licence without their name — choices the flat `Object.entries` above
      // could not express at all.
      const disclosableClaims = enumerateDisclosableClaims(credentialSubject);
      const claimRequests = claimRequestsFromPresentationRequest(request, specificType);

      // Set presentation state to show the disclosure sheet
      setPresentationState({
        showShareSheet: true,
        verifierName: plainLanguageRequest.verifierName,
        verifierVerified: plainLanguageRequest.isVerified,
        // From the RESOLVED request, not `request.verifier`: an OID4VP
        // authorization request names the verifier in `client_id`, so reading
        // `.verifier` left this undefined and the consent write was rejected
        // with "must start with did:".
        verifierDid: plainLanguageRequest.verifierDid || undefined,
        purpose: plainLanguageRequest.purpose,
        credentialType: specificType,
        credentialId: credential.id,
        disclosable: disclosableClaims,
        claimRequests,
        presentationRequest: request,
        credentialJwt: credential.credentialJwt,
        holderDid: credential.credential.credentialSubject?.id,
      });

      setStatus('preview');
    },
    [],
  );

  const handlePresentationRequest = useCallback(async () => {
    if (!scanResult?.rawData) {
      setStatus('error');
      setErrorMessage('Invalid presentation request');
      return;
    }

    setStatus('loading');

    try {
      // Parse the presentation request using SDK (async with JWT verification)
      const request = await ssiClient.parsePresentationRequest(scanResult.rawData);

      // Get matching credentials from wallet
      //
      // A FAILURE TO LOOK IS NOT AN ANSWER OF "NONE". An expired session made
      // this call return nothing, and the holder was told they hold no matching
      // credential while holding one — a message that names neither the cause
      // nor the right subsystem, and that a holder can do nothing about because
      // it describes their wallet rather than their session. Same class as
      // treating an unresolvable status list as "not revoked" (#163/#184), and
      // as the break-glass alarm rendering a failed check as all-clear (#419).
      // =====================================================================
      // MATCH AGAINST WHAT THIS WALLET HOLDS — NOT AGAINST THE SERVER'S LIST.
      // =====================================================================
      // This used `ssiClient.getMatchingCredentials(request)`, which reads the
      // BACKEND's credential list. A credential the wallet received straight from
      // an issuer (the HMS) is stored LOCALLY and is not in that list — so the
      // holder was told "you do not hold PrescriptionCredential" while the
      // prescription sat on the device. Measured 24 Sep 2026: the patient's four
      // server-side credentials were ALL health cards, and the prescription was
      // local-only.
      //
      // The wallet is the authority on what the wallet holds. `listCredentialEnvelopes`
      // is the same store everything else reads, so this cannot disagree with the
      // Cards screen.
      const wantedTypes = requestedTypes(request as never);
      if (wantedTypes.length === 0) {
        setStatus('error');
        setErrorMessage(
          'This request does not say which kind of credential it wants, so it cannot be answered safely.',
        );
        return;
      }

      let held: WalletCredential[];
      try {
        held = await listCredentialEnvelopes();
      } catch (error) {
        setStatus('error');
        const detail = failureMessage(error);
        setErrorMessage(
          `Could not read your credentials, so this is NOT confirmation that none match. ${detail}`,
        );
        return;
      }

      const matches: MatchingCredential[] = held
        .filter((credential) =>
          (credential.type ?? []).some((t) => wantedTypes.includes(t)),
        )
        .map((credential) => ({ credential, matchedAttributes: [] }));

      // Transform request into plain language using our utility
      const plainLanguageRequest = formatPresentationRequest(request);

      // PREFER A CREDENTIAL THIS WALLET CAN ACTUALLY NARROW.
      //
      // When several credentials satisfy the request, the one that can honour
      // the holder's selection is strictly better than one that cannot: a
      // `vc+jwt` has no disclosures to withhold, so presenting it discloses
      // every claim it carries no matter what the holder chose.
      //
      // BUT RANKING IS NOT CHOOSING. This used to take `ranked[0]` and proceed,
      // so when a holder had two prescriptions the tiebreak silently decided
      // which one was dispensed (steno: PHARMACY-FLOW-REVIEW.md, flaw A's
      // neighbourhood). The ranking now survives as the DEFAULT SELECTION and
      // the holder confirms it — see `preparePresentation`.
      if (matches.length === 0) {
        setStatus('error');
        setErrorMessage(
          `This request asks for ${wantedTypes.join(' or ')}, which you do not hold. Nothing was shared.`,
        );
        return;
      }

      const ranked = rankForNarrowing(matches);

      if (ranked.length > 1) {
        setStatus('choosing');
        setCandidates({ request, plainLanguageRequest, matches: ranked });
        return;
      }

      preparePresentation(ranked[0], request, plainLanguageRequest);
    } catch (error) {
      setStatus('error');
      const message = failureMessage(error);
      setErrorMessage(message);
      onError?.(message);
    }
  }, [scanResult, onError, preparePresentation]);


  const handleShareConfirm = useCallback(async (selectedPaths: string[]) => {
    if (!presentationState?.presentationRequest || !presentationState.credentialId) {
      setStatus('error');
      setErrorMessage('No presentation request to submit');
      return;
    }

    setStatus('loading');

    try {
      // NO SEPARATE BIOMETRIC CHECK HERE, deliberately.
      //
      // `biometricAuthService.authenticate()` returns a BOOLEAN over the JS
      // bridge and protects nothing — a caller that ignores it proceeds anyway
      // (steno #375). The real gate is that signing the presentation needs the
      // seed, and the seed is stored under `requireAuthentication`, so the
      // prompt raised inside `presentOverOid4vp` is one the holder cannot skip:
      // refuse it and there is no key, and therefore no presentation.

      // The holder's choice, carried as claim PATHS.
      //
      // These are already exactly what was chosen — the sheet hands back the
      // selected set rather than the full list with flags, so there is no
      // second filtering step here that could disagree with what the holder was
      // shown. A disclosure UI whose "what I displayed" and "what I submit"
      // are computed twice is a UI that can lie by accident.
      // Build and sign the presentation ON THIS DEVICE, then post it to the
      // verifier. `ssiClient.presentCredentials` used to be called here; it
      // posted attribute NAMES to a route that no longer exists and asked the
      // server to sign on the holder's behalf. See services/presentation.ts.
      //
      // THE CONSENT RECEIPT TRAVELS WITH IT. Consent is no longer a separate
      // authenticated call made after the fact — that attempt failed silently
      // for two reasons at once (an expired session, and a foreign key
      // requiring the verifier to be a registered user of our backend), and a
      // consent record the SERVER wrote on its own authority proved nothing
      // anyway. The holder signs the receipt here, on the device, in the same
      // unlocked session that signs the presentation (steno #279).
      const { receiptId } = await presentOverOid4vp({
        request: presentationState.presentationRequest as Oid4vpRequest,
        holderDid: presentationState.holderDid ?? '',
        credentialJwt: presentationState.credentialJwt ?? '',
        consent: {
          verifierName: presentationState.verifierName,
          purpose: presentationState.purpose,
          purposeCategory: consentPurposeFor(presentationState.purpose),
          credentialTypes: [presentationState.credentialType],
          // The holder's choice, carried as claim PATHS. The sheet hands back
          // exactly what was chosen rather than the full list with flags, so
          // there is no second filtering step here that could disagree with
          // what the holder was shown — a disclosure UI whose "what I displayed"
          // and "what I recorded" are computed twice can lie by accident.
          holderSelectedClaims: selectedPaths,
          requestedClaims: presentationState.claimRequests.map((r) => r.path),
        },
      });
      console.log('[consent] receipt signed and sent with the presentation:', receiptId);

      // Pull the record the backend wrote from that receipt, so the consent tab
      // reflects the share without a manual refresh.
      try {
        await useConsentStore.getState().fetchConsents();
      } catch {
        // The record exists regardless; this is only the local view of it.
      }

      setStatus('success');
      setSuccessMessage('Credential shared successfully!');
      setPresentationState(null);

      successTimerRef.current = setTimeout(() => {
        onSuccess?.();
        onClose();
      }, ACTION_FEEDBACK_DELAY_MS);
    } catch (error) {
      setStatus('error');
      const message = failureMessage(error);
      setErrorMessage(message);
      onError?.(message);
    }
  }, [presentationState, onSuccess, onError, onClose]);

  const handleShareClose = useCallback(() => {
    setPresentationState(null);
    setStatus('preview');
  }, []);

  const handleCopyDID = useCallback(async () => {
    if (!scanResult?.rawData) return;

    try {
      await Clipboard.setStringAsync(scanResult.rawData);
      setStatus('success');
      setSuccessMessage('DID copied to clipboard');

      successTimerRef.current = setTimeout(() => {
        onSuccess?.();
        onClose();
      }, ACTION_FEEDBACK_DELAY_MS);
    } catch (error) {
      setStatus('error');
      setErrorMessage('Failed to copy DID');
    }
  }, [scanResult, onSuccess, onClose]);

  const handlePrimaryAction = useCallback(() => {
    if (!scanResult) {
      onClose();
      return;
    }

    switch (scanResult.type) {
      case QRCodeType.CREDENTIAL_OFFER:
        handleCredentialOffer();
        break;
      case QRCodeType.PRESENTATION_REQUEST:
        handlePresentationRequest();
        break;
      case QRCodeType.DID:
        handleCopyDID();
        break;
      default:
        onClose();
    }
  }, [scanResult, handleCredentialOffer, handlePresentationRequest, handleCopyDID, onClose]);

  const handleSecondaryAction = useCallback(() => {
    onClose();
  }, [onClose]);

  // -- Render Helpers --

  const renderIcon = () => {
    if (status === 'loading') {
      return (
        <View style={[styles.iconContainer, { backgroundColor: colors.surface.elevated }]}>
          <ActivityIndicator size="large" color={colors.brand.primary} />
        </View>
      );
    }

    if (status === 'success') {
      return (
        <View style={[styles.iconContainer, { backgroundColor: colors.semantic.successLight }]}>
          <Ionicons name="checkmark-circle" size={48} color={colors.semantic.success} />
        </View>
      );
    }

    if (status === 'error') {
      return (
        <View style={[styles.iconContainer, { backgroundColor: colors.semantic.errorLight }]}>
          <Ionicons name="alert-circle" size={48} color={colors.semantic.error} />
        </View>
      );
    }

    return (
      <View style={[styles.iconContainer, { backgroundColor: config.iconBgColor }]}>
        <Ionicons name={config.icon} size={48} color={config.iconColor} />
      </View>
    );
  };

  const renderContent = () => {
    if (status === 'loading') {
      return (
        <>
          <Text style={styles.title}>Processing...</Text>
          <Text style={styles.description}>
            Please wait while we securely process your request.
          </Text>
        </>
      );
    }

    if (status === 'success') {
      return (
        <>
          <Text style={styles.title}>Success!</Text>
          <Text style={styles.description}>{successMessage}</Text>
        </>
      );
    }

    if (status === 'error') {
      return (
        <>
          <Text style={styles.title}>Something went wrong</Text>
          <Text style={styles.description}>{errorMessage}</Text>
        </>
      );
    }

    if (status === 'choosing' && candidates) {
      return (
        <>
          <Text style={styles.title}>Which one will you share?</Text>
          <Text style={styles.description}>
            {`${candidates.plainLanguageRequest.verifierName} asked for a credential, and you hold more than one that fits. Nothing is sent until you pick one and confirm what to disclose.`}
          </Text>

          <ScrollView style={styles.candidateList} contentContainerStyle={styles.candidateListContent}>
            {candidates.matches.map((match, index) => {
              const types = match.credential.type ?? [];
              const specific =
                types.find((t: string) => t !== 'VerifiableCredential') ?? 'Credential';
              const subject = match.credential.credential?.credentialSubject ?? {};
              // The distinguishing detail, read from what the ISSUER signed. A
              // list of two rows both reading "Prescription" would ask the holder
              // to choose blind, which is the failure this screen exists to fix.
              const medicine = readMedicineLabel(subject);

              return (
                <TouchableOpacity
                  key={match.credential.id}
                  style={[styles.candidate, index === 0 && styles.candidateDefault]}
                  activeOpacity={0.8}
                  onPress={() => handleCandidateChosen(match)}
                >
                  <Text style={styles.candidateType}>{formatClaimName(specific)}</Text>
                  {medicine ? (
                    <Text style={styles.candidateDetail}>{medicine}</Text>
                  ) : (
                    <Text style={styles.candidateDetail}>Tap to share this one</Text>
                  )}
                  {index === 0 && (
                    <Text style={styles.candidateBadge}>
                      Recommended — this one can withhold claims you do not choose
                    </Text>
                  )}
                </TouchableOpacity>
              );
            })}
          </ScrollView>

          <Text style={styles.previewNote}>
            You choose what to disclose on the next screen. Nothing is sent yet.
          </Text>
        </>
      );
    }

    return (
      <>
        <Text style={styles.title}>{config.title}</Text>
        <Text style={styles.description}>{config.description}</Text>
        
        {/* WHO is asking, WHY, and for WHAT — before the holder is asked to agree. */}
        {requestPreview && (
          <View style={styles.dataPreview}>
            <Text style={styles.dataLabel}>Who is asking</Text>
            <Text style={styles.previewValue}>{requestPreview.verifierName}</Text>
            <Text style={styles.previewNote}>
              {requestPreview.recognised
                ? 'This wallet recognises this organisation.'
                : requestPreview.selfAsserted
                  ? 'This name is what they call themselves. This wallet does not recognise them.'
                  : 'This wallet does not recognise this organisation.'}
            </Text>
            <Text style={styles.previewDid} numberOfLines={1}>{requestPreview.verifierDid}</Text>

            {requestPreview.purpose ? (
              <>
                <Text style={[styles.dataLabel, styles.previewSpacer]}>Why</Text>
                <Text style={styles.previewValue}>{requestPreview.purpose}</Text>
              </>
            ) : null}

            <Text style={[styles.dataLabel, styles.previewSpacer]}>
              What they are asking for
            </Text>
            {requestPreview.claims.length > 0 ? (
              requestPreview.claims.map((claim) => (
                <Text key={claim} style={styles.previewValue}>{`\u2022 ${formatClaimName(claim)}`}</Text>
              ))
            ) : (
              <Text style={styles.previewValue}>
                {requestPreview.types.join(', ') || 'A credential'}
              </Text>
            )}
            <Text style={styles.previewNote}>
              You choose what to share on the next screen. Nothing is sent yet.
            </Text>
          </View>
        )}
      </>
    );
  };

  /**
   * The holder picked one of several matching credentials.
   *
   * Proceeds through the SAME `preparePresentation` the single-match path uses,
   * so a chosen presentation and an automatic one cannot diverge in how they
   * disclose or sign.
   */
  const handleCandidateChosen = useCallback(
    (match: MatchingCredential) => {
      if (!candidates) return;
      const { request, plainLanguageRequest } = candidates;
      setCandidates(null);
      preparePresentation(match, request, plainLanguageRequest);
    },
    [candidates, preparePresentation],
  );

  const handleCloseSheet = useCallback(() => {
    if (status !== 'loading') {
      onClose();
    }
  }, [status, onClose]);

  const renderActions = () => {
    if (status === 'loading') return null;

    // The choice IS the action: tapping a row proceeds. Offering a Share button
    // here would imply a credential was already selected.
    if (status === 'choosing') return null;

    if (status === 'success' || status === 'error') {
      return (
        <View style={styles.actions}>
          <TouchableOpacity
            style={[styles.button, styles.buttonPrimary]}
            onPress={onClose}
            activeOpacity={0.8}
          >
            <Text style={styles.buttonPrimaryText}>Done</Text>
          </TouchableOpacity>
        </View>
      );
    }

    return (
      <View style={styles.actions}>
        {config.secondaryAction && (
          <TouchableOpacity
            style={[styles.button, styles.buttonSecondary]}
            onPress={handleSecondaryAction}
            activeOpacity={0.8}
          >
            <Text style={styles.buttonSecondaryText}>{config.secondaryAction}</Text>
          </TouchableOpacity>
        )}
        <TouchableOpacity
          style={[styles.button, styles.buttonPrimary]}
          onPress={handlePrimaryAction}
          activeOpacity={0.8}
        >
          <Text style={styles.buttonPrimaryText}>{config.primaryAction}</Text>
        </TouchableOpacity>
      </View>
    );
  };

  return (
    <>
      <BottomSheet
        visible={visible && !presentationState?.showShareSheet}
        onClose={handleCloseSheet}
        // 0.75, not the 0.5 default. This sheet now states who is asking, why,
        // and every claim they want, which is the information the holder needs
        // BEFORE deciding — it should be readable without scrolling in the
        // common case, with the scroll there for a long request.
        snapPoint={0.75}
      >
        <View style={styles.container}>
          {renderIcon()}
          {renderContent()}
          {renderActions()}
        </View>
      </BottomSheet>

      {presentationState?.showShareSheet && (
        <DisclosureSheet
          visible={true}
          onClose={handleShareClose}
          onConfirm={handleShareConfirm}
          credentialType={presentationState.credentialType}
          recipient={{
            name: presentationState.verifierName,
            verified: presentationState.verifierVerified,
            purpose: presentationState.purpose,
            did: presentationState.verifierDid,
          }}
          disclosable={presentationState.disclosable}
          requests={presentationState.claimRequests}
        />
      )}
    </>
  );
}

// -- Styles --

const styles = StyleSheet.create({
  container: {
    alignItems: 'center',
    paddingHorizontal: spacing.lg,
    paddingBottom: spacing.xl,
  },
  iconContainer: {
    width: 80,
    height: 80,
    borderRadius: 40,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: spacing.lg,
  },
  title: {
    ...typography.headingMd,
    color: colors.text.primary,
    textAlign: 'center',
    marginBottom: spacing.sm,
  },
  description: {
    ...typography.bodyMedium,
    color: colors.text.secondary,
    textAlign: 'center',
    marginBottom: spacing.lg,
    lineHeight: 22,
  },
  dataPreview: {
    width: '100%',
    backgroundColor: colors.surface.elevated,
    borderRadius: borderRadius.md,
    padding: spacing.md,
    marginBottom: spacing.lg,
  },
  dataLabel: {
    ...typography.labelMedium,
    color: colors.text.tertiary,
    marginBottom: spacing.xs,
  },
  dataScrollView: {
    maxHeight: 40,
  },
  dataText: {
    ...typography.mono,
    color: colors.text.secondary,
    fontSize: 12,
  },
  previewValue: {
    ...typography.bodyMedium,
    color: colors.text.primary,
    marginBottom: spacing.xxs,
  },
  previewNote: {
    ...typography.bodySmall,
    color: colors.text.tertiary,
    marginTop: spacing.xxs,
  },
  // -- The candidate chooser ------------------------------------------------
  // Capped so two or three matches scroll INSIDE the sheet instead of pushing
  // the confirm row past the sheet's own padding — the defect that hid the
  // disclosure sheet's footer under the navigation bar (measured y=2360..2400
  // of 2400 despite a correct inset).
  candidateList: {
    maxHeight: 320,
    alignSelf: 'stretch',
  },
  candidateListContent: {
    paddingBottom: spacing.xs,
  },
  candidate: {
    borderWidth: 1,
    borderColor: colors.border.subtle,
    borderRadius: borderRadius.md,
    padding: spacing.sm,
    marginTop: spacing.xs,
  },
  candidateDefault: {
    borderColor: colors.brand.primary,
  },
  candidateType: {
    ...typography.bodyMedium,
    color: colors.text.primary,
  },
  candidateDetail: {
    ...typography.bodySmall,
    color: colors.text.secondary,
    marginTop: spacing.xxs,
  },
  candidateBadge: {
    ...typography.bodySmall,
    color: colors.brand.primary,
    marginTop: spacing.xxs,
  },
  previewDid: {
    ...typography.mono,
    color: colors.text.tertiary,
    fontSize: 11,
    marginTop: spacing.xxs,
  },
  previewSpacer: {
    marginTop: spacing.md,
  },
  actions: {
    flexDirection: 'row',
    gap: spacing.md,
    width: '100%',
  },
  button: {
    flex: 1,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    alignItems: 'center',
    justifyContent: 'center',
  },
  buttonPrimary: {
    backgroundColor: colors.brand.primary,
  },
  buttonSecondary: {
    backgroundColor: colors.surface.elevated,
    borderWidth: 1,
    borderColor: colors.border.default,
  },
  buttonPrimaryText: {
    ...typography.labelMedium,
    color: colors.base.white,
  },
  buttonSecondaryText: {
    ...typography.labelMedium,
    color: colors.text.secondary,
  },
});

export default QRResultSheet;
