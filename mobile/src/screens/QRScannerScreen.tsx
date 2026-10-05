/**
 * SSI Healthcare Mobile - QR Scanner Screen
 *
 * Scans QR codes for:
 * - OID4VCI Credential Offers
 * - OID4VP Presentation Requests
 * - DID exchanges
 *
 * REFACTORED to use:
 * - Design tokens from theme system
 * - useCallback for event handlers
 * - Proper TypeScript types
 * - Accessibility attributes
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Dimensions,
  Animated,
} from 'react-native';
import { CameraView, useCameraPermissions, BarcodeScanningResult } from 'expo-camera';
import { Ionicons } from '@expo/vector-icons';
import { useNavigation, useRoute, RouteProp } from '@react-navigation/native';
import { qrScannerService, QRCodeType, ParsedQRCode } from '../services';
import { usePresentationShareStore } from '../store/presentationShareStore';
import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';
import { withOpacity } from '../theme/colors';
import { LoadingSpinner, Button } from '../components/common';
import { QRResultSheet } from '../components/sheets/QRResultSheet';
import { useCredentialStore } from '../store';
import type { RootStackParamList } from '../types';

// -- Constants --

const { width } = Dimensions.get('window');
const SCAN_AREA_SIZE = width * 0.7;
const ERROR_AUTO_DISMISS_MS = 3000;

// -- Types --

type QRScannerRouteProp = RouteProp<RootStackParamList, 'Scanner'>;

interface QRScannerScreenProps {
  onScanComplete?: (result: ParsedQRCode) => void;
}

// -- Permission View Component --

interface PermissionViewProps {
  onRequest: () => void;
  onCancel: () => void;
}

const PermissionView = React.memo<PermissionViewProps>(({ onRequest, onCancel }) => (
  <View style={styles.container}>
    <View style={styles.permissionContainer}>
      <Ionicons name="camera-outline" size={64} color={colors.text.disabled} />
      <Text style={styles.permissionTitle}>Camera Permission Required</Text>
      <Text style={styles.permissionText}>
        We need camera access to scan QR codes for receiving credentials and
        responding to verification requests.
      </Text>
      <Button
        label="Grant Permission"
        onPress={onRequest}
        variant="primary"
        size="large"
        style={styles.permissionButton}
        accessibilityHint="Opens system permission dialog"
      />
      <Button
        label="Go Back"
        onPress={onCancel}
        variant="ghost"
        size="medium"
        accessibilityHint="Returns to previous screen"
      />
    </View>
  </View>
));

PermissionView.displayName = 'PermissionView';

// -- Scan Result View Component --

interface ScanResultViewProps {
  result: ParsedQRCode;
  onAction: () => void;
  onRescan: () => void;
}

const ScanResultView = React.memo<ScanResultViewProps>(({ result, onAction, onRescan }) => {
  const iconName = result.type === QRCodeType.CREDENTIAL_OFFER
    ? 'document-text'
    : result.type === QRCodeType.PRESENTATION_REQUEST
    ? 'shield-checkmark'
    : 'finger-print';

  return (
    <View style={styles.resultContainer} accessibilityLabel={`Scanned ${qrScannerService.getTypeDescription(result.type)}`}>
      <View style={styles.resultBadge}>
        <Ionicons name={iconName} size={24} color={colors.brand.primary} />
        <Text style={styles.resultType}>
          {qrScannerService.getTypeDescription(result.type)}
        </Text>
      </View>

      <View style={styles.resultActions}>
        <Button
          label={qrScannerService.getActionText(result.type)}
          onPress={onAction}
          variant="primary"
          size="medium"
          style={styles.actionButton}
        />
        <Button
          label="Scan Again"
          onPress={onRescan}
          variant="outline"
          size="medium"
          style={styles.rescanButton}
        />
      </View>
    </View>
  );
});

ScanResultView.displayName = 'ScanResultView';

// -- Corner Component --

interface CornerProps {
  position: 'topLeft' | 'topRight' | 'bottomLeft' | 'bottomRight';
}

const Corner = React.memo<CornerProps>(({ position }) => (
  <View style={[styles.corner, styles[position]]} />
));

Corner.displayName = 'Corner';

// -- Screen Component --

export default function QRScannerScreen({ onScanComplete }: QRScannerScreenProps) {
  const navigation = useNavigation();
  const route = useRoute<QRScannerRouteProp>();
  const mode = route.params?.mode || 'receive';
  const { refreshCredentials } = useCredentialStore();

  const [permission, requestPermission] = useCameraPermissions();
  const [scanned, setScanned] = useState(false);
  const [scanning, setScanning] = useState(true);
  const [flashEnabled, setFlashEnabled] = useState(false);
  const [scanResult, setScanResult] = useState<ParsedQRCode | null>(null);
  const [showResultSheet, setShowResultSheet] = useState(false);
  const [invalidScanMessage, setInvalidScanMessage] = useState<string | null>(null);

  // Animation for scan line
  const scanLineAnim = useRef(new Animated.Value(0)).current;
  const errorTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const animation = Animated.loop(
      Animated.sequence([
        Animated.timing(scanLineAnim, {
          toValue: 1,
          duration: 2000,
          useNativeDriver: true,
        }),
        Animated.timing(scanLineAnim, {
          toValue: 0,
          duration: 2000,
          useNativeDriver: true,
        }),
      ])
    );
    animation.start();

    return () => animation.stop();
  }, [scanLineAnim]);

  // Cleanup error auto-dismiss timer on unmount
  useEffect(() => {
    return () => {
      if (errorTimerRef.current) clearTimeout(errorTimerRef.current);
    };
  }, []);

  const resetScanner = useCallback(() => {
    setScanned(false);
    setScanning(true);
    setScanResult(null);
    setShowResultSheet(false);
    setInvalidScanMessage(null);
  }, []);

  const handleBarcodeScanned = useCallback(
    (result: BarcodeScanningResult) => {
      if (scanned) return;

      setScanned(true);
      setScanning(false);

      const parsedResult = qrScannerService.validateScanResult(result);

      if (parsedResult) {
        // A verifier's answer belongs to the share session that is waiting for
        // it, not to this screen. Hand it over and get out of the way.
        if (parsedResult.type === QRCodeType.PRESENTATION_CHALLENGE) {
          usePresentationShareStore.getState().setPendingChallenge(parsedResult.rawData);
          navigation.goBack();
          return;
        }

        setScanResult(parsedResult);

        if (onScanComplete) {
          onScanComplete(parsedResult);
        }
      } else {
        // Show inline error instead of Alert.alert
        setInvalidScanMessage('The scanned QR code is not recognized. Try scanning again.');
        // Auto-reset after delay (tracked for cleanup on unmount)
        if (errorTimerRef.current) clearTimeout(errorTimerRef.current);
        errorTimerRef.current = setTimeout(resetScanner, ERROR_AUTO_DISMISS_MS);
      }
    },
    [scanned, onScanComplete, resetScanner, navigation]
  );

  const handleAction = useCallback(() => {
    if (!scanResult) return;
    // Open the QR result sheet instead of using Alert.alert
    setShowResultSheet(true);
  }, [scanResult]);

  const handleSheetClose = useCallback(() => {
    setShowResultSheet(false);
  }, []);

  const handleSheetSuccess = useCallback(() => {
    // Refresh credential store after accepting a credential
    refreshCredentials();
    navigation.goBack();
  }, [navigation, refreshCredentials]);

  const handleClose = useCallback(() => {
    navigation.goBack();
  }, [navigation]);

  const toggleFlash = useCallback(() => {
    setFlashEnabled((prev) => !prev);
  }, []);

  // Permission not determined yet
  if (!permission) {
    return <LoadingSpinner fullScreen message="Checking camera permission..." />;
  }

  // Permission denied
  if (!permission.granted) {
    return <PermissionView onRequest={requestPermission} onCancel={handleClose} />;
  }

  const scanLineTranslateY = scanLineAnim.interpolate({
    inputRange: [0, 1],
    outputRange: [0, SCAN_AREA_SIZE - 4],
  });

  return (
    <View style={styles.container}>
      <CameraView
        style={StyleSheet.absoluteFillObject}
        onBarcodeScanned={scanning ? handleBarcodeScanned : undefined}
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        enableTorch={flashEnabled}
        accessibilityLabel="Camera view for QR code scanning"
      >
        {/* Overlay with cutout */}
        <View style={styles.overlay}>
          {/* Header */}
          <View style={[styles.header, styles.dim]}>
            <TouchableOpacity
              style={styles.headerButton}
              onPress={handleClose}
              accessibilityRole="button"
              accessibilityLabel="Close scanner"
            >
              <Ionicons name="close" size={28} color={colors.text.inverse} />
            </TouchableOpacity>
            <Text style={styles.headerTitle}>
              {mode === 'share' ? 'Share Credential' : 'Scan QR Code'}
            </Text>
            <TouchableOpacity
              style={styles.headerButton}
              onPress={toggleFlash}
              accessibilityRole="button"
              accessibilityLabel={flashEnabled ? 'Turn off flash' : 'Turn on flash'}
            >
              <Ionicons
                name={flashEnabled ? 'flash' : 'flash-outline'}
                size={24}
                color={colors.text.inverse}
              />
            </TouchableOpacity>
          </View>

          {/* Scan area */}
          <View style={[styles.scanAreaContainer, styles.scanRow]}>
            <View style={styles.sideMask} />
            <View style={styles.scanArea} accessibilityLabel="QR code scan area">
              <Corner position="topLeft" />
              <Corner position="topRight" />
              <Corner position="bottomLeft" />
              <Corner position="bottomRight" />

              {scanning && (
                <Animated.View
                  style={[
                    styles.scanLine,
                    { transform: [{ translateY: scanLineTranslateY }] },
                  ]}
                />
              )}
            </View>
            <View style={styles.sideMask} />
          </View>

          {/* Instructions / Results */}
          <View style={[styles.footer, styles.dim]}>
            {invalidScanMessage ? (
              <View style={styles.errorContainer}>
                <Ionicons name="alert-circle" size={24} color={colors.semantic.error} />
                <Text style={styles.errorText}>{invalidScanMessage}</Text>
              </View>
            ) : scanResult ? (
              <ScanResultView
                result={scanResult}
                onAction={handleAction}
                onRescan={resetScanner}
              />
            ) : (
              <>
                <Text style={styles.instructions}>
                  Position a QR code inside the frame to scan
                </Text>
                <Text style={styles.supportedTypes}>
                  Supports: Credential Offers • Verification Requests • DIDs
                </Text>
              </>
            )}
          </View>
        </View>
      </CameraView>

      {/* QR Result Sheet - replaces Alert.alert */}
      <QRResultSheet
        visible={showResultSheet}
        onClose={handleSheetClose}
        scanResult={scanResult}
        onSuccess={handleSheetSuccess}
        onError={(error) => console.error('QR action failed:', error)}
      />
    </View>
  );
}

// -- Styles --

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background.primary,
  },
  // NO BACKGROUND HERE. This was a near-white 60% wash across the whole
  // camera, INCLUDING the scan window, so the one region that has to be
  // clearly visible was the same milky grey as everything else. A viewfinder
  // dims what is around the target, never the target.
  //
  // The mask is now four panels drawn around the scan window: the header and
  // footer carry their own dim, and the row holding the window has a dim strip
  // on each side. The window itself is left untouched.
  overlay: {
    flex: 1,
    backgroundColor: 'transparent',
  },
  dim: {
    backgroundColor: withOpacity(colors.base.black, 0.55),
  },
  scanRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  sideMask: {
    flex: 1,
    alignSelf: 'stretch',
    backgroundColor: withOpacity(colors.base.black, 0.55),
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingTop: 60,
    paddingHorizontal: spacing.lg,
    paddingBottom: spacing.lg,
  },
  headerButton: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: withOpacity(colors.base.black, 0.4),
    alignItems: 'center',
    justifyContent: 'center',
  },
  headerTitle: {
    fontSize: fontSizes.xl,
    fontWeight: fontWeights.bold,
    color: colors.text.inverse,
  },
  scanAreaContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  scanArea: {
    width: SCAN_AREA_SIZE,
    height: SCAN_AREA_SIZE,
    backgroundColor: 'transparent',
    borderRadius: borderRadius.lg,
    overflow: 'hidden',
  },
  corner: {
    position: 'absolute',
    width: 40,
    height: 40,
    borderColor: colors.brand.primary,
  },
  topLeft: {
    top: 0,
    left: 0,
    borderTopWidth: 4,
    borderLeftWidth: 4,
    borderTopLeftRadius: borderRadius.lg,
  },
  topRight: {
    top: 0,
    right: 0,
    borderTopWidth: 4,
    borderRightWidth: 4,
    borderTopRightRadius: borderRadius.lg,
  },
  bottomLeft: {
    bottom: 0,
    left: 0,
    borderBottomWidth: 4,
    borderLeftWidth: 4,
    borderBottomLeftRadius: borderRadius.lg,
  },
  bottomRight: {
    bottom: 0,
    right: 0,
    borderBottomWidth: 4,
    borderRightWidth: 4,
    borderBottomRightRadius: borderRadius.lg,
  },
  scanLine: {
    height: 4,
    backgroundColor: colors.brand.primary,
    shadowColor: colors.brand.primary,
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.8,
    shadowRadius: 8,
    elevation: 5,
  },
  footer: {
    padding: spacing.lg,
    paddingBottom: 50,
    alignItems: 'center',
  },
  instructions: {
    fontSize: fontSizes.lg,
    color: colors.text.inverse,
    textAlign: 'center',
    marginBottom: spacing.sm,
  },
  supportedTypes: {
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
    textAlign: 'center',
  },
  resultContainer: {
    width: '100%',
    backgroundColor: withOpacity(colors.text.inverse, 0.1),
    borderRadius: borderRadius.lg,
    padding: spacing.lg,
  },
  resultBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
    marginBottom: spacing.md,
  },
  resultType: {
    fontSize: fontSizes.xl,
    fontWeight: fontWeights.semibold,
    color: colors.text.inverse,
  },
  resultActions: {
    flexDirection: 'row',
    gap: spacing.md,
  },
  actionButton: {
    flex: 1,
  },
  rescanButton: {
    flex: 1,
  },
  permissionContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: spacing.xxl,
  },
  permissionTitle: {
    fontSize: fontSizes.xxl,
    fontWeight: fontWeights.bold,
    color: colors.text.primary,
    marginTop: spacing.lg,
    marginBottom: spacing.md,
    textAlign: 'center',
  },
  permissionText: {
    fontSize: fontSizes.md,
    color: colors.text.secondary,
    textAlign: 'center',
    lineHeight: 22,
    marginBottom: spacing.xl,
  },
  permissionButton: {
    marginBottom: spacing.md,
  },
  errorContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    backgroundColor: withOpacity(colors.semantic.error, 0.2),
    borderRadius: borderRadius.md,
    padding: spacing.md,
  },
  errorText: {
    fontSize: fontSizes.md,
    color: colors.text.inverse,
    flex: 1,
  },
});
