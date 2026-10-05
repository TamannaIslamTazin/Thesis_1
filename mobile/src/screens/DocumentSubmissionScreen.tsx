/**
 * SSI Healthcare Mobile - Document Submission Screen
 *
 * IDENTITY-AND-ISSUANCE-SPEC.md §2-3: the holder picks a document type —
 * never an authority — and the type determines where the submission routes.
 * Documents are encrypted on-device before anything leaves it
 * (services/documentSubmission.ts); this screen is the UI around that
 * orchestration, not a second place any of that logic lives.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { showAlert } from '../components/AppAlertHost';
import { failureMessage } from '../utils/userFacingError';
import { View, Text, ScrollView, StyleSheet, Alert } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as DocumentPicker from 'expo-document-picker';
import { File } from 'expo-file-system';
import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';

import { colors, spacing, fontSizes, fontWeights, borderRadius } from '../theme';
import { Card, Button, LoadingSpinner, ErrorState, SectionHeader, Badge } from '../components/common';
import { apiService } from '../services';
import {
  fetchDocumentType,
  submitIssuanceDocuments,
  SubmitIssuanceRequestError,
  type PickedDocument,
} from '../services/documentSubmission';
import { useAuth } from '../contexts';
import type { RootStackParamList } from '../types';

type DocumentTypeOption = Awaited<ReturnType<typeof apiService.getDocumentTypes>>['documentTypes'][number];

type NavigationProp = NativeStackNavigationProp<RootStackParamList>;

type ScreenState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; documentTypes: DocumentTypeOption[] };

export default function DocumentSubmissionScreen() {
  const { user } = useAuth();
  const navigation = useNavigation<NavigationProp>();
  const [state, setState] = useState<ScreenState>({ status: 'loading' });
  const [selectedTypeId, setSelectedTypeId] = useState<string | null>(null);
  const [documents, setDocuments] = useState<PickedDocument[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const loadDocumentTypes = useCallback(async () => {
    setState({ status: 'loading' });
    try {
      const { documentTypes } = await apiService.getDocumentTypes();
      setState({ status: 'ready', documentTypes });
    } catch (error) {
      setState({
        status: 'error',
        message: failureMessage(error),
      });
    }
  }, []);

  useEffect(() => {
    loadDocumentTypes();
  }, [loadDocumentTypes]);

  const selectedType = useMemo(() => {
    if (state.status !== 'ready' || !selectedTypeId) return null;
    return state.documentTypes.find((d) => d.id === selectedTypeId) ?? null;
  }, [state, selectedTypeId]);

  const handlePickDocument = useCallback(async () => {
    if (!selectedType) return;
    const acceptedMediaTypes = new Set(
      selectedType.requiredDocuments.flatMap((slot) => slot.acceptedMediaTypes),
    );
    const result = await DocumentPicker.getDocumentAsync({
      type: [...acceptedMediaTypes],
      copyToCacheDirectory: true,
      multiple: false,
    });
    if (result.canceled || result.assets.length === 0) return;

    const asset = result.assets[0];
    const mimeType = asset.mimeType ?? '';
    if (!acceptedMediaTypes.has(mimeType)) {
      showAlert(
        'Unsupported file type',
        `'${mimeType || 'unknown'}' is not accepted for ${selectedType.label}. Accepted: ${[...acceptedMediaTypes].join(', ')}.`,
      );
      return;
    }

    try {
      const file = new File(asset.uri);
      const buffer = await file.arrayBuffer();
      setDocuments((prev) => [
        ...prev,
        { uri: asset.uri, name: asset.name, mimeType, bytes: new Uint8Array(buffer) },
      ]);
    } catch (error) {
      showAlert('Could not read file', failureMessage(error));
    }
  }, [selectedType]);

  const handleRemoveDocument = useCallback((uri: string) => {
    setDocuments((prev) => prev.filter((d) => d.uri !== uri));
  }, []);

  const handleSubmit = useCallback(async () => {
    if (!selectedType) return;
    setSubmitError(null);
    setSubmitting(true);
    try {
      const documentType = await fetchDocumentType(selectedType.id);
      const result = await submitIssuanceDocuments(documentType, documents, user?.did ?? '');
      setDocuments([]);
      setSelectedTypeId(null);
      showAlert('Submitted', `Your ${selectedType.label} submission is now pending review.`, [
        { text: 'View status', onPress: () => (navigation as any).navigate('SubmissionStatus', { focusRequestId: result.id }) },
      ]);
    } catch (error) {
      const message =
        error instanceof SubmitIssuanceRequestError
          ? `${error.message} (failed at: ${error.stage}). Nothing was left half-submitted — you can retry from scratch.`
          : error instanceof Error
            ? error.message
            : String(error);
      setSubmitError(message);
    } finally {
      setSubmitting(false);
    }
  }, [selectedType, documents, navigation]);

  if (state.status === 'loading') {
    return <LoadingSpinner fullScreen message="Loading document types…" />;
  }
  if (state.status === 'error') {
    return <ErrorState message={state.message} onRetry={loadDocumentTypes} />;
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <SectionHeader title="Submit documents for verification" />
      <Text style={styles.helperText}>
        Choose what you are applying for. The document type decides which authority reviews
        it — you never choose the authority directly.
      </Text>

      <View style={styles.typeList}>
        {state.documentTypes.map((type) => (
          <Card
            key={type.id}
            variant={selectedTypeId === type.id ? 'success' : 'default'}
            onPress={() => {
              setSelectedTypeId(type.id);
              setDocuments([]);
              setSubmitError(null);
            }}
            style={styles.typeCard}
            accessibilityLabel={`Select ${type.label}`}
          >
            <View style={styles.typeCardRow}>
              <View style={styles.typeCardText}>
                <Text style={styles.typeLabel}>{type.label}</Text>
                <Text style={styles.typeAuthority}>Reviewed by {type.issuingAuthorityName}</Text>
              </View>
              {selectedTypeId === type.id && (
                <Ionicons name="checkmark-circle" size={22} color={colors.semantic.success} />
              )}
            </View>
          </Card>
        ))}
      </View>

      {selectedType && (
        <>
          <SectionHeader title="Documents" />
          <Text style={styles.helperText}>
            Required: {selectedType.requiredDocuments.map((slot) => slot.label).join(', ')}.
            Accepted formats: {selectedType.requiredDocuments[0]?.acceptedMediaTypes.join(', ')}.
          </Text>

          {documents.map((doc) => (
            <Card key={doc.uri} style={styles.docCard}>
              <View style={styles.typeCardRow}>
                <Text style={styles.docName} numberOfLines={1}>{doc.name}</Text>
                <Button
                  label="Remove"
                  variant="ghost"
                  size="small"
                  onPress={() => handleRemoveDocument(doc.uri)}
                />
              </View>
            </Card>
          ))}

          <Button
            label="Attach a document"
            icon="attach"
            variant="outline"
            onPress={handlePickDocument}
            fullWidth
            style={styles.attachButton}
          />

          {submitError && <Text style={styles.errorText}>{submitError}</Text>}

          <Button
            label={submitting ? 'Submitting…' : 'Submit for review'}
            onPress={handleSubmit}
            disabled={documents.length === 0 || submitting}
            loading={submitting}
            fullWidth
            style={styles.submitButton}
          />
          <Text style={styles.privacyNote}>
            Documents are encrypted on this device before upload. The backend never sees them —
            only the reviewing authority, once you submit, can decrypt them.
          </Text>
        </>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.background.primary },
  content: { padding: spacing.md, paddingBottom: spacing.xxl },
  helperText: {
    fontSize: fontSizes.sm,
    color: colors.text.secondary,
    marginBottom: spacing.md,
  },
  typeList: { gap: spacing.sm, marginBottom: spacing.md },
  typeCard: { marginBottom: spacing.sm },
  typeCardRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  typeCardText: { flex: 1 },
  typeLabel: { fontSize: fontSizes.md, fontWeight: fontWeights.semibold, color: colors.text.primary },
  typeAuthority: { fontSize: fontSizes.sm, color: colors.text.secondary, marginTop: 2 },
  docCard: { marginBottom: spacing.sm },
  docName: { flex: 1, fontSize: fontSizes.sm, color: colors.text.primary, marginRight: spacing.sm },
  attachButton: { marginBottom: spacing.md },
  submitButton: { marginTop: spacing.sm },
  errorText: { color: colors.semantic.error, fontSize: fontSizes.sm, marginBottom: spacing.sm },
  privacyNote: {
    fontSize: fontSizes.xs,
    color: colors.text.tertiary,
    marginTop: spacing.sm,
    textAlign: 'center',
  },
});
