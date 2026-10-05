/**
 * Folder presentation for every credential category, in one place.
 *
 * The folder grid and the folder's own screen must agree on a category's name
 * and icon; when this lived inside one screen, the other had to guess.
 */
import type { Ionicons } from '@expo/vector-icons';
import type { CredentialCategory } from '../../types';
import { colors } from '../../theme';

export interface CategoryConfig {
  bg: string;
  border: string;
  icon: string;
  iconName: keyof typeof Ionicons.glyphMap;
  label: string;
}

export const CATEGORY_CONFIG: Record<CredentialCategory, CategoryConfig> = {
  medical_record: {
    bg: colors.categoryCard.medical.bg,
    border: colors.categoryCard.medical.border,
    icon: colors.categoryCard.medical.icon,
    iconName: 'document-text',
    label: 'Medical Records',
  },
  vaccination: {
    bg: colors.categoryCard.vaccination.bg,
    border: colors.categoryCard.vaccination.border,
    icon: colors.categoryCard.vaccination.icon,
    iconName: 'shield-checkmark',
    label: 'Vaccinations',
  },
  prescription: {
    bg: colors.categoryCard.prescription.bg,
    border: colors.categoryCard.prescription.border,
    icon: colors.categoryCard.prescription.icon,
    iconName: 'medical',
    label: 'Prescriptions',
  },
  lab_result: {
    bg: colors.categoryCard.lab.bg,
    border: colors.categoryCard.lab.border,
    icon: colors.categoryCard.lab.icon,
    iconName: 'flask',
    label: 'Lab Results',
  },
  insurance: {
    bg: colors.categoryCard.insurance.bg,
    border: colors.categoryCard.insurance.border,
    icon: colors.categoryCard.insurance.icon,
    iconName: 'card',
    label: 'Insurance',
  },
  emergency: {
    bg: colors.categoryCard.emergency.bg,
    border: colors.categoryCard.emergency.border,
    icon: colors.categoryCard.emergency.icon,
    iconName: 'medkit',
    label: 'Emergency',
  },
  identity: {
    bg: colors.categoryCard.identity.bg,
    border: colors.categoryCard.identity.border,
    icon: colors.categoryCard.identity.icon,
    iconName: 'person',
    label: 'Identity',
  },
  other: {
    bg: colors.categoryCard.other.bg,
    border: colors.categoryCard.other.border,
    icon: colors.categoryCard.other.icon,
    iconName: 'folder',
    label: 'Other',
  },
};
