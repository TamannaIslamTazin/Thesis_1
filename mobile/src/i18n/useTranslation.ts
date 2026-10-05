/**
 * useTranslation — the hook a screen calls to read strings.
 *
 * Kept out of `i18n/index.ts` on purpose: that module is pure and testable with
 * no React and no store, which is what let `translate()` be checked directly. The
 * hook is the only part that needs the settings context, so it lives here.
 *
 * The language is NOT a module global. A screen cannot render in a language the
 * caller did not ask for, and a test can call `translate('bn', …)` without
 * mounting anything.
 */
import { useCallback } from 'react';

import { useSettings } from '../contexts/SettingsContext';
import { translate, type Language, type TParams } from './index';

export interface Translation {
  /** Translate a key, substituting `{{name}}` placeholders. */
  readonly t: (key: string, params?: TParams) => string;
  readonly language: Language;
}

export function useTranslation(): Translation {
  const { language } = useSettings();

  const t = useCallback(
    (key: string, params?: TParams) => translate(language, key, params),
    [language],
  );

  return { t, language };
}
