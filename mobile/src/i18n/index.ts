/**
 * Translation runtime — dependency-free, Bangla-ready.
 *
 * WHY NO i18n LIBRARY. The wallet runs in Hermes on the handset, and the
 * libraries worth using pull in `Intl` polyfills, plural rules and sometimes
 * native modules. What this app needs is small: a dot-path lookup, one
 * interpolation syntax, and a fallback that cannot show a raw KEY to a patient.
 * That is ~60 lines here and nothing to keep in step with an SDK upgrade.
 *
 * HOW TO TRANSLATE. Fill `bn.json`. Every key already exists there with an empty
 * value, generated from `en.json` so the two cannot drift:
 *
 *     node -e "..."   # or just edit bn.json by hand; keys are identical
 *
 * AN EMPTY OR MISSING TRANSLATION FALLS BACK TO ENGLISH, never to the key. A
 * patient reading `consent.dataTypesShared` would be worse than an untranslated
 * sentence, and this way a half-finished translation is still usable.
 *
 * WHAT IS DELIBERATELY NOT TRANSLATED:
 *   - a DID, a claim path, or any identifier from the wire
 *   - the word "DID" itself when it names the technology
 *   - dates and numbers: they are formatted by the platform locale, and
 *     `formatClaimLabel` already handles the English claim vocabulary.
 */
import en from './en.json';
import bn from './bn.json';

export type Language = 'en' | 'bn';

type Tree = { [key: string]: string | Tree };

const BUNDLES: Record<Language, Tree> = {
  en: en as Tree,
  bn: bn as Tree,
};

export const LANGUAGES: ReadonlyArray<{ code: Language; label: string }> = [
  { code: 'en', label: 'English' },
  { code: 'bn', label: 'বাংলা' },
];

/** Values substituted into `{{name}}` placeholders. */
export type TParams = Record<string, string | number>;

function lookup(tree: Tree, path: string): string | undefined {
  let node: string | Tree | undefined = tree;
  for (const part of path.split('.')) {
    if (typeof node !== 'object' || node === null) return undefined;
    node = node[part];
  }
  return typeof node === 'string' ? node : undefined;
}

function interpolate(template: string, params?: TParams): string {
  if (!params) return template;
  return template.replace(/\{\{(\w+)\}\}/g, (whole, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : whole,
  );
}

/**
 * Translate a key.
 *
 * `language` is passed in rather than read from a module global so a pure
 * `translate()` can be tested without a store, and so a screen cannot
 * accidentally render in a language the caller did not ask for.
 */
export function translate(language: Language, key: string, params?: TParams): string {
  const fromChosen = lookup(BUNDLES[language], key);
  // An empty string is "not yet translated", not a deliberate blank.
  if (fromChosen && fromChosen.length > 0) return interpolate(fromChosen, params);

  const fromEnglish = lookup(BUNDLES.en, key);
  if (fromEnglish && fromEnglish.length > 0) return interpolate(fromEnglish, params);

  // Nothing at all: return the key so it is obviously a bug in a screenshot,
  // rather than an empty space nobody notices.
  return key;
}

/** Every key that still needs a Bangla translation. Useful as a checklist. */
export function untranslatedKeys(): string[] {
  const walk = (node: Tree, prefix: string, out: string[]): void => {
    for (const [key, value] of Object.entries(node)) {
      const path = prefix ? `${prefix}.${key}` : key;
      if (typeof value === 'string') {
        if (value.trim().length === 0) out.push(path);
      } else {
        walk(value, path, out);
      }
    }
  };
  const missing: string[] = [];
  walk(BUNDLES.bn, '', missing);
  return missing;
}
