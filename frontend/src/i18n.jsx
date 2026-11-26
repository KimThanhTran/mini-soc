import { createContext, useContext, useMemo, useState } from 'react';
import { dictionaries } from './locales';

export const LANGUAGES = [['en', 'English'], ['vi', 'Tiếng Việt']];
const KEY = 'minisoc.lang';
const LOCALE = { en: 'en-GB', vi: 'vi-VN' };

export function detectLanguage() {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved && dictionaries[saved]) return saved;
  } catch {
    // storage blocked: use the browser's language
  }
  return (typeof navigator !== 'undefined' && navigator.language?.toLowerCase().startsWith('vi')) ? 'vi' : 'en';
}

/** Looks a key up in a language, falls back to English and then to the key, and fills {placeholders}. */
export function translate(lang, key, params = {}) {
  const found = dictionaries[lang]?.[key] ?? dictionaries.en[key] ?? key;
  return found.replace(/\{(\w+)\}/g, (whole, name) => (params[name] === undefined ? whole : String(params[name])));
}

const Context = createContext({ lang: 'en', setLang() {}, t: (k, p) => translate('en', k, p), time: (iso) => iso });

export function I18nProvider({ children }) {
  const [lang, setLangState] = useState(detectLanguage);
  const value = useMemo(() => ({
    lang,
    setLang: (next) => {
      setLangState(next);
      document.documentElement.lang = next;
      try { localStorage.setItem(KEY, next); } catch { /* lasts until reload */ }
    },
    t: (key, params) => translate(lang, key, params),
    time: (iso) => new Date(iso).toLocaleTimeString(LOCALE[lang], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
  }), [lang]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export const useT = () => useContext(Context);
