import { useEffect, useState } from 'react';
import { useT } from './i18n';

const KEY = 'minisoc.theme';

/** The saved choice, else the system's, else light. */
export function detectTheme() {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {
    // storage blocked: use the system's setting
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export const applyTheme = (theme) => { document.documentElement.dataset.theme = theme; };

export function ThemeSwitch() {
  const { t } = useT();
  const [theme, setTheme] = useState(detectTheme);
  useEffect(() => applyTheme(theme), [theme]);
  const next = theme === 'dark' ? 'light' : 'dark';
  const toggle = () => {
    setTheme(next);
    try { localStorage.setItem(KEY, next); } catch { /* the choice lasts until reload */ }
  };
  return (
    <button type="button" className="icon" onClick={toggle} aria-label={t(`theme.${next}`)} title={t(`theme.${next}`)}>
      {theme === 'dark' ? '☀️' : '🌙'}
    </button>
  );
}
