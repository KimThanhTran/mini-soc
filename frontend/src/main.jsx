import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { I18nProvider } from './i18n';
import { applyTheme, detectTheme } from './theme';
import './styles.css';

applyTheme(detectTheme());
createRoot(document.getElementById('root')).render(
  <I18nProvider>
    <App />
  </I18nProvider>,
);
