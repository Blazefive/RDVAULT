// ========================================
// I18N — Système d'internationalisation
// ========================================
import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';

import en from './locales/en.json';
import fr from './locales/fr.json';
import es from './locales/es.json';
import de from './locales/de.json';
import ru from './locales/ru.json';
import zh from './locales/zh.json';
import pt from './locales/pt.json';
import it from './locales/it.json';
import ja from './locales/ja.json';
import ko from './locales/ko.json';
import ar from './locales/ar.json';
import tr from './locales/tr.json';

const locales = { en, fr, es, de, ru, zh, pt, it, ja, ko, ar, tr };

export const LANGUAGES = [
  { code: 'en', name: 'English', flag: '🇬🇧' },
  { code: 'fr', name: 'Français', flag: '🇫🇷' },
  { code: 'es', name: 'Español', flag: '🇪🇸' },
  { code: 'de', name: 'Deutsch', flag: '🇩🇪' },
  { code: 'ru', name: 'Русский', flag: '🇷🇺' },
  { code: 'zh', name: '中文', flag: '🇨🇳' },
  { code: 'pt', name: 'Português', flag: '🇧🇷' },
  { code: 'it', name: 'Italiano', flag: '🇮🇹' },
  { code: 'ja', name: '日本語', flag: '🇯🇵' },
  { code: 'ko', name: '한국어', flag: '🇰🇷' },
  { code: 'ar', name: 'العربية', flag: '🇸🇦' },
  { code: 'tr', name: 'Türkçe', flag: '🇹🇷' },
];

const I18nContext = createContext();

/**
 * Récupère une traduction par clé avec support des clés imbriquées (dot notation)
 * Ex: t('login.title') → locales[lang].login.title
 * Supporte les variables : t('toast.secretSaved', { name: 'test' }) → "Secret test saved"
 */
function getTranslation(translations, key, vars = {}) {
  const parts = key.split('.');
  let value = translations;
  for (const part of parts) {
    if (value == null) return key;
    value = value[part];
  }
  if (typeof value !== 'string') return key;
  // Remplacer les variables {{var}}
  return value.replace(/\{\{(\w+)\}\}/g, (_, name) => vars[name] ?? `{{${name}}}`);
}

export function I18nProvider({ children, defaultLang = 'en' }) {
  const [lang, setLang] = useState(() => {
    return localStorage.getItem('rdvault-lang') || defaultLang;
  });

  useEffect(() => {
    localStorage.setItem('rdvault-lang', lang);
  }, [lang]);

  const t = useCallback((key, vars) => {
    // Chercher dans la langue courante, fallback sur anglais
    const result = getTranslation(locales[lang], key, vars);
    if (result === key && lang !== 'en') {
      return getTranslation(locales.en, key, vars);
    }
    return result;
  }, [lang]);

  return (
    <I18nContext.Provider value={{ t, lang, setLang }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useTranslation() {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error('useTranslation must be used within I18nProvider');
  return ctx;
}
