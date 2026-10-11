// ========================================
// FONCTIONS DE SÉCURITÉ UTILITAIRES
// ========================================
// Extraites de App.jsx pour modularisation
// NOTE : sanitizeForDisplay et validateSecretName vivent dans src/validation.js
// (les doublons qui existaient ici ont été supprimés).

import ar from '../locales/ar.json';
import de from '../locales/de.json';
import en from '../locales/en.json';
import es from '../locales/es.json';
import fr from '../locales/fr.json';
import it from '../locales/it.json';
import ja from '../locales/ja.json';
import ko from '../locales/ko.json';
import pt from '../locales/pt.json';
import ru from '../locales/ru.json';
import tr from '../locales/tr.json';
import zh from '../locales/zh.json';
import { validationMessageKey } from '../validation';

const LOCALES = { ar, de, en, es, fr, it, ja, ko, pt, ru, tr, zh };

/**
 * SÉCURITÉ: Construit et valide une URL pour ouverture dans un navigateur/RBI
 * Rejette les protocoles dangereux (javascript:, data:, etc.)
 * Le préfixe https:// est ajouté à toute valeur sans schéma http(s) explicite : un hôte qui
 * COMMENCE par « http » (httpd.corp.local, httpbin.org) n'est pas un schéma.
 */
export const buildSafeUrl = (rawUrl) => {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  const url = /^https?:/i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    return url;
  } catch { return null; }
};

/**
 * Encode un chemin d'engine Vault segment par segment
 * Les engine names peuvent contenir des / (ex: users/john) mais chaque segment doit être encodé
 */
export const encodeEnginePath = (name) => {
  return name.replace(/^\/+|\/+$/g, '')
    .split('/')
    .map(segment => encodeURIComponent(segment))
    .join('/');
};

/**
 * Encode un chemin de secret (clé Vault) segment par segment, en conservant les /
 * Ex: "dossier/sous dossier/clé" → "dossier/sous%20dossier/cl%C3%A9"
 * Un "/" final (préfixe de dossier pour un listing) est conservé.
 */
export const encodeSecretPath = (path) => {
  return String(path ?? '')
    .split('/')
    .map(segment => encodeURIComponent(segment))
    .join('/');
};

// ========================================
// MESSAGES D'ERREUR ASSAINIS ET TRADUITS
// ========================================
// Le message d'origine (serveur, Axios, exception) n'est JAMAIS affiché : il peut contenir un
// jeton, un chemin ou une donnée sensible. On renvoie un message générique choisi d'après le
// statut HTTP, le code réseau, ou une cause applicative SÛRE (erreur de validation, clé i18n
// posée par le code de l'application), traduit dans la langue de l'interface :
// - via `t` si l'appelant le fournit ;
// - sinon dans la langue courante (attribut lang du document, que I18nProvider tient à jour,
//   puis préférence enregistrée), avec repli sur l'anglais.
const HTTP_STATUS_KEYS = {
  400: 'error.sanitized.badRequest',
  401: 'error.sanitized.unauthenticated',
  403: 'error.sanitized.forbidden',
  404: 'error.sanitized.notFound',
  429: 'error.sanitized.tooManyRequests',
  500: 'error.sanitized.server',
  502: 'error.sanitized.unavailable',
  503: 'error.sanitized.unavailable'
};
const GENERIC_KEY = 'error.sanitized.generic';
const VALIDATION_KEY = 'error.sanitized.validation';

// Erreurs de validation levées par l'application (vaultApi : « Validation échouée: … », texte de
// validation.js) : cause connue → clé traduite ; sinon message de validation générique.
const VALIDATION_PREFIX = 'Validation échouée';
const VALIDATION_CAUSES = [
  [/Notes trop longues/i, 'error.notesTooLong']
];

function lookup(locale, key) {
  let value = locale;
  for (const part of key.split('.')) {
    if (value == null || typeof value !== 'object') return null;
    value = value[part];
  }
  return typeof value === 'string' ? value : null;
}

function currentLang() {
  try {
    const lang = typeof document !== 'undefined' ? document.documentElement?.lang : '';
    if (lang && Object.prototype.hasOwnProperty.call(LOCALES, lang)) return lang;
  } catch { /* hors navigateur */ }
  try {
    const stored = localStorage.getItem('rdvault-lang');
    if (stored && Object.prototype.hasOwnProperty.call(LOCALES, stored)) return stored;
  } catch { /* stockage indisponible */ }
  return 'en';
}

/** Traduit une clé : `t` de l'appelant si fourni, sinon la langue courante (repli anglais) */
function translate(key, vars, t) {
  if (typeof t === 'function') {
    const viaT = t(key, vars);
    if (typeof viaT === 'string' && viaT && viaT !== key) return viaT;
  }
  const raw = lookup(LOCALES[currentLang()], key) ?? lookup(LOCALES.en, key) ?? key;
  return raw.replace(/\{\{(\w+)\}\}/g, (_, name) => (vars && vars[name] != null ? String(vars[name]) : `{{${name}}}`));
}

/**
 * Texte d'une clé i18n dans la langue de l'interface, pour les modules sans `t`
 * (ex. bruteForceProtection) : `t` de l'appelant si fourni, sinon langue courante, repli anglais.
 * @param {string} key
 * @param {Object} [vars]
 * @param {Function} [t]
 * @returns {string}
 */
export const translateKey = (key, vars, t) => translate(key, vars, t);

/** Variables d'une clé i18n applicative : nombres et courtes chaînes uniquement */
function safeVars(vars) {
  if (!vars || typeof vars !== 'object') return undefined;
  const out = {};
  for (const [k, v] of Object.entries(vars)) {
    if (typeof v === 'number' && Number.isFinite(v)) out[k] = v;
    else if (typeof v === 'string' && v.length <= 64) out[k] = v;
  }
  return out;
}

/**
 * Clé i18n d'une cause applicative sûre, ou null :
 * - `err.i18nKey` (+ `err.i18nVars`) posé par le code de l'application (espace « error. » et
 *   clé existante uniquement : jamais un texte venant d'un serveur) ;
 * - erreur de validation de l'application (`err.code === 'VALIDATION'` ou message
 *   « Validation échouée: … » de vaultApi) : premier code de `err.validationErrors`
 *   ([{ field, code, params }], posé par vaultApi) s'il a une traduction, sinon cause connue
 *   du message, sinon message de validation générique.
 */
function applicationCause(err) {
  if (!err || typeof err !== 'object') return null;
  if (typeof err.i18nKey === 'string' && /^error\.[A-Za-z0-9_.]+$/.test(err.i18nKey) && lookup(LOCALES.en, err.i18nKey)) {
    return { key: err.i18nKey, vars: safeVars(err.i18nVars) };
  }
  const message = typeof err.message === 'string' ? err.message : '';
  if (err.code === 'VALIDATION' || message.startsWith(VALIDATION_PREFIX)) {
    const first = Array.isArray(err.validationErrors) ? err.validationErrors.find(v => v && typeof v.code === 'string') : null;
    if (first && /^[A-Za-z0-9_]+$/.test(first.code)) {
      const key = validationMessageKey(first.code);
      if (lookup(LOCALES.en, key)) return { key, vars: safeVars(first.params) };
    }
    const known = VALIDATION_CAUSES.find(([re]) => re.test(message));
    return { key: known ? known[1] : VALIDATION_KEY };
  }
  return null;
}

/**
 * Masque les erreurs techniques sensibles (message générique traduit).
 * @param {*} err
 * @param {Function} [t] - fonction de traduction de l'appelant (useTranslation)
 */
export const sanitizeError = (err, t) => {
  const status = err?.response?.status;
  if (status && HTTP_STATUS_KEYS[status]) return translate(HTTP_STATUS_KEYS[status], undefined, t);
  const cause = applicationCause(err);
  if (cause) return translate(cause.key, cause.vars, t);
  // Message générique pour éviter l'exposition d'informations sensibles
  return translate(GENERIC_KEY, undefined, t);
};

/**
 * Message d'erreur assaini et traduit, plus complet que sanitizeError (réseau, 429, 5xx)
 * @param {*} err
 * @param {string} [fallbackMsg] - repli fourni par l'appelant (déjà traduit) ; défaut : message générique traduit
 * @param {Function} [t] - fonction de traduction de l'appelant (useTranslation)
 */
export const sanitizeErrorMessage = (err, fallbackMsg, t) => {
  // Priorité 1 : status HTTP connu → message générique
  const status = err?.response?.status;
  if (status && HTTP_STATUS_KEYS[status]) return translate(HTTP_STATUS_KEYS[status], undefined, t);
  if (status >= 500) return translate('error.sanitized.server', undefined, t);
  // Priorité 2 : cause applicative sûre (validation, clé i18n posée par l'application)
  const cause = applicationCause(err);
  if (cause) return translate(cause.key, cause.vars, t);
  // Priorité 3 : message réseau
  if (err?.code === 'ECONNREFUSED') return translate('error.sanitized.connectionRefused', undefined, t);
  if (err?.code === 'ECONNABORTED' || err?.code === 'ETIMEDOUT') return translate('error.sanitized.timeout', undefined, t);
  // Repli
  return typeof fallbackMsg === 'string' && fallbackMsg ? fallbackMsg : translate(GENERIC_KEY, undefined, t);
};

/**
 * Ouvre une URL de manière sécurisée dans un nouvel onglet
 * Vérifie que le protocole est autorisé
 */
export const safeWindowOpen = (url) => {
  try {
    const parsed = new URL(url);
    if (['http:', 'https:', 'ftp:', 'ftps:'].includes(parsed.protocol)) {
      window.open(url, '_blank', 'noopener,noreferrer');
    }
  } catch { /* URL invalide, ignorer */ }
};
