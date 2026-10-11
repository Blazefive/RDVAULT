// ========================================
// TESTS : fonctions de sécurité utilitaires (src/utils/security.js)
// ========================================

import axios from 'axios';
import {
  buildSafeUrl,
  encodeEnginePath,
  encodeSecretPath,
  sanitizeError,
  sanitizeErrorMessage,
  safeWindowOpen,
} from './security';
import { createVaultApi } from '../services/vaultApi';
import en from '../locales/en.json';

// axios 1.x est publié en ESM (non transformé par Jest/CRA) : simulé, aucun appel réseau ici
jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

describe('buildSafeUrl', () => {
  it('conserve les URLs http/https', () => {
    expect(buildSafeUrl('https://example.com/path')).toBe('https://example.com/path');
    expect(buildSafeUrl('http://intranet')).toBe('http://intranet');
  });

  it('ajoute https:// aux URLs sans schéma', () => {
    expect(buildSafeUrl('example.com')).toBe('https://example.com');
  });

  it('RBI-15 : un hôte qui commence par « http » n\'est pas un schéma (https:// ajouté)', () => {
    expect(buildSafeUrl('httpd.corp.local')).toBe('https://httpd.corp.local');
    expect(buildSafeUrl('httpbin.org:8080/get')).toBe('https://httpbin.org:8080/get');
    expect(buildSafeUrl('https-gateway.example.com')).toBe('https://https-gateway.example.com');
  });

  it('RBI-15 : schéma http(s) explicite conservé, quelle que soit la casse', () => {
    expect(buildSafeUrl('http://x')).toBe('http://x');
    expect(buildSafeUrl('HTTPS://x')).toBe('HTTPS://x');
    expect(buildSafeUrl('HTTP://intranet/app')).toBe('HTTP://intranet/app');
  });

  it('rejette les schémas dangereux et les valeurs invalides', () => {
    // eslint-disable-next-line no-script-url -- volontaire : charge utile malveillante que le test doit voir refusée
    expect(buildSafeUrl('javascript:alert(1)')).toBeNull();
    expect(buildSafeUrl('data:text/html,<b>x</b>')).toBeNull();
    expect(buildSafeUrl('')).toBeNull();
    expect(buildSafeUrl(null)).toBeNull();
    expect(buildSafeUrl(42)).toBeNull();
  });
});

describe('encodeEnginePath', () => {
  it('encode chaque segment en conservant les /', () => {
    expect(encodeEnginePath('users/john doe')).toBe('users/john%20doe');
    expect(encodeEnginePath('team/é')).toBe('team/%C3%A9');
  });

  it('retire les / de début et de fin', () => {
    expect(encodeEnginePath('/secret/')).toBe('secret');
    expect(encodeEnginePath('///a/b///')).toBe('a/b');
  });

  it('encode les caractères réservés', () => {
    expect(encodeEnginePath('a?b')).toBe('a%3Fb');
    expect(encodeEnginePath('a#b')).toBe('a%23b');
  });
});

describe('encodeSecretPath', () => {
  it('encode chaque segment en conservant les / (y compris le / final)', () => {
    expect(encodeSecretPath('dossier/sous dossier/clé')).toBe('dossier/sous%20dossier/cl%C3%A9');
    expect(encodeSecretPath('dossier/')).toBe('dossier/');
  });

  it('gère les valeurs vides', () => {
    expect(encodeSecretPath('')).toBe('');
    expect(encodeSecretPath(null)).toBe('');
    expect(encodeSecretPath(undefined)).toBe('');
  });

  it('neutralise les caractères de traversée et de requête', () => {
    expect(encodeSecretPath('a?list=true')).toBe('a%3Flist%3Dtrue');
  });
});

// Langue de l'interface : attribut lang du document (tenu à jour par I18nProvider)
function setUiLang(lang) {
  document.documentElement.lang = lang;
}

describe('sanitizeError', () => {
  afterEach(() => { setUiLang(''); localStorage.clear(); });

  it('retourne un message générique selon le statut HTTP (français inchangé)', () => {
    setUiLang('fr');
    expect(sanitizeError({ response: { status: 403 } })).toBe('Accès refusé');
    expect(sanitizeError({ response: { status: 404 } })).toBe('Ressource introuvable');
    expect(sanitizeError({ response: { status: 400 } })).toBe('Requête invalide');
  });

  it('retourne un message générique par défaut', () => {
    setUiLang('fr');
    expect(sanitizeError({})).toBe('Une erreur est survenue');
    expect(sanitizeError({ message: 'hvs.secretToken123456789012345' })).toBe('Une erreur est survenue');
    expect(sanitizeError(null)).toBe('Une erreur est survenue');
  });

  it('RBI-29 : traduit dans la langue de l\'interface (plus de français en dur)', () => {
    setUiLang('en');
    expect(sanitizeError({ response: { status: 400 } })).toBe('Invalid request');
    expect(sanitizeError({ response: { status: 418 } })).toBe('An error occurred');
    setUiLang('de');
    expect(sanitizeError({ response: { status: 403 } })).toBe('Zugriff verweigert');
  });
});

describe('sanitizeErrorMessage', () => {
  afterEach(() => { setUiLang(''); localStorage.clear(); });

  it('mappe les statuts HTTP connus (français inchangé)', () => {
    setUiLang('fr');
    expect(sanitizeErrorMessage({ response: { status: 401 } })).toBe('Non authentifié');
    expect(sanitizeErrorMessage({ response: { status: 403 } })).toBe('Accès refusé');
    expect(sanitizeErrorMessage({ response: { status: 429 } })).toBe('Trop de requêtes, réessayez plus tard');
    expect(sanitizeErrorMessage({ response: { status: 503 } })).toBe('Service temporairement indisponible');
  });

  it('mappe les statuts 5xx inconnus vers « Erreur serveur »', () => {
    setUiLang('fr');
    expect(sanitizeErrorMessage({ response: { status: 599 } })).toBe('Erreur serveur');
  });

  it('mappe les erreurs réseau', () => {
    setUiLang('fr');
    expect(sanitizeErrorMessage({ code: 'ECONNREFUSED' })).toBe('Connexion au serveur refusée');
    expect(sanitizeErrorMessage({ code: 'ECONNABORTED' })).toBe('Délai de connexion dépassé');
    expect(sanitizeErrorMessage({ code: 'ETIMEDOUT' })).toBe('Délai de connexion dépassé');
  });

  it('ne divulgue jamais le message original', () => {
    setUiLang('fr');
    const err = new Error('X-Vault-Token: hvs.abcdefghijklmnopqrstuvwxyz');
    const msg = sanitizeErrorMessage(err);
    expect(msg).toBe('Une erreur est survenue');
    expect(msg).not.toContain('hvs.');
  });

  it('accepte un message de repli personnalisé et des erreurs nulles', () => {
    setUiLang('fr');
    expect(sanitizeErrorMessage(null, 'Échec TOTP')).toBe('Échec TOTP');
    expect(sanitizeErrorMessage(undefined)).toBe('Une erreur est survenue');
  });

  it('RBI-29 : messages dans la langue de l\'interface (anglais, allemand, russe)', () => {
    setUiLang('en');
    expect(sanitizeErrorMessage(new Error('boom'))).toBe('An error occurred');
    expect(sanitizeErrorMessage({ response: { status: 403 } })).toBe('Access denied');
    expect(sanitizeErrorMessage({ code: 'ETIMEDOUT' })).toBe('Connection timed out');
    setUiLang('de');
    expect(sanitizeErrorMessage(new Error('boom'))).toBe('Ein Fehler ist aufgetreten');
    setUiLang('ru');
    expect(sanitizeErrorMessage(new Error('boom'))).toBe('Произошла ошибка');
  });

  it('RBI-29 : langue prise dans la préférence enregistrée à défaut d\'attribut lang, sinon anglais', () => {
    localStorage.setItem('rdvault-lang', 'es');
    expect(sanitizeErrorMessage({ response: { status: 404 } })).toBe('Recurso no encontrado');
    localStorage.clear();
    expect(sanitizeErrorMessage({ response: { status: 404 } })).toBe('Resource not found');
  });

  it('RBI-29 : t de l\'appelant prioritaire', () => {
    setUiLang('fr');
    const t = jest.fn((key) => `[${key}]`);
    expect(sanitizeErrorMessage({ response: { status: 403 } }, undefined, t)).toBe('[error.sanitized.forbidden]');
    expect(sanitizeError({ response: { status: 401 } }, t)).toBe('[error.sanitized.unauthenticated]');
    // t qui ne connaît pas la clé (renvoie la clé) → repli sur les locales
    expect(sanitizeErrorMessage({ response: { status: 403 } }, undefined, (k) => k)).toBe('Accès refusé');
  });

  it('RBI-29 : erreur de validation de l\'application → cause traduite au lieu du message générique', () => {
    setUiLang('en');
    // Erreur levée par vaultApi.writeSecretV2 pour des notes de 10 001 caractères
    const notes = new Error('Validation échouée: Notes trop longues (max 10000 caractères)');
    const msg = sanitizeErrorMessage(notes);
    expect(msg).toBe('Notes are too long (max 10000 characters)');
    expect(msg).not.toMatch(/Une erreur|échouée|trop longues/);
    setUiLang('de');
    expect(sanitizeErrorMessage(notes)).toBe('Notizen sind zu lang (max. 10000 Zeichen)');
    // Autre cause de validation : message de validation générique traduit (texte d'origine jamais affiché)
    setUiLang('en');
    const other = new Error('Validation échouée: Le nom contient des caractères interdits');
    expect(sanitizeErrorMessage(other)).toBe('Invalid data: check the length and format of the fields');
    expect(sanitizeErrorMessage(Object.assign(new Error('x'), { code: 'VALIDATION' }))).toBe('Invalid data: check the length and format of the fields');
  });

  it('RBI-29 : erreur réelle de vaultApi.writeSecretV2 (notes de 10 001 caractères) → limite indiquée, en anglais', async () => {
    setUiLang('en');
    const api = createVaultApi('https://vault.test', 'hvs.TOKEN');
    let caught = null;
    try {
      await api.writeSecretV2('coffre', { name: 'notes-longues', username: 'u', password: 'p', notes: 'x'.repeat(10001) });
    } catch (err) {
      caught = err;
    }
    expect(caught).not.toBeNull();
    expect(axios.post).not.toHaveBeenCalled();
    const toast = `${en.error.saveSecret} ${sanitizeErrorMessage(caught)}`;
    expect(toast).not.toMatch(/Une erreur|An error occurred/);
    expect(toast).toContain('10000');
  });

  it('RBI-29 : clé i18n posée par l\'application acceptée (espace « error. », clé existante, variables bornées)', () => {
    setUiLang('en');
    const err = Object.assign(new Error('interne'), { i18nKey: 'error.customFieldKeyTooLong', i18nVars: { index: 3, secret: 'x'.repeat(200) } });
    expect(sanitizeErrorMessage(err)).toBe('Field 3 name is too long (max 256 characters)');
    // Clé hors espace « error. » ou inconnue : ignorée (message générique), jamais le texte d'origine
    expect(sanitizeErrorMessage(Object.assign(new Error('hvs.TOKEN'), { i18nKey: 'login.title' }))).toBe('An error occurred');
    expect(sanitizeErrorMessage(Object.assign(new Error('hvs.TOKEN'), { i18nKey: 'error.nExistePas' }))).toBe('An error occurred');
  });
});

describe('safeWindowOpen', () => {
  let openSpy;

  beforeEach(() => {
    openSpy = jest.spyOn(window, 'open').mockImplementation(() => null);
  });

  afterEach(() => {
    openSpy.mockRestore();
  });

  it('ouvre les URLs http(s)/ftp(s) avec noopener,noreferrer', () => {
    safeWindowOpen('https://example.com');
    expect(openSpy).toHaveBeenCalledWith('https://example.com', '_blank', 'noopener,noreferrer');
    safeWindowOpen('ftp://files.example.com');
    expect(openSpy).toHaveBeenCalledTimes(2);
  });

  it('ignore les schémas dangereux et les URLs invalides', () => {
    // eslint-disable-next-line no-script-url -- volontaire : charge utile malveillante que le test doit voir ignorée
    safeWindowOpen('javascript:alert(1)');
    safeWindowOpen('file:///etc/passwd');
    safeWindowOpen('pas une url');
    expect(openSpy).not.toHaveBeenCalled();
  });
});
