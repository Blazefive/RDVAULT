// ========================================
// TESTS : useAuth — messages d'échec de connexion traduits (I18N-27)
// ========================================
// Après un mauvais mot de passe, le toast mêlait la langue de l'interface et du français codé
// en dur : « Authentication failed : Requête invalide. Tentative échouée. 4 tentative(s)
// restante(s) avant blocage. ». Le motif HTTP, le nombre d'essais restants, le blocage et les
// erreurs de validation de l'identifiant / du mot de passe passent désormais par t(), et le
// séparateur « : » (typographie française) n'est plus imposé aux autres langues.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { useAuth } from './useAuth';
import { I18nProvider, useTranslation } from '../i18n';
import bruteForceProtection from '../bruteForceProtection';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
global.IS_REACT_ACT_ENVIRONMENT = true;

const noop = () => {};
let root = null;
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
  sessionStorage.clear();
  jest.restoreAllMocks();
  axios.post.mockReset();
  axios.get.mockReset();
});

// Monte useAuth dans un vrai I18nProvider (vraies locales) et collecte les toasts
async function mountAuth(lang) {
  localStorage.setItem('rdvault-lang', lang);
  const api = { current: null };
  const toasts = [];
  function Harness() {
    const { t } = useTranslation();
    api.current = useAuth({
      vaultUrl: 'https://vault.test', ldapAuthPath: 'auth/ldap', showToast: (m) => toasts.push(m), t,
      vaultApiRef: { current: { baseHeaders: () => ({}), axiosConfig: (c) => c } },
      fetchEnginesLikeUiRef: { current: async () => {} }, setSecretEngines: noop, setSelectedEngine: noop, setSecrets: noop,
      setCurrentView: noop, setVisiblePasswords: noop, setAllVaultSecrets: noop, setDiscoveredTags: noop,
      setMultiVaultSearch: noop, setSelectedSecrets: noop, setSearchState: { setSearch: noop, setSearchInput: noop },
    });
    return null;
  }
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  const mountInRoot = (reactRoot, element) => reactRoot.render(element); // hors Testing Library
  await act(async () => { mountInRoot(root, <I18nProvider><Harness /></I18nProvider>); });
  return { api, toasts };
}

async function attemptLogin(api, user, pass) {
  await act(async () => { api.current.setAuthUser(user); api.current.setPassword(pass); });
  await act(async () => { await api.current.handleLogin(); });
}

// Aucune trace des messages français de bruteForceProtection / sanitizeError / validation.js
const FRENCH = /Tentative|tentative|Requête|Compte|bloqué|caractères|username est|Une erreur/;

describe('I18N-27 : toast d\'échec de connexion entièrement dans la langue de l\'interface', () => {
  test('anglais : mauvais mot de passe (HTTP 400) → motif et essais restants traduits, « : » anglais', async () => {
    const { api, toasts } = await mountAuth('en');
    axios.post.mockRejectedValueOnce({ response: { status: 400 } });
    await attemptLogin(api, 'i18n-alice', 'wrong-password');
    expect(toasts).toHaveLength(1);
    expect(toasts[0]).not.toMatch(FRENCH);
    expect(toasts[0]).not.toContain(' : ');
    expect(toasts[0]).toBe('Authentication failed: Invalid request. 4 attempt(s) left before lockout.');
  });

  test('allemand : 403 → « Zugriff verweigert »', async () => {
    const { api, toasts } = await mountAuth('de');
    axios.post.mockRejectedValueOnce({ response: { status: 403 } });
    await attemptLogin(api, 'i18n-bob', 'wrong-password');
    expect(toasts[0]).not.toMatch(FRENCH);
    expect(toasts[0]).toContain('Authentifizierung fehlgeschlagen: Zugriff verweigert');
    expect(toasts[0]).toContain('4');
  });

  test('français : le texte reste en français, avec l\'espace avant « : »', async () => {
    const { api, toasts } = await mountAuth('fr');
    axios.post.mockRejectedValueOnce({ response: { status: 400 } });
    await attemptLogin(api, 'i18n-claire', 'wrong-password');
    expect(toasts[0]).toBe('Échec de l\'authentification : Requête invalide. 4 tentative(s) restante(s) avant blocage.');
  });

  test('statut inconnu (418) → message générique traduit', async () => {
    const { api, toasts } = await mountAuth('en');
    axios.post.mockRejectedValueOnce({ response: { status: 418 } });
    await attemptLogin(api, 'i18n-dan', 'wrong-password');
    expect(toasts[0]).toBe('Authentication failed: An error occurred. 4 attempt(s) left before lockout.');
  });

  test('5e échec : blocage annoncé dans la langue de l\'interface (plus « Trop de tentatives échouées »)', async () => {
    const { api, toasts } = await mountAuth('en');
    // 4 échecs espacés d'une minute (un échec pendant le délai exponentiel n'est pas décompté),
    // puis la 5e tentative une fois le dernier délai (8 s) écoulé
    const realNow = Date.now();
    const clock = jest.spyOn(Date, 'now');
    for (let i = 0; i < 4; i++) {
      clock.mockReturnValue(realNow + i * 61000);
      bruteForceProtection.registerFailedAttempt('i18n-erin');
    }
    clock.mockReturnValue(realNow + 4 * 61000);
    axios.post.mockRejectedValueOnce({ response: { status: 400 } });
    await attemptLogin(api, 'i18n-erin', 'wrong-password');
    expect(toasts).toHaveLength(1);
    expect(toasts[0]).not.toMatch(FRENCH);
    expect(toasts[0]).toBe('Too many failed attempts. Account locked for 5 minutes.');
    bruteForceProtection.registerSuccessfulAttempt('i18n-erin');
  });

  test('identifiant avec caractère de contrôle : erreur de validation traduite (validation.js)', async () => {
    const { api, toasts } = await mountAuth('en');
    await attemptLogin(api, 'bad\u0001user', 'whatever-123');
    expect(axios.post).not.toHaveBeenCalled();
    expect(toasts).toEqual(['The username contains control characters']);
  });

  test('mot de passe trop long : erreur de validation traduite avec la borne', async () => {
    const { api, toasts } = await mountAuth('ja');
    await attemptLogin(api, 'i18n-fay', 'x'.repeat(1025));
    expect(axios.post).not.toHaveBeenCalled();
    expect(toasts).toEqual(['パスワードが長すぎます（最大1024文字）']);
  });
});
