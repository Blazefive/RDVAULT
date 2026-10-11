// ========================================
// TESTS : useAuth / LoginForm — premier démarrage non détecté (suite F2 n°3, AUTH-14)
// ========================================
// La détection GET /v1/sys/init échoue (délai, serveur pas encore prêt) : le formulaire reste en mode
// connexion. Le coffre local vide refuse alors la connexion (400 « password confirmation required »).
// Avant : échec décompté par l'anti-force brute et création impossible jusqu'au redémarrage.
// Désormais : aucune tentative décomptée, détection relancée, formulaire de création affiché.
import { act } from 'react';
import axios from 'axios';
import fr from './locales/fr.json';
import bruteForceProtection from './bruteForceProtection';
import {
  flush, installBridges, removeBridges, createHost, renderApp, setInput, toastText, quiet, logout,
} from './hooks/testUtils/appHarness.jsx';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const URL_LOCAL = 'http://127.0.0.1:51234';
const err400 = (message) => Object.assign(new Error('HTTP 400'), { response: { status: 400, data: { errors: [message] } } });

let host; let root; let initProbe; let accounts;
beforeEach(() => {
  jest.useFakeTimers();
  quiet();
  localStorage.clear();
  sessionStorage.clear();
  localStorage.setItem('rdvault-lang', 'fr');
  installBridges();
  bruteForceProtection.reset('admin');
  window.electronConfig ={ getConfig: async () => ({ success: true, config: { APP_MODE: 'local', VAULT_URL: URL_LOCAL } }) };
  ({ host, root } = createHost());
  accounts = 0;
  initProbe = jest.fn(() => Promise.reject(Object.assign(new Error('timeout of 5000ms exceeded'), { code: 'ECONNABORTED' })));
  axios.get.mockImplementation((url) => {
    const u = String(url);
    if (u.endsWith('/v1/sys/init')) return initProbe();
    if (u.includes('/v1/auth/token/lookup-self')) return Promise.resolve({ status: 200, data: { data: { entity_name: 'admin', policies: ['default'] } } });
    if (u.includes('/v1/sys/policies/acl/')) return Promise.resolve({ status: 200, data: { data: { policy: '' } } });
    if (u.endsWith('/v1/sys/mounts')) return Promise.resolve({ status: 200, data: {} });
    return Promise.reject(Object.assign(new Error('404'), { response: { status: 404, data: {} } }));
  });
  // Serveur local vide : la première connexion exige la confirmation (comme localVaultServer.js)
  axios.post.mockImplementation((url, body) => {
    const u = String(url);
    if (u.includes('/v1/auth/ldap/login/')) {
      if (accounts === 0) {
        if (typeof body?.confirm !== 'string') return Promise.reject(err400('password confirmation required'));
        if (body.confirm !== body.password) return Promise.reject(err400('password confirmation does not match'));
        accounts = 1;
      }
      return Promise.resolve({ status: 200, data: { auth: { client_token: 'tok-admin', lease_duration: 0 } } });
    }
    return Promise.resolve({ status: 204, data: {} });
  });
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
  removeBridges();
  delete window.electronConfig;
  jest.useRealTimers();
  jest.restoreAllMocks();
});

async function submitLogin(user, password, confirm) {
  const inputs = host.querySelectorAll('.login-form input');
  await act(async () => { setInput(inputs[0], user); });
  const pw = host.querySelectorAll('.login-form input[type="password"]');
  await act(async () => { setInput(pw[0], password); });
  if (confirm !== undefined) await act(async () => { setInput(pw[1], confirm); });
  await act(async () => { host.querySelector('.btn-login').click(); });
  await flush(80);
}

test('détection en échec puis 400 « password confirmation required » : formulaire de création, rien de décompté', async () => {
  await renderApp(root);
  await flush(20);
  expect(initProbe).toHaveBeenCalledTimes(1);
  expect(host.querySelectorAll('.login-form input[type="password"]')).toHaveLength(1);

  await submitLogin('admin', 'Phrase-de-passe-longue-42');
  expect(toastText()).toContain(fr.login.setupRequired);
  expect(bruteForceProtection.getStats('admin').attempts || 0).toBe(0);
  // Détection relancée ; formulaire de création (confirmation du mot de passe maître)
  expect(initProbe).toHaveBeenCalledTimes(2);
  expect(host.querySelectorAll('.login-form input[type="password"]')).toHaveLength(2);
  expect(host.textContent).toContain(fr.login.setupTitle);

  await submitLogin('admin', 'Phrase-de-passe-longue-42', 'Phrase-de-passe-longue-42');
  expect(accounts).toBe(1);
  const loginCall = axios.post.mock.calls.filter(c => String(c[0]).includes('/v1/auth/ldap/login/')).pop();
  expect(loginCall[1]).toEqual({ password: 'Phrase-de-passe-longue-42', confirm: 'Phrase-de-passe-longue-42' });
  expect(host.querySelector('.login-form')).toBeNull();

  // Déconnexion : compte créé, formulaire de connexion habituel (détection toujours en échec)
  await logout(host);
  expect(host.querySelector('.login-form')).not.toBeNull();
  expect(host.querySelectorAll('.login-form input[type="password"]')).toHaveLength(1);
});

test('détection relancée qui répond « compte existant » : retour au formulaire de connexion', async () => {
  await renderApp(root);
  await flush(20);
  initProbe.mockImplementation(() => Promise.resolve({ status: 200, data: { initialized: true } }));
  await submitLogin('admin', 'Phrase-de-passe-longue-42');
  await flush(20);
  expect(host.querySelectorAll('.login-form input[type="password"]')).toHaveLength(1);
  expect(host.textContent).not.toContain(fr.login.setupTitle);
});

test('autre 400 (identifiants) : formulaire inchangé, échec décompté comme avant', async () => {
  accounts = 1;
  axios.post.mockImplementation(() => Promise.reject(err400('invalid credentials')));
  await renderApp(root);
  await flush(20);
  await submitLogin('admin', 'mauvais-mot-de-passe');
  expect(host.querySelectorAll('.login-form input[type="password"]')).toHaveLength(1);
  expect(initProbe).toHaveBeenCalledTimes(1);
  expect(bruteForceProtection.getStats('admin').attempts).toBe(1);
});
