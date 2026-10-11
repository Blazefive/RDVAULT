// ========================================
// TESTS : App.jsx — lien profond rdvault://share/… : champ « website » transmis à la session RBI
// ========================================
// RBI-11 : le processus principal accepte `website` (seconde adresse de référence pour la saisie,
// comme l'extension) ; App ne transmettait que `url` après confirmation d'un partage reçu.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import App from './App.jsx';
import { I18nProvider } from './i18n.js';
import fr from './locales/fr.json';
import { createFakeVault } from './hooks/testUtils/fakeVault';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const SHARE_TOKEN = 'hvs.SHARE-TOKEN';
let unwrapData;

function setupVault() {
  const vault = createFakeVault();
  const route = (method, fn) => (url, body, config) => {
    const u = String(url);
    if (method === 'post' && u.includes('/v1/auth/ldap/login/')) {
      return Promise.resolve({ status: 200, data: { auth: { client_token: 'tok-deeplink' } } });
    }
    if (method === 'post' && u.includes('/v1/sys/capabilities-self')) {
      const p = body?.paths?.[0];
      return Promise.resolve({ status: 200, data: { data: { [p]: ['create', 'read', 'update', 'delete', 'list'] } } });
    }
    if (method === 'post' && u.endsWith('/v1/sys/wrapping/unwrap') && config?.headers?.['X-Vault-Token'] === SHARE_TOKEN) {
      return Promise.resolve({ status: 200, data: { data: unwrapData } });
    }
    return fn(u, body);
  };
  axios.get.mockImplementation(route('get', vault.axios.get));
  axios.post.mockImplementation(route('post', vault.axios.post));
  axios.put.mockImplementation(route('put', vault.axios.put));
  axios.delete.mockImplementation(route('delete', vault.axios.delete));
  return vault;
}

async function flush(rounds = 60) {
  for (let i = 0; i < rounds; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await Promise.resolve(); });
  }
}
function setInput(el, value) {
  Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
}
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let root; let host; let shareListener; let launchSession;
beforeEach(() => {
  jest.useFakeTimers();
  localStorage.clear();
  localStorage.setItem('rdvault-lang', 'fr');
  window.electronSync = { writeState: jest.fn(async () => ({ success: true })) };
  window.electronClipboard = { copySecure: jest.fn(async () => ({ success: true })), clearNow: jest.fn(async () => ({ success: true })) };
  shareListener = null;
  launchSession = jest.fn(async () => ({ success: true }));
  window.electronRBI = {
    launchSession,
    onShareReceived: (cb) => { shareListener = cb; return () => { shareListener = null; }; },
  };
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
  delete window.electronSync;
  delete window.electronClipboard;
  delete window.electronRBI;
  jest.useRealTimers();
});

async function startApp() {
  await act(async () => { mountInRoot(root, <I18nProvider defaultLang="fr"><App /></I18nProvider>); });
  await flush();
  const inputs = host.querySelectorAll('.login-form input');
  await act(async () => { setInput(inputs[0], 'alice'); });
  await act(async () => { setInput(inputs[1], 'motdepasse-maitre'); });
  await act(async () => { host.querySelector('.btn-login').click(); });
  await flush(120);
}

async function receiveAndConfirm() {
  expect(typeof shareListener).toBe('function');
  await act(async () => { await shareListener(SHARE_TOKEN); });
  await flush(20);
  const dialog = document.querySelector('[role="dialog"]');
  expect(dialog.textContent).toContain(fr.confirm.openShare);
  const open = Array.from(dialog.querySelectorAll('button')).find(b => b.textContent.trim() === fr.confirm.open);
  await act(async () => { open.click(); });
  await flush(20);
}

test('partage reçu avec website : launchSession reçoit url ET website après confirmation', async () => {
  const vault = setupVault();
  vault.addEngine('kv');
  unwrapData = { url: 'https://app.example.com/login', website: 'https://sso.example.com', username: 'bob', password: 'MDP-PARTAGE' };
  await startApp();
  await receiveAndConfirm();
  expect(launchSession).toHaveBeenCalledTimes(1);
  expect(launchSession.mock.calls[0][0]).toEqual(expect.objectContaining({
    url: 'https://app.example.com/login', website: 'https://sso.example.com', username: 'bob', password: 'MDP-PARTAGE',
  }));
});

test('partage sans website (émetteur antérieur) : aucune option website, session lancée comme avant', async () => {
  const vault = setupVault();
  vault.addEngine('kv');
  unwrapData = { url: 'https://app.example.com/login', username: 'bob', password: 'p' };
  await startApp();
  await receiveAndConfirm();
  expect(launchSession).toHaveBeenCalledTimes(1);
  expect('website' in launchSession.mock.calls[0][0]).toBe(false);
});
