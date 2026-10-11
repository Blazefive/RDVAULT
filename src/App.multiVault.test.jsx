// ========================================
// TESTS : App.jsx — recherche multi-coffres incomplète signalée (PERF-5)
// ========================================
// Avant : la recherche dans tous les coffres ignorait en silence les entrées dont la lecture
// échouait (requête refusée par le navigateur, délai, 5xx) : résultats incomplets sans message.
// App réel, axios simulé (aucun réseau), même harnais que App.session.test.jsx.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import App from './App.jsx';
import { I18nProvider } from './i18n.js';
import fr from './locales/fr.json';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const httpError = (status) => Object.assign(new Error(String(status)), { response: { status, data: {} } });
const networkError = () => Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' }); // sans réponse HTTP
const ok = (data) => Promise.resolve({ status: 200, data });
const KV2 = { type: 'kv', options: { version: '2' } };

function installAxios() {
  axios.get.mockImplementation((url) => {
    const u = String(url);
    if (u.includes('/v1/auth/token/lookup-self')) return ok({ data: { entity_name: 'alice', policies: ['default'] } });
    if (u.includes('/v1/sys/policies/acl/')) return ok({ data: { policy: '' } });
    if (u.includes('/v1/sys/internal/ui/mounts') || u.endsWith('/v1/sys/mounts')) return ok({ 'kv/': KV2, 'zz-autre/': KV2 });
    if (u.includes('/v1/kv/metadata?list=true')) return ok({ data: { keys: ['srv-a'] } });
    if (u.includes('/v1/kv/data/srv-a')) return ok({ data: { data: { Username: 'alice', Password: 'pa' } } });
    if (u.includes('/v1/zz-autre/metadata?list=true')) return ok({ data: { keys: ['srv-b', 'srv-c'] } });
    if (u.includes('/v1/zz-autre/data/srv-b')) return ok({ data: { data: { Username: 'bob', Password: 'pb' } } });
    if (u.includes('/v1/zz-autre/data/srv-c')) return Promise.reject(networkError());
    return Promise.reject(httpError(404));
  });
  axios.post.mockImplementation((url) => {
    const u = String(url);
    if (u.includes('/v1/auth/ldap/login/')) return ok({ auth: { client_token: 'tok-mv' } });
    if (u.includes('/v1/sys/capabilities-self')) return ok({ data: {} });
    return Promise.resolve({ status: 204, data: {} });
  });
  axios.delete.mockImplementation(() => Promise.resolve({ status: 204, data: {} }));
}

async function flush(rounds = 40) {
  for (let i = 0; i < rounds; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await Promise.resolve(); });
  }
}
function setInput(el, value) {
  Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
}

// Rendu d'un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let root; let host;
beforeEach(() => {
  jest.useFakeTimers();
  localStorage.clear();
  localStorage.setItem('rdvault-lang', 'fr');
  window.electronSync = { writeState: jest.fn(async () => ({ success: true })) };
  installAxios();
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
  delete window.electronSync;
  jest.useRealTimers();
});

test('recherche multi-coffres : une entrée illisible est signalée par un avertissement', async () => {
  await act(async () => { mountInRoot(root, <I18nProvider defaultLang="fr"><App /></I18nProvider>); });
  await flush();
  const inputs = host.querySelectorAll('.login-form input');
  await act(async () => { setInput(inputs[0], 'alice'); });
  await act(async () => { setInput(inputs[1], 'motdepasse-maitre'); });
  await act(async () => { host.querySelector('.btn-login').click(); });
  await flush(80);
  expect(host.querySelector('.secrets-table')).not.toBeNull();

  await act(async () => { setInput(host.querySelector('.search-input'), 'srv'); });
  await act(async () => { jest.advanceTimersByTime(400); });
  await flush(10);
  await act(async () => { host.querySelector('.toolbar input[type="checkbox"]').click(); });
  // Relances de la lecture en échec (200 ms puis 600 ms), y compris celles de la synchro extension
  for (let i = 0; i < 6; i++) {
    // eslint-disable-next-line no-await-in-loop
    await flush(20);
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { jest.advanceTimersByTime(700); });
  }
  await flush(40);

  const tableText = host.querySelector('.secrets-table').textContent;
  expect(tableText).toContain('srv-a');
  expect(tableText).toContain('srv-b');
  const expected = fr.error.secretsUnreadable.replace('{{count}}', '1');
  expect(document.body.textContent).toContain(expected); // avant : aucun message
});
