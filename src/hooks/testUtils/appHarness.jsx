/* eslint-env jest */
// ========================================
// OUTIL DE TEST : App réel rendu dans jsdom, axios branché sur le faux coffre (fakeVault)
// ========================================
// Chaque fichier de test déclare lui-même jest.mock('axios', …) (hissé par Jest) ; ce module utilise
// l'axios simulé de ce fichier. Les intercepteurs de requête, s'ils sont simulés (`interceptors.request
// .handlers`), sont appelés avec { method, url } avant chaque requête, comme le ferait axios.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import App from '../../App.jsx';
import { I18nProvider } from '../../i18n.js';
import { createFakeVault } from './fakeVault.js';

export { act };

// Mock axios avec intercepteurs de requête observables (à utiliser dans la fabrique de jest.mock)
export function axiosMockWithInterceptors() {
  const handlers = [];
  return {
    __esModule: true,
    default: {
      get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn(),
      interceptors: {
        request: { handlers, use: jest.fn((fn) => handlers.push(fn) - 1), eject: jest.fn((id) => { handlers[id] = null; }) },
        response: { use: jest.fn(() => 0), eject: jest.fn() },
      },
    },
  };
}

/**
 * Faux coffre branché sur axios. Connexion : jeton « tok-N » ; lookup-self : policies fournies.
 * @param {Object} [options]
 * @param {Function} [options.delayFor] - (method, url) => Promise à attendre avant la réponse, ou null
 */
export function setupVault({ delayFor, policies = ['default'] } = {}) {
  const vault = createFakeVault();
  let tokenSeq = 0;
  const runRequestInterceptors = (method, url) => {
    const handlers = axios.interceptors?.request?.handlers;
    if (!Array.isArray(handlers)) return;
    for (const h of handlers) if (typeof h === 'function') h({ method, url });
  };
  const wrap = (method, fn) => (url, body, cfg) => {
    const u = String(url);
    runRequestInterceptors(method, u);
    if (method === 'post' && u.includes('/v1/auth/ldap/login/')) {
      tokenSeq += 1;
      return Promise.resolve({ status: 200, data: { auth: { client_token: `tok-${tokenSeq}` } } });
    }
    if (method === 'get' && u.includes('/v1/auth/token/lookup-self')) {
      return Promise.resolve({ status: 200, data: { data: { entity_name: 'alice', policies } } });
    }
    if (method === 'get' && u.includes('/v1/sys/policies/acl/')) {
      return Promise.resolve({ status: 200, data: { data: { policy: '' } } });
    }
    if (method === 'post' && u.includes('/v1/sys/capabilities-self')) {
      const p = body?.paths?.[0];
      return Promise.resolve({ status: 200, data: { data: { [p]: ['create', 'read', 'update', 'delete', 'list'] } } });
    }
    // Suppression d'un coffre (absente du faux coffre)
    const mount = method === 'delete' && u.match(/\/v1\/sys\/mounts\/(.+)$/);
    if (mount) {
      vault.engines.delete(decodeURIComponent(mount[1]).replace(/\/$/, ''));
      return Promise.resolve({ status: 204, data: {} });
    }
    const d = delayFor ? delayFor(method, u) : null;
    return d ? d.then(() => fn(u, body)) : fn(u, body);
  };
  axios.get.mockImplementation(wrap('get', vault.axios.get));
  axios.post.mockImplementation(wrap('post', vault.axios.post));
  axios.put.mockImplementation(wrap('put', vault.axios.put));
  axios.delete.mockImplementation(wrap('delete', vault.axios.delete));
  return vault;
}

export async function flush(rounds = 60) {
  for (let i = 0; i < rounds; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await Promise.resolve(); });
  }
}

// Laisse passer les délais (regroupement de la synchro extension, anti-rebond) et les lectures de fond
export async function settle(steps = 5, ms = 2000) {
  for (let i = 0; i < steps; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { jest.advanceTimersByTime(ms); });
    // eslint-disable-next-line no-await-in-loop
    await flush(60);
  }
}

export function setInput(el, value) {
  const proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
}

export function setSelect(el, value) {
  Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype, 'value').set.call(el, value);
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

export function installBridges() {
  window.electronSync = { writeState: jest.fn(async () => ({ success: true })) };
  window.electronClipboard = { copySecure: jest.fn(async () => ({ success: true })), clearNow: jest.fn(async () => ({ success: true })) };
}
export function removeBridges() {
  delete window.electronSync;
  delete window.electronClipboard;
}

export function createHost() {
  const host = document.createElement('div');
  document.body.appendChild(host);
  return { host, root: createRoot(host) };
}

// Rendu d'un root React 18 (hors Testing Library)
export const mountInRoot = (reactRoot, element) => reactRoot.render(element);

export async function renderApp(root) {
  await act(async () => { mountInRoot(root, <I18nProvider defaultLang="fr"><App /></I18nProvider>); });
  await flush();
}

export async function login(host, user = 'alice') {
  const inputs = host.querySelectorAll('.login-form input');
  await act(async () => { setInput(inputs[0], user); });
  await act(async () => { setInput(inputs[1], 'motdepasse-maitre'); });
  await act(async () => { host.querySelector('.btn-login').click(); });
  await flush(150);
}

export async function logout(host) {
  await act(async () => { host.querySelector('.user-menu-trigger').click(); });
  await flush(5);
  const item = Array.from(document.querySelectorAll('.user-menu-item')).pop();
  await act(async () => { item.click(); });
  await flush(40);
}

export async function typeSearch(host, text) {
  const input = host.querySelector('.search-input');
  await act(async () => { setInput(input, text); });
  await act(async () => { jest.advanceTimersByTime(400); });
  await flush();
}

export const multiBox = (host) => host.querySelector('.toolbar label.checkbox-label input[type="checkbox"]');
export const activeEngine = (host) => host.querySelector('.engine-card.active .engine-name')?.textContent.trim();
export const engineCard = (host, name) => Array.from(host.querySelectorAll('.engine-card'))
  .find(c => c.querySelector('.engine-name')?.textContent.trim() === name);
export const tableRows = (host) => Array.from(host.querySelectorAll('table.secrets-table tbody tr'));
export const rowByName = (host, name) => tableRows(host)
  .find(tr => (tr.querySelector('td.cell-name')?.textContent.trim() || '').replace(/^✓/, '').startsWith(name)) || null;
export const rowNames = (host) => tableRows(host).map(tr => tr.querySelector('td.cell-name')?.textContent.trim().replace(/^✓/, '')).filter(Boolean);

export async function rightClick(el) {
  await act(async () => {
    el.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 10, clientY: 10 }));
  });
  await flush();
}

export const menuItem = (text) => Array.from(document.querySelectorAll('.context-menu .context-menu-item'))
  .find(b => b.textContent.includes(text)) || null;

export function buttonByText(scope, text) {
  return Array.from(scope.querySelectorAll('button')).find(b => b.textContent.trim().includes(text)) || null;
}

export function toastText() {
  return document.querySelector('.toast')?.textContent || null;
}

// Faux DataTransfer (jsdom n'en fournit pas) partagé entre dragstart et drop
export function fakeDataTransfer() {
  const store = {};
  return {
    setData: (k, v) => { store[k] = v; },
    getData: (k) => store[k] || '',
    setDragImage: () => {},
    effectAllowed: '',
    dropEffect: '',
    store,
  };
}
export async function dispatchDrag(el, type, dataTransfer) {
  const ev = new Event(type, { bubbles: true, cancelable: true });
  Object.defineProperty(ev, 'dataTransfer', { value: dataTransfer });
  await act(async () => { el.dispatchEvent(ev); });
}

// Dernier état servi à l'extension : « coffre/nom:motdepasse » triés (null si rien n'a été publié)
export function lastExtensionState() {
  const calls = window.electronSync?.writeState?.mock?.calls || [];
  const st = calls.length ? calls[calls.length - 1][0] : null;
  return st ? { connected: st.connected, secrets: st.secrets.map(s => `${s.engine}/${s.name}:${s.password}`).sort() } : null;
}

// Console du code testé rendue muette (journaux attendus des chemins d'erreur)
export function quiet() {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'debug').mockImplementation(() => {});
}
