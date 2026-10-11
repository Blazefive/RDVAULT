// ========================================
// TESTS : PasskeysModal (« Mes passkeys ») — même coffre que le hook, suppression sérialisée
// ========================================
// - PASSKEYS-16 : l'écran lit le coffre personnel exact (users/<nom>/), jamais celui d'un autre
//   utilisateur ; compatibilité : ancien emplacement (même utilisateur) affiché, suppression
//   écrite dans le coffre personnel sans toucher à l'ancien blob.
// - PASSKEYS-17 : la suppression passe par la même file que les écritures de l'extension
//   (aucune passkey créée pendant la suppression n'est perdue).
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { I18nProvider } from '../i18n';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';
// eslint-disable-next-line import/first
import PasskeysModal from './PasskeysModal';
// eslint-disable-next-line import/first
import { usePasskeys, PASSKEY_SECRET_KEY } from '../hooks/usePasskeys';

global.IS_REACT_ACT_ENVIRONMENT = true;

const VAULT = 'http://v';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const blobUrl = (engine) => `${VAULT}/v1/${engine.split('/').map(encodeURIComponent).join('/')}/data/${encodeURIComponent(PASSKEY_SECRET_KEY)}`;
const pk = (rpId, credentialId, extra = {}) => ({ rpId, credentialId, privateKeyJwk: { d: credentialId }, userName: credentialId.toLowerCase(), ...extra });

// Faux KV v2 (versions + CAS) avec latence
let kv;
function installKv() {
  kv = { store: new Map(), calls: [], delayMs: 0 };
  axios.get.mockImplementation(async (url) => {
    kv.calls.push(['GET', url]);
    await sleep(kv.delayMs);
    const e = kv.store.get(url);
    if (!e) { const err = new Error('404'); err.response = { status: 404, data: { errors: [] } }; throw err; }
    return { data: { data: { data: JSON.parse(JSON.stringify(e.data)), metadata: { version: e.version } } } };
  });
  axios.post.mockImplementation(async (url, payload) => {
    kv.calls.push(['POST', url, payload]);
    await sleep(kv.delayMs);
    const cur = kv.store.get(url);
    const cas = payload && payload.options ? payload.options.cas : undefined;
    if (cas !== undefined && cas !== (cur ? cur.version : 0)) {
      const err = new Error('400'); err.response = { status: 400, data: { errors: ['check-and-set parameter did not match the current version'] } }; throw err;
    }
    kv.store.set(url, { data: JSON.parse(JSON.stringify(payload.data)), version: (cur ? cur.version : 0) + 1 });
    return { data: {} };
  });
}
const put = (engine, data) => { const url = blobUrl(engine); const cur = kv.store.get(url); kv.store.set(url, { data, version: (cur ? cur.version : 0) + 1 }); };
const get = (engine) => (kv.store.get(blobUrl(engine)) || {}).data;

const vaultApi = { baseHeaders: () => ({}), axiosConfig: (c) => c };
let roots = [];
// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
async function mountModal(element) {
  localStorage.setItem('rdvault-lang', 'en');
  const host = document.createElement('div'); document.body.appendChild(host);
  const root = createRoot(host); roots.push(root);
  await act(async () => { mountInRoot(root, <I18nProvider>{element}</I18nProvider>); });
  // Fin du chargement (une ou deux lectures selon l'emplacement des passkeys)
  const pause = kv.delayMs + 5;
  for (let i = 0; i < 50 && document.body.textContent.includes('Loading…'); i++) {
    await act(async () => { await sleep(pause); });
  }
  return host;
}
afterEach(() => { roots.forEach((r) => act(() => r.unmount())); roots = []; document.body.innerHTML = ''; localStorage.clear(); delete window.electronPasskey; });
const buttonByText = (container, txt) => Array.from(document.querySelectorAll('button')).find((b) => b.textContent.trim() === txt);

const ALICE = 'users/alice/Perso';
const JEAN = 'users/jean.dupont/Mes-Secrets';

test('PASSKEYS-16 : « jean.dupont » voit SON coffre, pas les passkeys d\'alice', async () => {
  installKv();
  put(ALICE, { items: { 'github.com': [pk('github.com', 'ALICE')] } });
  put(JEAN, { items: { 'gitlab.com': [pk('gitlab.com', 'JEAN')] } });
  await mountModal(<PasskeysModal onClose={() => {}} vaultApi={vaultApi} vaultUrl={VAULT} secretEngines={[{ name: ALICE, version: 2 }, { name: JEAN, version: 2 }]} authUser="jean.dupont" showToast={() => {}} />);
  expect(kv.calls.map((c) => c[1])).toEqual([blobUrl(JEAN)]);
  expect(document.body.textContent).toContain('gitlab.com');
  expect(document.body.textContent).not.toContain('github.com');
});

test('PASSKEYS-16 : sans coffre personnel, rien n\'est lu ailleurs (liste vide)', async () => {
  installKv();
  put('secret', { items: { 'a.com': [pk('a.com', 'SHARED')] } });
  await mountModal(<PasskeysModal onClose={() => {}} vaultApi={vaultApi} vaultUrl={VAULT} secretEngines={[{ name: 'secret', version: 2 }]} authUser="bob" showToast={() => {}} />);
  expect(kv.calls).toEqual([]);
  expect(document.body.textContent).toContain('No passkeys stored yet.');
});

test('compatibilité : passkeys de l\'ancien emplacement (même utilisateur) affichées ; suppression écrite dans le coffre personnel, ancien blob intact', async () => {
  installKv();
  const ARCHIVE = 'users/jean.dupont/Archive';
  const legacy = { items: { 'old.com': [pk('old.com', 'OLD1'), pk('old.com', 'OLD2')] } };
  put(ARCHIVE, legacy);
  const toasts = [];
  const view = await mountModal(<PasskeysModal onClose={() => {}} vaultApi={vaultApi} vaultUrl={VAULT} secretEngines={[{ name: ARCHIVE, version: 2 }, { name: JEAN, version: 2 }]} authUser="jean.dupont" showToast={(m, k) => toasts.push(k)} />);
  expect(document.body.textContent).toContain('old1');
  expect(document.body.textContent).toContain('old2');
  await act(async () => { buttonByText(view, 'Delete').click(); });
  await act(async () => { buttonByText(view, 'Confirm').click(); });
  for (let i = 0; i < 50 && !toasts.length; i++) await act(async () => { await sleep(10); });
  expect(toasts).toEqual(['success']);
  expect(get(JEAN).items['old.com'].map((p) => p.credentialId)).toEqual(['OLD2']);
  expect(get(ARCHIVE)).toEqual(legacy);
});

test('PASSKEYS-17 : suppression pendant une création par l\'extension → les deux effets sont conservés', async () => {
  installKv();
  put(JEAN, { items: { 'a.com': [pk('a.com', 'A')] } });
  // Hook de l'extension monté en parallèle (même file d'attente)
  let handler = null; const responses = [];
  window.electronPasskey = { onRequest: (fn) => { handler = fn; return () => {}; }, sendResponse: (c, r) => responses.push(r) };
  const engines = [{ name: JEAN, version: 2 }];
  function Hook() { usePasskeys({ vaultApi, token: 't', vaultUrl: VAULT, secretEngines: engines, authUser: 'jean.dupont' }); return null; }
  const view = await mountModal(<><Hook /><PasskeysModal onClose={() => {}} vaultApi={vaultApi} vaultUrl={VAULT} secretEngines={engines} authUser="jean.dupont" showToast={() => {}} /></>);
  kv.delayMs = 20;
  await act(async () => { buttonByText(view, 'Delete').click(); });
  await act(async () => {
    buttonByText(view, 'Confirm').click();
    await handler('passkey-store', { requestId: 'x', passkey: pk('b.com', 'B') });
    await sleep(120);
  });
  expect(responses[0].success).toBe(true);
  expect(get(JEAN).items['a.com']).toBeUndefined();          // suppression appliquée
  expect(get(JEAN).items['b.com'].map((p) => p.credentialId)).toEqual(['B']); // création conservée
});
