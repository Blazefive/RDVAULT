// ========================================
// TESTS : useSync + useSecrets — lectures de fond de l'extension par les listes gardées du tableau
// ========================================
// Avant : la synchro de l'extension lisait chaque coffre à la connexion (une requête par entrée), puis le
// tableau relisait encore toutes les entrées de chaque coffre ouvert. Et la vérification des autres coffres
// après une écriture ne lisait que les clés NOUVELLES : une entrée existante modifiée dans un coffre non
// affiché gardait son ancien mot de passe dans l'extension.
import React, { useState, act } from 'react';
import { createRoot } from 'react-dom/client';
import { I18nProvider } from '../i18n';
import { createFakeVault, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
import { useSecrets } from './useSecrets';
import { useSync, RECONCILE_DELAY_MS } from './useSync';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

let vault;
let writes;
const roots = [];
beforeEach(() => {
  vault = createFakeVault();
  axios.get.mockImplementation(vault.axios.get);
  axios.post.mockImplementation(vault.axios.post);
  axios.put.mockImplementation(vault.axios.put);
  axios.delete.mockImplementation(vault.axios.delete);
  writes = [];
  window.electronSync = { writeState: jest.fn(async (s) => { writes.push(JSON.parse(JSON.stringify(s))); return { success: true }; }) };
});
afterEach(() => {
  roots.splice(0).forEach(root => act(() => root.unmount()));
  delete window.electronSync;
  document.body.innerHTML = '';
});

// Rendu d'un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const flush = async (n = 40) => { for (let i = 0; i < n; i++) await act(async () => { await Promise.resolve(); }); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const dataReads = (from, engine) => vault.calls.slice(from)
  .filter(c => c.method === 'get' && c.path.startsWith(`v1/${engine}/data/`)).length;
const lastState = () => [...writes].reverse().find(w => w.connected);

function mount(engines, state) {
  const vaultApiRef = { current: createVaultApi(vault.VAULT_URL, 'tok-1') };
  const sessionTokenRef = { current: 'tok-1' };
  const syncExtensionRef = { current: null };
  const result = { current: null };
  function Harness() {
    const [secrets, setSecrets] = useState([]);
    const s = useSecrets({
      vaultApiRef, vaultUrl: vault.VAULT_URL, selectedEngine: state.engine, search: '', showDeleted: false,
      secrets, setSecrets, multiVaultSearch: false, allVaultSecrets: [],
      mergeDiscoveredAndSharedTagsRef: { current: null }, setDiscoveredTags: () => {},
      syncExtensionRef, restoreFocus: () => {},
      getTotpKeyName: (n) => n, checkTotpExists: async () => false, totpEngineName: 'TOTP',
      showToast: () => {}, t: fakeT, cacheMaxAgeMs: 60 * 60 * 1000,
    });
    const readEnginesRef = React.useRef(null);
    readEnginesRef.current = s.readEnginesWithCache;
    useSync({
      vaultApi: vaultApiRef.current, token: 'tok-1', vaultUrl: vault.VAULT_URL, authUser: 'alice',
      secretEngines: engines, selectedEngine: state.engine, syncExtensionRef,
      totpRateLimit: { canCall: () => true, registerCall: () => {} }, showToast: () => {},
      sessionTokenRef, isSecretRbiOnly: () => false, readEnginesRef,
    });
    result.current = { ...s, secrets };
    return null;
  }
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  roots.push(root);
  const paint = () => act(() => { mountInRoot(root, <I18nProvider defaultLang="fr"><Harness /></I18nProvider>); });
  paint();
  return { result, rerender: paint, vaultApiRef, syncExtensionRef };
}

test('une lecture par entrée et par session : le tableau réutilise ce que la synchro de fond a lu', async () => {
  const A = vault.addEngine('A');
  const B = vault.addEngine('B');
  for (let i = 0; i < 40; i++) vault.writeRaw('A', `a${i}`, { Password: `pa${i}` });
  for (let i = 0; i < 25; i++) vault.writeRaw('B', `b${i}`, { Password: `pb${i}` });
  const state = { engine: A };
  const { result, rerender } = mount([A, B], state);
  await flush();
  expect(dataReads(0, 'B')).toBe(25);
  expect(lastState().secrets).toHaveLength(65);

  // Ouverture de B : liste déjà lue par la synchro de fond, aucune entrée relue (avant : 25)
  state.engine = B; rerender();
  const from = vault.calls.length;
  await act(async () => { await result.current.fetchSecrets(B, false, { incremental: true }); });
  expect(dataReads(from, 'B')).toBe(0);
  expect(result.current.secrets).toHaveLength(25);
});

test('entrée EXISTANTE modifiée dans un coffre non affiché : l\'extension reçoit le nouveau mot de passe', async () => {
  const A = vault.addEngine('A');
  const B = vault.addEngine('B');
  for (let i = 0; i < 10; i++) vault.writeRaw('A', `a${i}`, { Password: `pa${i}` });
  for (let i = 0; i < 10; i++) vault.writeRaw('B', `b${i}`, { Password: `pb${i}` });
  const state = { engine: A };
  const { vaultApiRef, syncExtensionRef } = mount([A, B], state);
  await flush();
  expect(lastState().secrets.find(s => s.engine === 'B' && s.name === 'b3').password).toBe('pb3');

  // Écriture dans B pendant que A est affiché (ajout de tag depuis la recherche multi-coffres, migration…)
  await act(async () => {
    await vaultApiRef.current.writeSecretV2(B, { name: 'b3', username: '', password: 'NOUVEAU-b3', url: '', website: '', notes: '' });
  });
  const from = vault.calls.length;
  await act(async () => { syncExtensionRef.current(); });
  await act(async () => { await sleep(RECONCILE_DELAY_MS + 100); });
  await flush();
  expect(lastState().secrets.find(s => s.engine === 'B' && s.name === 'b3').password).toBe('NOUVEAU-b3');
  expect(dataReads(from, 'B')).toBe(1); // l'entrée écrite seule
  expect(dataReads(from, 'A')).toBe(0);
});
