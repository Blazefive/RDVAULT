// ========================================
// TESTS : useTags — rechargement multi-coffre incomplet signalé (PERF-5)
// ========================================
// Avant : après l'ajout d'un tag en recherche multi-coffre, le rechargement de tous les coffres
// ignorait en silence les entrées illisibles (erreur réseau) et affichait « Tag ajouté ».
import { act } from 'react';
import { renderHook, fakeT } from './testUtils/fakeVault';
import { useTags } from './useTags';

jest.mock('axios', () => ({
  __esModule: true,
  default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn(), interceptors: { request: { use: jest.fn() } } }
}));

global.IS_REACT_ACT_ENVIRONMENT = true;
afterEach(() => { document.body.innerHTML = ''; });

function mount(failingKey) {
  const toasts = [];
  let shown = null;
  const read = async (engine, key) => {
    if (key === failingKey) throw Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' });
    return { name: key, password: 'p', tags: '' };
  };
  const vaultApi = {
    writeSecretV2: jest.fn(async () => {}), writeSecretV1: jest.fn(),
    listKeysV2: async () => ['a', 'b', 'c'], listKeysV1: async () => [],
    readSecretV2: read, readSecretV1: read,
  };
  const engine = { name: 'kv', version: 2 };
  const view = renderHook(() => useTags({
    vaultUrl: 'http://v', baseHeaders: () => ({}), axiosConfig: (c) => c,
    selectedEngine: engine, secretEngines: [engine], multiVaultSearch: true,
    vaultApi, fetchSecretsRef: { current: async () => {} },
    setAllVaultSecrets: (list) => { shown = list; }, setLoadingAllSecrets: () => {},
    showToast: (m, k) => toasts.push([k, m]), t: fakeT,
  }));
  return { ...view, toasts, shownNames: () => (shown || []).map(s => s.name) };
}

test('ajout de tag en multi-coffre : entrée illisible au rechargement → avertissement (et non « Tag ajouté »)', async () => {
  const { result, toasts, shownNames } = mount('b');
  await act(async () => {
    await result.current.handleAddTagToSecret({ name: 'a', tags: '', engineName: 'kv', engineVersion: 2 }, 'prod');
  });
  expect(shownNames()).toEqual(['a', 'c']);
  const last = toasts[toasts.length - 1];
  expect(last[0]).toBe('warning');
  expect(last[1]).toContain('error.secretsUnreadable');
  expect(last[1]).toContain('"count":1');
});

test('rechargement complet : toast de succès inchangé', async () => {
  const { result, toasts } = mount(null);
  await act(async () => {
    await result.current.handleRemoveTagFromSecret({ name: 'a', tags: 'prod', engineName: 'kv', engineVersion: 2 }, 'prod');
  });
  expect(toasts[toasts.length - 1]).toEqual(['success', 'toast.tagRemoved']);
});
