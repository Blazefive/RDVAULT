// ========================================
// TESTS : useSecrets.fetchSecrets — listage interrompu par une borne (vague F)
// ========================================
// Hook réel + createVaultApi réel contre le faux Vault du projet.
// vaultApi.listKeysV2 lève LIST_TOO_LARGE (plus de 20 000 entrées) ou LIST_TOO_DEEP (plus de 20 niveaux
// de dossiers) avec les clés déjà listées (`err.partialKeys`). Avant : tableau VIDE et message d'erreur
// (après deux relances inutiles du listage complet). Attendu : la liste partielle est affichée, avec un
// avertissement traduit qui dit qu'elle est incomplète ; l'extension reçoit la même liste.
import { useState, act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi, MAX_LIST_DEPTH } from '../services/vaultApi';
import { useSecrets } from './useSecrets';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

let vault;
beforeEach(() => {
  vault = createFakeVault();
  axios.get.mockImplementation(vault.axios.get);
  axios.post.mockImplementation(vault.axios.post);
  axios.put.mockImplementation(vault.axios.put);
  axios.delete.mockImplementation(vault.axios.delete);
});
afterEach(() => { document.body.innerHTML = ''; });

function mount(engine, toasts, { apiOverrides = {}, pushes = [] } = {}) {
  const vaultApiRef = { current: { ...createVaultApi(vault.VAULT_URL, 'tok'), ...apiOverrides } };
  return renderHook(() => {
    const [secrets, setSecrets] = useState([]);
    const s = useSecrets({
      vaultApiRef, vaultUrl: vault.VAULT_URL, selectedEngine: engine, search: '', showDeleted: false,
      secrets, setSecrets, multiVaultSearch: false, allVaultSecrets: [],
      mergeDiscoveredAndSharedTagsRef: { current: null }, setDiscoveredTags: () => {},
      syncExtensionRef: { current: (update) => { if (update) pushes.push(update); } }, restoreFocus: () => {},
      getTotpKeyName: (n) => `T-${n}`, checkTotpExists: async () => false, totpEngineName: 'TOTP',
      showToast: (m, k) => toasts.push([k, m]), t: fakeT
    });
    return { ...s, secrets };
  });
}

const rootLists = (engine) => vault.calls.filter(c => c.method === 'get' && c.path === `v1/${engine}/metadata` && c.query.includes('list=true'));

test('LIST_TOO_DEEP (chemin réel de vaultApi) : entrées déjà listées affichées + avertissement, listage non relancé', async () => {
  const A = vault.addEngine('A');
  vault.writeRaw('A', 'top1', { Username: 'u1', Password: 'p1' });
  vault.writeRaw('A', 'top2', { Username: 'u2', Password: 'p2' });
  // Dossier imbriqué au-delà de la borne (listé APRÈS top1 et top2 : ordre alphabétique)
  const deep = Array.from({ length: MAX_LIST_DEPTH + 2 }, (_, i) => `z${i}`).join('/');
  vault.writeRaw('A', `${deep}/cache`, { Password: 'x' });
  const toasts = []; const pushes = [];
  const { result } = mount(A, toasts, { pushes });
  await act(async () => { await result.current.fetchSecrets(A); });

  expect(result.current.secrets.map(s => s.name)).toEqual(['top1', 'top2']); // avant : []
  expect(toasts).toHaveLength(1);
  expect(toasts[0][0]).toBe('warning');
  expect(toasts[0][1]).toContain('error.listTooDeepPartial');
  expect(toasts[0][1]).toContain(`"max":${MAX_LIST_DEPTH}`);
  expect(toasts[0][1]).toContain('"count":2');
  expect(rootLists('A')).toHaveLength(1); // avant : 3 listages (2 relances d'une erreur déterministe)
  expect(pushes[pushes.length - 1].secrets.map(s => s.name)).toEqual(['top1', 'top2']); // extension
});

test('LIST_TOO_LARGE : liste partielle affichée, lectures en échec ajoutées à l\'avertissement', async () => {
  const A = vault.addEngine('A');
  vault.writeRaw('A', 'a', { Password: 'pa' });
  vault.writeRaw('A', 'b', { Password: 'pb' });
  vault.writeRaw('A', 'c', { Password: 'pc' });
  vault.setFailWhen((method, path) => (method === 'get' && path === 'v1/A/data/c' ? 500 : null));
  let listCalls = 0;
  const apiOverrides = {
    listKeysV2: async () => {
      listCalls++;
      throw Object.assign(new Error('Listage interrompu'), {
        code: 'LIST_TOO_LARGE', i18nKey: 'error.listTooLarge', i18nVars: { max: 3 }, partialKeys: ['a', '.rdvault-passkeys', 'b', 'c'],
      });
    },
  };
  const toasts = [];
  const { result } = mount(A, toasts, { apiOverrides });
  await act(async () => { await result.current.fetchSecrets(A); });

  expect(result.current.secrets.map(s => s.name)).toEqual(['a', 'b']);
  expect(listCalls).toBe(1);
  expect(toasts).toHaveLength(1);
  expect(toasts[0][0]).toBe('warning');
  expect(toasts[0][1]).toContain('error.listTooLargePartial {"max":3,"count":3}');
  expect(toasts[0][1]).toContain('error.secretsUnreadable {"count":1}');
});

test('témoin : autre erreur de listage (réseau) → traitement inchangé (tableau vide, erreur)', async () => {
  const A = vault.addEngine('A');
  vault.writeRaw('A', 'a', { Password: 'pa' });
  vault.setFailWhen((method, path) => (method === 'get' && path === 'v1/A/metadata' ? 500 : null));
  const toasts = [];
  const { result } = mount(A, toasts);
  await act(async () => { await result.current.fetchSecrets(A); });
  expect(result.current.secrets).toEqual([]);
  expect(toasts[0][0]).toBe('error');
  expect(toasts[0][1]).toContain('error.engineList');
});
