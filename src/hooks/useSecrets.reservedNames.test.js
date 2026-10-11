// ========================================
// TESTS : useSecrets.fetchSecrets — noms réservés « .rdvault » (COMPAT-2)
// ========================================
// Hook réel + createVaultApi réel contre le faux Vault du projet.
// La 1.5.0 ne réservait aucun nom : une entrée « .rdvault-notes » ou « .rdvault » à la racine d'un
// coffre était une entrée ordinaire. Avant : TOUT nom commençant par « .rdvault » était masqué du
// tableau (et de la synchro de l'extension) après la mise à jour, sans message.
// Attendu : seuls les secrets internes réservés, par nom EXACT (« .rdvault-passkeys »,
// « .rdvault-keycheck »), restent masqués ; les autres entrées sont affichées et synchronisées.
import { useState, act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
import { useSecrets } from './useSecrets';
import { isInternalSecretKey, INTERNAL_SECRET_KEYS } from '../utils/passkeyEngine';

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

function mount(engine, toasts, pushes) {
  const vaultApiRef = { current: createVaultApi(vault.VAULT_URL, 'tok') };
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

test('liste des noms réservés : exactement les deux secrets internes du code serveur et client', () => {
  expect([...INTERNAL_SECRET_KEYS].sort()).toEqual(['.rdvault-keycheck', '.rdvault-passkeys']);
  expect(isInternalSecretKey('.rdvault-passkeys')).toBe(true);
  expect(isInternalSecretKey('.rdvault-keycheck')).toBe(true);
  for (const name of ['.rdvault', '.rdvault-notes', '.rdvault-passkeys-old', '.RDVAULT-PASSKEYS', 'dossier/.rdvault-passkeys', ' .rdvault-passkeys']) {
    expect(isInternalSecretKey(name)).toBe(false);
  }
});

test('entrées utilisateur « .rdvault… » de la 1.5.0 affichées et synchronisées ; secrets internes masqués', async () => {
  const P = vault.addEngine('Perso');
  vault.writeRaw('Perso', 'banque', { Username: 'u', Password: 'p' });
  vault.writeRaw('Perso', '.rdvault-notes', { Username: 'notes', Password: 'pn', Notes: 'pense-bête' });
  vault.writeRaw('Perso', '.rdvault', { Username: 'racine', Password: 'pr' });
  vault.writeRaw('Perso', 'dossier/.rdvault-x', { Password: 'px' });
  vault.writeRaw('Perso', '.rdvault-passkeys', { items: { 'site.fr': [] } });
  vault.writeRaw('Perso', '.rdvault-keycheck', { purpose: 'rdvault-key-check' });
  const toasts = []; const pushes = [];
  const { result } = mount(P, toasts, pushes);
  await act(async () => { await result.current.fetchSecrets(P); });

  const shown = result.current.secrets.map(s => s.name).sort();
  expect(shown).toEqual(['.rdvault', '.rdvault-notes', 'banque', 'dossier/.rdvault-x']); // avant : ['banque', 'dossier/.rdvault-x']
  const notes = result.current.secrets.find(s => s.name === '.rdvault-notes');
  expect(notes).toMatchObject({ username: 'notes', password: 'pn', notes: 'pense-bête' });
  // Extension : même liste, sans les secrets internes
  const synced = pushes[pushes.length - 1].secrets.map(s => s.name).sort();
  expect(synced).toEqual(shown);
  // Secrets internes jamais lus par le tableau (clés privées des passkeys)
  const reads = vault.calls.filter(c => c.method === 'get' && /\/data\//.test(c.path)).map(c => c.path);
  expect(reads.some(p => p.includes(encodeURIComponent('.rdvault-passkeys')) || p.includes('.rdvault-passkeys'))).toBe(false);
  expect(reads.some(p => p.includes('.rdvault-keycheck'))).toBe(false);
  expect(toasts).toEqual([]);
});

// Éditeur : une entrée créée ou renommée sous un nom réservé disparaîtrait aussitôt du tableau, puis
// serait réécrite par le stockage des passkeys (sans historique : PURGE-35 côté coffre local).
describe('COMPAT-2 — éditeur : noms réservés exacts refusés, autres noms « .rdvault… » permis', () => {
  const entry = (name) => ({ name, username: 'u', password: 'p', url: '', notes: '', tags: '', customFields: [], attachments: [], entryType: 'secret' });

  test.each(['.rdvault-passkeys', '.rdvault-keycheck'])('création « %s » refusée (blob absent), rien n\'est écrit', async (name) => {
    const P = vault.addEngine('Perso');
    const toasts = []; const pushes = [];
    const { result } = mount(P, toasts, pushes);
    await act(async () => { await result.current.fetchSecrets(P); });
    act(() => { result.current.setEditSecret({ name: '', username: '', password: '' }); });
    await act(async () => { await result.current.handleEditSecretSave(entry(name)); });

    expect(toasts[toasts.length - 1][0]).toBe('error');
    expect(toasts[toasts.length - 1][1]).toContain('error.secretNameReserved');
    expect(vault.latest('Perso', name)).toBeNull();
    expect(result.current.editSecret).not.toBeNull(); // la fiche reste ouverte
  });

  test('renommage vers « .rdvault-passkeys » refusé : l\'entrée d\'origine reste intacte', async () => {
    const P = vault.addEngine('Perso');
    vault.writeRaw('Perso', 'banque', { Username: 'u', Password: 'p', EntryType: 'secret' });
    const toasts = []; const pushes = [];
    const { result } = mount(P, toasts, pushes);
    await act(async () => { await result.current.fetchSecrets(P); });
    act(() => { result.current.setEditSecret(result.current.secrets.find(s => s.name === 'banque')); });
    await act(async () => { await result.current.handleEditSecretSave(entry('.rdvault-passkeys')); });

    expect(toasts[toasts.length - 1][1]).toContain('error.secretNameReserved');
    expect(vault.isLive('Perso', 'banque')).toBe(true);
    expect(vault.latest('Perso', '.rdvault-passkeys')).toBeNull();
  });

  test('« .rdvault-notes » (entrée 1.5.0) : modification enregistrée et toujours affichée', async () => {
    const P = vault.addEngine('Perso');
    vault.writeRaw('Perso', '.rdvault-notes', { Username: 'u', Password: 'p', EntryType: 'secret' });
    const toasts = []; const pushes = [];
    const { result } = mount(P, toasts, pushes);
    await act(async () => { await result.current.fetchSecrets(P); });
    act(() => { result.current.setEditSecret(result.current.secrets.find(s => s.name === '.rdvault-notes')); });
    await act(async () => { await result.current.handleEditSecretSave({ ...entry('.rdvault-notes'), password: 'nouveau' }); });

    expect(toasts[toasts.length - 1]).toEqual(['success', 'toast.secretSaved']);
    expect(vault.latest('Perso', '.rdvault-notes')).toMatchObject({ version: 2, data: { Password: 'nouveau' } });
    expect(result.current.secrets.map(s => s.name)).toContain('.rdvault-notes');
  });
});
