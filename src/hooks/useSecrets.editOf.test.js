// ========================================
// TESTS : useSecrets — SECRETS-11 indépendant du contenu (marqueur editOf) et toasts en RTL
// ========================================
// Hooks réels (useSecrets + useTotp + createVaultApi) contre le faux Vault du projet.
// - Marqueur explicite `editOf` : nom de l'entrée modifiée (ou null pour une création), le contenu de
//   la fiche n'est plus comparé à la liste (ligne périmée → modification, et non « existe déjà »).
// - « Modifier » sur la ligne AFFICHÉE elle-même (résultat multi-coffres du coffre sélectionné) :
//   modification, même si la liste du coffre est plus ancienne que le résultat.
// - Ligne d'un AUTRE coffre : jamais une modification dans le coffre affiché.
// - L'objet d'édition porte la décision (editOf), conservée si la fiche est rouverte.
// - En arabe, les noms insérés dans les toasts sont isolés (bidi).
import { useState, act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
import { useSecrets, editedEntryName } from './useSecrets';
import { useTotp } from './useTotp';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

const LRI = String.fromCharCode(0x2066);
const FSI = String.fromCharCode(0x2068);
const PDI = String.fromCharCode(0x2069);

let vault;
beforeEach(() => {
  vault = createFakeVault();
  axios.get.mockImplementation(vault.axios.get);
  axios.post.mockImplementation(vault.axios.post);
  axios.put.mockImplementation(vault.axios.put);
  axios.delete.mockImplementation(vault.axios.delete);
});
afterEach(() => {
  document.body.innerHTML = '';
  document.documentElement.dir = '';
});

/**
 * Monte useSecrets + useTotp. `state` est lu à chaque rendu : state.search / state.multi / state.all
 * simulent une recherche multi-coffres (résultats de readAllSecrets) ; rerender() les applique.
 */
function mount(state, toasts) {
  const vaultApiRef = { current: createVaultApi(vault.VAULT_URL, 'tok') };
  const showToast = (m, k) => toasts.push([k, m]);
  return renderHook(() => {
    const [secrets, setSecrets] = useState([]);
    const totp = useTotp({
      vaultUrl: vault.VAULT_URL, baseHeaders: vaultApiRef.current.baseHeaders, axiosConfig: vaultApiRef.current.axiosConfig,
      selectedEngine: state.engine, startClipboardTimer: async () => {}, showToast, t: fakeT, restoreFocus: () => {}
    });
    const s = useSecrets({
      vaultApiRef, vaultUrl: vault.VAULT_URL, selectedEngine: state.engine, search: state.search || '', showDeleted: false,
      secrets, setSecrets, multiVaultSearch: !!state.multi, allVaultSecrets: state.all || [],
      treeViewEnabled: false, currentPath: '', currentFolderContent: null,
      mergeDiscoveredAndSharedTagsRef: { current: null }, setDiscoveredTags: () => {},
      syncExtensionRef: { current: null }, restoreFocus: () => {},
      getTotpKeyName: totp.getTotpKeyName, checkTotpExists: totp.checkTotpExists, totpEngineName: totp.totpEngineName,
      showToast, t: fakeT
    });
    return { ...s, secrets };
  });
}

const run = (fn) => act(async () => { await fn(); });
const lastToast = (toasts) => toasts[toasts.length - 1];
const formEntry = (name, password, extra = {}) => ({
  name, username: 'u', password, url: '', notes: '', tags: '', customFields: [], attachments: [], entryType: 'secret', ...extra,
});
const rowOf = (result, name) => result.current.secrets.find(s => s.name === name);
// Ligne telle que readAllSecrets la renvoie (recherche multi-coffres), lue dans le faux coffre
const resultRow = (engineName, name) => {
  const d = vault.latest(engineName, name).data;
  return { name, username: d.Username || '', password: d.Password || '', url: '', website: '', notes: '', tags: d.Tags || '', customFields: [], attachments: [], entryType: 'secret', engineName, engineVersion: 2 };
};

describe('SECRETS-11 : marqueur explicite editOf', () => {
  test('editOf sur une copie au contenu périmé : modification (et non « existe déjà »)', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'banque', { Username: 'u', Password: 'pass-1', Tags: 'urgent', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    // Copie dont le contenu ne correspond plus à la ligne (tag retiré ailleurs entre-temps)
    act(() => { result.current.setEditSecret({ ...rowOf(result, 'banque'), tags: '', editOf: 'banque' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('banque', 'pass-2')));
    // Contenu courant différent de celui de la fiche : champs changés appliqués à la version courante
    // (services/staleWriteGuard.js), l'utilisateur en est informé
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretSavedMerged']);
    expect(vault.latest('Alpha', 'banque').data.Password).toBe('pass-2');
  });

  test('editOf: null sur une copie de même contenu (résultat multi-coffres) : création, l\'entrée n\'est pas écrasée', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'ancien', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    const { deleted, ...data } = rowOf(result, 'github');
    act(() => { result.current.setEditSecret({ ...data, engineName: 'Alpha', engineVersion: 2, editOf: null }); });
    await run(() => result.current.handleEditSecretSave(formEntry('github', 'ecrase')));
    expect(lastToast(toasts)[1]).toContain('error.secretNameExists');
    expect(vault.versionsOf('Alpha', 'github')).toHaveLength(1);
  });

  test('isNew l\'emporte sur editOf : création', () => {
    expect(editedEntryName({ name: 'a', isNew: true, editOf: 'a' }, [{ name: 'a' }])).toBeNull();
  });

  test('editOf d\'une ligne d\'un autre coffre que le coffre affiché : ignoré (création)', () => {
    expect(editedEntryName({ name: 'a', engineName: 'Beta', editOf: 'a' }, [{ name: 'a' }], { shownEngineName: 'Alpha' })).toBeNull();
    expect(editedEntryName({ name: 'a', engineName: 'Alpha', editOf: 'a' }, [], { shownEngineName: 'Alpha' })).toBe('a');
  });
});

describe('SECRETS-11 : ligne affichée elle-même, quel que soit son contenu', () => {
  test('« Modifier » sur un résultat multi-coffres plus récent que la liste du coffre : modification', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'banque', { Username: 'u', Password: 'pass-1', Tags: 'urgent', EntryType: 'secret' });
    const toasts = [];
    const state = { engine };
    const { result, rerender } = mount(state, toasts);
    await run(() => result.current.fetchSecrets(engine));
    // Tag retiré depuis les résultats multi-coffres : seuls les résultats sont relus (liste périmée)
    vault.writeRaw('Alpha', 'banque', { Username: 'u', Password: 'pass-1', Tags: '', EntryType: 'secret' });
    Object.assign(state, { multi: true, search: 'banque', all: [resultRow('Alpha', 'banque')] });
    rerender();
    const shown = result.current.filteredSecrets.find(s => s.name === 'banque');
    expect(shown).toBe(state.all[0]);
    act(() => { result.current.setEditSecret(shown); });
    await run(() => result.current.handleEditSecretSave(formEntry('banque', 'pass-2')));
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretSaved']);
    expect(vault.latest('Alpha', 'banque').data.Password).toBe('pass-2');
  });

  test('résultat homonyme d\'un AUTRE coffre (même contenu) : jamais une modification du coffre affiché', async () => {
    const engine = vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'p', EntryType: 'secret' });
    vault.writeRaw('Beta', 'github', { Username: 'u', Password: 'p', EntryType: 'secret' });
    const toasts = [];
    const state = { engine };
    const { result, rerender } = mount(state, toasts);
    await run(() => result.current.fetchSecrets(engine));
    Object.assign(state, { multi: true, search: 'github', all: [resultRow('Beta', 'github')] });
    rerender();
    act(() => { result.current.setEditSecret(result.current.filteredSecrets[0]); });
    expect(result.current.editSecret.editOf).toBeNull();
    // Renommage depuis cette fiche : l'entrée « github » du coffre affiché n'est pas supprimée
    await run(() => result.current.handleEditSecretSave(formEntry('github-2', 'p')));
    expect(vault.isLive('Alpha', 'github')).toBe(true);
    expect(vault.isLive('Alpha', 'github-2')).toBe(true);
  });
});

describe('SECRETS-11 : décision portée par l\'objet d\'édition', () => {
  test('editOf posé à l\'ouverture : nom de l\'entrée pour « Modifier », null pour une création ou une duplication', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'p', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret(rowOf(result, 'github')); });
    expect(result.current.editSecret).toMatchObject({ name: 'github', password: 'p', editOf: 'github' });
    act(() => { result.current.setEditSecret({ name: '', username: '', password: '', url: '', notes: '' }); });
    expect(result.current.editSecret.editOf).toBeNull();
    act(() => { result.current.setEditSecret({ ...rowOf(result, 'github'), name: 'github_copie' }); });
    expect(result.current.editSecret.editOf).toBeNull();
    act(() => { result.current.setEditSecret(null); });
    expect(result.current.editSecret).toBeNull();
  });

  test('fiche rouverte avec l\'objet d\'édition après un rafraîchissement de la liste : reste une modification', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'v1', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret(rowOf(result, 'github')); });
    const opened = result.current.editSecret;
    act(() => { result.current.setEditSecret(null); });
    // Entrée modifiée ailleurs (extension) puis liste relue : la ligne affichée a changé
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'v2-extension', EntryType: 'secret' });
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret(opened); });
    await run(() => result.current.handleEditSecretSave(formEntry('github', 'v3')));
    // Entrée modifiée ailleurs depuis l'ouverture : le champ changé dans la fiche l'emporte, l'utilisateur
    // est informé de la fusion (services/staleWriteGuard.js)
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretSavedMerged']);
    expect(vault.latest('Alpha', 'github').data.Password).toBe('v3');
  });
});

describe('BIDI : noms isolés dans les toasts en RTL', () => {
  test('arabe : nom existant isolé dans son propre sens, nom réservé isolé de gauche à droite', async () => {
    document.documentElement.dir = 'rtl';
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'banque', { Password: 'p', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret({ name: '', username: '', password: '', url: '', notes: '' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('banque', 'x')));
    expect(lastToast(toasts)[1]).toContain(`${FSI}banque${PDI}`);
    await run(() => result.current.handleEditSecretSave(formEntry('.rdvault-passkeys', 'x')));
    expect(lastToast(toasts)[1]).toContain(`${LRI}.rdvault-passkeys${PDI}`);
  });

  test('langue LTR : texte inchangé', async () => {
    document.documentElement.dir = 'ltr';
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'banque', { Password: 'p', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret({ name: '', username: '', password: '', url: '', notes: '' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('banque', 'x')));
    expect(lastToast(toasts)[1]).toBe('error.secretNameExists {"name":"banque"}');
  });
});
