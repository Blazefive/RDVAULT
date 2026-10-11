// ========================================
// TESTS : useSecrets — intégrité des entrées (vague E)
// ========================================
// Hooks réels (useSecrets + useTotp + createVaultApi) contre le faux Vault en mémoire du projet.
// - SECRETS-11 : « + Nouvelle entrée » / « Dupliquer » n'écrasent jamais une entrée existante.
// - SECRETS-19 : « Afficher les supprimés » est respecté par TOUS les rechargements.
// - SECRETS-32 : le rafraîchissement tardif d'un coffre qui n'est plus affiché est ignoré.
// - SECRETS-33 : une suppression douce (restaurable) ne détruit jamais la graine TOTP ; en KV v1
//                (suppression définitive), seulement sur demande explicite et si aucune autre
//                entrée ne revendique la clé.
// - Suites : HTTP 500 traduit (plus de phrase française codée en dur) ; 500 « decryption failed »
//            compté et signalé comme entrée illisible.
import { useState, act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
import { useSecrets } from './useSecrets';
import { useTotp } from './useTotp';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

let vault;
let legacy; // coffre KV v1 « legacy » en mémoire (pas de versions : DELETE définitif)
beforeEach(() => {
  vault = createFakeVault();
  legacy = new Map();
  const V1 = `${vault.VAULT_URL}/v1/legacy`;
  const keyOf = (url) => decodeURIComponent(String(url).slice(V1.length + 1).split('?')[0]);
  const err = (status) => { const e = new Error(String(status)); e.response = { status, data: {} }; return Promise.reject(e); };
  axios.get.mockImplementation((url) => {
    if (String(url).startsWith(V1)) {
      if (String(url).includes('?list=true')) return legacy.size ? Promise.resolve({ status: 200, data: { data: { keys: Array.from(legacy.keys()) } } }) : err(404);
      const k = keyOf(url);
      return legacy.has(k) ? Promise.resolve({ status: 200, data: { data: JSON.parse(JSON.stringify(legacy.get(k))) } }) : err(404);
    }
    return vault.axios.get(url);
  });
  axios.post.mockImplementation((url, body) => {
    if (String(url).startsWith(V1)) { legacy.set(keyOf(url), JSON.parse(JSON.stringify(body))); return Promise.resolve({ status: 204, data: {} }); }
    return vault.axios.post(url, body);
  });
  axios.put.mockImplementation(vault.axios.put);
  axios.delete.mockImplementation((url) => {
    if (String(url).startsWith(V1)) { legacy.delete(keyOf(url)); return Promise.resolve({ status: 204, data: {} }); }
    return vault.axios.delete(url);
  });
});
afterEach(() => { document.body.innerHTML = ''; });

/**
 * Monte useSecrets + useTotp. `state` est lu à chaque rendu : changer state.engine / state.showDeleted
 * puis appeler rerender() simule un changement de coffre ou de case à cocher.
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
      vaultApiRef, vaultUrl: vault.VAULT_URL, selectedEngine: state.engine, search: '', showDeleted: !!state.showDeleted,
      secrets, setSecrets, multiVaultSearch: false, allVaultSecrets: [],
      treeViewEnabled: !!state.tree, currentPath: state.currentPath || '', currentFolderContent: null,
      mergeDiscoveredAndSharedTagsRef: { current: null }, setDiscoveredTags: () => {},
      syncExtensionRef: { current: null }, restoreFocus: () => {},
      getTotpKeyName: totp.getTotpKeyName, checkTotpExists: totp.checkTotpExists, totpEngineName: totp.totpEngineName,
      showToast, t: fakeT
    });
    return { ...s, secrets, totp };
  });
}

const run = (fn) => act(async () => { await fn(); });
const lastToast = (toasts) => toasts[toasts.length - 1];
const formEntry = (name, password, extra = {}) => ({
  name, username: 'u', password, url: '', notes: '', tags: '', customFields: [], attachments: [], entryType: 'secret', ...extra,
});
const rowOf = (result, name) => result.current.secrets.find(s => s.name === name);

// ========================================
// SECRETS-11 : création / duplication
// ========================================
describe('SECRETS-11 : « Nouvelle entrée » et « Dupliquer » n\'écrasent pas une entrée existante', () => {
  test('création (vue liste) avec le nom d\'une entrée existante : refus, aucune nouvelle version, fiche ouverte', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'banque', { Username: 'societe', Password: 'Ancien-MDP-Banque', Notes: 'codes de secours: 1111 2222' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));

    act(() => { result.current.setEditSecret({ name: '', username: '', password: '', url: '', notes: '' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('banque', 'Mot-de-passe-du-wifi')));

    expect(lastToast(toasts)[0]).toBe('error');
    expect(lastToast(toasts)[1]).toContain('error.secretNameExists');
    expect(vault.versionsOf('Alpha', 'banque')).toHaveLength(1);
    expect(vault.latest('Alpha', 'banque').data.Notes).toBe('codes de secours: 1111 2222');
    expect(result.current.editSecret).not.toBeNull();
  });

  test('création dans un dossier (nom pré-rempli « prod/ ») : refus si le nom existe, et jamais de suppression de « prod/ »', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'prod/db', { Password: 'MDP-DB' });
    const toasts = [];
    const { result } = mount({ engine, tree: true, currentPath: 'prod' }, toasts);
    await run(() => result.current.fetchSecrets(engine));

    act(() => { result.current.setEditSecret({ name: 'prod/', username: '', password: '', url: '', notes: '' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('prod/db', 'ecrase')));
    expect(lastToast(toasts)[1]).toContain('error.secretNameExists');
    expect(vault.versionsOf('Alpha', 'prod/db')).toHaveLength(1);

    // Nom libre : créée, sans aucune tentative de suppression de l'« ancien nom » « prod/ »
    await run(() => result.current.handleEditSecretSave(formEntry('prod/cache', 'nouveau')));
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretSaved']);
    expect(vault.isLive('Alpha', 'prod/cache')).toBe(true);
    expect(vault.calls.some(c => c.path.endsWith('metadata/prod/') || c.path.endsWith('delete/prod/'))).toBe(false);
  });

  test('deuxième « Dupliquer » (x_copie existe déjà, contenu différent) : refus, x_copie intacte', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'x', { Username: 'u', Password: 'MDP-X', EntryType: 'secret' });
    vault.writeRaw('Alpha', 'x_copie', { Username: 'u', Password: 'MDP-COPIE-MODIFIE', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));

    // Même objet que SecretContextMenu (« Dupliquer ») : copie de la ligne avec le nom suffixé
    act(() => { result.current.setEditSecret({ ...rowOf(result, 'x'), name: 'x_copie' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('x_copie', 'MDP-X')));

    expect(lastToast(toasts)[1]).toContain('error.secretNameExists');
    expect(vault.versionsOf('Alpha', 'x_copie')).toHaveLength(1);
    expect(vault.latest('Alpha', 'x_copie').data.Password).toBe('MDP-COPIE-MODIFIE');
    expect(vault.isLive('Alpha', 'x')).toBe(true);
  });

  test('deuxième « Dupliquer » alors que x_copie est restée identique à x : refus quand même', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'x', { Username: 'u', Password: 'MDP-X', EntryType: 'secret' });
    vault.writeRaw('Alpha', 'x_copie', { Username: 'u', Password: 'MDP-X', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret({ ...rowOf(result, 'x'), name: 'x_copie' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('x_copie', 'AUTRE')));
    expect(lastToast(toasts)[1]).toContain('error.secretNameExists');
    expect(vault.versionsOf('Alpha', 'x_copie')).toHaveLength(1);
  });

  test('« Dupliquer » en vue arborescence (displayName de l\'entrée d\'origine) : création', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'prod/x', { Username: 'u', Password: 'MDP-X', EntryType: 'secret' });
    vault.writeRaw('Alpha', 'prod/x_copie', { Username: 'u', Password: 'MDP-X', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine, tree: true, currentPath: 'prod' }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret({ ...rowOf(result, 'prod/x'), displayName: 'x', name: 'prod/x_copie' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('prod/x_copie', 'AUTRE')));
    expect(lastToast(toasts)[1]).toContain('error.secretNameExists');
    expect(vault.versionsOf('Alpha', 'prod/x_copie')).toHaveLength(1);
  });

  test('première duplication (nom libre) : créée, la source reste intacte', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'x', { Username: 'u', Password: 'MDP-X', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret({ ...rowOf(result, 'x'), name: 'x_copie' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('x_copie', 'MDP-X')));
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretSaved']);
    expect(vault.versionsOf('Alpha', 'x_copie')).toHaveLength(1);
    expect(vault.isLive('Alpha', 'x')).toBe(true);
    expect(vault.versionsOf('Alpha', 'x')).toHaveLength(1);
  });

  test('« Modifier » une entrée existante (ligne du tableau) reste permis : nouvelle version', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'ancien', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret(rowOf(result, 'github')); });
    await run(() => result.current.handleEditSecretSave(formEntry('github', 'nouveau')));
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretSaved']);
    expect(vault.versionsOf('Alpha', 'github')).toHaveLength(2);
    expect(vault.latest('Alpha', 'github').data.Password).toBe('nouveau');
  });

  test('« Modifier » depuis la vue arborescence (copie de la ligne avec displayName) reste permis', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'prod/db', { Username: 'u', Password: 'ancien', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine, tree: true, currentPath: 'prod' }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret({ ...rowOf(result, 'prod/db'), displayName: 'db' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('prod/db', 'nouveau')));
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretSaved']);
    expect(vault.latest('Alpha', 'prod/db').data.Password).toBe('nouveau');
  });

  test('« Modifier » depuis la recherche multi-coffre (ligne avec engineName, sans « deleted ») reste permis', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'ancien', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    const { deleted, ...data } = rowOf(result, 'github');
    expect(deleted).toBe(false);
    // Ligne lue par readAllSecrets (+ un marqueur que l'appelant pourrait ajouter)
    act(() => { result.current.setEditSecret({ ...data, engineName: 'Alpha', engineVersion: 2, engine }); });
    await run(() => result.current.handleEditSecretSave(formEntry('github', 'nouveau')));
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretSaved']);
    expect(vault.latest('Alpha', 'github').data.Password).toBe('nouveau');
  });

  test('liste rafraîchie pendant la saisie (entrée modifiée ailleurs) : la fiche reste une modification', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'v1', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret(rowOf(result, 'github')); });
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'v2-extension', EntryType: 'secret' });
    await run(() => result.current.fetchSecrets(engine));
    await run(() => result.current.handleEditSecretSave(formEntry('github', 'v3')));
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretSaved']);
    expect(vault.latest('Alpha', 'github').data.Password).toBe('v3');
  });

  test('marqueur explicite isNew : traité comme une création', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'p', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret({ ...rowOf(result, 'github'), isNew: true }); });
    await run(() => result.current.handleEditSecretSave(formEntry('github', 'autre')));
    expect(lastToast(toasts)[1]).toContain('error.secretNameExists');
    expect(vault.versionsOf('Alpha', 'github')).toHaveLength(1);
  });

  test('création sur le nom d\'une entrée supprimée (restaurable) : permise, comme le renommage', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'ancien', { Password: 'old', EntryType: 'secret' });
    vault.versionsOf('Alpha', 'ancien')[0].deletion_time = '2026-01-01T00:00:00Z';
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret({ name: '', username: '', password: '', url: '', notes: '' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('ancien', 'neuf')));
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretSaved']);
    expect(vault.latest('Alpha', 'ancien')).toMatchObject({ version: 2, data: { Password: 'neuf' } });
  });

  test('création sur un nom dont la clé TOTP existe (entrée supprimée auparavant) : le rattachement est signalé', async () => {
    const engine = vault.addEngine('Alpha');
    vault.addTotp('ALPHA-banque');
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    act(() => { result.current.setEditSecret({ name: '', username: '', password: '', url: '', notes: '' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('banque', 'p')));
    expect(vault.isLive('Alpha', 'banque')).toBe(true);
    expect(lastToast(toasts)[0]).toBe('warning');
    expect(lastToast(toasts)[1]).toContain('toast.secretSavedTotpAttached');
  });
});

// ========================================
// SECRETS-19 : filtre « Afficher les supprimés »
// ========================================
describe('SECRETS-19 : « Afficher les supprimés » respecté par les rechargements sans argument', () => {
  test('fetchSecrets(coffre) sans 2e argument suit la case cochée', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'a1', { Password: 'p' });
    vault.writeRaw('Alpha', 'ancienne', { Password: 'p' });
    vault.versionsOf('Alpha', 'ancienne')[0].deletion_time = '2026-01-01T00:00:00Z';
    const toasts = [];
    const { result } = mount({ engine, showDeleted: true }, toasts);
    // Appel comme useTags / CreateFolderInlineModal / handleDeleteFolder (sans includeDeleted)
    await run(() => result.current.fetchSecrets(engine));
    expect(result.current.secrets.map(s => `${s.name}${s.deleted ? '(supprimée)' : ''}`).sort()).toEqual(['a1', 'ancienne(supprimée)']);
  });

  test('« Restaurer une version » garde les entrées supprimées affichées', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'a1', { Password: 'v1', EntryType: 'secret' });
    vault.writeRaw('Alpha', 'a1', { Password: 'v2', EntryType: 'secret' });
    vault.writeRaw('Alpha', 'ancienne', { Password: 'p' });
    vault.versionsOf('Alpha', 'ancienne')[0].deletion_time = '2026-01-01T00:00:00Z';
    const toasts = [];
    const { result } = mount({ engine, showDeleted: true }, toasts);
    await run(() => result.current.fetchSecrets(engine, true));
    act(() => { result.current.setVersionHistory({ secretName: 'a1' }); });
    await run(() => result.current.handleRestoreVersion(1, { Password: 'v1', EntryType: 'secret' }));
    expect(result.current.secrets.some(s => s.name === 'ancienne' && s.deleted)).toBe(true);
  });

  test('case décochée : comportement inchangé (pas d\'entrées supprimées)', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'a1', { Password: 'p' });
    vault.writeRaw('Alpha', 'ancienne', { Password: 'p' });
    vault.versionsOf('Alpha', 'ancienne')[0].deletion_time = '2026-01-01T00:00:00Z';
    const toasts = [];
    const { result } = mount({ engine, showDeleted: false }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    expect(result.current.secrets.map(s => s.name)).toEqual(['a1']);
  });
});

// ========================================
// SECRETS-32 : rafraîchissement d'un coffre qui n'est plus affiché
// ========================================
describe('SECRETS-32 : la liste affichée est toujours celle du coffre sélectionné', () => {
  test('fin de migration (rafraîchit le coffre source A) après ouverture du coffre C : ignoré', async () => {
    const A = vault.addEngine('a-src');
    const C = vault.addEngine('c-autre');
    vault.writeRaw('a-src', 'github', { Password: 'github-src' });
    vault.writeRaw('a-src', 'jira', { Password: 'j' });
    vault.writeRaw('c-autre', 'github', { Password: 'github-c' });
    const state = { engine: A };
    const toasts = [];
    const { result, rerender } = mount(state, toasts);
    await run(() => result.current.fetchSecrets(A));
    expect(result.current.secrets.map(s => s.name).sort()).toEqual(['github', 'jira']);

    // L'utilisateur ouvre C pendant l'opération ; l'effet d'App relit C
    state.engine = C;
    rerender();
    await run(() => result.current.fetchSecrets(C));
    // Fin de l'opération : rafraîchissement du coffre capturé au moment du dépôt
    await run(() => result.current.fetchSecrets(A));

    expect(result.current.secrets.map(s => `${s.name}:${s.password}`)).toEqual(['github:github-c']);
  });

  test('lecture du coffre affiché encore possible (rafraîchissement normal)', async () => {
    const A = vault.addEngine('a-src');
    vault.writeRaw('a-src', 'x', { Password: '1' });
    const toasts = [];
    const { result } = mount({ engine: A }, toasts);
    await run(() => result.current.fetchSecrets(A));
    vault.writeRaw('a-src', 'y', { Password: '2' });
    await run(() => result.current.fetchSecrets(A));
    expect(result.current.secrets.map(s => s.name).sort()).toEqual(['x', 'y']);
  });

  test('changement de coffre PENDANT la lecture : le résultat de l\'ancien coffre est abandonné', async () => {
    const A = vault.addEngine('a-src');
    const C = vault.addEngine('c-autre');
    vault.writeRaw('a-src', 'x', { Password: 'A' });
    vault.writeRaw('c-autre', 'y', { Password: 'C' });
    const state = { engine: A };
    const toasts = [];
    const { result, rerender } = mount(state, toasts);
    // Lecture de A retenue (liste) jusqu'au changement de coffre
    let release;
    const gate = new Promise(r => { release = r; });
    const baseGet = axios.get.getMockImplementation();
    axios.get.mockImplementation(async (url) => {
      if (String(url).includes('/v1/a-src/metadata?list=true')) await gate;
      return baseGet(url);
    });
    let pending;
    act(() => { pending = result.current.fetchSecrets(A); });
    state.engine = C;
    rerender();
    release();
    await run(() => pending);
    expect(result.current.secrets.map(s => s.name)).toEqual([]);
  });
});

// ========================================
// SECRETS-33 : graine TOTP et suppression
// ========================================
describe('SECRETS-33 : une suppression restaurable ne détruit pas la graine TOTP', () => {
  async function deleteEntry(result, name, extra = {}) {
    await run(() => result.current.confirmDeleteSecret({ name }));
    if (Object.keys(extra).length) act(() => { result.current.setSecretToDelete(prev => ({ ...prev, ...extra })); });
    await run(() => result.current.deleteSecret());
  }

  test('KV v2 : Supprimer puis Restaurer → l\'entrée revient AVEC sa clé TOTP', async () => {
    const engine = vault.addEngine('KV');
    vault.writeRaw('KV', 'banque', { Username: 'u', Password: 'p' });
    vault.addTotp('KV-banque');
    const toasts = [];
    const { result } = mount({ engine, showDeleted: true }, toasts);
    await run(() => result.current.fetchSecrets(engine));

    await deleteEntry(result, 'banque');
    expect(vault.isLive('KV', 'banque')).toBe(false);
    expect(vault.totp.has('KV-banque')).toBe(true);
    expect(vault.calls.some(c => c.method === 'delete' && c.path.startsWith('v1/TOTP/keys/'))).toBe(false);
    expect(lastToast(toasts)[1]).toContain('toast.secretDeletedTotpKept');

    await run(() => result.current.undeleteSecret({ name: 'banque' }));
    expect(vault.isLive('KV', 'banque')).toBe(true);
    expect(vault.totp.has('KV-banque')).toBe(true);
  });

  test('KV v2 : même avec la demande explicite (deleteTotp), la graine n\'est pas détruite par une suppression douce', async () => {
    const engine = vault.addEngine('KV');
    vault.writeRaw('KV', 'banque', { Password: 'p' });
    vault.addTotp('KV-banque');
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await deleteEntry(result, 'banque', { deleteTotp: true });
    expect(vault.totp.has('KV-banque')).toBe(true);
  });

  test('KV v1 (suppression définitive) sans demande explicite : graine conservée et signalée', async () => {
    vault.addEngine('legacy', 1);
    const engine = { name: 'legacy', version: 1, canWrite: true, canList: true };
    legacy.set('banque', { Username: 'u', Password: 'p' });
    vault.addTotp('LEGACY-banque');
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await deleteEntry(result, 'banque');
    expect(legacy.has('banque')).toBe(false);
    expect(vault.totp.has('LEGACY-banque')).toBe(true);
    expect(lastToast(toasts)[1]).toContain('toast.secretDeletedTotpKeptOrphan');
  });

  test('KV v1 avec demande explicite et clé non revendiquée : graine détruite', async () => {
    vault.addEngine('legacy', 1);
    const engine = { name: 'legacy', version: 1, canWrite: true, canList: true };
    legacy.set('banque', { Username: 'u', Password: 'p' });
    vault.addTotp('LEGACY-banque');
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await deleteEntry(result, 'banque', { deleteTotp: true });
    expect(vault.totp.has('LEGACY-banque')).toBe(false);
    expect(lastToast(toasts)).toEqual(['success', 'toast.secretDeleted']);
  });

  test('KV v1 avec demande explicite mais clé revendiquée par un autre coffre (même préfixe) : conservée', async () => {
    vault.addEngine('legacy', 1);
    vault.addEngine('users/alice/legacy');
    vault.writeRaw('users/alice/legacy', 'banque', { Password: 'perso' });
    const engine = { name: 'legacy', version: 1, canWrite: true, canList: true };
    legacy.set('banque', { Password: 'p' });
    vault.addTotp('LEGACY-banque');
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await deleteEntry(result, 'banque', { deleteTotp: true });
    expect(vault.totp.has('LEGACY-banque')).toBe(true);
    expect(lastToast(toasts)[1]).toContain('toast.totpKeptShared');
  });
});

// ========================================
// Suites (notes de la vague D)
// ========================================
describe('Suites : erreurs traduites et entrées indéchiffrables', () => {
  test('HTTP 500 à l\'enregistrement : message traduit (plus de phrase française codée en dur)', async () => {
    const engine = vault.addEngine('Alpha');
    vault.setFailWhen((method, path) => (method === 'post' && path === 'v1/Alpha/data/gros' ? 500 : null));
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    act(() => { result.current.setEditSecret({ name: '', username: '', password: '', url: '', notes: '' }); });
    await run(() => result.current.handleEditSecretSave(formEntry('gros', 'p')));
    expect(lastToast(toasts)[0]).toBe('error');
    expect(lastToast(toasts)[1]).not.toContain('Le secret est trop volumineux');
    expect(lastToast(toasts)[1]).toContain('error.secretTooLarge');
  });

  test('500 « decryption failed » : entrée comptée comme illisible et signalée (pas masquée en silence)', async () => {
    const engine = vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'ok', { Password: 'p' });
    vault.writeRaw('Alpha', 'abimee', { Password: 'p' });
    vault.setFailWhen((method, path) => {
      if (method === 'get' && path === 'v1/Alpha/data/abimee') return 500;
      return null;
    });
    const toasts = [];
    const { result } = mount({ engine }, toasts);
    await run(() => result.current.fetchSecrets(engine));
    expect(result.current.secrets.map(s => s.name)).toEqual(['ok']);
    expect(toasts.some(([k, m]) => k === 'warning' && m.includes('error.secretsUnreadable') && m.includes('"count":1'))).toBe(true);
  });
});
