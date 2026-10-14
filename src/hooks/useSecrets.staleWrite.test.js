// ========================================
// TESTS : écritures fondées sur une ligne PÉRIMÉE (Vault partagé, cache de lecture par coffre)
// ========================================
// Vault distant : la liste d'un coffre est gardée en cache jusqu'à 2 min (services/engineReadCache.js) ;
// une entrée modifiée entre-temps par un AUTRE client (autre poste, API, CLI) reste affichée avec son
// ancien contenu. « Modifier » puis « Enregistrer », ou « Ajouter / Retirer un tag », réécrivaient alors
// cette ligne périmée par-dessus la version plus récente (mot de passe changé ailleurs perdu).
// Désormais :
// - fiche « Modifier » : contenu courant relu avant l'écriture ; s'il a changé depuis l'ouverture, seuls
//   les champs changés dans la fiche lui sont appliqués (les autres gardent leur valeur COURANTE, jamais
//   l'ancienne), utilisateur informé ; écriture conditionnelle (check-and-set KV v2 sur la version relue :
//   une écriture concurrente entre la relecture et l'écriture est refusée par Vault, rien n'est écrit) ;
//   entrée supprimée ailleurs : rien n'est écrit (pas de résurrection silencieuse) ;
// - tags : le tag est appliqué au contenu COURANT de l'entrée (relu), écrit en check-and-set.
import { useState, act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
import { useSecrets } from './useSecrets';
import { useTags } from './useTags';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

const ENGINE = { name: 'kv', version: 2, canWrite: true };
let vault;
let beforeDataWrite; // (clé) => void : écriture « d'un autre client » juste avant l'écriture de l'application

// Faux Vault + check-and-set de KV v2 (options.cas : version courante attendue, 0 = absente) comme Vault
function casAwarePost(url, body) {
  const m = /\/v1\/kv\/data\/(.+)$/.exec(url);
  if (m) {
    const key = decodeURIComponent(m[1]);
    if (beforeDataWrite) { const f = beforeDataWrite; beforeDataWrite = null; f(key); }
    const cas = body?.options?.cas;
    if (cas !== undefined) {
      const current = vault.latest('kv', key)?.version || 0;
      if (current !== cas) {
        return Promise.reject(Object.assign(new Error('400'), {
          response: { status: 400, data: { errors: ['check-and-set parameter did not match the current version'] } },
        }));
      }
    }
  }
  return vault.axios.post(url, body);
}

beforeEach(() => {
  vault = createFakeVault();
  vault.addEngine('kv', 2);
  vault.writeRaw('kv', 'e', { Username: 'u', Password: 'V1', URL: '', Notes: '', Tags: 'a', EntryType: 'secret' });
  beforeDataWrite = null;
  axios.get.mockImplementation(vault.axios.get);
  axios.post.mockImplementation(casAwarePost);
  axios.put.mockImplementation(casAwarePost);
  axios.delete.mockImplementation(vault.axios.delete);
});
afterEach(() => { document.body.innerHTML = ''; });

// Écriture d'un AUTRE client : nouveau mot de passe
const otherClientWrites = (password) => vault.writeRaw('kv', 'e', { Username: 'u', Password: password, URL: '', Notes: '', Tags: 'a', EntryType: 'secret' });

function mount(toasts) {
  const vaultApiRef = { current: createVaultApi(vault.VAULT_URL, 'tok') };
  const showToast = (m, k) => toasts.push([k, m]);
  const fetchSecretsRef = { current: null };
  const view = renderHook(() => {
    const [secrets, setSecrets] = useState([]);
    const s = useSecrets({
      vaultApiRef, vaultUrl: vault.VAULT_URL, selectedEngine: ENGINE, search: '', showDeleted: false,
      secrets, setSecrets, multiVaultSearch: false, allVaultSecrets: [],
      treeViewEnabled: false, currentPath: '', currentFolderContent: null,
      mergeDiscoveredAndSharedTagsRef: { current: null }, setDiscoveredTags: () => {},
      syncExtensionRef: { current: null }, restoreFocus: () => {},
      getTotpKeyName: (n) => `KV-${n}`, checkTotpExists: async () => false, totpEngineName: 'TOTP',
      showToast, t: fakeT,
    });
    fetchSecretsRef.current = s.fetchSecrets;
    const tags = useTags({
      vaultUrl: vault.VAULT_URL, baseHeaders: vaultApiRef.current.baseHeaders, axiosConfig: vaultApiRef.current.axiosConfig,
      selectedEngine: ENGINE, secretEngines: [ENGINE], multiVaultSearch: false,
      vaultApi: vaultApiRef.current, fetchSecretsRef,
      setAllVaultSecrets: () => {}, setLoadingAllSecrets: () => {}, showToast, t: fakeT,
    });
    return { ...s, tags, secrets };
  });
  return view;
}

const run = (fn) => act(async () => { await fn(); });
const rowOf = (result) => result.current.secrets.find(s => s.name === 'e');
const lastToast = (toasts) => toasts[toasts.length - 1];

// Liste lue, puis modification par un autre client ; la relecture incrémentale (cache jeune) garde la
// ligne périmée — situation de l'application contre un Vault partagé pendant au plus 2 min
async function staleRow(result) {
  await run(() => result.current.fetchSecrets(ENGINE));
  otherClientWrites('V2-AUTRE-POSTE');
  await run(() => result.current.fetchSecrets(ENGINE, false, { incremental: true }));
  const row = rowOf(result);
  expect(row.password).toBe('V1'); // ligne affichée périmée (cache)
  return row;
}

test('Modifier / Enregistrer sur une ligne périmée : la version plus récente n\'est PAS écrasée, seuls les champs changés sont appliqués', async () => {
  const toasts = [];
  const { result } = mount(toasts);
  const row = await staleRow(result);
  await run(() => result.current.setEditSecret(row));
  await run(() => result.current.handleEditSecretSave({ ...row, notes: 'ma note' }));
  const stored = vault.latest('kv', 'e');
  expect(stored.data.Password).toBe('V2-AUTRE-POSTE'); // avant : 'V1' (ligne périmée réécrite)
  expect(stored.data.Notes).toBe('ma note');
  expect(stored.version).toBe(3);
  expect(lastToast(toasts)).toEqual(['success', 'toast.secretSavedMerged']);
  expect(rowOf(result).password).toBe('V2-AUTRE-POSTE');
  // Écriture conditionnelle à la version relue (2)
  const write = axios.post.mock.calls.filter(([u]) => /\/v1\/kv\/data\/e$/.test(u)).pop();
  expect(write[1].options).toEqual({ cas: 2 });
});

test('Renommer une ligne périmée : la nouvelle entrée porte le contenu COURANT (et non l\'ancien)', async () => {
  const toasts = [];
  const { result } = mount(toasts);
  const row = await staleRow(result);
  await run(() => result.current.setEditSecret(row));
  await run(() => result.current.handleEditSecretSave({ ...row, name: 'e-renommee' }));
  expect(vault.latest('kv', 'e-renommee').data.Password).toBe('V2-AUTRE-POSTE'); // avant : 'V1'
  expect(vault.isLive('kv', 'e')).toBe(false);
  expect(lastToast(toasts)).toEqual(['success', 'toast.secretSavedMerged']);
});

test('Entrée supprimée ailleurs depuis l\'ouverture : pas de résurrection silencieuse', async () => {
  const toasts = [];
  const { result } = mount(toasts);
  await run(() => result.current.fetchSecrets(ENGINE));
  const row = rowOf(result);
  await run(() => result.current.setEditSecret(row));
  vault.versionsOf('kv', 'e')[0].deletion_time = '2026-01-01T00:00:00Z'; // suppression douce ailleurs
  await run(() => result.current.handleEditSecretSave({ ...row, password: 'MOI' }));
  expect(vault.versionsOf('kv', 'e').length).toBe(1);
  expect(lastToast(toasts)[1]).toMatch(/^error\.secretChangedElsewhere/);
});

test('Ligne à jour : enregistrement normal, en check-and-set sur la version relue', async () => {
  const toasts = [];
  const { result } = mount(toasts);
  await run(() => result.current.fetchSecrets(ENGINE));
  const row = rowOf(result);
  await run(() => result.current.setEditSecret(row));
  await run(() => result.current.handleEditSecretSave({ ...row, password: 'MOI' }));
  expect(vault.latest('kv', 'e').data.Password).toBe('MOI');
  const write = axios.post.mock.calls.find(([u]) => /\/v1\/kv\/data\/e$/.test(u));
  expect(write[1].options).toEqual({ cas: 1 });
  expect(lastToast(toasts)).toEqual(['success', 'toast.secretSaved']);
});

test('Écriture concurrente entre la relecture et l\'écriture : refusée par check-and-set, rien d\'écrasé', async () => {
  const toasts = [];
  const { result } = mount(toasts);
  await run(() => result.current.fetchSecrets(ENGINE));
  const row = rowOf(result);
  await run(() => result.current.setEditSecret(row));
  beforeDataWrite = () => otherClientWrites('V2-COURSE');
  await run(() => result.current.handleEditSecretSave({ ...row, password: 'MOI' }));
  expect(vault.latest('kv', 'e').data.Password).toBe('V2-COURSE');
  expect(lastToast(toasts)[1]).toMatch(/^error\.secretChangedElsewhere/);
});

test('Ajouter un tag sur une ligne périmée : tag appliqué à la version courante (mot de passe récent conservé)', async () => {
  const toasts = [];
  const { result } = mount(toasts);
  const row = await staleRow(result);
  await run(() => result.current.tags.handleAddTagToSecret(row, 'nouveau'));
  const stored = vault.latest('kv', 'e');
  expect(stored.data.Password).toBe('V2-AUTRE-POSTE');
  expect(stored.data.Tags.split(/[\s,;]+/)).toEqual(expect.arrayContaining(['a', 'nouveau']));
  expect(stored.version).toBe(3);
});

test('Retirer un tag sur une ligne périmée : version courante conservée, tag retiré', async () => {
  const toasts = [];
  const { result } = mount(toasts);
  const row = await staleRow(result);
  await run(() => result.current.tags.handleRemoveTagFromSecret(row, 'a'));
  const stored = vault.latest('kv', 'e');
  expect(stored.data.Password).toBe('V2-AUTRE-POSTE');
  expect(stored.data.Tags).toBe('');
});
