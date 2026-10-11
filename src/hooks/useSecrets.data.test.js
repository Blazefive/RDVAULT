// ========================================
// TESTS : useSecrets — intégrité des données (suppression/TOTP, restauration, renommage)
// ========================================
// Hooks réels (useSecrets + useTotp + createVaultApi) contre un faux Vault en mémoire.
// - DATA-2 : supprimer une entrée ne détruit pas la clé TOTP d'un AUTRE coffre au nom voisin
//            (« Banque » et « users/x/Banque » produisent la même clé BANQUE-<entrée>).
// - DATA-4 : « Restaurer » une version réécrit la version complète (tags, champs, pièces jointes, type).
// - DATA-6 : renommer vers un nom existant est refusé ; un échec d'écriture ne fait pas disparaître l'entrée.
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
beforeEach(() => {
  vault = createFakeVault();
  axios.get.mockImplementation(vault.axios.get);
  axios.post.mockImplementation(vault.axios.post);
  axios.put.mockImplementation(vault.axios.put);
  axios.delete.mockImplementation(vault.axios.delete);
});
afterEach(() => { document.body.innerHTML = ''; });

function mount(engine, toasts) {
  const vaultApiRef = { current: createVaultApi(vault.VAULT_URL, 'tok') };
  const showToast = (m, k) => toasts.push([k, m]);
  return renderHook(() => {
    const [secrets, setSecrets] = useState([]);
    const totp = useTotp({
      vaultUrl: vault.VAULT_URL, baseHeaders: vaultApiRef.current.baseHeaders, axiosConfig: vaultApiRef.current.axiosConfig,
      selectedEngine: engine, startClipboardTimer: async () => {}, showToast, t: fakeT, restoreFocus: () => {}
    });
    const s = useSecrets({
      vaultApiRef, vaultUrl: vault.VAULT_URL, selectedEngine: engine, search: '', showDeleted: false,
      secrets, setSecrets, multiVaultSearch: false, allVaultSecrets: [],
      mergeDiscoveredAndSharedTagsRef: { current: null }, setDiscoveredTags: () => {},
      syncExtensionRef: { current: null }, restoreFocus: () => {},
      getTotpKeyName: totp.getTotpKeyName, checkTotpExists: totp.checkTotpExists, totpEngineName: totp.totpEngineName,
      showToast, t: fakeT
    });
    return { ...s, secrets, totp };
  });
}

// « Modifier » : la fiche reçoit la ligne du tableau (liste du coffre chargée), comme SecretContextMenu
async function openRow(result, engine, name) {
  await act(async () => { await result.current.fetchSecrets(engine); });
  const row = result.current.secrets.find(s => s.name === name);
  act(() => { result.current.setEditSecret(row); });
}

async function deleteEntry(result, name) {
  await act(async () => { await result.current.confirmDeleteSecret({ name }); });
  await act(async () => { await result.current.deleteSecret(); });
}

// Règle en vigueur depuis SECRETS-33 (useSecrets.integrity.test.js) : une suppression DOUCE (KV v2,
// restaurable) ne détruit jamais la graine TOTP ; en KV v1 (définitive), seulement sur demande
// explicite et si la clé n'est revendiquée par aucune autre entrée (scénarios KV v1 dans ce fichier-là).
describe('DATA-2 : suppression d\'une entrée et clé TOTP partagée entre coffres', () => {
  test('le TOTP du coffre personnel « users/hunter/Banque » survit à la suppression de « github » dans « Banque »', async () => {
    const shared = vault.addEngine('Banque');
    const perso = vault.addEngine('users/hunter/Banque');
    vault.writeRaw(perso.name, 'github', { Username: 'moi', Password: 'p' });
    vault.writeRaw(shared.name, 'github', { Username: 'equipe', Password: 'q' });
    vault.addTotp('BANQUE-github');

    const toasts = [];
    const { result } = mount(shared, toasts);
    expect(result.current.totp.getTotpKeyName('github')).toBe('BANQUE-github'); // convention historique inchangée
    await deleteEntry(result, 'github');

    expect(vault.isLive(shared.name, 'github')).toBe(false);       // l'entrée est bien supprimée
    expect(vault.totp.has('BANQUE-github')).toBe(true);           // le TOTP de l'autre coffre est intact
    expect(vault.calls.some(c => c.method === 'delete' && c.path.startsWith('v1/TOTP/keys/'))).toBe(false);
  });

  test('sans autre coffre concerné : suppression douce, la clé TOTP est CONSERVÉE (restaurable avec l\'entrée)', async () => {
    const shared = vault.addEngine('Banque');
    vault.addEngine('users/hunter/Banque'); // même préfixe TOTP mais pas d'entrée « github »
    vault.addEngine('Perso');               // autre préfixe
    vault.writeRaw('Perso', 'github', { Password: 'x' });
    vault.writeRaw(shared.name, 'github', { Password: 'q' });
    vault.addTotp('BANQUE-github');

    const toasts = [];
    const { result } = mount(shared, toasts);
    await deleteEntry(result, 'github');

    expect(vault.isLive(shared.name, 'github')).toBe(false);
    expect(vault.totp.has('BANQUE-github')).toBe(true);
    expect(toasts[toasts.length - 1][1]).toContain('toast.secretDeletedTotpKept');
  });

  test('inventaire des coffres impossible : la clé TOTP est conservée (jamais de suppression à l\'aveugle)', async () => {
    const shared = vault.addEngine('Banque');
    vault.writeRaw(shared.name, 'github', { Password: 'q' });
    vault.addTotp('BANQUE-github');
    vault.setFailWhen((method, path) => (method === 'get' && path.startsWith('v1/sys/') ? 503 : null));

    const toasts = [];
    const { result } = mount(shared, toasts);
    await deleteEntry(result, 'github');

    expect(vault.isLive(shared.name, 'github')).toBe(false);
    expect(vault.totp.has('BANQUE-github')).toBe(true);
  });
});

describe('DATA-4 : restauration d\'une version', () => {
  test('la version restaurée est identique à la version source (tags, champs, pièces jointes, type)', async () => {
    const engine = vault.addEngine('kv');
    const v1 = {
      Username: 'admin', Password: 'P1-ancien', URL: 'https://site.example', Website: '', Notes: 'note',
      Tags: 'prod critique',
      CustomFields: [{ key: 'Port', value: '2222' }, { key: 'Env', value: 'production', protected: false }],
      Attachments: [{ name: 'cert.pem', size: 3, type: 'text/plain', data: 'YWJj' }],
      EntryType: 'secret'
    };
    vault.writeRaw(engine.name, 'serveur', v1);
    vault.writeRaw(engine.name, 'serveur', { ...v1, Password: 'P2-nouveau', Tags: '' });

    const toasts = [];
    const { result } = mount(engine, toasts);
    act(() => { result.current.setVersionHistory({ secretName: 'serveur' }); });
    await act(async () => { await result.current.handleRestoreVersion(1, JSON.parse(JSON.stringify(v1))); });

    const cur = vault.latest(engine.name, 'serveur');
    expect(cur.version).toBe(3);
    expect(cur.data).toEqual(v1);
    expect(toasts[toasts.length - 1][0]).toBe('success');
  });

  test('une entrée SSH (clé privée multi-lignes) se restaure aussi', async () => {
    const engine = vault.addEngine('kv');
    const v1 = { Username: '', Password: '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----', URL: 'ssh-ed25519 AAAA u@h', Website: '', Notes: '', Tags: '', EntryType: 'ssh' };
    vault.writeRaw(engine.name, 'cle', v1);
    vault.writeRaw(engine.name, 'cle', { ...v1, Notes: 'v2' });
    const toasts = [];
    const { result } = mount(engine, toasts);
    act(() => { result.current.setVersionHistory({ secretName: 'cle' }); });
    await act(async () => { await result.current.handleRestoreVersion(1, JSON.parse(JSON.stringify(v1))); });
    expect(vault.latest(engine.name, 'cle').data).toEqual(v1);
  });
});

describe('DATA-6 : renommage dans l\'éditeur', () => {
  const entry = (name, password) => ({ name, username: 'perso', password, url: '', notes: '', tags: '', customFields: [], attachments: [], entryType: 'secret' });

  test('renommer vers un nom déjà utilisé est refusé et ne modifie aucune entrée', async () => {
    const engine = vault.addEngine('kv');
    vault.writeRaw(engine.name, 'github', { Username: 'perso', Password: 'MDP-PERSO', EntryType: 'secret' });
    vault.writeRaw(engine.name, 'github-pro', { Username: 'pro', Password: 'MDP-PRO', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount(engine, toasts);
    await openRow(result, engine, 'github');
    await act(async () => { await result.current.handleEditSecretSave(entry('github-pro', 'MDP-PERSO')); });

    expect(toasts[toasts.length - 1][0]).toBe('error');
    expect(toasts[toasts.length - 1][1]).toContain('error.secretNameExists');
    expect(vault.latest(engine.name, 'github-pro')).toMatchObject({ version: 1, data: { Password: 'MDP-PRO' } });
    expect(vault.isLive(engine.name, 'github')).toBe(true);
    expect(result.current.editSecret).not.toBeNull(); // la modale reste ouverte
  });

  test('un échec d\'écriture du nouveau nom laisse l\'ancienne entrée intacte', async () => {
    const engine = vault.addEngine('kv');
    vault.writeRaw(engine.name, 'serveur', { Username: 'u', Password: 'p', EntryType: 'secret' });
    vault.setFailWhen((method, path) => (method === 'post' && path === 'v1/kv/data/serveur-prod' ? 413 : null));
    const toasts = [];
    const { result } = mount(engine, toasts);
    await openRow(result, engine, 'serveur');
    await act(async () => { await result.current.handleEditSecretSave(entry('serveur-prod', 'p')); });

    expect(toasts[toasts.length - 1][0]).toBe('error');
    expect(vault.isLive(engine.name, 'serveur')).toBe(true);       // toujours visible
    expect(vault.latest(engine.name, 'serveur-prod')).toBeNull();
  });

  test('renommage réussi : nouvelle entrée écrite AVANT la suppression douce de l\'ancienne', async () => {
    const engine = vault.addEngine('kv');
    vault.writeRaw(engine.name, 'old', { Username: 'u', Password: 'p', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount(engine, toasts);
    await openRow(result, engine, 'old');
    await act(async () => { await result.current.handleEditSecretSave(entry('new', 'p')); });

    expect(toasts[toasts.length - 1]).toEqual(['success', 'toast.secretSaved']);
    expect(vault.isLive(engine.name, 'new')).toBe(true);
    expect(vault.isLive(engine.name, 'old')).toBe(false);
    expect(vault.latest(engine.name, 'old')).not.toBeNull(); // suppression douce : historique conservé
    const writeIdx = vault.calls.findIndex(c => c.method === 'post' && c.path === 'v1/kv/data/new');
    const deleteIdx = vault.calls.findIndex(c => c.method === 'post' && c.path === 'v1/kv/delete/old');
    expect(writeIdx).toBeGreaterThan(-1);
    expect(deleteIdx).toBeGreaterThan(writeIdx);
  });

  test('renommer vers le nom d\'une entrée supprimée (non visible) reste possible', async () => {
    const engine = vault.addEngine('kv');
    vault.writeRaw(engine.name, 'a', { Password: 'p', EntryType: 'secret' });
    vault.writeRaw(engine.name, 'b', { Password: 'old-b', EntryType: 'secret' });
    vault.versionsOf(engine.name, 'b')[0].deletion_time = '2026-01-01T00:00:00Z';
    const toasts = [];
    const { result } = mount(engine, toasts);
    await openRow(result, engine, 'a');
    await act(async () => { await result.current.handleEditSecretSave(entry('b', 'p')); });
    expect(toasts[toasts.length - 1]).toEqual(['success', 'toast.secretSaved']);
    expect(vault.latest(engine.name, 'b')).toMatchObject({ version: 2, data: { Password: 'p' } });
  });
});
