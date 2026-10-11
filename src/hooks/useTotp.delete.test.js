// ========================================
// TESTS : useTotp — suppression d'une clé TOTP et erreurs traduites (vague E)
// ========================================
// - SECRETS-12 : « Supprimer le TOTP » ne détruit plus la graine au premier clic (confirmation par une
//   seconde demande explicite, ou { confirmed: true } depuis une boîte de confirmation), et jamais
//   une clé revendiquée par l'entrée homonyme d'un autre coffre.
// - Suite LOCALVAULT-2 : findEngineSharingTotpKey applique la règle de « revendication exacte » du
//   serveur local (secretsService.deleteEngine) : « Prod-EU/db » et « Prod/EU-db » partagent PROD-EU-db.
// - Suite i18n : les toasts d'erreur TOTP gardent le statut HTTP (message traduit adapté) au lieu
//   d'un « Une erreur est survenue » générique.
import { act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
import { useTotp, findEngineSharingTotpKey } from './useTotp';
import fr from '../locales/fr.json';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

// Traducteur français minimal (vraies chaînes de fr.json, variables {{x}})
const tFr = (key, vars) => {
  const raw = key.split('.').reduce((o, k) => (o == null ? o : o[k]), fr);
  if (typeof raw !== 'string') return key;
  return raw.replace(/\{\{(\w+)\}\}/g, (_, n) => (vars && vars[n] != null ? String(vars[n]) : `{{${n}}}`));
};

let vault;
beforeEach(() => {
  vault = createFakeVault();
  axios.get.mockImplementation(vault.axios.get);
  axios.post.mockImplementation(vault.axios.post);
  axios.delete.mockImplementation(vault.axios.delete);
});
afterEach(() => {
  document.body.innerHTML = '';
  jest.restoreAllMocks();
});

const baseHeaders = () => ({ 'X-Vault-Token': 'tok' });
const axiosConfig = (c = {}) => c;
function mount(engine, toasts = [], { t = fakeT, vaultApi } = {}) {
  return renderHook(() => useTotp({
    vaultUrl: vault.VAULT_URL, baseHeaders, axiosConfig, selectedEngine: engine, vaultApi,
    startClipboardTimer: async () => {}, showToast: (m, k) => toasts.push([k, m]), t, restoreFocus: () => {}
  }));
}
const run = (fn) => act(async () => { await fn(); });
const totpDeletes = () => vault.calls.filter(c => c.method === 'delete' && c.path.startsWith('v1/TOTP/keys/'));

describe('findEngineSharingTotpKey : revendication exacte (angle mort du tiret)', () => {
  const api = () => createVaultApi(vault.VAULT_URL, 'tok');

  test('« Prod-EU/db » : la clé PROD-EU-db est revendiquée par « Prod/EU-db »', async () => {
    vault.addEngine('Prod-EU');
    vault.addEngine('Prod');
    vault.writeRaw('Prod-EU', 'db', { Password: 'a' });
    vault.writeRaw('Prod', 'EU-db', { Password: 'b' });
    expect(await findEngineSharingTotpKey(api(), { name: 'Prod-EU' }, 'db')).toBe('Prod');
    expect(await findEngineSharingTotpKey(api(), { name: 'Prod' }, 'EU-db')).toBe('Prod-EU');
  });

  test('pas de revendication sans entrée exacte (casse comprise) : null', async () => {
    vault.addEngine('Prod-EU');
    vault.addEngine('Prod');
    vault.writeRaw('Prod-EU', 'db', { Password: 'a' });
    vault.writeRaw('Prod', 'eu-db', { Password: 'b' }); // clé PROD-eu-db, distincte de PROD-EU-db
    expect(await findEngineSharingTotpKey(api(), { name: 'Prod-EU' }, 'db')).toBeNull();
  });

  test('même préfixe (« Banque » / « users/x/Banque ») toujours détecté ; entrée supprimée = revendiquée', async () => {
    vault.addEngine('Banque');
    vault.addEngine('users/x/Banque');
    vault.writeRaw('users/x/Banque', 'compte', { Password: 'p' });
    vault.versionsOf('users/x/Banque', 'compte')[0].deletion_time = '2026-01-01T00:00:00Z';
    expect(await findEngineSharingTotpKey(api(), { name: 'Banque' }, 'compte')).toBe('users/x/Banque');
  });
});

describe('SECRETS-12 : « Supprimer le TOTP »', () => {
  test('premier clic : aucune suppression, demande de confirmation ; second clic : supprimée', async () => {
    const engine = vault.addEngine('KV');
    vault.writeRaw('KV', 'banque', { Password: 'p' });
    vault.addTotp('KV-banque');
    const toasts = [];
    const { result } = mount(engine, toasts);

    let first;
    await run(async () => { first = await result.current.handleDeleteTotp({ name: 'banque' }); });
    expect(first).toBe(false);
    expect(totpDeletes()).toHaveLength(0);
    expect(vault.totp.has('KV-banque')).toBe(true);
    expect(toasts[0][0]).toBe('warning');
    expect(toasts[0][1]).toContain('toast.totpDeleteConfirm');

    let second;
    await run(async () => { second = await result.current.handleDeleteTotp({ name: 'banque' }); });
    expect(second).toBe(true);
    expect(vault.totp.has('KV-banque')).toBe(false);
    expect(toasts[toasts.length - 1]).toEqual(['success', expect.stringContaining('toast.totpDeleted')]);
  });

  test('la confirmation expire et ne vaut que pour la même entrée', async () => {
    const engine = vault.addEngine('KV');
    vault.addTotp('KV-a');
    vault.addTotp('KV-b');
    const toasts = [];
    const { result } = mount(engine, toasts);
    let now = 1_000_000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);

    await run(() => result.current.handleDeleteTotp({ name: 'a' }));
    await run(() => result.current.handleDeleteTotp({ name: 'b' })); // autre entrée : nouvelle demande
    expect(totpDeletes()).toHaveLength(0);

    now += 60_000; // bien après la fenêtre de confirmation
    await run(() => result.current.handleDeleteTotp({ name: 'b' }));
    expect(totpDeletes()).toHaveLength(0);
    expect(vault.totp.has('KV-b')).toBe(true);
  });

  test('{ confirmed: true } (boîte de confirmation) : suppression directe', async () => {
    const engine = vault.addEngine('KV');
    vault.addTotp('KV-banque');
    const toasts = [];
    const { result } = mount(engine, toasts);
    await run(() => result.current.handleDeleteTotp({ name: 'banque' }, { confirmed: true }));
    expect(vault.totp.has('KV-banque')).toBe(false);
  });

  test('clé partagée avec l\'entrée homonyme d\'un coffre de même préfixe : jamais supprimée', async () => {
    const engine = vault.addEngine('Banque');
    vault.addEngine('users/alice/Banque');
    vault.writeRaw('Banque', 'compte', { Password: 'p1' });
    vault.writeRaw('users/alice/Banque', 'compte', { Password: 'p2' });
    vault.addTotp('BANQUE-compte');
    const toasts = [];
    const { result } = mount(engine, toasts);
    await run(() => result.current.handleDeleteTotp({ name: 'compte' }));
    await run(() => result.current.handleDeleteTotp({ name: 'compte' }));
    expect(totpDeletes()).toHaveLength(0);
    expect(vault.totp.has('BANQUE-compte')).toBe(true);
    expect(toasts[toasts.length - 1][0]).toBe('warning');
    expect(toasts[toasts.length - 1][1]).toContain('error.totpDeleteShared');
    expect(toasts[toasts.length - 1][1]).toContain('users/alice/Banque');
  });

  test('clé revendiquée via l\'ambiguïté du tiret (Prod-EU/db ↔ Prod/EU-db) : conservée', async () => {
    const engine = vault.addEngine('Prod-EU');
    vault.addEngine('Prod');
    vault.writeRaw('Prod-EU', 'db', { Password: 'a' });
    vault.writeRaw('Prod', 'EU-db', { Password: 'b' });
    vault.addTotp('PROD-EU-db');
    const toasts = [];
    const { result } = mount(engine, toasts, { vaultApi: createVaultApi(vault.VAULT_URL, 'tok') });
    await run(() => result.current.handleDeleteTotp({ name: 'db' }, { confirmed: true }));
    expect(vault.totp.has('PROD-EU-db')).toBe(true);
    expect(toasts[toasts.length - 1][1]).toContain('error.totpDeleteShared');
  });

  test('inventaire des coffres impossible : clé conservée (jamais de suppression à l\'aveugle)', async () => {
    const engine = vault.addEngine('KV');
    vault.addTotp('KV-banque');
    vault.setFailWhen((method, path) => (method === 'get' && path.startsWith('v1/sys/') ? 503 : null));
    const toasts = [];
    const { result } = mount(engine, toasts);
    await run(() => result.current.handleDeleteTotp({ name: 'banque' }, { confirmed: true }));
    expect(vault.totp.has('KV-banque')).toBe(true);
    expect(toasts[toasts.length - 1][1]).toContain('error.totpDeleteUnverified');
  });
});

describe('Erreurs TOTP traduites avec le statut HTTP', () => {
  test('« Afficher le code TOTP » sans clé (404) : « Ressource introuvable », pas un message générique', async () => {
    const engine = vault.addEngine('KV');
    const toasts = [];
    const { result } = mount(engine, toasts, { t: tFr });
    await run(() => result.current.handleShowTotp({ name: 'absente' }));
    const [kind, msg] = toasts[toasts.length - 1];
    expect(kind).toBe('error');
    expect(msg).toContain(fr.error.sanitized.notFound);
    expect(msg).toContain(fr.error.totpCode);
    expect(msg).not.toContain(fr.error.sanitized.generic);
  });

  test('« Copier TOTP » refusé (403) : « Accès refusé »', async () => {
    const engine = vault.addEngine('KV');
    vault.addTotp('KV-x');
    vault.setFailWhen((method, path) => (path.startsWith('v1/TOTP/code/') ? 403 : null));
    const toasts = [];
    const { result } = mount(engine, toasts, { t: tFr });
    await run(() => result.current.handleCopyTotp({ name: 'x' }));
    expect(toasts[toasts.length - 1][1]).toContain(fr.error.sanitized.forbidden);
  });

  test('serveur injoignable (ECONNREFUSED) : « connexion refusée », pas un message générique', async () => {
    const engine = vault.addEngine('KV');
    axios.get.mockImplementation((url) => (String(url).includes('/v1/TOTP/')
      ? Promise.reject(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }))
      : vault.axios.get(url)));
    const toasts = [];
    const { result } = mount(engine, toasts, { t: tFr });
    await run(() => result.current.handleShowTotp({ name: 'x' }));
    expect(toasts[toasts.length - 1][1]).toContain(fr.error.sanitized.connectionRefused);
  });

  test('getTotpCode : l\'erreur levée garde le statut (message traduit, sans le corps du serveur)', async () => {
    const engine = vault.addEngine('KV');
    const { result } = mount(engine, [], { t: tFr });
    let caught;
    await run(async () => { try { await result.current.getTotpCode('KV-absente'); } catch (e) { caught = e; } });
    expect(caught).toBeInstanceOf(Error);
    expect(caught.message).toBe(fr.error.sanitized.notFound);
    expect(caught.response).toEqual({ status: 404 });
  });
});
