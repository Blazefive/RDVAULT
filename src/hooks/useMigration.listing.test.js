// ========================================
// TESTS : useMigration — listage de la destination impossible (vague F)
// ========================================
// Hook réel + createVaultApi réel contre le faux Vault du projet.
// Avant : fetchSecretsForEngine renvoyait [] sur TOUTE erreur de listage (réseau, 403, 5xx, liste trop
// grande) : la détection des doublons était sautée et une entrée homonyme de la destination était
// ÉCRASÉE (nouvelle version en KV v2, perte définitive en KV v1), sans aucun message.
// Attendu : opération interrompue avant toute écriture, message traduit ; 404 (coffre vide) et échec
// transitoire relancé avec succès : comportement normal.
import { act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
import { useMigration } from './useMigration';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

let vault;
let listFailures; // nom du coffre → liste d'erreurs à lever (une par listage racine), puis listage normal
const networkError = () => Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' });
const isRootList = (url, engine) => String(url).startsWith(`${vault.VAULT_URL}/v1/${engine}/metadata?list=true`);

beforeEach(() => {
  vault = createFakeVault();
  listFailures = {};
  axios.get.mockImplementation(async (url) => {
    for (const [engine, errors] of Object.entries(listFailures)) {
      if (isRootList(url, engine) && errors.length) throw errors.shift();
    }
    return vault.axios.get(url);
  });
  axios.post.mockImplementation(vault.axios.post);
  axios.put.mockImplementation(vault.axios.put);
  axios.delete.mockImplementation(vault.axios.delete);
});
afterEach(() => { document.body.innerHTML = ''; });

function mount(engine, engines, toasts, { apiOverrides = {}, refreshed = [], cleared = [] } = {}) {
  const vaultApi = { ...createVaultApi(vault.VAULT_URL, 'tok'), ...apiOverrides };
  return renderHook(() => useMigration({
    vaultApi, selectedEngine: engine, secretEngines: engines,
    fetchSecretsRef: { current: async (e) => { refreshed.push(e?.name); } }, clearSelection: () => cleared.push(true),
    syncExtensionRef: { current: null }, showToast: (m, k) => toasts.push([k, m]), t: fakeT
  }));
}
const run = (fn) => act(async () => { await fn(); });
const writesTo = (engine) => vault.calls.filter(c => c.method === 'post' && c.path.startsWith(`v1/${engine}/data/`));

describe('listage de la destination impossible : opération annulée, rien n\'est écrasé', () => {
  test('« Copier vers… », listage en 500 : l\'entrée homonyme de la destination n\'est PAS écrasée', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B');
    vault.writeRaw('A', 'github', { Password: 'MDP-A' });
    vault.writeRaw('B', 'github', { Password: 'MDP-B' });
    vault.setFailWhen((method, path) => (method === 'get' && path === 'v1/B/metadata' ? 500 : null));
    const toasts = []; const refreshed = []; const cleared = [];
    const { result } = mount(A, [A, B], toasts, { refreshed, cleared });
    await run(() => result.current.handleMigrateSecrets([{ name: 'github' }], B, 'copy'));

    expect(vault.versionsOf('B', 'github')).toHaveLength(1);            // avant : 2 versions (écrasée)
    expect(vault.latest('B', 'github').data.Password).toBe('MDP-B');
    expect(writesTo('B')).toHaveLength(0);                               // aucune écriture
    expect(toasts).toHaveLength(1);
    expect(toasts[0][0]).toBe('error');
    expect(toasts[0][1]).toContain('migrate.destinationUnlisted');
    expect(toasts[0][1]).toContain('"engine":"B"');
    expect(cleared).toHaveLength(0); // sélection conservée : l'utilisateur peut relancer
    expect(refreshed).toHaveLength(0);
  });

  test('« Migrer vers… » (déplacer), listage refusé (403) : source et destination intactes', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B');
    vault.writeRaw('A', 'x', { Password: 'SOURCE' });
    vault.writeRaw('B', 'x', { Password: 'CIBLE' });
    vault.setFailWhen((method, path) => (method === 'get' && path === 'v1/B/metadata' ? 403 : null));
    const toasts = [];
    const { result } = mount(A, [A, B], toasts);
    await run(() => result.current.handleMigrateSecrets([{ name: 'x' }], B, 'move'));
    expect(vault.isLive('A', 'x')).toBe(true);
    expect(vault.versionsOf('B', 'x')).toHaveLength(1);
    expect(toasts[0][0]).toBe('error');
    expect(toasts[0][1]).toContain('migrate.destinationUnlisted');
  });

  test('glisser-déposer et « Déplacer dans un dossier » : même interruption (réseau persistant)', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B');
    vault.writeRaw('A', 'x', { Password: 'SOURCE' });
    vault.writeRaw('A', 'dossier/x', { Password: 'DANS-DOSSIER' });
    vault.writeRaw('B', 'x', { Password: 'CIBLE' });
    const toasts = [];
    const { result } = mount(A, [A, B], toasts);
    // Trois tentatives par listage (withRetry : 2 relances) : toutes en échec
    listFailures.B = [networkError(), networkError(), networkError()];
    await run(() => result.current.migrateSecretsToEngine(['x'], 'A', 2, B));
    listFailures.A = [networkError(), networkError(), networkError()];
    await run(() => result.current.moveSecretsToFolder(['x'], 'dossier'));
    expect(vault.isLive('A', 'x')).toBe(true);
    expect(vault.versionsOf('A', 'dossier/x')).toHaveLength(1);
    expect(vault.versionsOf('B', 'x')).toHaveLength(1);
    expect(toasts.map(([k]) => k)).toEqual(['error', 'error']);
    expect(toasts.every(([, m]) => m.includes('migrate.destinationUnlisted'))).toBe(true);
  }, 15000);

  test('liste trop grande (LIST_TOO_LARGE, liste partielle) : interruption, aucune écriture', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B');
    vault.writeRaw('A', 'zz', { Password: 'SOURCE' });
    vault.writeRaw('B', 'zz', { Password: 'CIBLE' }); // au-delà de la liste partielle
    let listCalls = 0;
    const apiOverrides = {
      listKeysV2: async (engine) => {
        if (engine.name !== 'B') return [];
        listCalls++;
        throw Object.assign(new Error('Listage interrompu'), {
          code: 'LIST_TOO_LARGE', i18nKey: 'error.listTooLarge', i18nVars: { max: 1 }, partialKeys: ['aa'],
        });
      },
    };
    const toasts = [];
    const { result } = mount(A, [A, B], toasts, { apiOverrides });
    await run(() => result.current.handleMigrateSecrets([{ name: 'zz' }], B, 'copy'));
    expect(vault.versionsOf('B', 'zz')).toHaveLength(1);
    expect(writesTo('B')).toHaveLength(0);
    expect(listCalls).toBe(1); // erreur déterministe : jamais relancée
    expect(toasts[0][0]).toBe('error');
    expect(toasts[0][1]).toContain('migrate.destinationUnlisted');
    expect(toasts[0][1]).toContain('error.listTooLarge'); // cause traduite
  });

  test('fetchSecretsForEngine : propage l\'échec (plus de [] silencieux) ; 404 = coffre vide', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B'); const VIDE = vault.addEngine('VIDE');
    vault.writeRaw('A', 'a', { Password: 'p' });
    vault.setFailWhen((method, path) => (method === 'get' && path === 'v1/B/metadata' ? 503 : null));
    const { result } = mount(A, [A, B, VIDE], []);
    await expect(result.current.fetchSecretsForEngine(A)).resolves.toEqual([{ name: 'a' }]);
    await expect(result.current.fetchSecretsForEngine(VIDE)).resolves.toEqual([]);
    await expect(result.current.fetchSecretsForEngine(B)).rejects.toMatchObject({ response: { status: 503 } });
  }, 15000);
});

describe('témoins : comportement normal conservé', () => {
  test('destination vide (404 au listage) : copie effectuée', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B');
    vault.writeRaw('A', 'x', { Password: 'p' });
    const toasts = [];
    const { result } = mount(A, [A, B], toasts);
    await run(() => result.current.handleMigrateSecrets([{ name: 'x' }], B, 'copy'));
    expect(vault.isLive('B', 'x')).toBe(true);
    expect(toasts[0][0]).toBe('success');
  });

  test('échec transitoire du listage relancé avec succès : doublon détecté, renommage « _1 »', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B');
    vault.writeRaw('A', 'github', { Password: 'MDP-A' });
    vault.writeRaw('B', 'github', { Password: 'MDP-B' });
    listFailures.B = [networkError()];
    const toasts = [];
    const { result } = mount(A, [A, B], toasts);
    await run(() => result.current.handleMigrateSecrets([{ name: 'github' }], B, 'copy'));
    expect(vault.versionsOf('B', 'github')).toHaveLength(1);
    expect(vault.latest('B', 'github_1').data.Password).toBe('MDP-A');
    expect(toasts[0][0]).toBe('success');
  });
});
