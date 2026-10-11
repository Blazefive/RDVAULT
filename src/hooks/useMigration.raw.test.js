// ========================================
// TESTS : useMigration — copie des données brutes, sérialisation, coffre affiché (vague E)
// ========================================
// Hook réel + createVaultApi réel contre le faux Vault du projet (KV v2) et un coffre KV v1 en mémoire.
// - SECRETS-34 : « Migrer vers… », « Copier vers… » et « Déplacer dans un dossier » copient les données
//   BRUTES (champs hors schéma RDVAULT, conventions Vault en minuscules) comme le glisser-déposer ;
//   une source KV v1 (suppression définitive) n'est supprimée qu'après relecture conforme de la copie.
// - SECRETS-36 : deux opérations qui se chevauchent vers le même coffre ne choisissent plus le même
//   nom (file unique, noms pris relus au début de chaque opération).
// - SECRETS-32 : en fin d'opération, c'est le coffre AFFICHÉ qui est rafraîchi.
import { act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
import { useMigration } from './useMigration';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

// Secret écrit par un autre outil (CLI vault, script, API) : conventions Vault + champ métier
const EXTERNAL = { username: 'svc-backup', password: 'S3cr3t-ext', api_key: 'AKIA-EXTERNAL-KEY', Notes: 'compte de service' };

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let vault;
let legacy; // coffre KV v1 « legacy » (pas de versions : DELETE définitif)
let latency = 0;
let legacyReadOverride = null; // (clé) => données renvoyées à la relecture (simulation d'une copie altérée)
beforeEach(() => {
  vault = createFakeVault();
  legacy = new Map();
  latency = 0;
  legacyReadOverride = null;
  const V1 = `${vault.VAULT_URL}/v1/legacy`;
  const keyOf = (url) => decodeURIComponent(String(url).slice(V1.length + 1).split('?')[0]);
  const err404 = () => { const e = new Error('404'); e.response = { status: 404, data: {} }; return Promise.reject(e); };
  const delay = async () => { if (latency) await sleep(latency); };
  axios.get.mockImplementation(async (url) => {
    await delay();
    if (String(url).startsWith(V1)) {
      if (String(url).includes('?list=true')) return legacy.size ? { status: 200, data: { data: { keys: Array.from(legacy.keys()) } } } : err404();
      const k = keyOf(url);
      if (legacyReadOverride && legacy.has(k)) return { status: 200, data: { data: legacyReadOverride(k) } };
      return legacy.has(k) ? { status: 200, data: { data: JSON.parse(JSON.stringify(legacy.get(k))) } } : err404();
    }
    return vault.axios.get(url);
  });
  axios.post.mockImplementation(async (url, body) => {
    await delay();
    if (String(url).startsWith(V1)) { legacy.set(keyOf(url), JSON.parse(JSON.stringify(body))); return { status: 204, data: {} }; }
    return vault.axios.post(url, body);
  });
  axios.delete.mockImplementation(async (url) => {
    await delay();
    if (String(url).startsWith(V1)) { legacy.delete(keyOf(url)); return { status: 204, data: {} }; }
    return vault.axios.delete(url);
  });
});
afterEach(() => { document.body.innerHTML = ''; });

const LEGACY = { name: 'legacy', version: 1, canWrite: true, canList: true };

function mount(state, engines, toasts, refreshed = []) {
  const vaultApi = createVaultApi(vault.VAULT_URL, 'tok');
  return renderHook(() => useMigration({
    vaultApi, selectedEngine: state.engine, secretEngines: engines,
    fetchSecretsRef: { current: async (engine) => { refreshed.push(engine?.name); } },
    showDeleted: false, clearSelection: () => {},
    syncExtensionRef: { current: null }, showToast: (m, k) => toasts.push([k, m]), t: fakeT
  }));
}
const run = (fn) => act(async () => { await fn(); });

describe('SECRETS-34 : données brutes conservées par les chemins modaux', () => {
  test('« Migrer vers… » (déplacer, KV v2) : destination identique à la source, source supprimée en douceur', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B');
    vault.writeRaw('A', 'backup', EXTERNAL);
    const toasts = [];
    const { result } = mount({ engine: A }, [A, B], toasts);
    await run(() => result.current.handleMigrateSecrets([{ name: 'backup' }], B, 'move'));
    expect(vault.latest('B', 'backup').data).toEqual(EXTERNAL);
    expect(vault.isLive('A', 'backup')).toBe(false);
    expect(vault.versionsOf('A', 'backup')).toHaveLength(1); // historique restaurable
    expect(toasts[0][0]).toBe('success');
  });

  test('« Copier vers… » : copie complète, source intacte', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B');
    vault.writeRaw('A', 'backup', EXTERNAL);
    const toasts = [];
    const { result } = mount({ engine: A }, [A, B], toasts);
    await run(() => result.current.handleMigrateSecrets([{ name: 'backup' }], B, 'copy'));
    expect(vault.latest('B', 'backup').data).toEqual(EXTERNAL);
    expect(vault.isLive('A', 'backup')).toBe(true);
  });

  test('« Déplacer dans un dossier » (KV v2) : destination identique à la source', async () => {
    const A = vault.addEngine('A');
    vault.writeRaw('A', 'backup', EXTERNAL);
    const toasts = [];
    const { result } = mount({ engine: A }, [A], toasts);
    await run(() => result.current.handleMoveToFolder([{ name: 'backup' }], 'archive'));
    expect(vault.latest('A', 'archive/backup').data).toEqual(EXTERNAL);
    expect(vault.isLive('A', 'backup')).toBe(false);
  });

  test('source KV v1 : copie complète, source supprimée seulement après relecture conforme', async () => {
    const B = vault.addEngine('B');
    legacy.set('backup', EXTERNAL);
    const toasts = [];
    const { result } = mount({ engine: LEGACY }, [LEGACY, B], toasts);
    await run(() => result.current.handleMigrateSecrets([{ name: 'backup' }], B, 'move'));
    expect(vault.latest('B', 'backup').data).toEqual(EXTERNAL);
    expect(legacy.has('backup')).toBe(false);
    const destRead = vault.calls.findIndex(c => c.method === 'get' && c.path === 'v1/B/data/backup');
    expect(destRead).toBeGreaterThan(-1); // relecture de la destination avant la suppression définitive
    expect(toasts[0][0]).toBe('success');
  });

  test('source KV v1 : relecture de la copie non conforme → source CONSERVÉE, échec signalé', async () => {
    const L2 = { name: 'legacy', version: 1, canWrite: true, canList: true };
    vault.addEngine('B');
    legacy.set('backup', EXTERNAL);
    // Destination KV v1 elle aussi (même coffre en mémoire) : la relecture renvoie une donnée tronquée
    legacyReadOverride = (k) => (k === 'archive/backup' ? { username: 'svc-backup' } : JSON.parse(JSON.stringify(legacy.get(k))));
    const toasts = [];
    const { result } = mount({ engine: L2 }, [L2], toasts);
    await run(() => result.current.handleMoveToFolder([{ name: 'backup' }], 'archive'));
    expect(legacy.has('backup')).toBe(true);
    expect(toasts[0][0]).toBe('warning');
  });

  test('glisser-déposer depuis un coffre KV v1 : même vérification avant la suppression définitive', async () => {
    const B = vault.addEngine('B');
    legacy.set('backup', EXTERNAL);
    vault.setFailWhen((method, path) => (method === 'get' && path === 'v1/B/data/backup' ? 500 : null));
    const toasts = [];
    const { result } = mount({ engine: LEGACY }, [LEGACY, B], toasts);
    await run(() => result.current.migrateSecretsToEngine(['backup'], 'legacy', 1, B));
    expect(vault.latest('B', 'backup').data).toEqual(EXTERNAL); // écrite
    expect(legacy.has('backup')).toBe(true);                    // mais source conservée (copie non vérifiable)
    expect(toasts[0][0]).toBe('warning');
  });

  test('source illisible : rien n\'est écrit, échec compté', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B');
    vault.writeRaw('A', 'x', { Password: 'p' });
    vault.setFailWhen((method, path) => (method === 'get' && path === 'v1/A/data/x' ? 500 : null));
    const toasts = [];
    const { result } = mount({ engine: A }, [A, B], toasts);
    await run(() => result.current.handleMigrateSecrets([{ name: 'x' }], B, 'move'));
    expect(vault.latest('B', 'x')).toBeNull();
    expect(vault.isLive('A', 'x')).toBe(true);
    expect(toasts[0][0]).toBe('warning');
  });
});

describe('SECRETS-36 : opérations concurrentes vers le même coffre', () => {
  test('deux glisser-déposer qui se chevauchent (S1/x et S2/x → T) : T/x et T/x_1 distincts', async () => {
    const S1 = vault.addEngine('S1'); const S2 = vault.addEngine('S2'); const T = vault.addEngine('T');
    vault.writeRaw('S1', 'x', { Username: 'from-S1', Password: 'MDP-S1' });
    vault.writeRaw('S2', 'x', { Username: 'from-S2', Password: 'MDP-S2' });
    vault.writeRaw('T', 'autre', { Username: 't' });
    latency = 5;
    const toasts = [];
    const { result } = mount({ engine: S1 }, [S1, S2, T], toasts);
    await act(async () => {
      const p1 = result.current.migrateSecretsToEngine(['x'], 'S1', 2, T);
      await sleep(1); // le second dépôt est lancé pendant le premier
      const p2 = result.current.migrateSecretsToEngine(['x'], 'S2', 2, T);
      await Promise.all([p1, p2]);
    });
    expect(vault.versionsOf('T', 'x')).toHaveLength(1);
    expect(vault.latest('T', 'x').data.Username).toBe('from-S1');
    expect(vault.latest('T', 'x_1').data.Username).toBe('from-S2');
  });

  test('modale « Déplacer dans un dossier » et glisser-déposer simultanés vers le même dossier', async () => {
    const E = vault.addEngine('E');
    vault.writeRaw('E', 'a/x', { Password: 'A' });
    vault.writeRaw('E', 'b/x', { Password: 'B' });
    latency = 3;
    const toasts = [];
    const { result } = mount({ engine: E }, [E], toasts);
    await act(async () => {
      const p1 = result.current.handleMoveToFolder([{ name: 'a/x' }], 'c');
      await sleep(1);
      const p2 = result.current.moveSecretsToFolder(['b/x'], 'c');
      await Promise.all([p1, p2]);
    });
    expect(vault.versionsOf('E', 'c/x')).toHaveLength(1);
    expect(vault.latest('E', 'c/x').data.Password).toBe('A');
    expect(vault.latest('E', 'c/x_1').data.Password).toBe('B');
  });

  test('une opération en échec ne bloque pas la suivante', async () => {
    const A = vault.addEngine('A'); const B = vault.addEngine('B');
    vault.writeRaw('A', 'y', { Password: 'p' });
    const toasts = [];
    const { result } = mount({ engine: A }, [A, B], toasts);
    await run(() => result.current.migrateSecretsToEngine(['y'], 'inexistant', 2, B)); // coffre source introuvable
    await run(() => result.current.migrateSecretsToEngine(['y'], 'A', 2, B));
    expect(vault.isLive('B', 'y')).toBe(true);
  });
});

describe('SECRETS-32 : fin d\'opération → rafraîchissement du coffre affiché', () => {
  test('dépôt depuis A, ouverture de C pendant l\'opération : C (affiché) est rafraîchi, pas A', async () => {
    const A = vault.addEngine('a-src'); const B = vault.addEngine('b-dst'); const C = vault.addEngine('c-autre');
    vault.writeRaw('a-src', 'jira', { Password: 'j' });
    latency = 3;
    const state = { engine: A };
    const toasts = [];
    const refreshed = [];
    const { result, rerender } = mount(state, [A, B, C], toasts, refreshed);
    let p;
    await act(async () => {
      p = result.current.migrateSecretsToEngine(['jira'], 'a-src', 2, B);
      await sleep(1);
    });
    state.engine = C; // l'utilisateur ouvre un autre coffre pendant l'opération
    rerender();
    await act(async () => { await p; });
    expect(vault.isLive('b-dst', 'jira')).toBe(true);
    expect(refreshed).toEqual(['c-autre']);
  });
});
