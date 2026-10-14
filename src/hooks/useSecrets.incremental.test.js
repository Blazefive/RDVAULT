// ========================================
// TESTS : useSecrets — relectures ciblées et listes gardées par coffre (PERF, chasse « longue session »)
// ========================================
// Hooks réels (useSecrets + createVaultApi) contre le faux Vault en mémoire du projet. Avant : chaque
// écriture, chaque changement de coffre, chaque bascule « Afficher les supprimés » et chaque recherche
// multi-coffres relisaient TOUTES les entrées (une requête par entrée). Les invariants sont vérifiés en
// même temps : contenu à jour, entrées supprimées, ordre, intégrité, extension servie, session.
import { useState, act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
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

const run = (fn) => act(async () => { await fn(); });

// Lectures d'entrées (données et métadonnées, hors listage) adressées au faux coffre depuis `from`
// Chemin « v1/<coffre>/… » du faux coffre ramené à « <coffre>/… »
const readsSince = (from) => vault.calls.slice(from)
  .map(c => ({ ...c, path: c.path.replace(/^v1\//, '') }))
  .filter(c => c.method === 'get' && !c.query.includes('list=true')
    && /\/(data|metadata)\//.test(`/${c.path}`) && !c.path.startsWith('TOTP'));
const dataReads = (from) => readsSince(from).filter(c => c.path.includes('/data/'));
const metaReads = (from) => readsSince(from).filter(c => c.path.includes('/metadata/'));

function mount(state, toasts = []) {
  const vaultApiRef = { current: createVaultApi(vault.VAULT_URL, 'tok-1') };
  const syncExtensionRef = { current: jest.fn() };
  const view = renderHook(() => {
    const [secrets, setSecrets] = useState([]);
    const s = useSecrets({
      vaultApiRef, vaultUrl: vault.VAULT_URL, selectedEngine: state.engine, search: '', showDeleted: !!state.showDeleted,
      secrets, setSecrets, multiVaultSearch: false, allVaultSecrets: [],
      treeViewEnabled: false, currentPath: '', currentFolderContent: null,
      mergeDiscoveredAndSharedTagsRef: { current: null }, setDiscoveredTags: () => {},
      syncExtensionRef, restoreFocus: () => {},
      getTotpKeyName: (n) => `T-${n}`, checkTotpExists: async () => false, totpEngineName: 'TOTP',
      showToast: (m, k) => toasts.push([k, m]), t: fakeT,
      cacheMaxAgeMs: state.maxAgeMs ?? 60 * 60 * 1000,
    });
    return { ...s, secrets };
  });
  return { ...view, vaultApiRef, syncExtensionRef, toasts };
}

function seed(name, n, { deleted = [] } = {}) {
  const engine = vault.addEngine(name);
  for (let i = 0; i < n; i++) {
    const key = i % 5 === 0 ? `dossier-${i % 3}/e-${String(i).padStart(4, '0')}` : `e-${String(i).padStart(4, '0')}`;
    vault.writeRaw(name, key, { Username: `u${i}`, Password: `p${i}`, EntryType: 'secret' });
  }
  for (const key of deleted) {
    const v = vault.versionsOf(name, key);
    v[v.length - 1].deletion_time = '2026-01-01T00:00:00Z';
  }
  return engine;
}

const formEntry = (row, password) => ({ ...row, password, customFields: [], attachments: [] });
const names = (result) => result.current.secrets.map(s => `${s.name}${s.deleted ? ':supprimée' : ''}`);
const listingOrder = (name) => {
  const keys = [];
  const walk = (prefix) => {
    const e = vault.engines.get(name);
    const out = new Set();
    for (const k of e.secrets.keys()) {
      if (prefix && !k.startsWith(prefix)) continue;
      const rel = k.slice(prefix.length);
      const i = rel.indexOf('/');
      out.add(i === -1 ? rel : rel.slice(0, i + 1));
    }
    for (const k of Array.from(out).sort()) { if (k.endsWith('/')) walk(prefix + k); else keys.push(prefix + k); }
  };
  walk('');
  return keys;
};

test('enregistrer UNE entrée : seule l\'entrée écrite est relue (avant : tout le coffre) ; tableau et extension à jour', async () => {
  const engine = seed('Main', 300);
  const { result, syncExtensionRef } = mount({ engine });
  await run(() => result.current.fetchSecrets(engine));
  expect(result.current.secrets).toHaveLength(300);
  const before = result.current.secrets;

  const row = result.current.secrets.find(s => s.name === 'e-0007');
  act(() => { result.current.setEditSecret(row); });
  const from = vault.calls.length;
  await run(() => result.current.handleEditSecretSave(formEntry(row, 'NOUVEAU-7')));

  // Relecture de l'entrée avant l'écriture (contrôle de fraîcheur, services/staleWriteGuard.js) puis
  // relecture après l'écriture ; avant : 300 lectures
  expect(dataReads(from).map(c => c.path)).toEqual(['Main/data/e-0007', 'Main/data/e-0007']);
  expect(result.current.secrets.find(s => s.name === 'e-0007').password).toBe('NOUVEAU-7');
  expect(result.current.secrets).toHaveLength(300);
  // Lignes inchangées réutilisées (objets identiques : pas de re-rendu)
  expect(result.current.secrets.find(s => s.name === 'e-0008')).toBe(before.find(s => s.name === 'e-0008'));
  // Extension servie : la liste complète du coffre, avec la modification
  const push = syncExtensionRef.current.mock.calls.filter(c => c[0] && c[0].engine).pop()[0];
  expect(push.secrets).toHaveLength(300);
  expect(push.secrets.find(s => s.name === 'e-0007').password).toBe('NOUVEAU-7');
  expect(push.listedKeys).toHaveLength(300);
});

test('renommage et création : nouvelle entrée à sa place dans l\'ordre du listage, ancien nom retiré', async () => {
  const engine = seed('Main', 40);
  const { result } = mount({ engine });
  await run(() => result.current.fetchSecrets(engine));
  const row = result.current.secrets.find(s => s.name === 'e-0003');
  act(() => { result.current.setEditSecret(row); });
  const from = vault.calls.length;
  await run(() => result.current.handleEditSecretSave(formEntry({ ...row, name: 'aaa-renommee' }, 'p3')));
  // e-0003 relue avant l'écriture (contrôle de fraîcheur) puis, comme aaa-renommee, après
  expect(dataReads(from).map(c => c.path).sort()).toEqual(['Main/data/aaa-renommee', 'Main/data/e-0003', 'Main/data/e-0003']);
  expect(names(result)).toEqual(listingOrder('Main').filter(k => vault.isLive('Main', k)));
  expect(names(result)).toContain('aaa-renommee');
  expect(names(result)).not.toContain('e-0003');

  act(() => { result.current.setEditSecret({ name: '', isNew: true }); });
  await run(() => result.current.handleEditSecretSave({ name: 'dossier-1/zzz', username: '', password: 'n', url: '', notes: '', tags: '', customFields: [], attachments: [] }));
  expect(names(result)).toEqual(listingOrder('Main').filter(k => vault.isLive('Main', k)));
});

test('suppression puis restauration (« Afficher les supprimés » cochée) : ligne supprimée puis rétablie, entrée seule relue', async () => {
  const engine = seed('Main', 50);
  const state = { engine, showDeleted: true };
  const { result } = mount(state);
  await run(() => result.current.fetchSecrets(engine, true));
  const from = vault.calls.length;
  await run(() => result.current.confirmDeleteSecret(result.current.secrets.find(s => s.name === 'e-0004')));
  await run(() => result.current.deleteSecret());
  expect(readsSince(from).filter(c => !c.path.endsWith('/e-0004'))).toEqual([]);
  expect(result.current.secrets.find(s => s.name === 'e-0004').deleted).toBe(true);
  const from2 = vault.calls.length;
  await run(() => result.current.undeleteSecret(result.current.secrets.find(s => s.name === 'e-0004')));
  expect(readsSince(from2).filter(c => !c.path.endsWith('/e-0004'))).toEqual([]);
  expect(result.current.secrets.find(s => s.name === 'e-0004').deleted).toBe(false);
  expect(result.current.secrets.find(s => s.name === 'e-0004').password).toBe('p4');
});

test('changer de coffre puis revenir : liste gardée, aucune entrée relue (seul le listage) ; écriture dans l\'autre coffre relue seule', async () => {
  const main = seed('Main', 120);
  const other = seed('Other', 30);
  const state = { engine: main };
  const { result, rerender, vaultApiRef } = mount(state);
  await run(() => result.current.fetchSecrets(main, false, { incremental: true }));
  state.engine = other; rerender();
  await run(() => result.current.fetchSecrets(other, false, { incremental: true }));
  expect(result.current.secrets).toHaveLength(30);

  // Écriture dans Main pendant qu'Other est affiché (migration, glisser-déposer…) : notée au journal
  await run(() => vaultApiRef.current.writeSecretToEngine(main, 'nouvelle-copie', { Password: 'copie' }, { cas: 0 }));
  state.engine = main; rerender();
  const from = vault.calls.length;
  await run(() => result.current.fetchSecrets(main, false, { incremental: true }));
  expect(dataReads(from).map(c => c.path)).toEqual(['Main/data/nouvelle-copie']); // avant : 121 lectures
  expect(result.current.secrets).toHaveLength(121);
  expect(names(result)).toEqual(listingOrder('Main'));
});

test('« Afficher les supprimés » : cocher ne lit que l\'état des entrées non lisibles ; décocher ne lit rien', async () => {
  const deleted = ['e-0001', 'e-0002', 'e-0013'];
  const engine = seed('Main', 200, { deleted });
  const { result } = mount({ engine });
  await run(() => result.current.fetchSecrets(engine, false, { incremental: true }));
  expect(result.current.secrets).toHaveLength(197);
  let from = vault.calls.length;
  await run(() => result.current.fetchSecrets(engine, true, { incremental: true }));
  expect(dataReads(from)).toEqual([]);
  expect(metaReads(from).map(c => c.path.split('/').pop()).sort()).toEqual(deleted); // avant : 200 + 197
  expect(result.current.secrets.filter(s => s.deleted).map(s => s.name).sort()).toEqual(deleted);
  expect(names(result)).toEqual(listingOrder('Main').map(k => (deleted.includes(k) ? `${k}:supprimée` : k)));
  from = vault.calls.length;
  await run(() => result.current.fetchSecrets(engine, false, { incremental: true }));
  expect(readsSince(from)).toEqual([]); // avant : 197 lectures
  expect(result.current.secrets).toHaveLength(197);
  expect(result.current.secrets.some(s => s.deleted)).toBe(false);
});

test('intégrité : entrée illisible jamais mise en cache — relue, signalée et gardée à chaque relecture', async () => {
  const engine = seed('Main', 30);
  const toasts = [];
  const { result } = mount({ engine }, toasts);
  await run(() => result.current.fetchSecrets(engine));
  vault.setFailWhen((method, path) => (method === 'get' && path === 'v1/Main/data/e-0009' ? 500 : null));
  const row = result.current.secrets.find(s => s.name === 'e-0011');
  act(() => { result.current.setEditSecret(row); });
  const from = vault.calls.length;
  await run(() => result.current.handleEditSecretSave(formEntry(row, 'x')));
  // e-0009 était lisible au chargement : relue seulement si elle est écrite ; ici, non touchée → gardée
  // (e-0011 : relue avant l'écriture — contrôle de fraîcheur — puis après)
  expect(dataReads(from).map(c => c.path)).toEqual(['Main/data/e-0011', 'Main/data/e-0011']);

  // Nouvelle session de lecture complète : e-0009 illisible → signalée, jamais confondue avec absente
  await run(() => result.current.fetchSecrets(engine));
  expect(toasts.some(([k, m]) => k === 'warning' && m.includes('error.secretsUnreadable'))).toBe(true);
  expect(result.current.secrets.find(s => s.name === 'e-0009')).toBeTruthy(); // ligne gardée
  toasts.length = 0;
  const from2 = vault.calls.length;
  await run(() => result.current.fetchSecrets(engine, false, { incremental: true }));
  expect(dataReads(from2).map(c => c.path)).toEqual(['Main/data/e-0009']); // relue (pas de cache)
  expect(toasts.some(([k, m]) => k === 'warning' && m.includes('error.secretsUnreadable'))).toBe(true);
  vault.setFailWhen(null);
  await run(() => result.current.fetchSecrets(engine, false, { incremental: true }));
  expect(result.current.secrets.find(s => s.name === 'e-0009').password).toBe('p9');
});

test('session : un autre service Vault (nouveau jeton) ne réutilise jamais la liste de la session précédente', async () => {
  const engine = seed('Main', 20);
  const { result, rerender, vaultApiRef } = mount({ engine });
  await run(() => result.current.fetchSecrets(engine, false, { incremental: true }));
  vaultApiRef.current = createVaultApi(vault.VAULT_URL, 'tok-2');
  rerender();
  const from = vault.calls.length;
  await run(() => result.current.fetchSecrets(engine, false, { incremental: true }));
  expect(dataReads(from)).toHaveLength(20);
});

test('liste gardée trop ancienne (Vault partagé) : relecture complète', async () => {
  const engine = seed('Main', 10);
  const { result } = mount({ engine, maxAgeMs: 0 });
  await run(() => result.current.fetchSecrets(engine, false, { incremental: true }));
  await new Promise(r => setTimeout(r, 5));
  const from = vault.calls.length;
  await run(() => result.current.fetchSecrets(engine, false, { incremental: true }));
  expect(dataReads(from)).toHaveLength(10);
});

test('recherche multi-coffres : listes gardées réutilisées, format de readAllSecrets, échecs comptés', async () => {
  const main = seed('Main', 60, { deleted: ['e-0001'] });
  const other = seed('Other', 25);
  const { result, vaultApiRef } = mount({ engine: main });
  await run(() => result.current.fetchSecrets(main, false, { incremental: true }));
  let r;
  let from = vault.calls.length;
  await run(async () => { r = await result.current.readEnginesWithCache([main, other]); });
  expect(dataReads(from).filter(c => c.path.startsWith('Main/'))).toEqual([]); // Main déjà lu
  expect(dataReads(from).filter(c => c.path.startsWith('Other/'))).toHaveLength(25);
  expect(r.secrets).toHaveLength(59 + 25);
  expect(r.secrets.every(s => s.engineName && s.engineVersion === 2 && !('deleted' in s))).toBe(true);
  expect(r).toMatchObject({ aborted: false, failed: 0, forbidden: 0, failedEngines: [], partialEngines: [] });

  // Second passage : aucune entrée relue ; une écriture : cette entrée seule
  await run(() => vaultApiRef.current.writeSecretV2(other, { name: 'e-0003', username: 'x', password: 'maj', url: '', website: '', notes: '' }));
  vault.setFailWhen((method, path) => (method === 'get' && path === 'v1/Other/data/e-0003' ? 503 : null));
  from = vault.calls.length;
  await run(async () => { r = await result.current.readEnginesWithCache([main, other]); });
  expect(new Set(dataReads(from).map(c => c.path))).toEqual(new Set(['Other/data/e-0003'])); // relances comprises
  expect(r.failedKeys).toEqual([{ engine: 'Other', key: 'e-0003' }]);
  vault.setFailWhen(null);
  await run(async () => { r = await result.current.readEnginesWithCache([main, other]); });
  expect(r.secrets.find(s => s.engineName === 'Other' && s.name === 'e-0003').password).toBe('maj');

  // Annulée : rien de lu, résultat marqué
  const ac = new AbortController();
  ac.abort();
  await run(async () => { r = await result.current.readEnginesWithCache([main, other], { signal: ac.signal }); });
  expect(r.aborted).toBe(true);
});

test('import des Paramètres (APP-6) : listes oubliées, coffre relu entièrement', async () => {
  const engine = seed('Main', 15);
  const { result } = mount({ engine });
  await run(() => result.current.fetchSecrets(engine, false, { incremental: true }));
  // Écriture directe sans passer par vaultApi ni par un intercepteur (axios simulé) : invisible du journal
  vault.writeRaw('Main', 'e-0002', { Password: 'importé' });
  act(() => { result.current.invalidateEngines(['Main']); });
  const from = vault.calls.length;
  await run(() => result.current.fetchSecrets(engine, false, { incremental: true }));
  expect(dataReads(from)).toHaveLength(15);
  expect(result.current.secrets.find(s => s.name === 'e-0002').password).toBe('importé');
});
