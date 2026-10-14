// ========================================
// TESTS : lecture d'un coffre avec liste gardée en cache (relectures ciblées)
// ========================================
// Faux service Vault instrumenté : chaque lecture (données, métadonnées, lecture groupée) est comptée.
import { createEngineReadCache, readEngineEntries, READ_FAILED, READ_SKIPPED } from './engineReadCache';
import { noteVaultWrite, forgetVaultWrites } from './vaultWriteLog';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

const V = 'http://v';
const engine = { name: 'kv', version: 2 };
const httpError = (status) => Object.assign(new Error(`HTTP ${status}`), { response: { status } });

/**
 * Coffre en mémoire : clé → { password, deleted?, fail? (statut renvoyé à la lecture) }.
 * Métadonnées servies par axios.get (comme useSecrets), données par readSecretV2.
 */
function fakeVault(entries, { batch = false } = {}) {
  const stats = { list: 0, data: 0, meta: 0, batch: 0, batchKeys: 0 };
  const api = {
    baseHeaders: () => ({}), axiosConfig: (c) => c,
    listKeysV2: async () => { stats.list++; return Object.keys(entries); },
    listKeysV1: async () => { stats.list++; return Object.keys(entries); },
    readSecretV2: async (e, key) => {
      stats.data++;
      const x = entries[key];
      if (!x) throw httpError(404);
      if (x.fail) throw httpError(x.fail);
      if (x.deleted) throw httpError(404);
      return { name: key, password: x.password };
    },
  };
  api.readSecretV1 = api.readSecretV2;
  if (batch) {
    api.readSecretsBatchV2 = async (e, keys) => {
      stats.batch++; stats.batchKeys += keys.length;
      if (batch === 'broken') throw httpError(404);
      return keys.map((key) => {
        const x = entries[key];
        if (!x) return { key, error: httpError(404) };
        if (x.fail) return { key, error: httpError(x.fail) };
        if (x.deleted) return { key, deleted: true };
        return { key, item: { name: key, password: x.password } };
      });
    };
  }
  axios.get.mockImplementation(async (url) => {
    stats.meta++;
    const key = decodeURIComponent(String(url).split('/metadata/')[1]);
    const x = entries[key];
    if (!x) throw httpError(404);
    return { data: { data: { current_version: 1, versions: { 1: { deletion_time: x.deleted ? '2026-01-01T00:00:00Z' : '' } } } } };
  });
  return { api, stats };
}

const run = (fn) => Promise.resolve().then(fn);
const read = (api, opts = {}) => readEngineEntries(api, opts.engine || engine, { vaultUrl: V, run, ...opts });
const names = (r) => r.results.filter(x => x && x !== READ_FAILED).map(x => `${x.name}${x.deleted ? ':supprimée' : ''}`);

beforeEach(() => forgetVaultWrites());

test('relecture avec cache : seules les entrées nouvelles, écrites (journal) ou touchées sont lues ; ordre du listage', async () => {
  const entries = { a: { password: '1' }, b: { password: '2' }, c: { password: '3' } };
  const { api, stats } = fakeVault(entries);
  const first = await read(api);
  expect(stats.data).toBe(3);
  expect(names(first)).toEqual(['a', 'b', 'c']);

  // Écriture notée par vaultApi (journal) + nouvelle entrée + entrée touchée par l'appelant
  entries.b.password = '2bis';
  noteVaultWrite('post', `${V}/v1/kv/data/b`);
  entries.aa = { password: 'new' };
  entries.c.password = '3bis';
  const ordered = { a: entries.a, aa: entries.aa, b: entries.b, c: entries.c };
  Object.keys(entries).forEach(k => delete entries[k]);
  Object.assign(entries, ordered);
  stats.data = 0;
  const second = await read(api, { previous: first.entry, touched: ['c'] });
  expect(stats.data).toBe(3); // aa (nouvelle), b (journal), c (touchée) — pas a
  expect(second.results.map(r => r.password)).toEqual(['1', 'new', '2bis', '3bis']);
  expect(second.results[0]).toBe(first.results[0]); // objet réutilisé (ligne non re-rendue)

  // Entrée retirée du listage : oubliée sans lecture
  delete entries.a;
  stats.data = 0;
  const third = await read(api, { previous: second.entry });
  expect(stats.data).toBe(0);
  expect(names(third)).toEqual(['aa', 'b', 'c']);
  expect(stats.list).toBe(3); // le listage, lui, a toujours lieu
});

test('« Afficher les supprimés » : seules les entrées non lisibles (404) sont consultées ; retour arrière sans lecture', async () => {
  const entries = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`e${i}`, { password: `p${i}`, deleted: i % 10 === 0 }]));
  const { api, stats } = fakeVault(entries);
  const off = await read(api);
  expect(names(off)).toHaveLength(45);
  stats.data = 0; stats.meta = 0;
  const on = await read(api, { previous: off.entry, includeDeleted: true });
  expect(stats.meta).toBe(5);  // avant : 50 métadonnées + 45 données
  expect(stats.data).toBe(0);
  expect(names(on).filter(n => n.endsWith(':supprimée'))).toEqual(['e0:supprimée', 'e10:supprimée', 'e20:supprimée', 'e30:supprimée', 'e40:supprimée']);
  expect(names(on)).toHaveLength(50);
  stats.data = 0; stats.meta = 0;
  const offAgain = await read(api, { previous: on.entry, includeDeleted: false });
  expect(stats.data + stats.meta).toBe(0);
  expect(names(offAgain)).toEqual(names(off));
  // Entrée supprimée connue, de nouveau demandée avec les supprimées : aucune lecture
  const onAgain = await read(api, { previous: offAgain.entry, includeDeleted: true });
  expect(stats.data + stats.meta).toBe(0);
  expect(names(onAgain)).toEqual(names(on));
});

test('intégrité : entrée illisible (500) ou refusée (403) jamais mise en cache — relue et signalée à chaque fois', async () => {
  const entries = { ok: { password: 'x' }, cassee: { password: 'y', fail: 500 }, interdite: { password: 'z', fail: 403 } };
  const { api, stats } = fakeVault(entries);
  const first = await read(api);
  expect(first.results).toEqual([expect.objectContaining({ name: 'ok' }), READ_FAILED, null]);
  expect(first.failedKeys).toEqual(['cassee']);
  expect(first.forbiddenCount).toBe(1);
  stats.data = 0;
  const second = await read(api, { previous: first.entry });
  expect(stats.data).toBe(2); // cassee et interdite relues, ok réutilisée
  expect(second.failedKeys).toEqual(['cassee']);
  expect(second.forbiddenCount).toBe(1);
  // Réparée : lue normalement ensuite
  delete entries.cassee.fail;
  const third = await read(api, { previous: second.entry });
  expect(names(third)).toEqual(['ok', 'cassee']);
});

test('cache trop ancien, journal dépassé ou autre version de coffre : tout est relu', async () => {
  const entries = { a: { password: '1' }, b: { password: '2' } };
  const { api, stats } = fakeVault(entries);
  const first = await read(api);
  stats.data = 0;
  await read(api, { previous: { ...first.entry, at: Date.now() - 10000 }, maxAgeMs: 5000 });
  expect(stats.data).toBe(2);
  stats.data = 0;
  await read(api, { previous: first.entry, maxAgeMs: 5000 });
  expect(stats.data).toBe(0);
  forgetVaultWrites(); // fin de session : le journal ne permet plus de savoir ce qui a changé
  stats.data = 0;
  await read(api, { previous: first.entry });
  expect(stats.data).toBe(2);
  stats.data = 0;
  await read(api, { previous: { ...first.entry, version: 1 } });
  expect(stats.data).toBe(2);
});

test('noms réservés exacts jamais lus ; liste partielle transmise ; erreur de listage et lecture caduque', async () => {
  const entries = { '.rdvault-passkeys': { password: 'k' }, '.rdvault-keycheck': { password: 'k' }, '.rdvault-notes': { password: 'n' } };
  const { api, stats } = fakeVault(entries);
  const r = await read(api);
  expect(names(r)).toEqual(['.rdvault-notes']);
  expect(stats.data).toBe(1);

  const limit = Object.assign(new Error('large'), { code: 'LIST_TOO_LARGE', partialKeys: ['.rdvault-notes'] });
  api.listKeysV2 = async () => { throw limit; };
  const partial = await read(api);
  expect(partial.listLimit).toBe(limit);
  expect(names(partial)).toEqual(['.rdvault-notes']);

  const boom = httpError(403);
  api.listKeysV2 = async () => { throw boom; };
  expect(await read(api)).toEqual({ listError: boom });

  api.listKeysV2 = async () => ['.rdvault-notes'];
  expect(await read(api, { run: async () => READ_SKIPPED })).toEqual({ stale: true });
  expect(await read(api, { isStale: () => true })).toEqual({ stale: true });
});

test('lecture groupée (coffre local) : un appel par lot de 250 clés, statuts identiques ; repli unitaire si elle échoue', async () => {
  const entries = Object.fromEntries(Array.from({ length: 600 }, (_, i) => [`k${String(i).padStart(3, '0')}`, { password: `p${i}` }]));
  entries.k001.deleted = true;
  entries.k002.fail = 500;
  const { api, stats } = fakeVault(entries, { batch: true });
  const r = await read(api);
  expect(stats.batch).toBe(3);
  expect(stats.data + stats.meta).toBe(0);
  expect(names(r)).toHaveLength(598);
  expect(r.failedKeys).toEqual(['k002']);
  // Avec les supprimées : la lecture groupée donne déjà l'état (aucune métadonnée à lire)
  stats.batch = 0;
  const withDeleted = await read(api, { includeDeleted: true });
  expect(stats.batch).toBe(3);
  expect(stats.meta).toBe(0);
  expect(names(withDeleted)).toContain('k001:supprimée');
  // Entrée supprimée connue par la lecture groupée : rien à relire quand la case est cochée ensuite
  stats.batch = 0;
  const toggled = await read(api, { previous: r.entry, includeDeleted: true });
  expect(stats.batch).toBe(1); // k002 (illisible, jamais en cache) seulement
  expect(stats.batchKeys).toBe(1200 + 1);
  expect(names(toggled)).toContain('k001:supprimée');

  // Route absente (Vault distant, ancien serveur) : lecture unitaire, même résultat
  const broken = fakeVault(entries, { batch: 'broken' });
  const fallback = await read(broken.api);
  expect(broken.stats.batch).toBe(3);
  expect(broken.stats.data).toBe(600);
  expect(names(fallback)).toEqual(names(r));
  expect(fallback.failedKeys).toEqual(['k002']);
});

test('bascule « Afficher les supprimés » (revalidate, coffre local) : suppression faite HORS de la fenêtre vue, puis masquée une fois la case décochée', async () => {
  // Scénario de l'e2e app-ui : entrée lue vivante, puis supprimée par l'API directe (absente du journal)
  const entries = Object.fromEntries(Array.from({ length: 6 }, (_, i) => [`s${i}`, { password: `p${i}` }]));
  const { api, stats } = fakeVault(entries, { batch: true });
  const first = await read(api);
  expect(names(first)).toHaveLength(6);
  entries.s3.deleted = true; // suppression externe : aucune note au journal
  // Sans revalidate, le cache (s3 « vivante ») serait servi tel quel
  const cached = await read(api, { previous: first.entry, includeDeleted: true });
  expect(names(cached)).toContain('s3');
  // Case cochée (revalidate) : tout est relu par lots, s3 apparaît supprimée
  stats.batch = 0;
  const on = await read(api, { previous: first.entry, includeDeleted: true, revalidate: true });
  expect(stats.batch).toBe(1);
  expect(names(on)).toContain('s3:supprimée');
  // Case décochée (revalidate) : s3 masquée, 5 lignes
  const off = await read(api, { previous: on.entry, includeDeleted: false, revalidate: true });
  expect(names(off)).toEqual(['s0', 's1', 's2', 's4', 's5']);
  // Vault distant (pas de lecture groupée) : revalidate sans effet, relecture incrémentale bornée par l'âge
  const remote = fakeVault(entries);
  const r1 = await read(remote.api);
  remote.stats.data = 0; remote.stats.meta = 0;
  await read(remote.api, { previous: r1.entry, includeDeleted: true, revalidate: true });
  expect(remote.stats.data + remote.stats.meta).toBe(1); // s3 seulement (état inconnu)
});

test('KV v1 : pas de métadonnées, une entrée 404 reste masquée sans relecture', async () => {
  const entries = { a: { password: '1' }, b: { password: '2', deleted: true } };
  const { api, stats } = fakeVault(entries);
  const v1 = { name: 'legacy', version: 1 };
  const first = await read(api, { engine: v1, includeDeleted: true });
  expect(stats.meta).toBe(0);
  expect(names(first)).toEqual(['a']);
  stats.data = 0;
  await read(api, { engine: v1, includeDeleted: true, previous: first.entry });
  expect(stats.data).toBe(0);
});

test('cache lié au service Vault : un autre service (session) ne voit jamais les listes du précédent', () => {
  const cache = createEngineReadCache();
  const apiA = {}; const apiB = {};
  cache.bind(apiA);
  cache.set(apiA, engine, { version: 2, records: new Map() });
  expect(cache.get(apiA, engine)).not.toBeNull();
  expect(cache.get(apiB, engine)).toBeNull();
  cache.set(apiB, engine, { version: 2, records: new Map() }); // refusé : pas le service courant
  cache.bind(apiB);
  expect(cache.size()).toBe(0);
  expect(cache.get(apiA, engine)).toBeNull();
  expect(cache.get(apiB, { name: 'kv', version: 1 })).toBeNull();
});
