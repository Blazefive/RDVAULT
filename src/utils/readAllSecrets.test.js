// ========================================
// TESTS : lecture de tous les coffres (src/utils/readAllSecrets.js) — PERF-5
// ========================================
// Avant : Promise.all sur toutes les clés de tous les coffres (une requête par entrée,
// toutes en même temps) et erreurs avalées. Chromium refuse les requêtes au-delà de
// ~2 700 en vol (net::ERR_INSUFFICIENT_RESOURCES, erreur SANS réponse HTTP) : des
// entrées disparaissaient en silence du tableau, de l'extension, de la recherche
// multi-coffres et de l'audit.
import { readAllSecrets } from './readAllSecrets';
import { DEFAULT_READ_CONCURRENCY } from './mapLimit';

const tick = () => new Promise(r => setTimeout(r, 0));
const networkError = () => Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' });
const httpError = (status) => Object.assign(new Error(String(status)), { response: { status } });

// Faux vaultApi : `keysByEngine` = { nom: [clés] } ; `onRead(engine, key)` peut lever
function fakeApi(keysByEngine, onRead = () => {}) {
  const stats = { inFlight: 0, peak: 0, reads: 0 };
  const read = async (engine, key) => {
    stats.inFlight++; stats.peak = Math.max(stats.peak, stats.inFlight); stats.reads++;
    try {
      await tick();
      onRead(engine, key);
      return { name: key, username: 'u', password: `pw-${key}`, url: '', notes: '' };
    } finally {
      stats.inFlight--;
    }
  };
  const list = async (engine) => {
    if (keysByEngine[engine.name] instanceof Error) throw keysByEngine[engine.name];
    return keysByEngine[engine.name] || [];
  };
  return { stats, api: { listKeysV2: list, listKeysV1: list, readSecretV2: read, readSecretV1: read } };
}

const keys = (prefix, n) => Array.from({ length: n }, (_, i) => `${prefix}-${i}`);

test('concurrence bornée par une file GLOBALE, même avec deux lecteurs simultanés', async () => {
  const { api, stats } = fakeApi({ A: keys('a', 300), B: keys('b', 300) });
  const engines = [{ name: 'A', version: 2 }, { name: 'B', version: 2 }];
  // Ex. synchro de l'extension + recherche multi-coffres lancées en même temps
  const [r1, r2] = await Promise.all([
    readAllSecrets(api, engines, { priority: 'low' }),
    readAllSecrets(api, engines),
  ]);
  expect(r1.secrets).toHaveLength(600);
  expect(r2.secrets).toHaveLength(600);
  expect(stats.peak).toBeLessThanOrEqual(DEFAULT_READ_CONCURRENCY); // avant : 1 200 en vol
  expect(r1.failed).toBe(0);
});

test('échec réseau persistant : compté et identifié, jamais ignoré en silence', async () => {
  const { api } = fakeApi({ A: ['ok-1', 'casse', 'ok-2'] }, (engine, key) => { if (key === 'casse') throw networkError(); });
  const r = await readAllSecrets(api, [{ name: 'A', version: 2 }], { retries: 1 });
  expect(r.secrets.map(s => s.name)).toEqual(['ok-1', 'ok-2']);
  expect(r.failed).toBe(1); // avant : propriété absente, échec invisible
  expect(r.failedKeys).toEqual([{ engine: 'A', key: 'casse' }]);
});

test('échec transitoire relancé : l\'entrée est finalement lue', async () => {
  let attempts = 0;
  const { api } = fakeApi({ A: ['x', 'y'] }, (engine, key) => {
    if (key === 'y' && attempts++ === 0) throw networkError(); // ERR_INSUFFICIENT_RESOURCES : pas de réponse
  });
  const r = await readAllSecrets(api, [{ name: 'A', version: 2 }]);
  expect(r.secrets.map(s => s.name)).toEqual(['x', 'y']);
  expect(r.failed).toBe(0);
});

test('404 (entrée supprimée en douceur, encore listée) ignorée ; 403 comptée à part', async () => {
  const { api } = fakeApi({ A: ['vivante', 'supprimee', 'interdite'] }, (engine, key) => {
    if (key === 'supprimee') throw httpError(404);
    if (key === 'interdite') throw httpError(403);
  });
  const r = await readAllSecrets(api, [{ name: 'A', version: 2 }]);
  expect(r.secrets.map(s => s.name)).toEqual(['vivante']);
  expect(r.failed).toBe(0);
  expect(r.forbidden).toBe(1);
});

test('listage impossible (réseau) : coffre signalé ; 403/404 au listage : ignoré comme avant', async () => {
  const { api } = fakeApi({ A: networkError(), B: httpError(403), C: httpError(404), D: ['d'] });
  const r = await readAllSecrets(api, ['A', 'B', 'C', 'D'].map(name => ({ name, version: 2 })), { retries: 0 });
  expect(r.secrets.map(s => s.name)).toEqual(['d']);
  expect(r.failedEngines).toEqual(['A']);
  expect(r.listedKeys).toEqual({ D: ['d'] });
});

// Vague F : erreur de borne de vaultApi (LIST_TOO_LARGE / LIST_TOO_DEEP) portant les clés déjà listées.
// Avant : coffre entièrement absent du résultat (et listage relancé deux fois pour rien).
test('borne de listage atteinte : liste PARTIELLE lue, coffre signalé (partialEngines et failedEngines), sans relance', async () => {
  let listCalls = 0;
  const limitError = Object.assign(new Error('Listage interrompu'), {
    code: 'LIST_TOO_LARGE', i18nKey: 'error.listTooLarge', i18nVars: { max: 3 }, partialKeys: ['p-0', '.rdvault-passkeys', 'p-1'],
  });
  const { api } = fakeApi({ B: ['b'] });
  const list = api.listKeysV2;
  api.listKeysV2 = async (engine) => {
    if (engine.name !== 'A') return list(engine);
    listCalls++;
    throw limitError;
  };
  const r = await readAllSecrets(api, [{ name: 'A', version: 2 }, { name: 'B', version: 2 }]);
  expect(r.secrets.map(s => `${s.engineName}/${s.name}`).sort()).toEqual(['A/p-0', 'A/p-1', 'B/b']);
  expect(r.partialEngines).toEqual([{ engine: 'A', code: 'LIST_TOO_LARGE', i18nKey: 'error.listTooLarge', i18nVars: { max: 3 }, listed: 3 }]);
  expect(r.failedEngines).toEqual(['A']); // les appelants existants avertissent d'une liste incomplète
  expect(r.listedKeys.A).toEqual(['p-0', 'p-1']);
  expect(listCalls).toBe(1);
});

test('secrets internes .rdvault exclus ; keyFilter (lecture incrémentale) et mapSecret', async () => {
  const { api, stats } = fakeApi({ A: ['.rdvault-passkeys', 'connu', 'nouveau'] });
  const r = await readAllSecrets(api, [{ name: 'A', version: 2 }], {
    keyFilter: (engine, listed) => listed.filter(k => k !== 'connu'),
    mapSecret: (s, engine) => ({ name: s.name, engine: engine.name }),
  });
  expect(r.secrets).toEqual([{ name: 'nouveau', engine: 'A' }]);
  expect(r.listedKeys.A).toEqual(['connu', 'nouveau']);
  expect(stats.reads).toBe(1);
});

// COMPAT-2 : seuls les noms internes EXACTS (« .rdvault-passkeys », « .rdvault-keycheck ») à la racine sont
// réservés. Avant : filtre par préfixe « .rdvault », les entrées utilisateur « .rdvault-notes » ou « .rdvault »
// de la 1.5.0 (affichées dans le tableau) manquaient à l'extension, à la recherche multi-coffres et à l'audit.
test('COMPAT-2 : noms réservés exacts exclus, autres noms « .rdvault… » lus comme des entrées ordinaires', async () => {
  const listed = ['.rdvault-passkeys', '.rdvault-keycheck', '.rdvault-notes', '.rdvault', '.rdvault-passkeys-old',
    'dossier/.rdvault-passkeys', 'web'];
  const readKeys = [];
  const { api } = fakeApi({ A: listed }, (engine, key) => { readKeys.push(key); });
  const r = await readAllSecrets(api, [{ name: 'A', version: 2 }]);
  const expected = ['.rdvault', '.rdvault-notes', '.rdvault-passkeys-old', 'dossier/.rdvault-passkeys', 'web'];
  expect(r.secrets.map(s => s.name).sort()).toEqual(expected); // avant : ['dossier/.rdvault-passkeys', 'web']
  expect(r.listedKeys.A.slice().sort()).toEqual(expected);
  expect(readKeys).not.toContain('.rdvault-passkeys'); // blob des clés privées jamais lu
  expect(readKeys).not.toContain('.rdvault-keycheck');
  expect(r.failed).toBe(0);
});

test('annulation : les lectures non lancées sont abandonnées et le résultat marqué aborted', async () => {
  const ac = new AbortController();
  let reads = 0;
  const { api } = fakeApi({ A: keys('a', 200) }, () => { reads++; if (reads === 5) ac.abort(); });
  const r = await readAllSecrets(api, [{ name: 'A', version: 2 }], { signal: ac.signal });
  expect(r.aborted).toBe(true);
  expect(r.failed).toBe(0); // une annulation n'est pas un échec
  expect(reads).toBeLessThan(200);
});
