// ========================================
// TESTS : vérification HIBP bornée, regroupée et annulable (PERF-9)
// ========================================
// Avant : une requête à la fois suivie d'une pause fixe de 120 ms (~11 min pour 5 000 mots
// de passe), sans signal d'annulation : la boucle continuait après la fermeture de la modale
// et après la déconnexion, en gardant les mots de passe en mémoire.
import crypto from 'crypto';
import { TextEncoder } from 'util';
import { checkBreaches, checkBreach } from './passwordHealth';

if (typeof global.TextEncoder === 'undefined') global.TextEncoder = TextEncoder;

const subtle = {
  digest: async (_algo, data) => {
    const h = crypto.createHash('sha1').update(Buffer.from(data)).digest();
    return h.buffer.slice(h.byteOffset, h.byteOffset + h.byteLength);
  },
};
const sha1 = (s) => crypto.createHash('sha1').update(s).digest('hex').toUpperCase();
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Faux service HIBP : mesure la concurrence et les instants de départ des requêtes
function fakeHibp({ latencyMs = 0, breached = {} } = {}) {
  const stats = { calls: 0, inFlight: 0, peak: 0, starts: [], urls: [], signals: [] };
  const fetchImpl = async (url, init) => {
    stats.calls++; stats.inFlight++; stats.peak = Math.max(stats.peak, stats.inFlight);
    stats.starts.push(Date.now()); stats.urls.push(url); stats.signals.push(init?.signal);
    try {
      if (latencyMs) await sleep(latencyMs);
      if (init?.signal?.aborted) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
      const prefix = url.slice(-5);
      const lines = Object.entries(breached)
        .filter(([pwd]) => sha1(pwd).startsWith(prefix))
        .map(([pwd, n]) => `${sha1(pwd).slice(5)}:${n}`);
      return { ok: true, text: async () => `${lines.join('\n')}\n0000000000000000000000000000000000A:0\n` };
    } finally {
      stats.inFlight--;
    }
  };
  return { stats, fetchImpl };
}

const items = (n, prefix = 'mdp-') => Array.from({ length: n }, (_, i) => ({ password: `${prefix}${i}`, breachCount: null }));

test('annulation : plus aucune requête après abort ; items restants « non vérifiés »', async () => {
  const ac = new AbortController();
  const { stats, fetchImpl } = fakeHibp();
  const list = items(40);
  const res = await checkBreaches(list, {
    fetchImpl, subtle, concurrency: 1, minIntervalMs: 0, signal: ac.signal,
    onProgress: () => ac.abort(), // annulé dès la première réponse
  });
  expect(stats.calls).toBe(1); // avant : 40 (aucune annulation possible)
  expect(res.aborted).toBe(true);
  expect(list.filter(i => i.breachCount === null)).toHaveLength(39); // pas marqués « erreur »
  expect(res.errors).toBe(0);
});

test('requêtes concurrentes bornées (6 en vol au plus) : bien plus rapide que la boucle en série', async () => {
  const { stats, fetchImpl } = fakeHibp({ latencyMs: 40 });
  const list = items(36);
  const t0 = Date.now();
  const res = await checkBreaches(list, { fetchImpl, subtle, minIntervalMs: 0 });
  const elapsed = Date.now() - t0;
  expect(stats.peak).toBe(6);       // avant : 1
  expect(res.checked).toBe(36);
  expect(elapsed).toBeLessThan(36 * 40); // avant : ≥ 36 × (40 + 120) ms
});

test('débit plafonné : départs espacés d\'au moins minIntervalMs (service public ménagé)', async () => {
  const { stats, fetchImpl } = fakeHibp();
  await checkBreaches(items(8), { fetchImpl, subtle, minIntervalMs: 30 });
  expect(stats.starts).toHaveLength(8);
  // Débit moyen : 8 départs étalés sur au moins 7 intervalles (une machine chargée ne peut que
  // retarder les minuteries, jamais les avancer ; marge de 5 ms pour l'arrondi des minuteries)
  expect(stats.starts[7] - stats.starts[0]).toBeGreaterThanOrEqual(7 * 30 - 5);
});

test('un seul appel /range par préfixe SHA-1 (mots de passe distincts, même préfixe)', async () => {
  // « Pw-1532 » et « Pw-1824 » partagent le préfixe SHA-1 6AD63
  expect(sha1('Pw-1532').slice(0, 5)).toBe(sha1('Pw-1824').slice(0, 5));
  const { stats, fetchImpl } = fakeHibp({ breached: { 'Pw-1824': 42 } });
  const list = [{ password: 'Pw-1532', breachCount: null }, { password: 'Pw-1824', breachCount: null }, { password: 'Pw-1824', breachCount: null }];
  const res = await checkBreaches(list, { fetchImpl, subtle, minIntervalMs: 0 });
  expect(stats.calls).toBe(1);
  expect(list.map(i => i.breachCount)).toEqual([0, 42, 42]);
  expect(res.breached).toBe(2);
});

test('k-anonymity conservée ; le signal est transmis à fetch ; progression en items', async () => {
  const { stats, fetchImpl } = fakeHibp({ breached: { 'mdp-1': 3 } });
  const ac = new AbortController();
  const progress = [];
  const list = items(3);
  await checkBreaches(list, { fetchImpl, subtle, minIntervalMs: 0, signal: ac.signal, onProgress: (d, t) => progress.push([d, t]) });
  for (const url of stats.urls) expect(url).toMatch(/^https:\/\/api\.pwnedpasswords\.com\/range\/[0-9A-F]{5}$/);
  expect(stats.signals.every(s => s === ac.signal)).toBe(true);
  expect(progress[progress.length - 1]).toEqual([3, 3]);
  expect(list[1].breachCount).toBe(3);
  // checkBreach (un seul mot de passe) accepte aussi le signal
  await checkBreach('mdp-1', { fetchImpl, subtle, signal: ac.signal });
  expect(stats.signals[stats.signals.length - 1]).toBe(ac.signal);
});

test('erreur HTTP : items du préfixe marqués en erreur (-1), les autres vérifiés', async () => {
  let n = 0;
  const fetchImpl = async () => (n++ === 0 ? { ok: false, status: 503, text: async () => '' } : { ok: true, text: async () => '' });
  const list = items(3);
  const res = await checkBreaches(list, { fetchImpl, subtle, concurrency: 1, minIntervalMs: 0 });
  expect(res.errors).toBe(1);
  expect(list.filter(i => i.breachCount === -1)).toHaveLength(1);
  expect(list.filter(i => i.breachCount === 0)).toHaveLength(2);
});
