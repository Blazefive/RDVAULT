// ========================================
// UTILITAIRE : concurrence bornée et relances (lectures massives du coffre)
// ========================================
// Le renderer Chromium refuse les requêtes au-delà d'environ 2 700 en vol
// (net::ERR_INSUFFICIENT_RESOURCES, sans réponse HTTP). Lancer une requête par
// entrée avec Promise.all faisait disparaître des entrées dès ~1 350 secrets
// (tableau, extension, recherche multi-coffres, audit). Toutes les lectures
// massives passent donc par une file GLOBALE (`vaultReadLimiter`) : quel que soit
// le nombre de lectures lancées en même temps (tableau + synchro extension +
// recherche multi-coffres…), au plus DEFAULT_READ_CONCURRENCY requêtes sont en vol.
//
// Deux priorités : 'high' (ce que l'utilisateur attend à l'écran, ex. le tableau)
// passe avant 'low' (tâches de fond, ex. synchro de l'extension).

export const DEFAULT_READ_CONCURRENCY = 24;

/**
 * Crée une file à concurrence bornée.
 * @param {number} limit - Nombre maximal de tâches simultanées (>= 1)
 * @returns {{ run: Function, stats: Function }}
 */
export function createLimiter(limit = DEFAULT_READ_CONCURRENCY) {
  const max = Math.max(1, Math.floor(Number(limit) || 1));
  // Files FIFO avec index de tête (évite le coût O(n) de Array.shift sur des milliers de tâches)
  const queues = { high: { items: [], head: 0 }, low: { items: [], head: 0 } };
  let active = 0;
  let peak = 0;

  const take = (q) => {
    if (q.head >= q.items.length) return null;
    const job = q.items[q.head];
    q.items[q.head] = undefined;
    q.head++;
    // Compactage périodique pour libérer la mémoire des tâches déjà lancées
    if (q.head > 1024 && q.head * 2 > q.items.length) {
      q.items = q.items.slice(q.head);
      q.head = 0;
    }
    return job;
  };

  // Fin d'une tâche : une place se libère pour la suivante
  const release = () => { active--; pump(); };

  const start = (job) => {
    active++;
    if (active > peak) peak = active;
    Promise.resolve()
      .then(job.fn)
      .then(job.resolve, job.reject)
      .finally(release);
  };

  function pump() {
    while (active < max) {
      const job = take(queues.high) || take(queues.low);
      if (!job) return;
      start(job);
    }
  }

  /**
   * Exécute `fn` dès qu'une place se libère.
   * @param {Function} fn - Tâche asynchrone
   * @param {{ priority?: 'high'|'low' }} [opts]
   * @returns {Promise<*>} Résultat (ou rejet) de `fn`
   */
  const run = (fn, { priority = 'high' } = {}) => new Promise((resolve, reject) => {
    const q = priority === 'low' ? queues.low : queues.high;
    q.items.push({ fn, resolve, reject });
    pump();
  });

  /** Diagnostic (tests) : tâches en cours, en attente et pic de concurrence observé */
  const stats = () => ({
    active,
    pending: (queues.high.items.length - queues.high.head) + (queues.low.items.length - queues.low.head),
    peak,
    limit: max,
  });

  return { run, stats };
}

/** File globale partagée par toutes les lectures massives du coffre */
export const vaultReadLimiter = createLimiter(DEFAULT_READ_CONCURRENCY);

/**
 * Applique `fn` à chaque élément avec au plus `limit` appels simultanés (file locale).
 * Les résultats gardent l'ordre des éléments. `fn` doit gérer ses propres erreurs :
 * un rejet fait échouer l'ensemble (les autres appels en cours se terminent).
 * Annulation : si `signal` est annulé, plus aucun nouvel appel n'est lancé
 * (les cases non traitées restent `undefined`).
 *
 * @param {Iterable} items
 * @param {number} limit
 * @param {Function} fn - (item, index) => Promise
 * @param {{ signal?: AbortSignal }} [opts]
 * @returns {Promise<Array>}
 */
export async function mapLimit(items, limit, fn, { signal } = {}) {
  const list = Array.from(items || []);
  const results = new Array(list.length);
  let next = 0;
  const worker = async () => {
    while (next < list.length) {
      if (signal?.aborted) return;
      const i = next++;
      // eslint-disable-next-line no-await-in-loop -- volontaire : un appel à la fois par « ouvrier »
      results[i] = await fn(list[i], i);
    }
  };
  const workers = Math.max(1, Math.min(Math.floor(Number(limit) || 1), list.length));
  await Promise.all(Array.from({ length: workers }, worker));
  return results;
}

// Erreurs APPLICATIVES déterministes levées sans réponse HTTP (services/vaultApi.js) : entrée refusée
// avant écriture (VALIDATION), listage au-delà des bornes (LIST_TOO_LARGE, LIST_TOO_DEEP). Les relancer
// donnerait le même résultat après un délai inutile (et, pour un listage de 20 000 clés, deux listages
// complets de plus).
const NON_TRANSIENT_CODES = new Set(['VALIDATION', 'LIST_TOO_LARGE', 'LIST_TOO_DEEP']);

/**
 * Erreur transitoire (relance utile) : pas de réponse HTTP (requête refusée par le
 * navigateur, connexion coupée, délai dépassé) ou 429 / 502 / 503 / 504.
 * Une annulation volontaire (AbortController) n'est jamais relancée, ni une erreur
 * applicative déterministe (NON_TRANSIENT_CODES).
 */
export function isTransientError(err) {
  if (!err) return false;
  if (err.name === 'AbortError' || err.name === 'CanceledError' || err.code === 'ERR_CANCELED') return false;
  if (NON_TRANSIENT_CODES.has(err.code)) return false;
  const status = err.response?.status;
  if (status === undefined || status === null) return true;
  return status === 429 || status === 502 || status === 503 || status === 504;
}

const wait = (ms, signal) => new Promise((resolve) => {
  if (signal?.aborted) { resolve(); return; }
  const timer = setTimeout(done, ms);
  function done() {
    clearTimeout(timer);
    signal?.removeEventListener?.('abort', done);
    resolve();
  }
  signal?.addEventListener?.('abort', done, { once: true });
});

/**
 * Exécute `fn` et la relance (au plus `retries` fois, délai croissant) sur erreur transitoire.
 * Les autres erreurs (403, 404…) sont propagées immédiatement.
 * @param {Function} fn
 * @param {{ retries?: number, delayMs?: number, signal?: AbortSignal }} [opts]
 */
export async function withRetry(fn, { retries = 2, delayMs = 200, signal } = {}) {
  let attempt = 0;
  for (;;) {
    try {
      // eslint-disable-next-line no-await-in-loop -- relances successives, par construction
      return await fn();
    } catch (err) {
      if (attempt >= retries || !isTransientError(err) || signal?.aborted) throw err;
      attempt++;
      // eslint-disable-next-line no-await-in-loop
      await wait(delayMs * (3 ** (attempt - 1)), signal);
      if (signal?.aborted) throw err;
    }
  }
}
