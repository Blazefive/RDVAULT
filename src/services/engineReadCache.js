// ========================================
// SERVICE : lecture des entrées d'un coffre avec cache par coffre (relectures ciblées)
// ========================================
// Avant : chaque écriture (une entrée enregistrée, supprimée, restaurée, déplacée…), chaque changement de
// coffre, chaque bascule de « Afficher les supprimés » et chaque recherche multi-coffres relisait TOUTES
// les entrées, une requête par entrée (≈ 1 240 requêtes et 2,4 s pour un coffre de 1 200 entrées).
//
// Désormais, la liste des entrées de chaque coffre déjà lu est gardée (cache lié au service Vault, donc
// à la session : un autre jeton ne voit jamais le cache du précédent) et une relecture :
// 1. LISTE toujours les clés (API KV standard : quelques requêtes, une par dossier) : entrées ajoutées ou
//    retirées, ordre, liste partielle (bornes LIST_TOO_LARGE / LIST_TOO_DEEP) détectés comme avant ;
// 2. ne LIT que les entrées absentes du cache, celles écrites depuis la lecture précédente (journal des
//    écritures, services/vaultWriteLog.js, plus les noms touchés passés par l'appelant) et, pour
//    « Afficher les supprimés », l'état (métadonnées) des seules entrées dont on ne sait pas encore si
//    elles sont supprimées ;
// 3. relit TOUT si le cache est plus ancien que `maxAgeMs` (écritures d'autres clients d'un Vault
//    partagé) ou si le journal ne permet pas de savoir ce qui a changé.
// Les entrées illisibles (réseau, délai, 5xx, intégrité « decryption failed ») et refusées (403) ne
// sont jamais mises en cache : relues à chaque fois, signalées comme avant. Une entrée illisible n'est
// jamais confondue avec une entrée absente.
//
// Coffre LOCAL (option batchRead de vaultApi) : les entrées à lire d'un coffre KV v2 le sont par la
// lecture groupée du serveur local (quelques requêtes au lieu d'une par entrée), avec repli automatique
// sur la lecture unitaire si la route échoue. Contre un Vault distant, seule l'API KV v2 standard sert.
import axios from 'axios';
import { encodeEnginePath } from '../utils/security';
import { withRetry } from '../utils/mapLimit';
import { isInternalSecretKey } from '../utils/passkeyEngine';
import { vaultWriteSeq, vaultWritesSince, ALL_KEYS } from './vaultWriteLog';
import { BATCH_READ_MAX_KEYS } from './vaultApi';

/** Lecture en échec (réseau, délai, 5xx, intégrité) : entrée signalée, jamais confondue avec absente */
export const READ_FAILED = Symbol('read-failed');
/** Lecture abandonnée (lecture plus récente, autre coffre, fin de session) */
export const READ_SKIPPED = Symbol('read-skipped');

// États mémorisés d'une entrée listée
const LIVE = 'live';         // version courante lisible : ligne mémorisée
const DELETED = 'deleted';   // version courante supprimée en douceur (métadonnées) : ligne « supprimée »
const GONE = 'gone';         // lecture 404 sans consultation des métadonnées : supprimée (ou disparue)
const ABSENT = 'absent';     // métadonnées 404 : listée mais disparue

/** Ligne d'une entrée supprimée en douceur (« Afficher les supprimés »), comme auparavant */
const deletedRow = (key) => ({ name: key, username: '', password: '', url: '', notes: '', deleted: true });

/**
 * Cache des lectures, par coffre, lié à un service Vault (une session). Changer de service (nouveau
 * jeton, déconnexion) vide le cache.
 */
export function createEngineReadCache() {
  let api = null;
  const engines = new Map(); // nom du coffre → entrée { version, at, seq, records: Map<clé, { state, row }> }
  return {
    /** Service Vault courant : un autre service vide le cache (rien ne passe d'une session à l'autre) */
    bind(vaultApi) {
      if (api !== vaultApi) {
        engines.clear();
        api = vaultApi;
      }
    },
    get api() { return api; },
    get(vaultApi, engine) {
      if (!engine || vaultApi !== api) return null;
      const entry = engines.get(engine.name);
      return entry && entry.version === engine.version ? entry : null;
    },
    set(vaultApi, engine, entry) {
      if (!engine || !entry || vaultApi !== api) return;
      engines.set(engine.name, entry);
    },
    drop(name) { engines.delete(name); },
    clear() { engines.clear(); api = null; },
    size() { return engines.size; },
  };
}

/**
 * Lit les entrées d'un coffre en réutilisant `previous` (entrée du cache) quand c'est possible.
 *
 * @param {Object} vaultApi - Service Vault (listKeysV1/V2, readSecretV1/V2, baseHeaders, axiosConfig,
 *   readSecretsBatchV2 facultatif)
 * @param {{ name: string, version: number }} engine
 * @param {Object} opts
 * @param {string} opts.vaultUrl - URL du coffre (lecture des métadonnées KV v2)
 * @param {boolean} [opts.includeDeleted=false] - KV v2 : lignes des entrées supprimées en douceur
 * @param {Object|null} [opts.previous] - Entrée du cache (null : tout est lu)
 * @param {Iterable<string>} [opts.touched] - Noms d'entrées écrites par l'appelant : relues
 * @param {number} [opts.maxAgeMs=Infinity] - Âge maximal du cache avant relecture complète
 * @param {boolean} [opts.revalidate=false] - Demande explicite de l'utilisateur (bascule « Afficher les
 *   supprimés ») : si la lecture groupée est disponible (coffre local, KV v2), TOUT est relu par lots
 *   (quelques requêtes) au lieu de se fier au cache ; sinon (Vault distant : une requête par entrée),
 *   relecture incrémentale bornée par `maxAgeMs` comme d'habitude
 * @param {Function} opts.run - (fn) => Promise : exécute une requête dans la file globale ; renvoie
 *   READ_SKIPPED si la lecture est devenue caduque
 * @param {Function} [opts.isStale] - () => vrai si la lecture est devenue caduque
 * @returns {Promise<{ stale: true } | { listError: Error } | {
 *   keys: string[], results: Array, listLimit: Error|null, forbiddenCount: number, failedKeys: string[],
 *   entry: Object, reads: number }>} results : une case par clé de `keys` — ligne, null (absente,
 *   supprimée masquée, refusée) ou READ_FAILED
 */
export async function readEngineEntries(vaultApi, engine, {
  vaultUrl, includeDeleted = false, previous = null, touched = null, maxAgeMs = Infinity, revalidate = false,
  run, isStale = () => false,
} = {}) {
  const { listKeysV2, listKeysV1, readSecretV2, readSecretV1, baseHeaders, axiosConfig } = vaultApi;
  const v2 = engine.version === 2;
  const startSeq = vaultWriteSeq();
  const now = Date.now();
  // Revalidation à bas coût : le journal ne connaît que les écritures de CETTE fenêtre ; une suppression
  // faite ailleurs (API directe, autre client) n'y figure pas. Quand l'utilisateur demande explicitement
  // l'état des suppressions et que la lecture groupée est disponible, tout est relu par lots.
  const cheapFullRead = revalidate && v2 && typeof vaultApi.readSecretsBatchV2 === 'function';

  // Cache réutilisable : même version de coffre, assez récent, et journal des écritures exploitable
  let base = !cheapFullRead && previous && previous.version === engine.version && (now - previous.at) <= maxAgeMs ? previous : null;
  let dirty = new Set();
  if (base) {
    const written = vaultWritesSince(engine, base.seq);
    if (written === ALL_KEYS) base = null;
    else dirty = written;
  }
  if (touched) for (const k of touched) if (typeof k === 'string') dirty.add(k);

  // 1. Listage (toujours) — erreurs et liste partielle traitées par l'appelant, comme avant
  let allKeys;
  let listLimit = null;
  try {
    allKeys = await run(() => withRetry(() => (v2 ? listKeysV2(engine) : listKeysV1(engine))));
  } catch (err) {
    if (!Array.isArray(err?.partialKeys)) return { listError: err };
    listLimit = err;
    allKeys = err.partialKeys;
  }
  if (allKeys === READ_SKIPPED || isStale()) return { stale: true };
  // Secrets internes RDVAULT (passkeys, témoin de clé) : noms réservés EXACTS (COMPAT-2), jamais lus ici
  const keys = (Array.isArray(allKeys) ? allKeys : []).filter(k => !isInternalSecretKey(k));

  // 2. Entrées réutilisées, entrées à lire (données, ou métadonnées puis données)
  const results = new Array(keys.length);
  const records = new Map();
  const toRead = []; // { index, key, meta }
  keys.forEach((key, index) => {
    const rec = base && !dirty.has(key) ? base.records.get(key) : null;
    if (rec) {
      if (rec.state === LIVE) { results[index] = rec.row; records.set(key, rec); return; }
      if (rec.state === DELETED) { results[index] = includeDeleted && v2 ? rec.row : null; records.set(key, rec); return; }
      if (rec.state === ABSENT) { results[index] = null; records.set(key, rec); return; }
      if (rec.state === GONE && !(includeDeleted && v2)) { results[index] = null; records.set(key, rec); return; }
    }
    toRead.push({ index, key, meta: includeDeleted && v2 });
  });

  let forbiddenCount = 0;
  const failedKeys = [];
  let reads = 0;
  // Même traitement qu'une lecture unitaire : 403 compté (refus), 404 absente/supprimée, autre → échec
  const noteReadError = (err, key) => {
    const status = err?.response?.status;
    if (status === 403) forbiddenCount++;
    else if (status !== 404) failedKeys.push(key);
    return status === 403 || status === 404 ? null : READ_FAILED;
  };
  const settle = ({ index, key }, value, state, row) => {
    results[index] = value;
    if (state) records.set(key, { state, row });
  };

  // Lecture unitaire (API KV standard) d'une entrée
  const readOne = async (job) => {
    const { key, meta } = job;
    if (meta) {
      let metaRes;
      reads++;
      try {
        metaRes = await withRetry(() => axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() })));
      } catch (err) {
        const value = noteReadError(err, key);
        settle(job, value, err?.response?.status === 404 ? ABSENT : null, null);
        return;
      }
      const currentVersion = metaRes.data?.data?.current_version;
      const versionData = metaRes.data?.data?.versions?.[currentVersion];
      if (versionData?.deletion_time) {
        const row = deletedRow(key);
        settle(job, row, DELETED, row);
        return;
      }
    }
    reads++;
    try {
      const item = await withRetry(() => (v2 ? readSecretV2(engine, key) : readSecretV1(engine, key)));
      const row = { ...item, deleted: false };
      settle(job, row, LIVE, row);
    } catch (err) {
      const value = noteReadError(err, key);
      settle(job, value, err?.response?.status === 404 ? GONE : null, null);
    }
  };

  // Lecture groupée (coffre local, KV v2) : statut de la version courante et données en une requête
  const readChunk = async (chunk) => {
    let answers;
    reads++;
    try {
      answers = await withRetry(() => vaultApi.readSecretsBatchV2(engine, chunk.map(j => j.key)));
    } catch {
      return false; // repli : lecture unitaire de ce lot
    }
    answers.forEach((a, i) => {
      const job = chunk[i];
      if (a.item) {
        const row = { ...a.item, deleted: false };
        settle(job, row, LIVE, row);
      } else if (a.deleted) {
        const row = deletedRow(job.key);
        settle(job, job.meta ? row : null, DELETED, row);
      } else {
        const value = noteReadError(a.error, job.key);
        // 404 sans « deleted » : entrée disparue (comme des métadonnées 404)
        settle(job, value, a.error?.response?.status === 404 ? ABSENT : null, null);
      }
    });
    return true;
  };

  const tasks = [];
  if (v2 && typeof vaultApi.readSecretsBatchV2 === 'function' && toRead.length > 0) {
    for (let i = 0; i < toRead.length; i += BATCH_READ_MAX_KEYS) {
      const chunk = toRead.slice(i, i + BATCH_READ_MAX_KEYS);
      tasks.push(run(() => readChunk(chunk)).then((done) => {
        if (done === READ_SKIPPED) return READ_SKIPPED;
        if (done) return null;
        // Repli : lecture unitaire de ce lot (route absente, réponse invalide, erreur réseau persistante)
        return Promise.all(chunk.map(job => run(() => readOne(job)))).then(r => (r.includes(READ_SKIPPED) ? READ_SKIPPED : null));
      }));
    }
  } else {
    for (const job of toRead) tasks.push(run(() => readOne(job)));
  }
  const outcome = await Promise.all(tasks);
  if (outcome.includes(READ_SKIPPED) || isStale()) return { stale: true };

  return {
    keys,
    results,
    listLimit,
    forbiddenCount,
    failedKeys,
    reads,
    // Nouvelle entrée du cache : clés listées seulement (une clé disparue est oubliée), âge conservé
    // tant que la relecture n'est pas complète
    entry: { version: engine.version, at: base ? base.at : now, seq: startSeq, records },
  };
}
