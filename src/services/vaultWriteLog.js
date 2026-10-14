// ========================================
// SERVICE : journal des écritures adressées au coffre (invalidation ciblée des caches de lecture)
// ========================================
// Les listes d'entrées gardées en cache par coffre (services/engineReadCache.js) ne sont relues que pour
// les entrées ÉCRITES depuis leur lecture. Ce journal retient le chemin de chaque requête d'écriture
// (toute méthode autre que GET / HEAD / OPTIONS vers `…/v1/…`), d'où qu'elle vienne :
// - notée explicitement par les fonctions d'écriture de vaultApi (noteVaultWrite) ;
// - observée par un intercepteur de requête axios (ensureVaultWriteObserver) : écritures directes de
//   l'interface (Paramètres › import, panneau d'administration, restauration d'une version…).
// Seul le CHEMIN est retenu (nom du coffre et de l'entrée, jamais le contenu). Un chemin noté deux fois
// (fonction de vaultApi + intercepteur) est sans conséquence : l'invalidation est idempotente.
// Journal borné : au-delà, les écritures les plus anciennes sont oubliées et un cache plus ancien
// qu'elles est entièrement relu (jamais d'entrée périmée gardée faute de trace).
import axios from 'axios';
import { encodeEnginePath } from '../utils/security';

const READ_METHODS = new Set(['get', 'head', 'options']);
const MAX_ENTRIES = 5000;

// Requête de LECTURE envoyée en POST (lecture groupée du coffre local) : marquée par ce drapeau de
// configuration axios, elle n'est pas prise pour une écriture.
export const READ_ONLY_REQUEST_FLAG = 'rdvaultReadOnly';

/** Toutes les entrées du coffre sont à relire (journal dépassé, opération sur le coffre lui-même…) */
export const ALL_KEYS = 'all';

let seq = 0;
let floor = 0;          // écritures de numéro <= floor oubliées
let entries = [];       // { seq, path } : chemin après « /v1/ », sans paramètres, non décodé

/** Chemin après le premier « /v1/ » (sans paramètres de requête), ou null */
function vaultPathOf(url) {
  if (typeof url !== 'string') return null;
  const i = url.indexOf('/v1/');
  if (i === -1) return null;
  return url.slice(i + 4).split('?')[0].split('#')[0];
}

/**
 * Note une requête adressée au coffre ; seules les écritures sont retenues.
 * @param {string} method - Méthode HTTP (insensible à la casse)
 * @param {string} url - URL complète `${vaultUrl}/v1/…`
 */
export function noteVaultWrite(method, url) {
  const m = String(method || 'get').toLowerCase();
  if (READ_METHODS.has(m)) return;
  const path = vaultPathOf(url);
  if (path === null) return;
  // Requêtes sans effet sur les entrées des coffres (connexion, jeton, TOTP, capacités, emballage…) : non
  // retenues (journal court). Restent les coffres eux-mêmes (montages) et les droits (policies).
  if (/^(auth|TOTP|totp)\//.test(path)) return;
  if (path.startsWith('sys/') && !/^sys\/(mounts|remount|policies)(\/|$)/.test(path)) return;
  seq += 1;
  entries.push({ seq, path });
  if (entries.length > MAX_ENTRIES) {
    const drop = entries.length - MAX_ENTRIES;
    floor = entries[drop - 1].seq;
    entries = entries.slice(drop);
  }
}

/** Numéro de la dernière écriture notée (à relever AVANT une lecture) */
export function vaultWriteSeq() {
  return seq;
}

/**
 * Oublie toutes les écritures notées jusqu'ici (fin de session : les noms d'entrées de la session
 * précédente ne restent pas en mémoire). Un cache antérieur sera relu entièrement.
 */
export function forgetVaultWrites() {
  // Numéro avancé : toute lecture antérieure (même sans écriture depuis) est considérée périmée
  seq += 1;
  floor = seq;
  entries = [];
}

const decodeSegment = (s) => {
  try { return decodeURIComponent(s); } catch { return null; }
};

/**
 * Entrées du coffre `engine` écrites depuis l'écriture n° `sinceSeq` : ensemble des noms d'entrées, ou
 * ALL_KEYS (coffre à relire en entier : journal dépassé, coffre recréé ou supprimé, chemin non reconnu).
 * Reconnaît les chemins KV v2 (data, delete, undelete, destroy, metadata) et KV v1 (clé directe),
 * clé encodée d'un bloc (encodeURIComponent) ou segment par segment.
 * @param {{ name: string, version: number }} engine
 * @param {number} sinceSeq
 * @returns {Set<string>|'all'}
 */
export function vaultWritesSince(engine, sinceSeq) {
  if (!engine || typeof engine.name !== 'string') return ALL_KEYS;
  if (!Number.isFinite(sinceSeq) || sinceSeq < floor) return ALL_KEYS;
  const prefix = encodeEnginePath(engine.name);
  const keys = new Set();
  for (const w of entries) {
    if (w.seq <= sinceSeq) continue;
    const p = w.path;
    if (p.startsWith('sys/')) {
      // Coffre créé, supprimé ou reconfiguré, droits modifiés : tout est relu
      if (p.startsWith('sys/mounts') || p.startsWith('sys/remount') || p.startsWith('sys/policies')) {
        const target = p.startsWith('sys/mounts/') ? p.slice('sys/mounts/'.length).replace(/\/+$/, '') : null;
        if (target === null || target === prefix || p.startsWith('sys/policies') || p.startsWith('sys/remount')) return ALL_KEYS;
      }
      continue;
    }
    if (p !== prefix && !p.startsWith(`${prefix}/`)) continue;
    const rest = p.slice(prefix.length + 1);
    if (!rest) return ALL_KEYS;
    if (engine.version === 2) {
      const m = /^(data|delete|undelete|destroy|metadata)\/(.+)$/.exec(rest);
      if (!m) return ALL_KEYS; // opération inconnue, ou coffre imbriqué : prudence
      const key = decodeSegment(m[2]);
      if (key === null) return ALL_KEYS;
      keys.add(key);
    } else {
      const key = decodeSegment(rest);
      if (key === null) return ALL_KEYS;
      keys.add(key);
    }
  }
  return keys;
}

/**
 * Envoie une écriture en la notant AVANT l'envoi et APRÈS la réponse (succès ou échec) : une lecture
 * commencée pendant que l'écriture était en vol (donc susceptible d'avoir lu l'ancienne valeur) voit
 * toujours une écriture postérieure à son début et relira l'entrée.
 * @param {string} method
 * @param {string} url
 * @param {Function} send - () => Promise de la requête
 */
export async function trackVaultWrite(method, url, send) {
  noteVaultWrite(method, url);
  try {
    return await send();
  } finally {
    noteVaultWrite(method, url);
  }
}

let observerInstalled = false;

/**
 * Pose (une seule fois) l'intercepteur axios qui note les écritures de toute l'interface. Sans
 * intercepteurs (axios simulé des tests), seules les écritures notées par vaultApi sont connues.
 */
export function ensureVaultWriteObserver() {
  if (observerInstalled) return;
  try {
    const requests = axios.interceptors?.request;
    if (typeof requests?.use !== 'function') return;
    const note = (config) => {
      try {
        if (config && !config[READ_ONLY_REQUEST_FLAG]) noteVaultWrite(config.method, config.url);
      } catch { /* observation seulement : la requête part telle quelle */ }
    };
    requests.use((config) => { note(config); return config; });
    // Écriture terminée (réponse ou erreur) : notée de nouveau (voir trackVaultWrite)
    const responses = axios.interceptors?.response;
    if (typeof responses?.use === 'function') {
      responses.use(
        (response) => { note(response?.config); return response; },
        (error) => { note(error?.config); return Promise.reject(error); },
      );
    }
    observerInstalled = true;
  } catch { /* axios sans intercepteurs */ }
}
