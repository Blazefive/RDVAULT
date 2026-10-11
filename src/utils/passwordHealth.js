// ========================================
// AUDIT DE SÉCURITÉ DES MOTS DE PASSE
// ========================================
// Analyse locale (hors ligne) de la santé des mots de passe du coffre :
//   - mots de passe faibles (entropie insuffisante)
//   - mots de passe réutilisés sur plusieurs entrées
//   - (sur demande) mots de passe compromis via Have I Been Pwned
//
// CONFIDENTIALITÉ : la vérification de fuite utilise le modèle « k-anonymity » de
// HIBB : on calcule le SHA-1 du mot de passe et on n'envoie QUE les 5 premiers
// caractères hexadécimaux du condensat à l'API. Le mot de passe en clair ne quitte
// jamais l'appareil, et l'appel n'est effectué que si l'utilisateur le déclenche.

import { calculateEntropy } from './passwordStrength';
import { mapLimit } from './mapLimit';

// En dessous de ce seuil d'entropie (bits), un mot de passe est considéré faible
// (cohérent avec le palier « Faible » de getPasswordStrength).
export const WEAK_ENTROPY_THRESHOLD = 50;

// Noms de champs personnalisés pouvant contenir un mot de passe secondaire
const PASSWORD_FIELD_HINTS = ['password', 'passwd', 'pass', 'pwd', 'motdepasse', 'mot_de_passe', 'mdp'];

/**
 * Extrait le mot de passe d'un secret (champ principal, sinon champ personnalisé).
 * @param {object} secret
 * @returns {string}
 */
export function extractPassword(secret) {
  if (!secret || typeof secret !== 'object') return '';
  if (typeof secret.password === 'string' && secret.password) return secret.password;
  const cf = Array.isArray(secret.customFields) ? secret.customFields : [];
  for (const f of cf) {
    const key = String(f?.key || '').toLowerCase();
    if (f?.value && PASSWORD_FIELD_HINTS.some(h => key.includes(h))) return String(f.value);
  }
  return '';
}

/** Identité d'affichage d'une entrée (sans le mot de passe en clair). */
function describe(secret) {
  return {
    name: secret.name || '(sans nom)',
    engine: secret.engineName || '',
    username: secret.username || '',
    url: secret.url || secret.website || '',
  };
}

/**
 * Analyse l'ensemble des secrets (hors ligne, aucune requête réseau).
 * @param {Array<object>} secrets - Secrets déchiffrés (forme vaultApi.readSecret*)
 * @param {{ weakThreshold?: number }} [options]
 * @returns {{ total, items, weak, reused, reusedGroups, score }}
 */
export function analyzeVault(secrets, { weakThreshold = WEAK_ENTROPY_THRESHOLD } = {}) {
  const items = [];
  const byPassword = new Map();

  for (const s of (secrets || [])) {
    if (s?.entryType === 'placeholder') continue;
    const password = extractPassword(s);
    if (!password) continue;
    const entropy = calculateEntropy(password);
    const item = {
      ...describe(s),
      entropy,
      weak: entropy < weakThreshold,
      reused: false,
      // null = non vérifié ; -1 = erreur ; 0 = non trouvé ; >0 = nombre d'occurrences dans les fuites
      breachCount: null,
      password, // conservé en mémoire uniquement pour la vérification HIBP à la demande
    };
    items.push(item);
    const bucket = byPassword.get(password) || [];
    bucket.push(item);
    byPassword.set(password, bucket);
  }

  const reusedGroups = [];
  for (const [, bucket] of byPassword) {
    if (bucket.length > 1) {
      bucket.forEach(i => { i.reused = true; });
      reusedGroups.push(bucket.map(describe));
    }
  }

  const weak = items.filter(i => i.weak);
  const reused = items.filter(i => i.reused);

  return {
    total: items.length,
    items,
    weak,
    reused,
    reusedGroups,
    score: computeScore(items.length, weak.length, reused.length),
  };
}

/**
 * Score de santé global sur 100 (100 = aucun problème).
 * Pénalise proportionnellement les mots de passe faibles et réutilisés.
 */
export function computeScore(total, weakCount, reusedCount) {
  if (!total) return 100;
  const problems = weakCount + reusedCount; // un même mot de passe peut cumuler les deux
  const ratio = Math.min(1, problems / (total * 2));
  return Math.max(0, Math.round(100 - ratio * 100));
}

/** SHA-1 hexadécimal majuscule via l'API Web Crypto (disponible dans le renderer). */
async function sha1Hex(str, subtle) {
  const impl = subtle || (typeof crypto !== 'undefined' ? crypto.subtle : null);
  if (!impl) throw new Error('Web Crypto indisponible');
  const data = new TextEncoder().encode(str);
  const buf = await impl.digest('SHA-1', data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

/**
 * Interroge l'API « range » de HIBP pour un préfixe SHA-1 de 5 caractères.
 * @returns {Promise<Map<string, number>>} suffixe (majuscules) → nombre d'occurrences
 */
async function fetchRange(prefix, { fetchImpl, signal } = {}) {
  const doFetch = fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
  if (!doFetch) throw new Error('fetch indisponible');
  // Add-Padding : HIBP renvoie des entrées factices (compte 0) pour masquer la taille réelle de la réponse.
  const init = { headers: { 'Add-Padding': 'true' } };
  if (signal) init.signal = signal;
  const res = await doFetch(`${HIBP_RANGE_URL}${prefix}`, init);
  if (!res.ok) throw new Error('HIBP ' + res.status);
  const text = await res.text();
  const counts = new Map();
  for (const line of text.split('\n')) {
    const [suf, countStr] = line.trim().split(':');
    if (suf) counts.set(suf.toUpperCase(), parseInt(countStr, 10) || 0);
  }
  return counts;
}

/**
 * Vérifie si un mot de passe figure dans les fuites connues (Have I Been Pwned),
 * en k-anonymity : seuls les 5 premiers caractères du SHA-1 sont transmis.
 * @param {string} password
 * @param {{ fetchImpl?: Function, subtle?: SubtleCrypto, signal?: AbortSignal }} [deps] - injection pour les tests
 * @returns {Promise<number>} Nombre d'occurrences (0 = non compromis)
 */
export async function checkBreach(password, { fetchImpl, subtle, signal } = {}) {
  const hash = await sha1Hex(password, subtle);
  const counts = await fetchRange(hash.slice(0, 5), { fetchImpl, signal });
  return counts.get(hash.slice(5)) || 0;
}

// Pause annulable (résolue immédiatement si le signal est annulé)
const pause = (ms, signal) => new Promise((resolve) => {
  if (!ms || signal?.aborted) { resolve(); return; }
  const onAbort = () => { clearTimeout(timer); resolve(); };
  const timer = setTimeout(() => { signal?.removeEventListener?.('abort', onAbort); resolve(); }, ms);
  signal?.addEventListener?.('abort', onAbort, { once: true });
});

/**
 * Vérifie une liste d'items (mutés en place : breachCount renseigné).
 *
 * PERFORMANCE (avant : une requête à la fois + 120 ms de pause, ~11 min pour 5 000 mots
 * de passe, sans annulation possible) :
 * - un même mot de passe n'est haché et interrogé qu'une fois ;
 * - une réponse /range (préfixe de 5 caractères) sert à tous les mots de passe de ce préfixe ;
 * - au plus `concurrency` requêtes en vol (6), départs espacés d'au moins `minIntervalMs`
 *   (100 ms, soit 10 requêtes/s au maximum) pour rester courtois avec le service public.
 * ANNULATION : `signal` arrête l'envoi de nouvelles requêtes et annule celles en cours ; les
 * items non vérifiés gardent breachCount = null (rien n'est marqué en erreur).
 *
 * @param {Array<{password:string, breachCount:number|null}>} items
 * @param {{ fetchImpl?, subtle?, onProgress?, concurrency?, minIntervalMs?, delayMs?, signal? }} [opts]
 *   delayMs : ancien nom de minIntervalMs (compatibilité)
 * @returns {Promise<{ breached: number, errors: number, checked: number, aborted: boolean }>}
 */
export async function checkBreaches(items, {
  fetchImpl, subtle, onProgress, concurrency = 6, minIntervalMs, delayMs, signal,
} = {}) {
  const interval = Math.max(0, Number(minIntervalMs ?? delayMs ?? 100) || 0);
  const list = Array.isArray(items) ? items : [];
  const total = list.length;
  let breached = 0;
  let errors = 0;
  let done = 0;
  const aborted = () => !!signal?.aborted;
  const progress = () => { if (onProgress) onProgress(done, total); };
  const settle = (group, count) => {
    for (const item of group) {
      item.breachCount = count;
      if (count > 0) breached++;
      else if (count === -1) errors++;
    }
    done += group.length;
    progress();
  };

  // Déduplication : un même mot de passe n'est haché et interrogé qu'une fois.
  const byPassword = new Map();
  for (const item of list) {
    const group = byPassword.get(item.password);
    if (group) group.push(item);
    else byPassword.set(item.password, [item]);
  }

  // Regroupement par préfixe SHA-1 : une seule requête /range par préfixe
  const byPrefix = new Map();
  for (const [password, group] of byPassword) {
    if (aborted()) break;
    let hash;
    try {
      // eslint-disable-next-line no-await-in-loop -- condensats locaux, rapides
      hash = await sha1Hex(password, subtle);
    } catch {
      settle(group, -1);
      continue;
    }
    const prefix = hash.slice(0, 5);
    const bucket = byPrefix.get(prefix) || [];
    bucket.push({ suffix: hash.slice(5), group });
    byPrefix.set(prefix, bucket);
  }

  let nextStart = 0;
  await mapLimit(Array.from(byPrefix), concurrency, async ([prefix, bucket]) => {
    // Espacement des départs (≤ 1000 / interval requêtes par seconde)
    const now = Date.now();
    const waitMs = Math.max(0, nextStart - now);
    nextStart = Math.max(now, nextStart) + interval;
    await pause(waitMs, signal);
    if (aborted()) return;
    let counts;
    try {
      counts = await fetchRange(prefix, { fetchImpl, signal });
    } catch {
      if (aborted()) return; // annulation : items laissés « non vérifiés »
      for (const { group } of bucket) settle(group, -1);
      return;
    }
    if (aborted()) return;
    for (const { suffix, group } of bucket) settle(group, counts.get(suffix) || 0);
  }, { signal });

  return { breached, errors, checked: done, aborted: aborted() };
}
