// ========================================
// SERVICE : aucune écriture fondée sur une ligne PÉRIMÉE (Vault partagé)
// ========================================
// Contre un Vault distant, la liste d'un coffre est gardée en cache (services/engineReadCache.js, jusqu'à
// 2 min) : une entrée modifiée ou supprimée entre-temps par un AUTRE client (autre poste, API, CLI,
// extension) reste affichée avec son ancien contenu. Une écriture construite à partir de cette ligne
// (fiche « Modifier », ajout / retrait d'un tag) remplaçait alors la version plus récente par l'ancien
// contenu (ex. mot de passe changé ailleurs perdu parce qu'on corrigeait une note).
// Ce service relit le contenu COURANT de l'entrée juste avant l'écriture :
// - prepareEditWrite (fiche « Modifier ») : les champs que l'utilisateur a changés dans la fiche sont
//   appliqués à la version COURANTE ; les autres gardent leur valeur courante (jamais l'ancienne). Écriture
//   en check-and-set (KV v2) sur la version relue : une écriture concurrente entre la relecture et
//   l'écriture est refusée par Vault (rien n'est écrit). Entrée supprimée ailleurs : rien n'est écrit (pas
//   de résurrection silencieuse) ;
// - readCurrentEntry : contenu courant (et version) auquel appliquer une modification ciblée (tag).
// KV v1 n'a pas de versions : même fusion, petite fenêtre de concurrence restante (comme Migrer).
// Aucun format de stockage ni appel non standard : GET …/data/<clé> et options.cas de l'API KV v2.

/** Champs stockés d'une entrée (schéma RDVAULT, ceux qu'écrivent writeSecretV2 / writeSecretV1) */
const STORED_FIELDS = ['username', 'password', 'url', 'website', 'notes', 'tags', 'Port', 'customFields', 'attachments', 'entryType'];

const DEFAULTS = { customFields: '[]', attachments: '[]', entryType: 'secret' };

/** Valeur comparable d'un champ stocké, avec les valeurs par défaut de entryFromKvData (absent ≡ vide) */
const fieldOf = (row, field) => {
  const v = row ? row[field] : undefined;
  if (v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0)) {
    return field in DEFAULTS ? DEFAULTS[field] : '';
  }
  if (typeof v === 'object') {
    try { return JSON.stringify(v); } catch { return String(v); }
  }
  return String(v);
};

/**
 * Vrai si les deux lignes portent le même contenu stocké (propriétés d'affichage ignorées)
 * @param {Object} a
 * @param {Object} b
 */
export function sameStoredEntry(a, b) {
  return STORED_FIELDS.every(f => fieldOf(a, f) === fieldOf(b, f));
}

/**
 * Fiche `form` ouverte sur `baseRow`, entrée valant maintenant `current` : champs changés dans la fiche
 * (form ≠ base) pris dans la fiche, les autres dans la version courante. Propriétés hors schéma
 * (nom, marqueurs d'affichage) : celles de la fiche.
 * @param {Object} form
 * @param {Object} baseRow
 * @param {Object} current
 */
export function mergeOntoCurrent(form, baseRow, current) {
  const out = { ...form };
  for (const f of STORED_FIELDS) {
    if (fieldOf(form, f) === fieldOf(baseRow, f)) out[f] = current ? current[f] : undefined;
  }
  return out;
}

/** Refus check-and-set de Vault (version concurrente) : 400 « check-and-set parameter did not match… » */
export function isCasConflict(err) {
  if (err?.response?.status !== 400) return false;
  const errors = err?.response?.data?.errors;
  return Array.isArray(errors) && errors.some(e => typeof e === 'string' && /check-and-set/i.test(e));
}

/**
 * Contenu courant d'une entrée et, en KV v2, sa version.
 * @param {Object} vaultApi - Service createVaultApi
 * @param {{ name: string, version: number }} engine
 * @param {string} key
 * @returns {Promise<{ item: Object, version: number|null }|null>} null : service sans lecture (aucune
 *   relecture possible) ; rejet axios (404 : absente ou supprimée)
 */
export async function readCurrentEntry(vaultApi, engine, key) {
  if (!vaultApi) return null;
  if (engine.version === 2) {
    if (typeof vaultApi.readSecretV2Versioned === 'function') return vaultApi.readSecretV2Versioned(engine, key);
    if (typeof vaultApi.readSecretV2 === 'function') return { item: await vaultApi.readSecretV2(engine, key), version: null };
    return null;
  }
  if (typeof vaultApi.readSecretV1 === 'function') return { item: await vaultApi.readSecretV1(engine, key), version: null };
  return null;
}

/**
 * Contenu à écrire pour la fiche « Modifier » de l'entrée existante `key`, ouverte sur `baseRow`.
 * - { ok: true, entry, cas, merged } : `entry` à écrire (fiche telle quelle si l'entrée n'a pas changé
 *   depuis l'ouverture ; sinon fusion sur la version courante, merged = true) ; cas = version relue (KV v2)
 *   à passer à l'écriture, ou undefined (KV v1, version inconnue, vérification impossible) ;
 * - { ok: false, reason: 'gone' } : entrée supprimée ailleurs depuis l'ouverture — rien à écrire.
 * Lecture refusée (403 : policy en écriture seule) ou sans ligne de référence : fiche telle quelle
 * (comportement antérieur). Toute autre erreur de lecture (réseau, 5xx) est propagée : rien n'est écrit.
 * @param {Object} vaultApi
 * @param {{ name: string, version: number }} engine
 * @param {string} key - nom de l'entrée À L'OUVERTURE de la fiche (avant un éventuel renommage)
 * @param {Object|null} baseRow - contenu de l'entrée à l'ouverture de la fiche
 * @param {Object} form - contenu de la fiche à enregistrer
 */
export async function prepareEditWrite(vaultApi, engine, key, baseRow, form) {
  if (!baseRow || typeof baseRow !== 'object') return { ok: true, entry: form, cas: undefined, merged: false };
  let current;
  try {
    current = await readCurrentEntry(vaultApi, engine, key);
  } catch (err) {
    const status = err?.response?.status;
    if (status === 404) return { ok: false, reason: 'gone' };
    if (status === 403) return { ok: true, entry: form, cas: undefined, merged: false };
    throw err;
  }
  if (!current) return { ok: true, entry: form, cas: undefined, merged: false };
  const cas = engine.version === 2 && current.version ? current.version : undefined;
  if (sameStoredEntry(current.item, baseRow)) return { ok: true, entry: form, cas, merged: false };
  return { ok: true, entry: mergeOntoCurrent(form, baseRow, current.item), cas, merged: true };
}
