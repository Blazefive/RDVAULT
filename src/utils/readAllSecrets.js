// ========================================
// UTILITAIRE : lecture de tous les secrets de plusieurs coffres
// ========================================
// Factorise la boucle « lister les clés puis lire chaque secret » utilisée par :
// - la recherche multi-coffre (App.jsx)
// - la synchronisation extension Chrome (useSync.js)
// - le rafraîchissement des tags en mode multi-coffre (useTags.js)
// - l'audit de santé des mots de passe (PasswordHealthModal.jsx)
// - le chargement des tags dans le panneau admin (AdminPanel.jsx)
//
// PERFORMANCE / FIABILITÉ : les lectures passent par la file globale bornée
// (utils/mapLimit.js, au plus ~24 requêtes en vol tous appelants confondus) et les
// échecs transitoires (requête refusée par le navigateur, délai, 5xx) sont relancés.
// Un échec persistant est COMPTÉ (`failed`, `failedKeys`, `failedEngines`) : l'appelant
// le signale au lieu de laisser des entrées disparaître en silence.
// 404 (entrée supprimée en douceur, encore listée) et 403 (lecture non autorisée) ne
// sont pas des échecs : comportement inchangé (403 compté à part dans `forbidden`).
//
// Listage interrompu par une borne de vaultApi (LIST_TOO_LARGE / LIST_TOO_DEEP, clés déjà
// listées dans `err.partialKeys`) : les clés déjà listées sont lues (liste PARTIELLE) au lieu
// d'un coffre entièrement absent, et le coffre est SIGNALÉ dans `partialEngines` (code et clé
// i18n de la cause) ET dans `failedEngines` : les appelants qui ne distinguent pas les deux cas
// avertissent toujours d'une liste incomplète, jamais de troncature muette.
//
// Annulation coopérative : si `signal` (AbortSignal) est fourni et devient
// aborted, les lectures non encore lancées sont abandonnées et le résultat est
// marqué `aborted`. Les appels réseau déjà lancés se terminent normalement mais
// leurs résultats sont ignorés par l'appelant.

import secureLogger from '../secureLogger';
import { vaultReadLimiter, withRetry } from './mapLimit';
import { isInternalSecretKey } from './passkeyEngine';

/**
 * Lit tous les secrets de tous les coffres fournis.
 *
 * @param {Object} vaultApi - Service créé par createVaultApi (listKeysV1/V2, readSecretV1/V2)
 * @param {Array<{name: string, version: number}>} engines - Coffres à lire
 * @param {Object} [options]
 * @param {AbortSignal} [options.signal] - Signal d'annulation
 * @param {Function} [options.mapSecret] - Transformation optionnelle de chaque secret (secret, engine) => objet (null = exclu)
 * @param {'high'|'low'} [options.priority='high'] - Priorité dans la file globale
 * @param {Object} [options.limiter] - File à concurrence bornée (tests ; défaut : file globale)
 * @param {number} [options.retries=2] - Relances sur erreur transitoire
 * @param {Function} [options.keyFilter] - (engine, clés listées) => clés à lire (mise à jour incrémentale)
 * @returns {Promise<{ secrets: Array, aborted: boolean, failed: number, forbidden: number,
 *   failedKeys: Array<{engine: string, key: string}>, failedEngines: Array<string>,
 *   partialEngines: Array<{engine: string, code: string, i18nKey: string, i18nVars: Object, listed: number}>,
 *   listedKeys: Object<string, Array<string>> }>} listedKeys : clés listées par coffre (listage réussi,
 *   ou partiel pour les coffres de partialEngines) ; partialEngines : coffres listés partiellement
 *   (également présents dans failedEngines)
 */
export async function readAllSecrets(vaultApi, engines, {
  signal, mapSecret, priority = 'high', limiter = vaultReadLimiter, retries = 2, keyFilter,
} = {}) {
  const isAborted = () => !!signal?.aborted;
  const { listKeysV2, listKeysV1, readSecretV2, readSecretV1 } = vaultApi;
  const failedKeys = [];
  const failedEngines = [];
  const partialEngines = [];
  const listedKeys = {};
  let forbidden = 0;

  // Une place dans la file globale par requête (ou chaîne de listage) ; relances dans la même place.
  // Tâche annulée avant son tour : aucune requête n'est envoyée.
  const queued = (fn) => limiter.run(() => (isAborted() ? null : withRetry(fn, { retries, signal })), { priority });

  const enginePromises = (engines || []).map(async (engine) => {
    if (isAborted()) return [];
    let allKeys;
    try {
      allKeys = await queued(() => (engine.version === 2 ? listKeysV2(engine) : listKeysV1(engine)));
    } catch (err) {
      if (Array.isArray(err?.partialKeys) && !isAborted()) {
        // Borne de listage atteinte (LIST_TOO_LARGE / LIST_TOO_DEEP) : liste partielle lue, coffre signalé
        secureLogger.warn('[readAllSecrets] Coffre listé partiellement');
        failedEngines.push(engine.name);
        partialEngines.push({
          engine: engine.name, code: err.code, i18nKey: err.i18nKey, i18nVars: err.i18nVars, listed: err.partialKeys.length,
        });
        allKeys = err.partialKeys;
      } else {
        const status = err?.response?.status;
        // 404 = coffre vide ; 403 = listage non autorisé : coffre ignoré (comportement historique)
        if (status !== 404 && status !== 403 && !isAborted()) failedEngines.push(engine.name);
        secureLogger.warn('[readAllSecrets] Coffre ignoré');
        return [];
      }
    }
    if (isAborted()) return [];

    // Exclure les secrets internes RDVAULT, par nom EXACT à la racine (« .rdvault-passkeys »,
    // « .rdvault-keycheck ») : COMPAT-2, même règle que le tableau (useSecrets). Une entrée utilisateur
    // « .rdvault-notes » ou « .rdvault » (permise en 1.5.0) est lue : extension, recherche, audit.
    const listed = (allKeys || []).filter(k => !isInternalSecretKey(k));
    listedKeys[engine.name] = listed;
    const keys = keyFilter ? (keyFilter(engine, listed) || []) : listed;

    const secretPromises = keys.map((key) => queued(
      () => (engine.version === 2 ? readSecretV2(engine, key) : readSecretV1(engine, key))
    ).then((secret) => {
      if (!secret) return null;
      const enriched = { ...secret, engineName: engine.name, engineVersion: engine.version };
      return mapSecret ? mapSecret(enriched, engine) : enriched;
    }).catch((err) => {
      const status = err?.response?.status;
      if (status === 404) {
        // Entrée supprimée (en douceur) mais encore listée, ou nom invalide : ignorée
        secureLogger.debug('[readAllSecrets] Secret ignoré (404)');
      } else if (status === 403) {
        forbidden++;
      } else if (!isAborted()) {
        failedKeys.push({ engine: engine.name, key });
      }
      return null;
    }));

    const secrets = await Promise.all(secretPromises);
    return secrets.filter(s => s !== null && s !== undefined);
  });

  const allEngineSecrets = await Promise.all(enginePromises);
  if (failedKeys.length || failedEngines.length) {
    secureLogger.warn('[readAllSecrets] Lectures en échec :', failedKeys.length, 'entrée(s),', failedEngines.length, 'coffre(s)');
  }
  return {
    secrets: allEngineSecrets.flat(),
    aborted: isAborted(),
    failed: failedKeys.length,
    forbidden,
    failedKeys,
    failedEngines,
    partialEngines,
    listedKeys,
  };
}
