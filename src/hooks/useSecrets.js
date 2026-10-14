// ========================================
// HOOK: useSecrets — CRUD des secrets Vault
// ========================================
import { useState, useCallback, useMemo, useRef } from 'react';
import axios from 'axios';
import secureLogger from '../secureLogger';
import { encodeEnginePath, sanitizeErrorMessage } from '../utils/security';
import { vaultReadLimiter } from '../utils/mapLimit';
import { findEngineSharingTotpKey } from './useTotp';
import { isInternalSecretKey } from '../utils/passkeyEngine';
import { isolateInRtl } from '../components/admin/i18nHelpers';
import { createEngineReadCache, readEngineEntries, READ_FAILED, READ_SKIPPED } from '../services/engineReadCache';
import { ensureVaultWriteObserver, forgetVaultWrites, trackVaultWrite } from '../services/vaultWriteLog';
import { prepareEditWrite, isCasConflict } from '../services/staleWriteGuard';

// BIDI : valeurs isolées dans les toasts en RTL — nom de coffre, nom réservé (identifiants techniques) de
// gauche à droite, nom d'entrée (texte libre) dans son propre sens. Texte inchangé dans les langues LTR.
const technical = (value) => isolateInRtl(value, 'ltr');
const entryName = (value) => isolateInRtl(value, 'auto');

// Âge maximal par défaut des listes gardées en cache par coffre avant une relecture complète (écritures
// d'autres clients d'un Vault partagé, invisibles du journal des écritures de l'application)
export const DEFAULT_ENGINE_CACHE_MAX_AGE_MS = 2 * 60 * 1000;

const sameValue = (a, b) => {
  if (a === b) return true;
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    try { return JSON.stringify(a) === JSON.stringify(b); } catch { return false; }
  }
  return false;
};

const sameSecret = (a, b) => {
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  const ka = Object.keys(a);
  if (ka.length !== Object.keys(b).length) return false;
  return ka.every(k => sameValue(a[k], b[k]));
};

// Propriétés d'affichage ajoutées aux lignes (fetchSecrets, vue arborescence, recherche multi-coffre) :
// ignorées pour reconnaître la ligne d'origine d'une fiche ouverte
const UI_ONLY_KEYS = new Set(['deleted', 'displayName', 'engineName', 'engineVersion']);

// Même contenu que la ligne (champs de la ligne seulement : l'appelant peut ajouter ses propres marqueurs)
const sameEntryData = (row, entry) => Object.keys(row)
  .filter(k => k !== 'name' && !UI_ONLY_KEYS.has(k))
  .every(k => sameValue(row[k], entry[k]));

/**
 * SECRETS-11 : nom de l'entrée EXISTANTE que modifie la fiche ouverte avec `entry`, ou null pour une
 * création (« + Nouvelle entrée » : nom vide ou dossier « a/b/ » pré-rempli, marqueur `isNew`) ou une
 * duplication (« Dupliquer » : copie d'une ligne sous un autre nom). Évalué À L'OUVERTURE de la fiche,
 * dans cet ordre :
 * 1. Marqueur explicite `editOf` (posé par l'appelant, ou par setEditSecret sur l'objet d'édition) :
 *    nom de l'entrée modifiée, ou null / '' pour une création. Le contenu n'est pas comparé : une ligne
 *    périmée (tag retiré ailleurs, liste relue entre-temps) reste une modification.
 * 2. Ligne AFFICHÉE elle-même (« Modifier » passe la ligne du tableau : vue liste, vue arborescence,
 *    résultat multi-coffres du coffre sélectionné) : modification, quel que soit son contenu. Une
 *    duplication est toujours une copie, jamais l'objet affiché.
 * 3. Sinon (copie d'une ligne), comparaison du contenu avec la ligne du coffre affiché : copie de même
 *    contenu marquée par l'affichage — `displayName` (vue arborescence, dernier segment du nom) ou
 *    `engineName` (recherche multi-coffre) — modification ; sinon création ou duplication.
 * Une ligne d'un AUTRE coffre que le coffre affiché (engineName différent) n'est jamais une modification
 * dans le coffre affiché (un renommage y supprimerait l'entrée homonyme).
 * @param {Object|null} entry - Objet passé à setEditSecret
 * @param {Array} rows - Entrées du coffre affiché
 * @param {Object} [context]
 * @param {Array} [context.displayedRows] - Lignes affichées par le tableau (filteredSecrets)
 * @param {string|null} [context.shownEngineName] - Nom du coffre affiché
 * @returns {string|null}
 */
export function editedEntryName(entry, rows, { displayedRows = null, shownEngineName = null } = {}) {
  if (!entry || typeof entry !== 'object' || entry.isNew) return null;
  const foreign = typeof entry.engineName === 'string' && entry.engineName !== ''
    && !!shownEngineName && entry.engineName !== shownEngineName;
  if (Object.prototype.hasOwnProperty.call(entry, 'editOf')) {
    const origin = entry.editOf;
    if (typeof origin !== 'string' || !origin || origin.endsWith('/') || foreign) return null;
    return origin;
  }
  const name = typeof entry.name === 'string' ? entry.name : '';
  if (!name || name.endsWith('/') || foreign || entry.isFolder) return null;
  if (Array.isArray(displayedRows) && displayedRows.includes(entry)) return name; // ligne affichée
  const row = (rows || []).find(s => s && s.name === name && !s.isFolder);
  if (!row) return null;
  if (row === entry) return name;              // « Modifier » en vue liste : la ligne elle-même
  if (!sameEntryData(row, entry)) return null; // contenu d'une autre entrée : duplication
  // Copie de même contenu : ligne de la vue arborescence ou résultat multi-coffre → modification.
  // Une copie « Dupliquer » (vue liste, sans ces marqueurs, ou displayName de l'entrée d'origine)
  // reste une création, même si l'entrée visée a le même contenu.
  if (typeof entry.displayName === 'string') return entry.displayName === name.split('/').pop() ? name : null;
  return entry.engineName ? name : null;
}

/**
 * PERFORMANCE : après un rafraîchissement, réutilise l'objet déjà affiché de chaque
 * entrée dont le contenu n'a pas changé. Les lignes mémoïsées du tableau ne se
 * re-rendent alors que pour les entrées réellement modifiées (et la liste entière
 * est conservée telle quelle si rien n'a changé).
 * @param {Array} prev - Liste affichée
 * @param {Array} next - Liste relue
 * @returns {Array}
 */
export function reuseUnchangedSecrets(prev, next) {
  if (!Array.isArray(prev) || prev.length === 0 || !Array.isArray(next)) return next;
  const byName = new Map();
  for (const p of prev) if (p && typeof p.name === 'string') byName.set(p.name, p);
  let identical = prev.length === next.length;
  const out = next.map((n, i) => {
    const p = n && byName.get(n.name);
    const kept = p && sameSecret(p, n) ? p : n;
    if (kept !== prev[i]) identical = false;
    return kept;
  });
  return identical ? prev : out;
}

export function useSecrets(options) {
  const {
    vaultApiRef,
    vaultUrl,
    selectedEngine,
    search,
    showDeleted,
    // État `secrets` détenu par App.jsx (permet d'appeler useTreeView(secrets)
    // AVANT useSecrets et de passer les valeurs de la vue arborescence en clair)
    secrets, setSecrets,
    treeViewEnabled = false, currentPath = '', currentFolderContent = null,
    multiVaultSearch, allVaultSecrets,
    mergeDiscoveredAndSharedTagsRef,
    setDiscoveredTags,
    syncExtensionRef,
    restoreFocus,
    // TOTP
    getTotpKeyName, checkTotpExists, totpEngineName,
    showToast, t,
    // Âge maximal du cache par coffre (App : plus long en mode local, seul écrivain du coffre)
    cacheMaxAgeMs = DEFAULT_ENGINE_CACHE_MAX_AGE_MS,
  } = options;

  const [editSecret, setEditSecretState] = useState(null);
  const [secretToDelete, setSecretToDelete] = useState(null);
  const [deletingSecret, setDeletingSecret] = useState(false);
  const [loadingSecrets, setLoadingSecrets] = useState(false);
  const [versionHistory, setVersionHistory] = useState(null);
  const [loadingAllSecrets, setLoadingAllSecrets] = useState(false);

  // Lecture en cours : une lecture plus récente (autre coffre, rafraîchissement, nouvelle session)
  // rend la précédente caduque — ses requêtes non encore lancées sont abandonnées et son résultat
  // ignoré (il ne peut plus écraser la liste d'un autre coffre affiché entre-temps).
  const fetchGenRef = useRef(0);
  // Coffre dont les lignes sont affichées (session + nom) : rafraîchir CE coffre (après une
  // écriture) garde le tableau affiché au lieu de le remplacer par le spinner puis de remonter
  // toutes les lignes (perte du défilement, plus d'une seconde à 5 000 entrées).
  const loadedRef = useRef({ api: null, engine: null });

  // Valeurs COURANTES (lues par les callbacks déjà capturés : opérations longues, useTags…)
  const showDeletedRef = useRef(showDeleted);
  showDeletedRef.current = showDeleted;
  const selectedEngineRef = useRef(selectedEngine);
  selectedEngineRef.current = selectedEngine;
  const secretsRef = useRef(secrets);
  secretsRef.current = secrets;

  // Lignes affichées par le tableau (filteredSecrets, mis à jour à chaque rendu plus bas)
  const displayedRowsRef = useRef([]);

  // SECRETS-11 : entrée existante modifiée par la fiche ouverte (null = création / duplication),
  // déterminée à l'ouverture (la liste peut être rafraîchie pendant la saisie). La décision est portée
  // par l'objet d'édition lui-même (marqueur `editOf`, ajouté sur une copie si l'appelant ne l'a pas
  // fourni) : la fiche rouverte avec cet objet reste une modification (ou une création), sans dépendre
  // du contenu de la liste.
  const editOriginRef = useRef(null);
  // Contenu de l'entrée existante À L'OUVERTURE de la fiche (ligne affichée, éventuellement gardée en cache) :
  // comparé au contenu courant avant l'enregistrement (staleWriteGuard) — une version écrite entre-temps par
  // un autre client n'est jamais remplacée par cette ligne périmée.
  const editBaseRef = useRef(null);
  const setEditSecret = useCallback((value) => {
    if (typeof value === 'function') { setEditSecretState(value); return; }
    const origin = editedEntryName(value, secretsRef.current, {
      displayedRows: displayedRowsRef.current,
      shownEngineName: selectedEngineRef.current?.name || null,
    });
    editOriginRef.current = origin;
    editBaseRef.current = origin && value && typeof value === 'object' ? value : null;
    if (!value || typeof value !== 'object') { setEditSecretState(value); return; }
    setEditSecretState(value.editOf === origin ? value : { ...value, editOf: origin });
  }, []);

  // Le coffre `engine` n'est plus celui affiché (l'utilisateur en a ouvert un autre)
  const isNotShownEngine = (engine) => !!selectedEngineRef.current && !!engine && engine.name !== selectedEngineRef.current.name;

  // PERFORMANCE : listes gardées par coffre (services/engineReadCache.js) — une écriture, un changement de
  // coffre, « Afficher les supprimés » ou la recherche multi-coffres ne relisent plus que les entrées
  // nouvelles, écrites ou dont l'état manque. Cache lié au service Vault (APP-3 : vidé dès qu'un autre
  // jeton est en service, rien ne passe d'une session à l'autre).
  const readCacheRef = useRef(null);
  if (!readCacheRef.current) readCacheRef.current = createEngineReadCache();
  const readCache = readCacheRef.current;
  ensureVaultWriteObserver();
  if (readCache.api && readCache.api !== vaultApiRef.current) {
    // Fin de session (déconnexion, expiration, autre utilisateur) : entrées en mémoire libérées,
    // noms d'entrées écrites oubliés
    readCache.clear();
    forgetVaultWrites();
  }

  /**
   * Relit la liste du coffre `engine` (coffre affiché).
   * includeDeleted : par défaut, la case « Afficher les supprimés » COURANTE (SECRETS-19 : les
   * rechargements sans 2e argument — tags, dossiers, restauration… — ne la perdent plus).
   * options.incremental : réutilise la liste gardée en cache pour ce coffre — seules les entrées
   *   nouvelles, écrites depuis (journal des écritures + options.touched) ou dont l'état manque sont lues ;
   *   sans cette option, toutes les entrées sont relues (le cache est alors renouvelé).
   * options.touched : noms des entrées que l'appelant vient d'écrire (relues dans tous les cas).
   * options.revalidate : bascule « Afficher les supprimés » — coffre local (lecture groupée) : tout est
   *   relu par lots, pour refléter une suppression faite hors de cette fenêtre (voir engineReadCache).
   */
  const fetchSecrets = async (engine, includeDeleted = showDeletedRef.current, { incremental = false, touched = null, revalidate = false } = {}) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi || !engine) return;
    // SECRETS-32 : rafraîchissement tardif d'un coffre qui n'est plus affiché (fin de glisser-déposer,
    // ajout de tag en recherche multi-coffre…) : ignoré, il remplacerait la liste du coffre ouvert
    // (et « Supprimer » / « Modifier » viseraient alors l'entrée homonyme de ce dernier).
    if (isNotShownEngine(engine)) {
      // Écritures déjà notées dans le journal : la liste gardée de ce coffre sera relue en conséquence
      return;
    }

    const gen = ++fetchGenRef.current;
    const isStale = () => gen !== fetchGenRef.current || vaultApiRef.current !== vaultApi || isNotShownEngine(engine);
    // Lecture caduque : si aucune lecture plus récente n'a pris le relais (fin de session),
    // l'indicateur de chargement est retiré ; sinon c'est la plus récente qui le gère.
    const abandon = () => { if (gen === fetchGenRef.current) setLoadingSecrets(false); };
    const refreshOfShownEngine = loadedRef.current.api === vaultApi && loadedRef.current.engine === engine.name;
    // Nouvelle synchro de l'extension pour ce coffre (cache incrémental de useSync)
    const pushToExtension = (list, failedKeys = [], listedKeys = []) => {
      try {
        syncExtensionRef?.current?.({ engine, secrets: list.filter(s => !s.deleted), failedKeys, listedKeys, api: vaultApi });
      } catch { /* synchro best effort */ }
    };

    if (!refreshOfShownEngine) setLoadingSecrets(true);
    try {
      // PERFORMANCE / FIABILITÉ : toutes les requêtes passent par la file globale bornée
      // (au plus ~24 en vol, tous lecteurs confondus) : sans cela Chromium refusait les
      // requêtes au-delà de ~2 700 en vol et des entrées disparaissaient sans avertissement.
      // Priorité haute : le tableau passe avant les lectures de fond (synchro extension).
      const queued = (fn) => vaultReadLimiter.run(() => (isStale() ? READ_SKIPPED : fn()), { priority: 'high' });
      readCache.bind(vaultApi);
      // Listage (toujours) puis lecture des seules entrées nécessaires (services/engineReadCache.js).
      // Listage interrompu par une borne de vaultApi (LIST_TOO_LARGE / LIST_TOO_DEEP) : les clés déjà
      // listées (listLimit.partialKeys) sont affichées, avec un avertissement traduit (liste incomplète),
      // au lieu d'un tableau vide. Toute autre erreur de listage : traitement inchangé (bloc catch final).
      // Secrets internes RDVAULT (passkeys, témoin de clé) masqués — COMPAT-2 : noms réservés EXACTS ; une
      // entrée utilisateur « .rdvault-notes » (permise en 1.5.0) reste affichée.
      // Secrets listés mais non lisibles (403) : comptés et signalés à l'utilisateur au lieu d'être
      // silencieusement ignorés. 404 = entrée supprimée en douceur (encore listée) : ignorée, comme avant.
      // Toute autre erreur (réseau, délai, 5xx, intégrité), après relances, est comptée comme ÉCHEC et signalée.
      const read = await readEngineEntries(vaultApi, engine, {
        vaultUrl,
        includeDeleted,
        previous: incremental ? readCache.get(vaultApi, engine) : null,
        touched,
        revalidate,
        maxAgeMs: cacheMaxAgeMs,
        run: queued,
        isStale,
      });
      if (read.stale || isStale()) { abandon(); return; }
      if (read.listError) throw read.listError;
      const { keys, results, listLimit, forbiddenCount, failedKeys } = read;
      readCache.set(vaultApi, engine, read.entry);
      secureLogger.debug('[fetchSecrets]', engine.name, keys.length, 'lectures :', read.reads);
      const all = results.filter(s => s !== null && s !== READ_FAILED);
      secureLogger.debug('[fetchSecrets]', results.length, 'valid:', all.length, 'forbidden:', forbiddenCount, 'failed:', failedKeys.length);

      if (listLimit) {
        // Liste partielle : avertissement prioritaire (un seul toast à la fois), lectures en échec ajoutées
        secureLogger.warn('[fetchSecrets] Liste partielle :', keys.length);
        const partialKey = listLimit.code === 'LIST_TOO_DEEP' ? 'error.listTooDeepPartial' : 'error.listTooLargePartial';
        const max = Number(listLimit.i18nVars?.max) || 0;
        let message = t(partialKey, { max, count: keys.length });
        if (failedKeys.length > 0) message += ` ${t('error.secretsUnreadable', { count: failedKeys.length })}`;
        showToast(message, 'warning', 10000);
      } else if (failedKeys.length > 0) {
        secureLogger.warn('[fetchSecrets] Entrées non lues :', failedKeys.length);
        showToast(t('error.secretsUnreadable', { count: failedKeys.length }), 'warning', 6000);
      } else if (forbiddenCount > 0) {
        showToast(t('error.secretsForbidden', { count: forbiddenCount }), 'warning', 4000);
      }

      // Extraire les tags découverts depuis les secrets + tags partagés
      const mergeFn = mergeDiscoveredAndSharedTagsRef.current;
      if (mergeFn) {
        const tags = await mergeFn(all);
        if (isStale()) { abandon(); return; }
        secureLogger.debug('[fetchSecrets] tags:', tags.length);
        setDiscoveredTags(tags);
      }

      setSecrets(prev => {
        // Rafraîchissement du coffre affiché : une entrée momentanément illisible garde sa
        // ligne actuelle (signalée par le toast) au lieu de disparaître.
        if (!refreshOfShownEngine || failedKeys.length === 0) return reuseUnchangedSecrets(prev, all);
        const prevByName = new Map((prev || []).map(s => [s.name, s]));
        const merged = [];
        results.forEach((r, i) => {
          if (r === READ_FAILED) {
            const old = prevByName.get(keys[i]);
            if (old) merged.push(old);
          } else if (r !== null) {
            merged.push(r);
          }
        });
        return reuseUnchangedSecrets(prev, merged);
      });
      loadedRef.current = { api: vaultApi, engine: engine.name };
      setLoadingSecrets(false);
      pushToExtension(all, failedKeys, keys);
    } catch (err) {
      if (isStale()) { abandon(); return; }
      readCache.drop(engine.name);
      loadedRef.current = { api: null, engine: null };
      setLoadingSecrets(false);
      if (err.response?.status === 403) {
        setSecrets([]);
        showToast(t('error.noReadAccess'), 'error', 3500);
      } else if (err.response?.status === 404) {
        setSecrets([]);
        pushToExtension([]); // coffre vide (Vault répond 404 au listage)
      } else {
        setSecrets([]);
        showToast(`${t('error.engineList')} : ${sanitizeErrorMessage(err)}`, 'error', 3500);
      }
    }
  };

  /**
   * Recherche multi-coffres et rechargements qui en dépendent : entrées vivantes de plusieurs coffres, en
   * réutilisant les listes gardées en cache (seules les entrées nouvelles ou écrites depuis sont lues ;
   * les coffres lus ici alimentent aussi le cache, un changement de coffre ensuite ne relit rien).
   * Résultat au format de readAllSecrets (utils/readAllSecrets.js) : lignes enrichies de engineName /
   * engineVersion, échecs comptés (failedKeys, failedEngines), listes partielles (partialEngines,
   * également dans failedEngines), refus (forbidden), annulation (aborted).
   * @param {Array<{ name: string, version: number }>} engines
   * @param {{ signal?: AbortSignal, priority?: 'high'|'low' }} [opts]
   */
  const readEnginesWithCache = async (engines, { signal, priority = 'high' } = {}) => {
    const vaultApi = vaultApiRef.current;
    const failedKeys = [];
    const failedEngines = [];
    const partialEngines = [];
    const listedKeys = {};
    let forbidden = 0;
    if (!vaultApi) {
      return { secrets: [], aborted: true, failed: 0, forbidden: 0, failedKeys, failedEngines, partialEngines, listedKeys };
    }
    readCache.bind(vaultApi);
    // Annulée (recherche fermée, coffres changés) ou session terminée : lectures non lancées abandonnées
    const isStale = () => !!signal?.aborted || vaultApiRef.current !== vaultApi;
    const run = (fn) => vaultReadLimiter.run(() => (isStale() ? READ_SKIPPED : fn()), { priority });
    const perEngine = await Promise.all((engines || []).map(async (engine) => {
      if (!engine || isStale()) return [];
      const read = await readEngineEntries(vaultApi, engine, {
        vaultUrl, includeDeleted: false, previous: readCache.get(vaultApi, engine), maxAgeMs: cacheMaxAgeMs, run, isStale,
      });
      if (read.stale || isStale()) return [];
      if (read.listError) {
        // 404 = coffre vide ; 403 = listage non autorisé : coffre ignoré (comportement historique)
        const status = read.listError?.response?.status;
        if (status !== 404 && status !== 403) failedEngines.push(engine.name);
        readCache.drop(engine.name);
        return [];
      }
      readCache.set(vaultApi, engine, read.entry);
      if (read.listLimit) {
        failedEngines.push(engine.name);
        partialEngines.push({
          engine: engine.name, code: read.listLimit.code, i18nKey: read.listLimit.i18nKey,
          i18nVars: read.listLimit.i18nVars, listed: (read.listLimit.partialKeys || []).length,
        });
      }
      listedKeys[engine.name] = read.keys;
      forbidden += read.forbiddenCount;
      for (const key of read.failedKeys) failedKeys.push({ engine: engine.name, key });
      return read.results
        .filter(r => r && r !== READ_FAILED && !r.deleted)
        .map(({ deleted, ...row }) => ({ ...row, engineName: engine.name, engineVersion: engine.version }));
    }));
    return {
      secrets: perEngine.flat(),
      aborted: isStale(),
      failed: failedKeys.length,
      forbidden,
      failedKeys,
      failedEngines,
      partialEngines,
      listedKeys,
    };
  };

  /**
   * Listes gardées de ces coffres oubliées : relues entièrement à la prochaine lecture (écritures faites
   * hors des chemins suivis, ex. import des Paramètres — APP-6).
   * @param {string[]} engineNames
   */
  const invalidateEngines = (engineNames) => {
    for (const name of engineNames || []) readCache.drop(name);
  };

  // Relecture du coffre affiché après une écriture de l'application : seules les entrées touchées
  // (et celles notées dans le journal des écritures) sont relues
  const refreshAfterWrite = (engine, touched) => fetchSecrets(engine, undefined, { incremental: true, touched });

  const confirmDeleteSecret = async (secret) => {
    const totpKeyName = getTotpKeyName(secret.name);
    const totpExists = await checkTotpExists(totpKeyName);
    setSecretToDelete({ ...secret, totpExists });
  };

  const deleteSecret = async () => {
    if (!secretToDelete || !selectedEngine) return;
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { deleteSecretV2, deleteSecretV1, baseHeaders, axiosConfig } = vaultApi;

    const key = secretToDelete.name;
    try {
      setDeletingSecret(true);

      // KV v2 : suppression DOUCE (restaurable) ; KV v1 : DELETE définitif, sans historique
      const definitive = selectedEngine.version !== 2;
      if (selectedEngine.version === 2) await deleteSecretV2(selectedEngine, key);
      else await deleteSecretV1(selectedEngine, key);

      // Graine TOTP de l'entrée (SECRETS-33) : non relisible, donc non sauvegardable. Elle n'est
      // JAMAIS détruite par une suppression restaurable (« Restaurer » rend l'entrée avec son 2FA).
      // Seulement lors d'une suppression définitive (KV v1), sur demande explicite de l'utilisateur
      // (secretToDelete.deleteTotp, case de la boîte de confirmation) et si aucune entrée d'un autre
      // coffre ne revendique la même clé (nommage non injectif, cf. useTotp) ; dans le doute
      // (inventaire impossible), elle est conservée : jamais de perte de graine 2FA.
      let totpOutcome = null; // 'kept' | 'orphan' | { engine } | 'unverified' | 'deleted'
      if (secretToDelete.totpExists) {
        if (!definitive) totpOutcome = 'kept';
        else if (secretToDelete.deleteTotp !== true) totpOutcome = 'orphan';
        else {
          try {
            const sharedWith = await findEngineSharingTotpKey(vaultApi, selectedEngine, key);
            if (sharedWith) totpOutcome = { engine: sharedWith };
          } catch {
            totpOutcome = 'unverified';
          }
          if (!totpOutcome) {
            try {
              const totpKeyName = getTotpKeyName(key);
              await axios.delete(`${vaultUrl}/v1/${totpEngineName}/keys/${encodeURIComponent(totpKeyName)}`, axiosConfig({ headers: baseHeaders() }));
              totpOutcome = 'deleted';
            } catch (totpErr) { /* clé déjà absente ou refusée : l'entrée reste supprimée */ }
          }
        }
      }

      setSecrets(prev => prev.filter(s => s.name !== key));
      setSecretToDelete(null);

      if (selectedEngine.version === 1) await new Promise(r => setTimeout(r, 300));

      await refreshAfterWrite(selectedEngine, [key]);
      syncExtensionRef.current?.();
      restoreFocus();
      if (totpOutcome === 'kept') showToast(t('toast.secretDeletedTotpKept', { action: t('contextMenu.restore') }), 'success', 6000);
      else if (totpOutcome === 'orphan') showToast(t('toast.secretDeletedTotpKeptOrphan'), 'warning', 6000);
      else if (totpOutcome?.engine) showToast(t('toast.totpKeptShared', { engine: technical(totpOutcome.engine) }), 'warning', 6000);
      else if (totpOutcome === 'unverified') showToast(t('toast.totpKeptUnverified'), 'warning', 6000);
      else showToast(t('toast.secretDeleted'), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.deleteSecret')} ${msg}`, 'error');
    } finally {
      setDeletingSecret(false);
    }
  };

  const undeleteSecret = async (secret) => {
    if (!selectedEngine || selectedEngine.version !== 2) return;
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { baseHeaders, axiosConfig } = vaultApi;

    const key = secret.name;
    try {
      const metaRes = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(selectedEngine.name)}/metadata/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
      const versions = Object.keys(metaRes.data?.data?.versions || {}).map(Number);

      if (versions.length > 0) {
        const undeleteUrl = `${vaultUrl}/v1/${encodeEnginePath(selectedEngine.name)}/undelete/${encodeURIComponent(key)}`;
        await trackVaultWrite('post', undeleteUrl, () => axios.post(undeleteUrl, { versions }, axiosConfig({ headers: baseHeaders() })));
      }
      await fetchSecrets(selectedEngine, showDeleted, { incremental: true, touched: [key] });
      syncExtensionRef.current?.();
      showToast(t('toast.secretRestored', { version: entryName(key) }), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.retrieveSecret')} ${msg}`, 'error');
    }
  };

  const handleRestoreVersion = async (version, versionData) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { baseHeaders, axiosConfig } = vaultApi;

    try {
      if (!selectedEngine || selectedEngine.version !== 2 || !versionHistory) return;
      if (!versionData || typeof versionData !== 'object' || Array.isArray(versionData)) {
        throw new Error('Version invalide');
      }

      // Restaurer = réécrire la version telle qu'elle a été stockée (objet brut lu par
      // VersionHistoryModal) : tags, champs personnalisés, pièces jointes, type d'entrée (SSH…)
      // et tout champ inconnu sont conservés. Ces données viennent du coffre lui-même : pas de
      // re-mappage par writeSecretV2, qui n'en garderait qu'une partie.
      const restoreUrl = `${vaultUrl}/v1/${encodeEnginePath(selectedEngine.name)}/data/${encodeURIComponent(versionHistory.secretName)}`;
      await trackVaultWrite('post', restoreUrl, () => axios.post(
        restoreUrl,
        { data: { ...versionData } },
        axiosConfig({ headers: baseHeaders() })
      ));

      await refreshAfterWrite(selectedEngine, [versionHistory.secretName]);
      syncExtensionRef.current?.();
      showToast(t('toast.versionRestored', { version }), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.restoreVersion')} ${msg}`, 'error');
    }
  };

  // Entrée modifiée ou supprimée par un autre client depuis l'ouverture de la fiche : rien n'a été écrit.
  // Avertissement, puis relecture de l'entrée (la fiche rouverte part de la version actuelle).
  const notifyChangedElsewhere = async (name) => {
    restoreFocus();
    showToast(t('error.secretChangedElsewhere', { name: entryName(name) }), 'error', 8000);
    try {
      await refreshAfterWrite(selectedEngine, [name]);
    } catch { /* relecture best effort */ }
  };

  const handleEditSecretSave = useCallback(async (updated) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { writeSecretV2, writeSecretV1, deleteSecretV2, deleteSecretV1 } = vaultApi;

    try {
      if (!selectedEngine) throw new Error('Aucun moteur sélectionné');
      if (!updated.name || !updated.name.trim()) { showToast(t('error.nameRequired'), 'error'); return; }

      // Création de dossier via .placeholder
      if (updated.entryType === 'folder') {
        const folderName = updated.name.trim().replace(/\/+$/, '');
        const placeholderPath = (treeViewEnabled && currentPath ? `${currentPath}/` : '') + folderName + '/.placeholder';
        const placeholderEntry = {
          name: placeholderPath,
          username: '', password: '', url: '', website: '', notes: '', tags: '',
          entryType: 'placeholder'
        };
        if (selectedEngine.version === 2) await writeSecretV2(selectedEngine, placeholderEntry);
        else await writeSecretV1(selectedEngine, placeholderEntry);
        setEditSecret(null);
        // Rechargement selon la case « Afficher les supprimés » courante (entrée écrite seule relue)
        await refreshAfterWrite(selectedEngine, [placeholderPath]);
        syncExtensionRef.current?.();
        restoreFocus();
        showToast(t('toast.folderCreated'), 'success');
        return;
      }

      if (!updated.website) updated.website = '';

      // Entrée existante modifiée par la fiche (null = « + Nouvelle entrée » ou « Dupliquer »)
      const originName = editOriginRef.current;
      const isRename = !!originName && originName !== updated.name;
      const isCreate = !originName;

      // Renommage : le TOTP verrouille le nom (la clé dépend du nom de l'entrée)
      if (isRename) {
        const totpKeyName = getTotpKeyName(originName);
        const hasTot = await checkTotpExists(totpKeyName);
        if (hasTot) {
          showToast(t('error.totpLocksRename'), 'error');
          return;
        }
      }
      // COMPAT-2 : nom réservé exact (stockage des passkeys, témoin de clé) refusé à la création et au
      // renommage : l'entrée serait masquée du tableau puis réécrite par RDVAULT (comme l'import le refuse)
      if ((isRename || isCreate) && isInternalSecretKey(updated.name)) {
        showToast(t('error.secretNameReserved', { name: technical(updated.name) }), 'error');
        return;
      }
      // Renommage, création et duplication (SECRETS-11) : ne jamais écraser une autre entrée
      // visible (une entrée supprimée peut être réutilisée : son historique reste consultable).
      // État invérifiable (403…) : comportement antérieur.
      if (isRename || isCreate) {
        const targetStatus = vaultApi.secretStatus ? await vaultApi.secretStatus(selectedEngine, updated.name) : 'unknown';
        if (targetStatus === 'live') {
          showToast(t('error.secretNameExists', { name: entryName(updated.name) }), 'error');
          return;
        }
      }

      // Vault partagé : l'entrée modifiée (ou renommée) a pu être changée par un autre client depuis
      // l'ouverture de la fiche (ligne affichée gardée en cache jusqu'à 2 min). Contenu courant relu : les
      // champs changés dans la fiche lui sont appliqués, les autres gardent leur valeur COURANTE (jamais la
      // valeur périmée de la fiche) ; écriture en check-and-set sur la version relue. Entrée supprimée
      // ailleurs, ou écrite entre la relecture et l'écriture : rien n'est écrit, utilisateur averti, ligne
      // relue ; la fiche reste ouverte (saisie conservée).
      let toWrite = updated;
      let cas;
      let merged = false;
      if (originName) {
        const prepared = await prepareEditWrite(vaultApi, selectedEngine, originName, editBaseRef.current, updated);
        if (!prepared.ok) {
          await notifyChangedElsewhere(originName);
          return;
        }
        toWrite = prepared.entry;
        merged = prepared.merged;
        // Modification sur place (KV v2) : écriture conditionnelle à la version relue
        if (!isRename) cas = prepared.cas;
      }

      // Écrire d'abord : si l'écriture échoue (validation, taille…), l'ancienne entrée reste intacte
      try {
        if (selectedEngine.version === 2) await writeSecretV2(selectedEngine, toWrite, cas !== undefined ? { cas } : undefined);
        else await writeSecretV1(selectedEngine, toWrite);
      } catch (writeErr) {
        // Version écrite ailleurs entre la relecture et l'écriture : refusée par Vault, rien n'est écrit
        if (isCasConflict(writeErr)) {
          await notifyChangedElsewhere(originName || updated.name);
          return;
        }
        throw writeErr;
      }

      // Puis supprimer l'ancien nom (suppression douce en KV v2) ; un échec ici laisse deux
      // entrées identiques, jamais zéro. Jamais pour une création (nom pré-rempli « dossier/ »).
      if (isRename) {
        try {
          if (selectedEngine.version === 2) {
            await deleteSecretV2(selectedEngine, originName);
          } else {
            await deleteSecretV1(selectedEngine, originName);
          }
        } catch (err) {
          secureLogger.debug('[Vault] Erreur suppression ancienne entrée');
        }
      }

      // Nouveau nom dont la clé TOTP existe déjà (conservée lors de la suppression d'une entrée
      // homonyme, SECRETS-33) : elle s'y rattache, l'utilisateur en est averti.
      const totpAttached = (isCreate || isRename) ? await checkTotpExists(getTotpKeyName(updated.name)) : false;

      setEditSecret(null);
      // Rechargement selon la case « Afficher les supprimés » courante : seules l'entrée écrite et,
      // pour un renommage, l'ancien nom sont relus (avant : tout le coffre, ≈ 1 240 requêtes à 1 200 entrées)
      await refreshAfterWrite(selectedEngine, isRename ? [updated.name, originName] : [updated.name]);
      syncExtensionRef.current?.();
      restoreFocus();
      if (totpAttached) showToast(t('toast.secretSavedTotpAttached'), 'warning', 6000);
      else if (merged) showToast(t('toast.secretSavedMerged'), 'success', 8000);
      else showToast(t('toast.secretSaved'), 'success');
    } catch (err) {
      restoreFocus();
      let msg = sanitizeErrorMessage(err, undefined, t);

      // Écriture refusée par le serveur : entrée trop volumineuse (413), ou très probablement
      // (500 : comportement historique de certains serveurs) — message traduit
      if (err.response?.status === 413 || err.response?.status === 500) {
        msg = t('error.secretTooLarge');
      }

      showToast(`${t('error.saveSecret')} ${msg}`, 'error');
    }
  }, [selectedEngine, editSecret, showDeleted, treeViewEnabled, currentPath]); // eslint-disable-line

  const handleEditSecretClose = useCallback(() => {
    setEditSecret(null);
    restoreFocus();
  }, []); // eslint-disable-line

  // Mémoiser le filtrage du tableau (hot path).
  // Les valeurs de la vue arborescence sont des dépendances explicites : un
  // changement de dossier courant ou de mode d'affichage recalcule le filtrage.
  const filteredSecrets = useMemo(() => {
    const rawSourceSecrets = multiVaultSearch && search.trim()
      ? allVaultSecrets
      : (treeViewEnabled && !multiVaultSearch
          ? (search.trim()
              ? secrets
                  .filter(s => !currentPath || s.name.startsWith(currentPath + '/'))
                  .map(s => ({ ...s, displayName: s.name.split('/').pop() }))
              : (currentFolderContent || []))
          : secrets);
    const sourceSecrets = rawSourceSecrets.filter(s => !s.name?.endsWith('/.placeholder') && s.name !== '.placeholder');
    const filtered = sourceSecrets.filter(s => {
      const searchRaw = search.trim();
      if (!searchRaw) return true;

      const searchTags = [];
      const textParts = [];
      for (const part of searchRaw.split(/\s+/)) {
        if (part.startsWith('#') && part.length > 1) {
          searchTags.push(part.slice(1).toLowerCase());
        } else {
          textParts.push(part);
        }
      }
      const textQuery = textParts.join(' ').toLowerCase();

      if (searchTags.length > 0) {
        const secretTags = s.tags ? s.tags.toLowerCase().split(/[\s,;]+/).filter(t => t) : [];
        const allTagsMatch = searchTags.every(tag => secretTags.some(st => st.includes(tag)));
        if (!allTagsMatch) return false;
        if (!textQuery) return true;
      }

      if (s.isFolder) {
        return s.displayName.toLowerCase().includes(textQuery) ||
               s.name.toLowerCase().includes(textQuery);
      }

      const searchName = treeViewEnabled && s.name.includes('/')
        ? s.name.split('/').pop()
        : s.name;

      const matchesStandard =
        searchName.toLowerCase().includes(textQuery) ||
        (s.username && s.username.toLowerCase().includes(textQuery)) ||
        (s.notes && s.notes.toLowerCase().includes(textQuery)) ||
        (s.url && s.url.toLowerCase().includes(textQuery)) ||
        false;

      const matchesCustomFields = s.customFields && Array.isArray(s.customFields) && s.customFields.some(
        field => field.value && !field.protected && String(field.value).toLowerCase().includes(textQuery)
      );

      return matchesStandard || matchesCustomFields;
    });

    return filtered;
  }, [multiVaultSearch, search, allVaultSecrets, secrets, treeViewEnabled, currentPath, currentFolderContent]);
  displayedRowsRef.current = filteredSecrets;

  return {
    editSecret, setEditSecret,
    secretToDelete, setSecretToDelete,
    deletingSecret,
    loadingSecrets, setLoadingSecrets,
    versionHistory, setVersionHistory,
    loadingAllSecrets, setLoadingAllSecrets,
    fetchSecrets,
    readEnginesWithCache,
    invalidateEngines,
    confirmDeleteSecret,
    deleteSecret,
    undeleteSecret,
    handleRestoreVersion,
    handleEditSecretSave,
    handleEditSecretClose,
    filteredSecrets,
  };
}
