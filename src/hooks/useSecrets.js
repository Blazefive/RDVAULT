// ========================================
// HOOK: useSecrets — CRUD des secrets Vault
// ========================================
import { useState, useCallback, useMemo, useRef } from 'react';
import axios from 'axios';
import secureLogger from '../secureLogger';
import { encodeEnginePath, sanitizeErrorMessage } from '../utils/security';
import { vaultReadLimiter, withRetry } from '../utils/mapLimit';
import { findEngineSharingTotpKey } from './useTotp';
import { isInternalSecretKey } from '../utils/passkeyEngine';
import { isolateInRtl } from '../components/admin/i18nHelpers';

// BIDI : valeurs isolées dans les toasts en RTL — nom de coffre, nom réservé (identifiants techniques) de
// gauche à droite, nom d'entrée (texte libre) dans son propre sens. Texte inchangé dans les langues LTR.
const technical = (value) => isolateInRtl(value, 'ltr');
const entryName = (value) => isolateInRtl(value, 'auto');

// Marqueurs internes de fetchSecrets (jamais placés dans l'état)
const READ_FAILED = Symbol('read-failed');
const READ_SKIPPED = Symbol('read-skipped');

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
  const setEditSecret = useCallback((value) => {
    if (typeof value === 'function') { setEditSecretState(value); return; }
    const origin = editedEntryName(value, secretsRef.current, {
      displayedRows: displayedRowsRef.current,
      shownEngineName: selectedEngineRef.current?.name || null,
    });
    editOriginRef.current = origin;
    if (!value || typeof value !== 'object') { setEditSecretState(value); return; }
    setEditSecretState(value.editOf === origin ? value : { ...value, editOf: origin });
  }, []);

  // Le coffre `engine` n'est plus celui affiché (l'utilisateur en a ouvert un autre)
  const isNotShownEngine = (engine) => !!selectedEngineRef.current && !!engine && engine.name !== selectedEngineRef.current.name;

  // includeDeleted : par défaut, la case « Afficher les supprimés » COURANTE (SECRETS-19 : les
  // rechargements sans 2e argument — tags, dossiers, restauration… — ne la perdent plus).
  const fetchSecrets = async (engine, includeDeleted = showDeletedRef.current) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi || !engine) return;
    // SECRETS-32 : rafraîchissement tardif d'un coffre qui n'est plus affiché (fin de glisser-déposer,
    // ajout de tag en recherche multi-coffre…) : ignoré, il remplacerait la liste du coffre ouvert
    // (et « Supprimer » / « Modifier » viseraient alors l'entrée homonyme de ce dernier).
    if (isNotShownEngine(engine)) return;
    const { listKeysV2, listKeysV1, readSecretV2, readSecretV1, baseHeaders, axiosConfig } = vaultApi;

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
      let allKeys;
      // Listage interrompu par une borne de vaultApi (LIST_TOO_LARGE / LIST_TOO_DEEP) : les clés déjà
      // listées (err.partialKeys) sont affichées, avec un avertissement traduit (liste incomplète),
      // au lieu d'un tableau vide. Toute autre erreur de listage : traitement inchangé (bloc catch final).
      let listLimit = null;
      try {
        allKeys = await queued(() => withRetry(() => (engine.version === 2 ? listKeysV2(engine) : listKeysV1(engine))));
      } catch (err) {
        if (!Array.isArray(err?.partialKeys)) throw err;
        listLimit = err;
        allKeys = err.partialKeys;
      }
      if (allKeys === READ_SKIPPED || isStale()) { abandon(); return; }
      // Masquer les secrets internes RDVAULT (passkeys, témoin de clé) de la liste affichée. COMPAT-2 : noms
      // réservés EXACTS ; une entrée utilisateur « .rdvault-notes » (permise en 1.5.0) reste affichée.
      const keys = allKeys.filter(k => !isInternalSecretKey(k));
      secureLogger.debug('[fetchSecrets]', engine.name, keys.length);

      // Secrets listés mais non lisibles (403) : comptés et signalés à l'utilisateur
      // au lieu d'être silencieusement ignorés (l'utilisateur croirait sinon que
      // le coffre est vide ou incomplet sans raison). 404 = entrée supprimée en douceur
      // (encore listée) : ignorée, comme avant. Toute autre erreur (réseau, délai, 5xx),
      // après relances, est comptée comme ÉCHEC et signalée.
      let forbiddenCount = 0;
      const failedKeys = [];
      const noteReadError = (err, key) => {
        const status = err?.response?.status;
        if (status === 403) forbiddenCount++;
        else if (status !== 404) failedKeys.push(key);
        return status === 403 || status === 404 ? null : READ_FAILED;
      };

      const readOne = async (key) => {
        if (engine.version === 2 && includeDeleted) {
          let metaRes;
          try {
            metaRes = await withRetry(() => axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() })));
          } catch (err) {
            return noteReadError(err, key);
          }
          const currentVersion = metaRes.data?.data?.current_version;
          const versionData = metaRes.data?.data?.versions?.[currentVersion];
          if (versionData?.deletion_time) {
            return { name: key, username: '', password: '', url: '', notes: '', deleted: true };
          }
        }
        try {
          const item = await withRetry(() => (engine.version === 2 ? readSecretV2(engine, key) : readSecretV1(engine, key)));
          return { ...item, deleted: false };
        } catch (err) {
          return noteReadError(err, key);
        }
      };

      const results = await Promise.all(keys.map(key => queued(() => readOne(key))));
      if (isStale() || results.includes(READ_SKIPPED)) { abandon(); return; }
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

      await fetchSecrets(selectedEngine);
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
        await axios.post(`${vaultUrl}/v1/${encodeEnginePath(selectedEngine.name)}/undelete/${encodeURIComponent(key)}`, { versions }, axiosConfig({ headers: baseHeaders() }));
      }
      await fetchSecrets(selectedEngine, showDeleted);
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
      await axios.post(
        `${vaultUrl}/v1/${encodeEnginePath(selectedEngine.name)}/data/${encodeURIComponent(versionHistory.secretName)}`,
        { data: { ...versionData } },
        axiosConfig({ headers: baseHeaders() })
      );

      await fetchSecrets(selectedEngine);
      syncExtensionRef.current?.();
      showToast(t('toast.versionRestored', { version }), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.restoreVersion')} ${msg}`, 'error');
    }
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
        // Rechargement selon la case « Afficher les supprimés » courante
        await fetchSecrets(selectedEngine);
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

      // Écrire d'abord : si l'écriture échoue (validation, taille…), l'ancienne entrée reste intacte
      if (selectedEngine.version === 2) await writeSecretV2(selectedEngine, updated);
      else await writeSecretV1(selectedEngine, updated);

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
      // Rechargement selon la case « Afficher les supprimés » courante
      await fetchSecrets(selectedEngine);
      syncExtensionRef.current?.();
      restoreFocus();
      if (totpAttached) showToast(t('toast.secretSavedTotpAttached'), 'warning', 6000);
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
    confirmDeleteSecret,
    deleteSecret,
    undeleteSecret,
    handleRestoreVersion,
    handleEditSecretSave,
    handleEditSecretClose,
    filteredSecrets,
  };
}
