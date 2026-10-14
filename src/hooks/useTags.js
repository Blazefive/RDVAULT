import { useState, useRef } from 'react';
import axios from 'axios';
import secureLogger from '../secureLogger';
import { sanitizeErrorMessage } from '../utils/security';
import { readAllSecrets } from '../utils/readAllSecrets';
import { readCurrentEntry, isCasConflict } from '../services/staleWriteGuard';
import { isolateInRtl } from '../components/admin/i18nHelpers';

// Écritures vers tags-shared (secret des tags ou création du montage), toutes origines confondues
// (AdminPanel passe par tagManager) : observées via un intercepteur axios pour invalider le cache
// d'absence ci-dessous dès la première écriture.
let sharedTagsWriteSeq = 0;
try {
  axios.interceptors?.request?.use?.((config) => {
    const method = String(config?.method || 'get').toLowerCase();
    if (method !== 'get' && /\/v1\/(sys\/mounts\/)?tags-shared(\/|$)/.test(String(config?.url || ''))) {
      sharedTagsWriteSeq++;
    }
    return config;
  });
} catch { /* axios simulé sans intercepteurs (tests) */ }

/**
 * Coffres listés PARTIELLEMENT par une lecture readAllSecrets (borne LIST_TOO_LARGE / LIST_TOO_DEEP,
 * `partialEngines`) : messages traduits précis (borne et nombre d'entrées lues), sans doublon.
 * @param {Object} result - Résultat de readAllSecrets
 * @param {Function} t - Traduction
 * @returns {string[]}
 */
export function partialListMessages(result, t) {
  const partial = Array.isArray(result?.partialEngines) ? result.partialEngines : [];
  return Array.from(new Set(partial.map(p => t(p?.code === 'LIST_TOO_DEEP' ? 'error.listTooDeepPartial' : 'error.listTooLargePartial', {
    max: Number(p?.i18nVars?.max) || 0,
    count: Number(p?.listed) || 0,
  }))));
}

/**
 * Entrées ou coffres illisibles (réseau, délai, 5xx après relances) d'une lecture readAllSecrets, hors
 * coffres listés partiellement (présents aussi dans `failedEngines`, signalés par partialListMessages).
 * @param {Object} result - Résultat de readAllSecrets
 * @returns {number}
 */
export function unreadableCount(result) {
  const partial = Array.isArray(result?.partialEngines) ? result.partialEngines.length : 0;
  return (Number(result?.failed) || 0) + Math.max(0, (result?.failedEngines?.length || 0) - partial);
}

/**
 * Lecture multi-coffres incomplète : message traduit, ou null si elle est complète. Liste tronquée par une
 * borne : message précis (error.listTooLargePartial / error.listTooDeepPartial) au lieu de
 * error.secretsUnreadable, qui attribue l'incomplétude à une erreur réseau ; autres échecs ajoutés à la suite.
 * @param {Object} result - Résultat de readAllSecrets
 * @param {Function} t - Traduction
 * @returns {string|null}
 */
export function incompleteReadMessage(result, t) {
  const parts = partialListMessages(result, t);
  const unreadable = unreadableCount(result);
  if (unreadable > 0) parts.push(t('error.secretsUnreadable', { count: unreadable }));
  return parts.length ? parts.join(' ') : null;
}

/**
 * Hook de gestion des tags (decouverte, ajout, suppression, couleurs).
 *
 * @param {Object} options
 * @param {string} options.vaultUrl - URL du serveur Vault
 * @param {Function} options.baseHeaders - Fonction retournant les headers de base
 * @param {Function} options.axiosConfig - Fonction retournant la config axios
 * @param {Object|null} options.selectedEngine - Engine actuellement selectionne
 * @param {Array} options.secretEngines - Liste de tous les engines
 * @param {boolean} options.multiVaultSearch - Mode recherche multi-vault actif
 * @param {Object} options.vaultApi - Service Vault API (read/write/list/delete)
 * @param {Object} options.fetchSecretsRef - Ref vers la fonction fetchSecrets (pour eviter dep circulaire)
 * @param {Function} options.setAllVaultSecrets - Setter pour les secrets multi-vault
 * @param {Function} options.setLoadingAllSecrets - Setter pour l'indicateur de chargement
 * @param {Object} [options.readEnginesRef] - Ref vers la lecture multi-coffres avec cache (useSecrets
 *   readEnginesWithCache) : seule l'entrée écrite est relue ; absente, tous les coffres sont relus
 * @param {Function} options.showToast - Fonction pour afficher un toast
 * @param {Function} options.t - Fonction de traduction
 * @returns {Object} Etats et handlers de tags
 */
export function useTags({
  vaultUrl, baseHeaders, axiosConfig,
  selectedEngine, secretEngines, multiVaultSearch,
  vaultApi, fetchSecretsRef,
  setAllVaultSecrets, setLoadingAllSecrets,
  readEnginesRef,
  showToast, t
}) {
  const [discoveredTags, setDiscoveredTags] = useState([]);
  // Absence (404) ou refus (403) du secret tags-shared/data/tags, mémorisés pour la session courante
  // (référence de baseHeaders, qui change avec le jeton / l'URL) et jusqu'à la prochaine écriture.
  const sharedTagsMissingRef = useRef(null);

  const { writeSecretV2, writeSecretV1 } = vaultApi;

  // Recharge tous les secrets de tous les coffres (mode recherche multi-coffre).
  // Renvoie le message d'une lecture incomplète (liste tronquée par une borne, entrées ou coffres
  // illisibles), ou null : l'appelant l'affiche au lieu du toast de succès.
  // PERFORMANCE : avec la lecture multi-coffres à cache (readEnginesRef), seules les entrées écrites depuis
  // la lecture précédente sont relues (avant : toutes les entrées de tous les coffres).
  const reloadAllVaultSecrets = async () => {
    setLoadingAllSecrets(true);
    try {
      const readEngines = readEnginesRef?.current;
      const result = typeof readEngines === 'function'
        ? await readEngines(secretEngines)
        : await readAllSecrets(vaultApi, secretEngines);
      setAllVaultSecrets(result.secrets);
      return incompleteReadMessage(result, t);
    } finally {
      setLoadingAllSecrets(false);
    }
  };

  // Rafraîchissement après l'écriture d'un tag (entrée `entryName` relue, et non tout le coffre).
  // Recherche multi-coffre : les résultats sont relus ET, si l'entrée est celle du coffre sélectionné,
  // sa liste aussi (APP-5 : restée périmée, elle faisait prendre « Modifier » depuis les résultats pour
  // une création, refusée, et réécrivait l'ancien tag une fois la recherche vidée). Renvoie le message
  // d'une lecture incomplète, ou null.
  const refreshAfterTagWrite = async (targetEngine, entryName) => {
    const targeted = { incremental: true, touched: [entryName] };
    if (!multiVaultSearch) {
      await fetchSecretsRef.current(targetEngine, undefined, targeted);
      return null;
    }
    const incomplete = await reloadAllVaultSecrets();
    if (selectedEngine && targetEngine.name === selectedEngine.name) await fetchSecretsRef.current(selectedEngine, undefined, targeted);
    return incomplete;
  };

  // Toast de fin : succès, ou avertissement si le rechargement multi-coffre est incomplet
  const toastAfterReload = (incomplete, successKey) => {
    if (incomplete) showToast(incomplete, 'warning', 10000);
    else showToast(t(successKey), 'success', 1500);
  };

  const extractTagsFromSecrets = (secretsList) => {
    const allTags = new Set();
    secretsList.forEach(secret => {
      if (secret.tags && typeof secret.tags === 'string') {
        // Parser les tags (separes par espaces, virgules ou points-virgules)
        const tags = secret.tags.split(/[\s,;]+/).filter(t => t.trim());
        tags.forEach(tag => allTags.add(tag.trim()));
      }
    });
    return Array.from(allTags).sort();
  };

  // Charger les tags partages depuis le coffre tags-shared. Le secret est souvent absent : sans
  // cache, chaque rafraichissement de liste refaisait la requete (et une 404 dans le journal).
  const loadSharedTags = async () => {
    const missing = sharedTagsMissingRef.current;
    if (missing && missing.headers === baseHeaders && missing.seq === sharedTagsWriteSeq) return [];
    const seqAtRequest = sharedTagsWriteSeq;
    try {
      const res = await axios.get(`${vaultUrl}/v1/tags-shared/data/tags`, axiosConfig({ headers: baseHeaders() }));
      sharedTagsMissingRef.current = null;
      return res.data?.data?.data?.tags || [];
    } catch (err) {
      const status = err?.response?.status;
      if (status === 404 || status === 403) {
        sharedTagsMissingRef.current = { headers: baseHeaders, seq: seqAtRequest };
      } else {
        secureLogger.warn('[TAGS] Impossible de charger les tags partages');
      }
      return [];
    }
  };

  // Fusionner les tags decouverts et les tags partages
  const mergeDiscoveredAndSharedTags = async (secretsList) => {
    const discoveredFromSecrets = extractTagsFromSecrets(secretsList);
    const sharedFromVault = await loadSharedTags();

    // Fusionner et dedupliquer
    const allTags = new Set([...discoveredFromSecrets, ...sharedFromVault]);
    return Array.from(allTags).sort();
  };

  /**
   * Écrit le changement de tags `changeTags(tags) => tags` sur l'entrée `secret` du coffre `targetEngine`.
   * Vault partagé : la ligne affichée peut être périmée (cache de lecture jusqu'à 2 min) ; la réécrire
   * telle quelle remplaçait une version plus récente écrite par un autre client (mot de passe changé
   * ailleurs perdu). Le tag est donc appliqué au contenu COURANT de l'entrée, relu juste avant, et écrit
   * en check-and-set (KV v2) sur la version relue : une écriture concurrente fait échouer l'opération
   * (message d'erreur) au lieu d'être écrasée. Lecture refusée (403) : repli sur la ligne affichée.
   */
  const writeTagChange = async (targetEngine, secret, changeTags) => {
    let base = secret;
    let cas;
    try {
      const current = await readCurrentEntry(vaultApi, targetEngine, secret.name);
      if (current) {
        base = { ...current.item, name: secret.name };
        if (targetEngine.version === 2 && current.version) cas = current.version;
      }
    } catch (err) {
      if (err?.response?.status !== 403) throw err; // absente / supprimée ailleurs, réseau : rien n'est écrit
    }
    const updatedSecret = { ...base, tags: changeTags(base.tags) };
    if (targetEngine.version === 2) {
      await writeSecretV2(targetEngine, updatedSecret, cas !== undefined ? { cas } : undefined);
    } else {
      await writeSecretV1(targetEngine, updatedSecret);
    }
  };

  /**
   * Entrée modifiée (écriture concurrente refusée par check-and-set) ou supprimée ailleurs (404 à la
   * relecture) : rien n'a été écrit. Avertissement dédié et relecture de l'entrée ; vrai si traité.
   */
  const handleChangedElsewhere = async (err, secret) => {
    if (!isCasConflict(err) && err?.response?.status !== 404) return false;
    showToast(t('error.secretChangedElsewhere', { name: isolateInRtl(secret?.name || '', 'auto') }), 'error', 8000);
    try {
      const engine = secret?.engineName ? secretEngines.find(e => e.name === secret.engineName) : selectedEngine;
      if (engine) await refreshAfterTagWrite(engine, secret.name);
    } catch { /* relecture best effort */ }
    return true;
  };

  const handleAddTagToSecret = async (secret, tagToAdd) => {
    try {
      // Ajouter le tag aux tags existants (de la version COURANTE de l'entrée, voir writeTagChange)
      const addTag = (tags) => [...(tags ? tags.split(/[\s,;]+/).filter(t => t) : []), tagToAdd].join(' ');

      // Determiner quel engine utiliser (important pour la recherche multi-vault)
      let targetEngine = selectedEngine;
      if (secret.engineName && secret.engineVersion) {
        // En mode recherche multi-vault, trouver l'engine correspondant
        targetEngine = secretEngines.find(
          e => e.name === secret.engineName && e.version === secret.engineVersion
        );
      }

      if (!targetEngine) {
        showToast(t('error.engineNotFound'), 'error');
        return;
      }

      // Sauvegarder dans Vault
      await writeTagChange(targetEngine, secret, addTag);

      // Rafraichir la liste des secrets (entrée modifiée seule relue)
      toastAfterReload(await refreshAfterTagWrite(targetEngine, secret.name), 'toast.tagAdded');
    } catch (err) {
      if (await handleChangedElsewhere(err, secret)) return;
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.tagAdd')} ${msg}`, 'error');
    }
  };

  const handleRemoveTagFromSecret = async (secret, tagToRemove) => {
    try {
      // Retirer le tag des tags existants (de la version COURANTE de l'entrée, voir writeTagChange)
      const removeTag = (tags) => (tags ? tags.split(/[\s,;]+/).filter(t => t) : []).filter(tag => tag !== tagToRemove).join(' ');

      // Determiner quel engine utiliser (important pour la recherche multi-vault)
      let targetEngine = selectedEngine;
      if (secret.engineName && secret.engineVersion) {
        // En mode recherche multi-vault, trouver l'engine correspondant
        targetEngine = secretEngines.find(
          e => e.name === secret.engineName && e.version === secret.engineVersion
        );
      }

      if (!targetEngine) {
        showToast(t('error.engineNotFound'), 'error');
        return;
      }

      // Sauvegarder dans Vault
      await writeTagChange(targetEngine, secret, removeTag);

      // Rafraichir la liste des secrets (entrée modifiée seule relue)
      toastAfterReload(await refreshAfterTagWrite(targetEngine, secret.name), 'toast.tagRemoved');
    } catch (err) {
      if (await handleChangedElsewhere(err, secret)) return;
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.tagRemove')} ${msg}`, 'error');
    }
  };

  // Fonction pour generer une couleur unique et coherente pour chaque tag
  const getTagColor = (tag) => {
    const colors = [
      '#3b82f6', // blue
      '#10b981', // green
      '#f59e0b', // amber
      '#ef4444', // red
      '#8b5cf6', // violet
      '#ec4899', // pink
      '#06b6d4', // cyan
      '#f97316', // orange
      '#84cc16', // lime
      '#6366f1', // indigo
      '#14b8a6', // teal
      '#f43f5e', // rose
      '#a855f7', // purple
      '#22c55e', // green-500
      '#eab308', // yellow
      '#0ea5e9', // sky
      '#d946ef', // fuchsia
      '#fb923c', // orange-400
      '#4ade80', // green-400
      '#facc15'  // yellow-400
    ];

    // Hash simple base sur tous les caracteres du tag
    let hash = 0;
    for (let i = 0; i < tag.length; i++) {
      hash = ((hash << 5) - hash) + tag.charCodeAt(i);
      hash = hash & hash; // Convert to 32bit integer
    }

    return colors[Math.abs(hash) % colors.length];
  };

  return {
    discoveredTags, setDiscoveredTags,
    extractTagsFromSecrets,
    loadSharedTags,
    mergeDiscoveredAndSharedTags,
    handleAddTagToSecret,
    handleRemoveTagFromSecret,
    getTagColor
  };
}
