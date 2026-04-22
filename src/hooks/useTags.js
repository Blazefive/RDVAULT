import { useState } from 'react';
import axios from 'axios';
import * as tagManager from '../utils/tagManager';
import secureLogger from '../secureLogger';
import { sanitizeErrorMessage } from '../utils/security';

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
 * @param {Function} options.showToast - Fonction pour afficher un toast
 * @param {Function} options.t - Fonction de traduction
 * @returns {Object} Etats et handlers de tags
 */
export function useTags({
  vaultUrl, baseHeaders, axiosConfig,
  selectedEngine, secretEngines, multiVaultSearch,
  vaultApi, fetchSecretsRef,
  setAllVaultSecrets, setLoadingAllSecrets,
  showToast, t
}) {
  const [discoveredTags, setDiscoveredTags] = useState([]);

  const { readSecretV2, writeSecretV2, listKeysV2, readSecretV1, writeSecretV1, listKeysV1 } = vaultApi;

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

  // Charger les tags partages depuis le coffre tags-shared
  const loadSharedTags = async () => {
    try {
      const sharedTags = await tagManager.getSharedTags(vaultUrl, baseHeaders(), axiosConfig, axios);
      return sharedTags;
    } catch (err) {
      secureLogger.warn('[TAGS] Impossible de charger les tags partages');
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

  const handleAddTagToSecret = async (secret, tagToAdd) => {
    try {
      // Ajouter le tag aux tags existants
      const currentTags = secret.tags ? secret.tags.split(/[\s,;]+/).filter(t => t) : [];
      const newTags = [...currentTags, tagToAdd].join(' ');

      // Mettre a jour l'entree
      const updatedSecret = { ...secret, tags: newTags };

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
      if (targetEngine.version === 2) {
        await writeSecretV2(targetEngine, updatedSecret);
      } else {
        await writeSecretV1(targetEngine, updatedSecret);
      }

      // Rafraichir la liste des secrets
      if (multiVaultSearch) {
        // En mode recherche multi-vault, recharger tous les secrets
        setLoadingAllSecrets(true);
        const allEngineSecrets = await Promise.all(
          secretEngines.map(async (engine) => {
            try {
              const keys = engine.version === 2 ? await listKeysV2(engine) : await listKeysV1(engine);
              const secretPromises = keys.map(async (key) => {
                try {
                  const s = engine.version === 2 ? await readSecretV2(engine, key) : await readSecretV1(engine, key);
                  return { ...s, engineName: engine.name, engineVersion: engine.version };
                } catch { return null; }
              });
              return (await Promise.all(secretPromises)).filter(s => s !== null);
            } catch { return []; }
          })
        );
        const allSecrets = allEngineSecrets.flat();
        setAllVaultSecrets(allSecrets);
        setLoadingAllSecrets(false);
      } else {
        await fetchSecretsRef.current(targetEngine);
      }

      showToast(t('toast.tagAdded'), 'success', 1500);
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.tagAdd')} ${msg}`, 'error');
    }
  };

  const handleRemoveTagFromSecret = async (secret, tagToRemove) => {
    try {
      // Retirer le tag des tags existants
      const currentTags = secret.tags ? secret.tags.split(/[\s,;]+/).filter(t => t) : [];
      const newTags = currentTags.filter(tag => tag !== tagToRemove).join(' ');

      // Mettre a jour l'entree
      const updatedSecret = { ...secret, tags: newTags };

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
      if (targetEngine.version === 2) {
        await writeSecretV2(targetEngine, updatedSecret);
      } else {
        await writeSecretV1(targetEngine, updatedSecret);
      }

      // Rafraichir la liste des secrets
      if (multiVaultSearch) {
        // En mode recherche multi-vault, recharger tous les secrets
        setLoadingAllSecrets(true);
        const allEngineSecrets = await Promise.all(
          secretEngines.map(async (engine) => {
            try {
              const keys = engine.version === 2 ? await listKeysV2(engine) : await listKeysV1(engine);
              const secretPromises = keys.map(async (key) => {
                try {
                  const s = engine.version === 2 ? await readSecretV2(engine, key) : await readSecretV1(engine, key);
                  return { ...s, engineName: engine.name, engineVersion: engine.version };
                } catch { return null; }
              });
              return (await Promise.all(secretPromises)).filter(s => s !== null);
            } catch { return []; }
          })
        );
        const allSecrets = allEngineSecrets.flat();
        setAllVaultSecrets(allSecrets);
        setLoadingAllSecrets(false);
      } else {
        await fetchSecretsRef.current(targetEngine);
      }

      showToast(t('toast.tagRemoved'), 'success', 1500);
    } catch (err) {
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
